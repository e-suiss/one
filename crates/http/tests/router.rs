//! Router behaviour: problem fallback and readiness (T-31, T-40 (7)).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use one_http::{Limits, Probe, Sources, internal_router, public_router};
use one_runtime::UnixNanos;
use one_testkit::{SeededRng, VirtualClock};
use tower::ServiceExt;

fn sources() -> Sources {
    Sources {
        clock: Arc::new(VirtualClock::new(UnixNanos(1_791_504_000_000_000_000))),
        rng: Arc::new(SeededRng::new(7)),
    }
}

struct Fixed(&'static str, bool);

impl Probe for Fixed {
    fn name(&self) -> &'static str {
        self.0
    }
    fn check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>> {
        let ready = self.1;
        Box::pin(async move { ready })
    }
}

async fn call(router: axum::Router, path: &str) -> (StatusCode, String, String) {
    let response = router
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let body = response.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8(body.to_vec()).unwrap(),
    )
}

#[tokio::test]
async fn t_31_unknown_path_is_an_rfc_9457_problem() {
    let (status, content_type, body) =
        call(public_router(Limits::default(), sources()), "/nope").await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(content_type, "application/problem+json");
    assert!(body.contains("\"code\":\"not_found\""));
}

#[tokio::test]
async fn t_31_every_response_has_a_request_id_and_mutations_need_a_key() {
    let response = public_router(Limits::default(), sources())
        .oneshot(Request::post("/x").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let id = response
        .headers()
        .get("request-id")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    assert!(id.starts_with("req_") && id.len() == 30, "{id}");
}

#[tokio::test]
async fn t_40_livez_answers_and_readyz_follows_probes() {
    let (status, _, _) = call(
        internal_router(Vec::new(), Limits::default(), sources()),
        "/livez",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let ok: Vec<Arc<dyn Probe>> = vec![Arc::new(Fixed("postgres", true))];
    let (status, _, _) = call(internal_router(ok, Limits::default(), sources()), "/readyz").await;
    assert_eq!(status, StatusCode::OK);

    let down: Vec<Arc<dyn Probe>> = vec![
        Arc::new(Fixed("postgres", true)),
        Arc::new(Fixed("objects", false)),
    ];
    let (status, _, body) = call(
        internal_router(down, Limits::default(), sources()),
        "/readyz",
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(body.contains("\"objects\""));
}
