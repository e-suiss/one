//! The HTTP layer of `one-server`: a hardened public router answering RFC 9457 problems and an internal router with `/livez` and `/readyz` (T-31, T-40 (7)).

pub mod openapi;
mod problem;
pub mod rules;

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tower_http::catch_panic::CatchPanicLayer;
use tower_http::limit::RequestBodyLimitLayer;
use tower_http::timeout::TimeoutLayer;

pub use problem::Problem;
pub use rules::Sources;

/// Explicit request limits; framework defaults are never relied on.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
    /// Maximum request body size in bytes.
    pub max_body_bytes: usize,
    /// Whole-request timeout.
    pub request_timeout: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_body_bytes: 256 * 1024,
            request_timeout: Duration::from_secs(10),
        }
    }
}

/// A readiness dependency: only PostgreSQL and the object store make the process unready (T-40 (7)).
pub trait Probe: Send + Sync {
    /// Stable name shown in `/readyz`.
    fn name(&self) -> &'static str;
    /// Resolves to `true` when the dependency answers.
    fn check(&self) -> Pin<Box<dyn Future<Output = bool> + Send + '_>>;
}

#[derive(Debug, Serialize)]
struct ProbeStatus {
    name: &'static str,
    ready: bool,
}

#[derive(Debug, Serialize)]
struct Readiness {
    ready: bool,
    probes: Vec<ProbeStatus>,
}

/// The public router: no routes yet beyond the problem fallback; every response carries `Request-Id` and every mutation needs `Idempotency-Key`.
pub fn public_router(limits: Limits, sources: Sources) -> Router {
    let routes = Router::new()
        .fallback(not_found)
        .layer(axum::middleware::from_fn(rules::idempotency));
    harden(with_request_id(routes, sources), limits)
}

fn with_request_id(routes: Router, sources: Sources) -> Router {
    routes.layer(axum::middleware::from_fn_with_state(
        sources,
        rules::request_id,
    ))
}

/// The internal router with `/livez` and `/readyz`.
pub fn internal_router(probes: Vec<Arc<dyn Probe>>, limits: Limits, sources: Sources) -> Router {
    let routes = Router::new()
        .route("/livez", get(|| async { StatusCode::NO_CONTENT }))
        .route(
            "/readyz",
            get(move || {
                let probes = probes.clone();
                async move { readyz(&probes).await }
            }),
        )
        .fallback(not_found);
    harden(with_request_id(routes, sources), limits)
}

async fn readyz(probes: &[Arc<dyn Probe>]) -> (StatusCode, Json<Readiness>) {
    let mut statuses = Vec::with_capacity(probes.len());
    for probe in probes {
        statuses.push(ProbeStatus {
            name: probe.name(),
            ready: probe.check().await,
        });
    }
    let ready = statuses.iter().all(|s| s.ready);
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (
        status,
        Json(Readiness {
            ready,
            probes: statuses,
        }),
    )
}

/// Wraps routes in the shared outer stack; apply it last.
pub fn harden(routes: Router, limits: Limits) -> Router {
    routes
        .layer(RequestBodyLimitLayer::new(limits.max_body_bytes))
        .layer(TimeoutLayer::with_status_code(
            StatusCode::SERVICE_UNAVAILABLE,
            limits.request_timeout,
        ))
        .layer(CatchPanicLayer::custom(problem::from_panic))
}

async fn not_found() -> Problem {
    Problem::new(StatusCode::NOT_FOUND, "not_found", "Not Found")
}
