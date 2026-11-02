//! Fetching the discovery document over a real loopback connection: an error status, a document from plain HTTP and a closed port are each unreachable, and a redirect is never followed (E-2, E-3, T-23).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::time::Duration;

use axum::Router;
use axum::http::{StatusCode, header};
use axum::response::IntoResponse;
use axum::routing::get;
use one_access_client::discovery::{DiscoveryError, PATH};
use one_access_client::fetch::{FetchError, discover};

async fn serve(router: Router) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await });
    format!("http://{addr}")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn e_3_an_error_status_is_unreachable() {
    let issuer =
        serve(Router::new().route(PATH, get(|| async { StatusCode::SERVICE_UNAVAILABLE }))).await;
    assert_eq!(
        discover(&client(), &issuer).await,
        Err(FetchError::Status(503))
    );
}

#[tokio::test]
async fn e_3_a_document_over_plain_http_is_refused() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://{}", listener.local_addr().unwrap());
    let doc = serde_json::json!({
        "policy_decision_point": issuer,
        "access_evaluation_endpoint": format!("{issuer}/access/v1/evaluation"),
        "capabilities": ["urn:esuiss:access:adp:1"],
    })
    .to_string();
    let router = Router::new().route(
        PATH,
        get(move || async move { ([(header::CONTENT_TYPE, "application/json")], doc) }),
    );
    tokio::spawn(async move { axum::serve(listener, router).await });
    assert_eq!(
        discover(&client(), &issuer).await,
        Err(FetchError::Discovery(DiscoveryError::Origin))
    );
}

#[tokio::test]
async fn e_3_a_redirect_is_not_followed() {
    let issuer = serve(Router::new().route(
        PATH,
        get(|| async {
            (
                StatusCode::FOUND,
                [(header::LOCATION, "https://elsewhere.example/")],
            )
                .into_response()
        }),
    ))
    .await;
    assert_eq!(
        discover(&client(), &issuer).await,
        Err(FetchError::Status(302))
    );
}

#[tokio::test]
async fn t_23_a_closed_port_is_unreachable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(
        discover(&client(), &format!("http://{addr}")).await,
        Err(FetchError::Connect)
    );
}
