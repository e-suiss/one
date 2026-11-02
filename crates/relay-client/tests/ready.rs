//! Relay readiness over a real loopback connection: a success is ready, an error status and a closed port are unreachable (E-2, T-23).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::time::Duration;

use axum::Router;
use axum::http::StatusCode;
use axum::routing::get;
use one_relay_client::{READY_PATH, Unreachable, ready};

async fn serve(status: StatusCode) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let router = Router::new().route(READY_PATH, get(move || async move { status }));
    tokio::spawn(async move { axum::serve(listener, router).await });
    format!("http://{addr}/")
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn t_23_relay_readiness() {
    assert_eq!(ready(&client(), &serve(StatusCode::OK).await).await, Ok(()));
    assert_eq!(
        ready(&client(), &serve(StatusCode::SERVICE_UNAVAILABLE).await).await,
        Err(Unreachable::Status(503))
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    drop(listener);
    assert_eq!(
        ready(&client(), &format!("http://{addr}")).await,
        Err(Unreachable::Connect)
    );
}
