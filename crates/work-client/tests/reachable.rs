//! Work reachability over a real loopback connection: any HTTP answer, a 404 included, is reachable and a closed port is not (E-2, T-23).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::time::Duration;

use axum::Router;
use one_work_client::{Unreachable, reachable};

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

#[tokio::test]
async fn t_23_work_reachability() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, Router::new()).await });
    assert_eq!(
        reachable(&client(), &format!("http://{addr}")).await,
        Ok(())
    );
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = closed.local_addr().unwrap();
    drop(closed);
    assert_eq!(
        reachable(&client(), &format!("http://{addr}")).await,
        Err(Unreachable::Connect)
    );
}
