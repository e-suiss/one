//! Start-up checks against a real PostgreSQL (OP-14, T-32; Access OP-52, OP-53): full TLS verification is always requested, old servers and oversized pools are refused, a plain connection fails the TLS check and a single node fails a replicated declaration.

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use one_store::StoreError;
use one_store::connect::{
    ConnectError, Durability, Target, check_server, fits, options, supported,
};
use one_store::testing::fresh;
use sqlx::postgres::PgSslMode;

#[test]
fn t_32_options_verify_the_server_fully() {
    let t = Target {
        host: "db.tr-1.internal",
        port: 5432,
        database: "one",
        user: "one_api",
        password: "x",
        root_cert: b"-----BEGIN CERTIFICATE-----\n",
    };
    assert!(matches!(options(&t).get_ssl_mode(), PgSslMode::VerifyFull));
}

#[test]
fn t_5_version_and_pool_limits() {
    assert!(supported(180_000) && supported(180_006));
    assert!(!supported(170_005));
    assert!(fits(70, 100) && !fits(71, 100));
}

#[tokio::test]
async fn op_14_the_server_check_refuses_unsafe_settings() {
    let db = fresh().await.unwrap();
    let single = Durability::SingleNode;
    check_server(&db.app, 8, false, single).await.unwrap();
    assert!(matches!(
        check_server(&db.app, 8, true, single).await,
        Err(StoreError::Unsafe(ConnectError::NoTls))
    ));
    assert!(matches!(
        check_server(&db.app, 100_000, false, single).await,
        Err(StoreError::Unsafe(ConnectError::PoolSize { .. }))
    ));
    assert!(matches!(
        check_server(&db.app, 8, false, Durability::Replicated).await,
        Err(StoreError::Unsafe(ConnectError::Durability { .. }))
    ));
}
