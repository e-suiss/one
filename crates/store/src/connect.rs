//! Opening the database safely, as Access does (OP-14, T-32; Access OP-24, OP-52, OP-53): TLS with full verification against an explicit root, SCRAM only, PostgreSQL 18 or later, bounded transactions, durable commits and pools that fit the server.

use std::time::Duration;

use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions, PgSslMode};

use crate::StoreError;

/// Oldest server version accepted, the same as Access and Work (T-5).
pub const MIN_SERVER_VERSION: i32 = 180_000;

/// Longest transaction of an application role.
pub const TRANSACTION_TIMEOUT: &str = "30s";

/// Longest idle-in-transaction pause.
pub const IDLE_IN_TRANSACTION_TIMEOUT: &str = "10s";

/// Share of `max_connections` the pools may take together.
pub const POOL_SHARE_PERCENT: u32 = 70;

/// Where and as whom to connect.
pub struct Target<'a> {
    /// Server host name, checked against its certificate.
    pub host: &'a str,
    /// Port.
    pub port: u16,
    /// Database.
    pub database: &'a str,
    /// Login role.
    pub user: &'a str,
    /// Its password, from the process secret store (T-51).
    pub password: &'a str,
    /// PEM of the root the server certificate must chain to.
    pub root_cert: &'a [u8],
}

/// Why the database is not safe to use; the process does not start.
#[derive(Debug, thiserror::Error)]
pub enum ConnectError {
    /// Server older than PostgreSQL 18.
    #[error("server version {0} is older than PostgreSQL 18")]
    Version(i32),
    /// Passwords are not stored as SCRAM.
    #[error("password_encryption is {0}, not scram-sha-256")]
    Scram(String),
    /// The connection is not encrypted.
    #[error("the connection does not use TLS")]
    NoTls,
    /// A commit may be acknowledged before it is durable (Access OP-24).
    #[error(
        "synchronous_commit is {commit} with standbys {standbys:?}; commits must wait for durability"
    )]
    Durability {
        /// `synchronous_commit`.
        commit: String,
        /// `synchronous_standby_names`.
        standbys: String,
    },
    /// The pools would take more than their share of `max_connections`.
    #[error(
        "pools need {need} connections, more than {POOL_SHARE_PERCENT}% of max_connections ({max})"
    )]
    PoolSize {
        /// Connections the pools need.
        need: u32,
        /// `max_connections`.
        max: u32,
    },
}

/// Connection options: `verify-full` against `root_cert`, the timeouts as startup parameters.
#[must_use]
pub fn options(t: &Target<'_>) -> PgConnectOptions {
    PgConnectOptions::new()
        .host(t.host)
        .port(t.port)
        .database(t.database)
        .username(t.user)
        .password(t.password)
        .ssl_mode(PgSslMode::VerifyFull)
        .ssl_root_cert_from_pem(t.root_cert.to_vec())
        .application_name("one")
        .options([
            ("transaction_timeout", TRANSACTION_TIMEOUT),
            (
                "idle_in_transaction_session_timeout",
                IDLE_IN_TRANSACTION_TIMEOUT,
            ),
        ])
}

/// A pool of `size` connections with a short acquire timeout; the queue lives in the application.
///
/// # Errors
/// [`StoreError::Db`].
pub async fn pool(opts: PgConnectOptions, size: u32) -> Result<PgPool, StoreError> {
    Ok(PgPoolOptions::new()
        .max_connections(size)
        .min_connections(size.min(2))
        .acquire_timeout(Duration::from_secs(2))
        .connect_with(opts)
        .await?)
}

/// Whether a `server_version_num` is supported.
#[must_use]
pub const fn supported(version: i32) -> bool {
    version >= MIN_SERVER_VERSION
}

/// Whether `pools` connections fit `max_connections`.
#[must_use]
pub const fn fits(pools: u32, max_connections: u32) -> bool {
    (pools as u64).saturating_mul(100)
        <= (max_connections as u64).saturating_mul(POOL_SHARE_PERCENT as u64)
}

/// How the deployment declares its durability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Synchronous standbys required (Access OP-24).
    Replicated,
    /// A single node, for the local stack and CI only.
    SingleNode,
}

/// Checks the server before the process serves anything: version, SCRAM, TLS on this connection, durable commits as declared and room for `pools` connections.
///
/// # Errors
/// [`StoreError::Unsafe`] with the first failed check, [`StoreError::Db`].
pub async fn check_server(
    pool: &PgPool,
    pools: u32,
    require_tls: bool,
    durability: Durability,
) -> Result<(), StoreError> {
    let row = sqlx::query!(
        r#"SELECT current_setting('server_version_num')::int AS "version!",
                  current_setting('password_encryption') AS "scram!",
                  current_setting('max_connections')::int AS "max!",
                  coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false) AS "tls!",
                  current_setting('synchronous_commit') AS "commit!",
                  current_setting('synchronous_standby_names') AS "standbys!""#
    )
    .fetch_one(pool)
    .await?;
    if !supported(row.version) {
        return Err(ConnectError::Version(row.version).into());
    }
    if row.scram != "scram-sha-256" {
        return Err(ConnectError::Scram(row.scram).into());
    }
    if require_tls && !row.tls {
        return Err(ConnectError::NoTls.into());
    }
    let standbys_ok = durability == Durability::SingleNode || !row.standbys.trim().is_empty();
    if !matches!(row.commit.as_str(), "on" | "remote_apply") || !standbys_ok {
        return Err(ConnectError::Durability {
            commit: row.commit,
            standbys: row.standbys,
        }
        .into());
    }
    let max = u32::try_from(row.max).map_err(|_| StoreError::Corrupt)?;
    if !fits(pools, max) {
        return Err(ConnectError::PoolSize { need: pools, max }.into());
    }
    Ok(())
}
