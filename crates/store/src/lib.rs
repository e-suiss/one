//! PostgreSQL access for One: migrations, owner-scoped transactions under forced row-level security, the outbox, idempotency and the job queue; all cloud SQL lives in this crate (T-32 (1, 2, 3), OP-3, OP-27).

pub mod idempotency;
pub mod jobs;
pub mod outbox;
pub mod scope;

#[cfg(feature = "testing")]
pub mod testing;

/// The connection pool type, so other crates need no driver dependency (T-32 (2)).
pub use sqlx::PgPool as Pool;

/// Row identifiers (`UUIDv7`, T-32 (10)).
pub use uuid::Uuid;

/// The embedded migrations; run by the separate migration step, never at application start (OP-27).
pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!();

/// Cluster roles, created once by the database administrator (T-32 (8)).
pub const BOOTSTRAP_ROLES: &str = include_str!("../bootstrap/roles.sql");

/// Per-database setup run by the database administrator before the first migration.
pub const BOOTSTRAP_DATABASE: &str = include_str!("../bootstrap/database.sql");

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// The database rejected or could not run the statement.
    #[error("database: {0}")]
    Db(#[from] sqlx::Error),
    /// The migrations could not be applied.
    #[error("migrations: {0}")]
    Migrate(#[from] sqlx::migrate::MigrateError),
    /// An owner identifier is not a valid scope.
    #[error("invalid owner identifier")]
    Owner,
    /// The same idempotency key was used with different content (OP-3).
    #[error("idempotency key reused with different content")]
    Conflict,
    /// A stored row does not match the model.
    #[error("stored row is malformed")]
    Corrupt,
}

/// Runs the migrations as a member of `one_owner`, from the separate migration step and never at application start (OP-27).
///
/// # Errors
/// [`StoreError::Migrate`].
pub async fn migrate(owner: &Pool) -> Result<(), StoreError> {
    MIGRATOR.run(owner).await?;
    Ok(())
}
