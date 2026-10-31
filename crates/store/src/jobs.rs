//! The job queue (T-27 (7), OP-12, OP-16): owners enqueue idempotent jobs in their own transaction; workers in `one_queue` lease due or expired jobs with `FOR UPDATE SKIP LOCKED`, and only the lease holder, identified by the attempt count it leased, can finish or release a job. Rows are never deleted.

use one_proto::JobId;
use one_proto::key_permission::PermissionId;
use sqlx::PgPool;
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;

/// The closed `job_kind` list of `conformance/store/plain-columns.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKind {
    /// Memory consolidation.
    Consolidation,
    /// Personal model training.
    PersonalTraining,
    /// Recomputing vectors after an embedding model change (OP-24).
    Reembedding,
    /// Data export.
    Export,
    /// Retention expiry and deferred erasure (OP-12, OP-30 (1)).
    Shred,
}

impl JobKind {
    /// Every kind.
    pub const ALL: [Self; 5] = [
        Self::Consolidation,
        Self::PersonalTraining,
        Self::Reembedding,
        Self::Export,
        Self::Shred,
    ];

    /// The column value.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Consolidation => "consolidation",
            Self::PersonalTraining => "personal_training",
            Self::Reembedding => "reembedding",
            Self::Export => "export",
            Self::Shred => "shred",
        }
    }

    /// The kind of a column value.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == name)
    }
}

/// A job to enqueue.
pub struct NewJob<'a> {
    /// Row id.
    pub id: JobId,
    /// Kind.
    pub kind: JobKind,
    /// SHA-256 of the idempotency key.
    pub idempotency_key: &'a [u8; 32],
    /// Key permission the job runs under (PV-65), when it reads encrypted data without the user.
    pub permission_id: Option<PermissionId>,
    /// Seconds from now before the job is due.
    pub delay_secs: f64,
    /// Encrypted job parameters.
    pub payload: Option<&'a [u8]>,
}

impl OwnerTx {
    /// Enqueues `job`; returns `false` when a job with the same idempotency key exists.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn enqueue_job(&mut self, job: &NewJob<'_>) -> Result<bool, StoreError> {
        let inserted = sqlx::query!(
            "INSERT INTO one.job (owner, job_id, job_kind, idempotency_key, permission_id, run_after, ciphertext)
             VALUES ($1, $2, $3, $4, $5, now() + make_interval(secs => $6), $7)
             ON CONFLICT (owner, idempotency_key) DO NOTHING",
            self.owner.as_str(),
            Uuid::from_bytes(job.id.to_bytes()),
            job.kind.as_str(),
            job.idempotency_key.as_slice(),
            job.permission_id.map(|p| Uuid::from_bytes(*p.as_bytes())),
            job.delay_secs,
            job.payload
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        Ok(inserted == 1)
    }
}

/// A leased job.
pub struct Lease {
    /// Owner of the row.
    pub owner: String,
    /// Row id.
    pub job_id: JobId,
    /// Kind.
    pub kind: JobKind,
    /// Key permission the job runs under.
    pub permission_id: Option<PermissionId>,
    /// Attempt number of this lease; it identifies the holder.
    pub attempt: i32,
    /// Encrypted job parameters.
    pub payload: Option<Vec<u8>>,
}

/// Leases up to `limit` due jobs, and running jobs whose lease ran out, for `lease_secs`.
///
/// # Errors
/// [`StoreError::Corrupt`] for an unknown kind, [`StoreError::Db`].
pub async fn lease(queue: &PgPool, limit: i64, lease_secs: f64) -> Result<Vec<Lease>, StoreError> {
    let rows = sqlx::query!(
        r#"UPDATE one.job j
              SET state = 'running', attempts = j.attempts + 1,
                  lease_until = now() + make_interval(secs => $2)
             FROM (SELECT owner, job_id FROM one.job
                    WHERE (state = 'pending' AND run_after <= now())
                       OR (state = 'running' AND lease_until < now())
                    ORDER BY run_after, job_id
                    LIMIT $1
                      FOR UPDATE SKIP LOCKED) due
            WHERE j.owner = due.owner AND j.job_id = due.job_id
        RETURNING j.owner AS "owner!", j.job_id AS "job_id!", j.job_kind AS "job_kind!",
                  j.permission_id AS "permission_id?", j.attempts AS "attempts!", j.ciphertext AS "payload?""#,
        limit,
        lease_secs
    )
    .fetch_all(queue)
    .await?;
    rows.into_iter()
        .map(|r| {
            Ok(Lease {
                kind: JobKind::from_name(&r.job_kind).ok_or(StoreError::Corrupt)?,
                owner: r.owner,
                job_id: JobId::from_bytes(r.job_id.into_bytes())
                    .map_err(|_| StoreError::Corrupt)?,
                permission_id: r
                    .permission_id
                    .map(|p| PermissionId::from_bytes(p.into_bytes()).ok_or(StoreError::Corrupt))
                    .transpose()?,
                attempt: r.attempts,
                payload: r.payload,
            })
        })
        .collect()
}

/// Marks a leased job done; returns `false` when the lease is no longer held.
///
/// # Errors
/// [`StoreError::Db`].
pub async fn finish(queue: &PgPool, lease: &Lease) -> Result<bool, StoreError> {
    let done = sqlx::query!(
        "UPDATE one.job SET state = 'done', lease_until = NULL
          WHERE owner = $1 AND job_id = $2 AND state = 'running' AND attempts = $3",
        lease.owner,
        Uuid::from_bytes(lease.job_id.to_bytes()),
        lease.attempt
    )
    .execute(queue)
    .await?
    .rows_affected();
    Ok(done == 1)
}

/// Gives a leased job back: due again after `retry_after_secs`, or `failed` when `None`; returns `false` when the lease is no longer held.
///
/// # Errors
/// [`StoreError::Db`].
pub async fn release(
    queue: &PgPool,
    lease: &Lease,
    retry_after_secs: Option<f64>,
) -> Result<bool, StoreError> {
    let released = sqlx::query!(
        "UPDATE one.job
            SET state = CASE WHEN $4::float8 IS NULL THEN 'failed' ELSE 'pending' END,
                lease_until = NULL,
                run_after = CASE WHEN $4::float8 IS NULL THEN run_after
                                 ELSE now() + make_interval(secs => $4::float8) END
          WHERE owner = $1 AND job_id = $2 AND state = 'running' AND attempts = $3",
        lease.owner,
        Uuid::from_bytes(lease.job_id.to_bytes()),
        lease.attempt,
        retry_after_secs
    )
    .execute(queue)
    .await?
    .rows_affected();
    Ok(released == 1)
}
