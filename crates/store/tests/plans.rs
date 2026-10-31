//! Plans of the frequent queries (T-32 (10)): with sequential scans priced out, each still finds an index, so a missing or unusable index fails here instead of in production. The statements match the crate's queries; a new frequent query is added here with its index.

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use one_store::testing::fresh;
use sqlx::{AssertSqlSafe, Executor, PgPool, Row};

const QUEUE: [&str; 2] = [
    "SELECT owner, job_id FROM one.job
      WHERE (state = 'pending' AND run_after <= now()) OR (state = 'running' AND lease_until < now())
      ORDER BY run_after, job_id LIMIT 10 FOR UPDATE SKIP LOCKED",
    "SELECT owner, id FROM one.outbox
      WHERE state = 'pending' AND run_after <= now()
      ORDER BY run_after, id LIMIT 10 FOR UPDATE SKIP LOCKED",
];

const OWNER: [&str; 6] = [
    "SELECT d.retention_class FROM one.record_key k
       JOIN one.class_dek d ON d.owner = k.owner AND d.dek_id = k.dek_id
      WHERE k.owner = 'party:a' AND k.record_key_id = '019a0000-0000-7001-8000-000000000001'",
    "UPDATE one.record SET status = 'deleted', deleted_at = now()
      WHERE owner = 'party:a' AND record_key_id = '019a0000-0000-7001-8000-000000000001' AND deleted_at IS NULL",
    "SELECT DISTINCT retention_class FROM one.legal_hold WHERE owner = 'party:a' AND deleted_at IS NULL",
    "SELECT request_digest, ciphertext FROM one.idempotency WHERE owner = 'party:a' AND idempotency_key = '\\x00'",
    "SELECT dek_id FROM one.class_dek WHERE owner = 'party:a' AND retention_class = 'one_memory' AND deleted_at IS NULL",
    "UPDATE one.job SET state = 'pending', run_after = now()
      WHERE owner = 'party:a' AND job_kind = 'shred' AND state = 'held'",
];

async fn seq_scans(pool: &PgPool, owner: Option<&str>, sql: &str) -> Vec<String> {
    let mut tx = pool.begin().await.unwrap();
    tx.execute("SET LOCAL enable_seqscan = off").await.unwrap();
    if let Some(owner) = owner {
        sqlx::query("SELECT set_config('app.owner', $1, true)")
            .bind(owner)
            .execute(&mut *tx)
            .await
            .unwrap();
    }
    let plan = sqlx::query(AssertSqlSafe(format!("EXPLAIN {sql}")))
        .fetch_all(&mut *tx)
        .await
        .unwrap();
    tx.rollback().await.unwrap();
    plan.iter()
        .map(|r| r.get::<String, _>(0))
        .filter(|line| line.contains("Seq Scan"))
        .collect()
}

#[tokio::test]
async fn t_32_frequent_queries_use_an_index() {
    let db = fresh().await.unwrap();
    let mut bad = Vec::new();
    for sql in QUEUE {
        for line in seq_scans(&db.queue, None, sql).await {
            bad.push(format!("{sql}\n  {line}"));
        }
    }
    for sql in OWNER {
        for line in seq_scans(&db.app, Some("party:a"), sql).await {
            bad.push(format!("{sql}\n  {line}"));
        }
    }
    assert!(bad.is_empty(), "{}", bad.join("\n"));
}
