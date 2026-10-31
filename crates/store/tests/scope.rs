//! Row-level security in behaviour: an owner sees and writes only its own rows, an unscoped statement writes nothing, rows cannot be deleted, encrypted columns cannot be rewritten in place, and the queue role cannot read personal tables (T-32 (3, 6, 8), OP-4, OP-6).

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use one_proto::EventId;
use one_store::outbox::NewEvent;
use one_store::scope::{Owner, OwnerTx};
use one_store::testing::{TestDb, fresh};
use one_store::{StoreError, Uuid};
use sqlx::{AssertSqlSafe, Row};

fn id(n: u8) -> Uuid {
    Uuid::from_bytes([0x01, 0x9a, 0, 0, 0, 0, 0x70, n, 0x80, 0, 0, 0, 0, 0, 0, n])
}

async fn account(db: &TestDb, owner: &str) -> Owner {
    let owner = Owner::new(owner).unwrap();
    let mut tx = OwnerTx::begin(&db.app, &owner).await.unwrap();
    tx.open_account("tr").await.unwrap();
    tx.commit().await.unwrap();
    owner
}

fn denied(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(sqlx::error::DatabaseError::code)
        .is_some_and(|c| c == "42501")
}

async fn seed_record(db: &TestDb, owner: &Owner) {
    let mut tx = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.owner', $1, true)")
        .bind(owner.as_str())
        .execute(&mut *tx)
        .await
        .unwrap();
    sqlx::query(
        "INSERT INTO one.class_dek (owner, dek_id, retention_class, kek_id, wrapped_dek)
         VALUES ($1, $2, 'one_memory', 'kek-1', $3)",
    )
    .bind(owner.as_str())
    .bind(id(10))
    .bind(vec![7_u8; 40])
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO one.record_key (owner, record_key_id, dek_id, wrapped_record_key) VALUES ($1, $2, $3, $4)",
    )
    .bind(owner.as_str())
    .bind(id(11))
    .bind(id(10))
    .bind(vec![8_u8; 40])
    .execute(&mut *tx)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO one.record (owner, id, version, status, retention_class, region, record_key_id, dek_id,
                                 ciphertext, ciphertext_len, promise_version)
         VALUES ($1, $2, 1, 'active', 'one_memory', 'tr', $3, $4, $5, 3, 1)",
    )
    .bind(owner.as_str())
    .bind(id(12))
    .bind(id(11))
    .bind(id(10))
    .bind(vec![1_u8, 2, 3])
    .execute(&mut *tx)
    .await
    .unwrap();
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn t_32_an_owner_sees_only_its_own_rows() {
    let db = fresh().await.unwrap();
    let a = account(&db, "party:a").await;
    let b = account(&db, "party:b").await;
    let mut tx = OwnerTx::begin(&db.app, &a).await.unwrap();
    tx.enqueue_event(&NewEvent {
        id: EventId::from_bytes(id(1).into_bytes()).unwrap(),
        event_type: "one.test",
        idempotency_key: &[1; 32],
        payload: b"x",
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();

    let mut c = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.owner', $1, true)")
        .bind(b.as_str())
        .execute(&mut *c)
        .await
        .unwrap();
    let seen: i64 = sqlx::query("SELECT count(*) FROM one.outbox")
        .fetch_one(&mut *c)
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0);
    let accounts: i64 = sqlx::query("SELECT count(*) FROM one.account")
        .fetch_one(&mut *c)
        .await
        .unwrap()
        .get(0);
    assert_eq!(accounts, 1);
    let foreign = sqlx::query("INSERT INTO one.outbox (owner, id, event_type, idempotency_key, ciphertext) VALUES ($1, $2, 'one.test', $3, $4)")
        .bind(a.as_str())
        .bind(id(2))
        .bind(vec![2_u8; 32])
        .bind(vec![0_u8])
        .execute(&mut *c)
        .await
        .unwrap_err();
    assert!(denied(&foreign), "{foreign}");
}

#[tokio::test]
async fn t_32_an_unscoped_statement_reads_and_writes_nothing() {
    let db = fresh().await.unwrap();
    account(&db, "party:a").await;
    let seen: i64 = sqlx::query("SELECT count(*) FROM one.account")
        .fetch_one(&db.app)
        .await
        .unwrap()
        .get(0);
    assert_eq!(seen, 0);
    let write = sqlx::query("INSERT INTO one.account (owner, region) VALUES ('party:c', 'tr')")
        .execute(&db.app)
        .await
        .unwrap_err();
    assert!(denied(&write), "{write}");
}

#[tokio::test]
async fn op_6_rows_are_never_deleted_and_ciphertext_is_never_rewritten() {
    let db = fresh().await.unwrap();
    let a = account(&db, "party:a").await;
    seed_record(&db, &a).await;
    let mut tx = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.owner', $1, true)")
        .bind(a.as_str())
        .execute(&mut *tx)
        .await
        .unwrap();
    let delete = sqlx::query("DELETE FROM one.record")
        .execute(&mut *tx)
        .await
        .unwrap_err();
    assert!(denied(&delete), "{delete}");
    tx.rollback().await.unwrap();

    for statement in [
        "UPDATE one.record SET ciphertext = '\\x00'",
        "UPDATE one.record SET retention_class = 'one_model'",
        "UPDATE one.record_key SET dek_id = record_key_id",
        "TRUNCATE one.outbox",
    ] {
        let mut tx = db.app.begin().await.unwrap();
        sqlx::query("SELECT set_config('app.owner', $1, true)")
            .bind(a.as_str())
            .execute(&mut *tx)
            .await
            .unwrap();
        let e = sqlx::query(statement).execute(&mut *tx).await.unwrap_err();
        assert!(denied(&e), "{statement}: {e}");
        tx.rollback().await.unwrap();
    }

    let mut tx = db.app.begin().await.unwrap();
    sqlx::query("SELECT set_config('app.owner', $1, true)")
        .bind(a.as_str())
        .execute(&mut *tx)
        .await
        .unwrap();
    let shred = sqlx::query(
        "UPDATE one.record_key SET wrapped_record_key = NULL, deleted_at = now() WHERE record_key_id = $1",
    )
    .bind(id(11))
    .execute(&mut *tx)
    .await
    .unwrap();
    assert_eq!(shred.rows_affected(), 1);
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn t_32_the_queue_role_cannot_read_personal_tables() {
    let db = fresh().await.unwrap();
    let a = account(&db, "party:a").await;
    seed_record(&db, &a).await;
    for table in [
        "account",
        "class_dek",
        "record_key",
        "record",
        "idempotency",
        "legal_hold",
        "memory_record",
        "memory_edge",
        "episode",
        "derivation",
        "index_part",
        "object",
    ] {
        let e = sqlx::query(AssertSqlSafe(format!("SELECT count(*) FROM one.{table}")))
            .fetch_one(&db.queue)
            .await
            .unwrap_err();
        assert!(denied(&e), "{table}: {e}");
    }
}

#[test]
fn t_32_owner_identifiers_follow_the_column_check() {
    assert!(Owner::new("party:01JABCDEF.x-y_z").is_ok());
    for bad in ["", "a b", "a/b", "é", &"a".repeat(201)] {
        assert!(matches!(Owner::new(bad), Err(StoreError::Owner)), "{bad:?}");
    }
    assert!(Owner::new(&"a".repeat(200)).is_ok());
}
