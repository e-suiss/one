//! Crypto-shred and legal holds against a real database: a record key shred leaves the class DEK and other records, a class shred clears every key of the class, another owner's keys are out of reach, and a hold parks the request as a job that runs once the last order lifts (M-25, OP-9 (1), OP-12, OP-30).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_proto::data_class::RetentionClass;
use one_proto::{DekId, JobId, LegalHoldId, RecordKeyId};
use one_store::Uuid;
use one_store::jobs::{self, JobKind, NewJob};
use one_store::scope::{Owner, OwnerTx};
use one_store::shred::Shred;
use one_store::testing::{TestDb, fresh};

fn id(n: u8) -> Uuid {
    Uuid::from_bytes([0x01, 0x9a, 0, 0, 0, 0, 0x70, n, 0x80, 0, 0, 0, 0, 0, 0, n])
}

fn dek(n: u8) -> DekId {
    DekId::from_bytes(id(n).into_bytes()).unwrap()
}

fn record_key(n: u8) -> RecordKeyId {
    RecordKeyId::from_bytes(id(n).into_bytes()).unwrap()
}

fn hold(n: u8) -> LegalHoldId {
    LegalHoldId::from_bytes(id(n).into_bytes()).unwrap()
}

async fn scoped(db: &TestDb, owner: &str) -> OwnerTx {
    let owner = Owner::new(owner).unwrap();
    let mut tx = OwnerTx::begin(&db.app, &owner).await.unwrap();
    tx.open_account("tr").await.unwrap();
    tx
}

async fn seed_dek(db: &TestDb, owner: &str, n: u8, class: &str) {
    sqlx::query(
        "INSERT INTO one.class_dek (owner, dek_id, retention_class, kek_id, wrapped_dek)
         VALUES ($1, $2, $3, 'kek-1', $4)",
    )
    .bind(owner)
    .bind(id(n))
    .bind(class)
    .bind(vec![n; 40])
    .execute(&db.owner)
    .await
    .unwrap();
}

async fn seed_record(db: &TestDb, owner: &str, n: u8, dek_n: u8, class: &str) {
    sqlx::query(
        "INSERT INTO one.record_key (owner, record_key_id, dek_id, wrapped_record_key) VALUES ($1, $2, $3, $4)",
    )
    .bind(owner)
    .bind(id(n))
    .bind(id(dek_n))
    .bind(vec![n; 40])
    .execute(&db.owner)
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO one.record (owner, id, version, status, retention_class, region, record_key_id, dek_id,
                                 ciphertext, ciphertext_len, promise_version)
         VALUES ($1, $2, 1, 'active', $3, 'tr', $2, $4, $5, 3, 1)",
    )
    .bind(owner)
    .bind(id(n))
    .bind(class)
    .bind(id(dek_n))
    .bind(vec![n; 3])
    .execute(&db.owner)
    .await
    .unwrap();
}

async fn seeded(db: &TestDb, owner: &str) {
    scoped(db, owner).await.commit().await.unwrap();
    seed_dek(db, owner, 1, "one_memory").await;
    seed_dek(db, owner, 2, "one_model").await;
    seed_record(db, owner, 11, 1, "one_memory").await;
    seed_record(db, owner, 12, 1, "one_memory").await;
    seed_record(db, owner, 21, 2, "one_model").await;
}

async fn key_live(db: &TestDb, owner: &str, n: u8) -> bool {
    sqlx::query_scalar(
        "SELECT wrapped_record_key IS NOT NULL FROM one.record_key WHERE owner = $1 AND record_key_id = $2",
    )
    .bind(owner)
    .bind(id(n))
    .fetch_one(&db.owner)
    .await
    .unwrap()
}

async fn dek_live(db: &TestDb, owner: &str, n: u8) -> bool {
    sqlx::query_scalar(
        "SELECT wrapped_dek IS NOT NULL FROM one.class_dek WHERE owner = $1 AND dek_id = $2",
    )
    .bind(owner)
    .bind(id(n))
    .fetch_one(&db.owner)
    .await
    .unwrap()
}

async fn record_status(db: &TestDb, owner: &str, n: u8) -> String {
    sqlx::query_scalar("SELECT status FROM one.record WHERE owner = $1 AND id = $2")
        .bind(owner)
        .bind(id(n))
        .fetch_one(&db.owner)
        .await
        .unwrap()
}

#[tokio::test]
async fn m_25_a_record_key_shred_leaves_the_dek_and_other_records() {
    let db = fresh().await.unwrap();
    seeded(&db, "party:a").await;
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Done
    );
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Done
    );
    assert_eq!(
        tx.shred_record_key(record_key(99)).await.unwrap(),
        Shred::Missing
    );
    tx.commit().await.unwrap();
    assert!(!key_live(&db, "party:a", 11).await);
    assert_eq!(record_status(&db, "party:a", 11).await, "deleted");
    assert!(key_live(&db, "party:a", 12).await);
    assert_eq!(record_status(&db, "party:a", 12).await, "active");
    assert!(dek_live(&db, "party:a", 1).await);
}

#[tokio::test]
async fn op_9_a_class_shred_clears_every_key_of_the_class_only() {
    let db = fresh().await.unwrap();
    seeded(&db, "party:a").await;
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(
        tx.shred_class(RetentionClass::OneMemory).await.unwrap(),
        Shred::Done
    );
    tx.commit().await.unwrap();
    assert!(!dek_live(&db, "party:a", 1).await);
    assert!(!key_live(&db, "party:a", 11).await);
    assert!(!key_live(&db, "party:a", 12).await);
    assert_eq!(record_status(&db, "party:a", 12).await, "deleted");
    assert!(dek_live(&db, "party:a", 2).await);
    assert!(key_live(&db, "party:a", 21).await);
    assert_eq!(record_status(&db, "party:a", 21).await, "active");
}

#[tokio::test]
async fn pv_22_a_dek_shred_takes_its_record_keys() {
    let db = fresh().await.unwrap();
    seeded(&db, "party:a").await;
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(tx.shred_dek(dek(2)).await.unwrap(), Shred::Done);
    assert_eq!(tx.shred_dek(dek(98)).await.unwrap(), Shred::Missing);
    tx.commit().await.unwrap();
    assert!(!dek_live(&db, "party:a", 2).await);
    assert!(!key_live(&db, "party:a", 21).await);
    assert!(dek_live(&db, "party:a", 1).await);
}

#[tokio::test]
async fn t_32_another_owners_keys_are_out_of_reach() {
    let db = fresh().await.unwrap();
    seeded(&db, "party:a").await;
    let mut tx = scoped(&db, "party:b").await;
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Missing
    );
    assert_eq!(tx.shred_dek(dek(1)).await.unwrap(), Shred::Missing);
    assert_eq!(
        tx.shred_class(RetentionClass::OneMemory).await.unwrap(),
        Shred::Done
    );
    tx.commit().await.unwrap();
    assert!(key_live(&db, "party:a", 11).await);
    assert!(dek_live(&db, "party:a", 1).await);
}

#[tokio::test]
async fn op_30_a_hold_parks_the_shred_until_the_last_order_lifts() {
    let db = fresh().await.unwrap();
    seeded(&db, "party:a").await;
    let mut tx = scoped(&db, "party:a").await;
    tx.place_hold(hold(1), RetentionClass::OneMemory)
        .await
        .unwrap();
    tx.place_hold(hold(2), RetentionClass::OneMemory)
        .await
        .unwrap();
    assert_eq!(
        tx.held_classes().await.unwrap(),
        [RetentionClass::OneMemory]
    );
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Held
    );
    assert_eq!(
        tx.shred_class(RetentionClass::OneMemory).await.unwrap(),
        Shred::Held
    );
    assert_eq!(
        tx.shred_class(RetentionClass::OneModel).await.unwrap(),
        Shred::Done
    );
    tx.enqueue_job(&NewJob {
        id: JobId::from_bytes(id(50).into_bytes()).unwrap(),
        kind: JobKind::Shred,
        idempotency_key: &[50; 32],
        permission_id: None,
        delay_secs: 0.0,
        payload: None,
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    assert!(key_live(&db, "party:a", 11).await);

    let leased = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    assert_eq!(leased.len(), 1);
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Held
    );
    assert!(tx.hold_job(&leased[0]).await.unwrap());
    tx.commit().await.unwrap();
    assert!(jobs::lease(&db.queue, 10, 60.0).await.unwrap().is_empty());

    let mut tx = scoped(&db, "party:a").await;
    assert!(tx.lift_hold(hold(1)).await.unwrap());
    assert!(!tx.lift_hold(hold(1)).await.unwrap());
    tx.commit().await.unwrap();
    let leased = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    assert_eq!(leased.len(), 1);
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Held
    );
    assert!(tx.hold_job(&leased[0]).await.unwrap());
    assert!(tx.lift_hold(hold(2)).await.unwrap());
    assert_eq!(tx.held_classes().await.unwrap(), [] as [RetentionClass; 0]);
    tx.commit().await.unwrap();

    let leased = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    assert_eq!(leased.len(), 1);
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(
        tx.shred_record_key(record_key(11)).await.unwrap(),
        Shred::Done
    );
    assert!(tx.finish_job(&leased[0]).await.unwrap());
    tx.commit().await.unwrap();
    assert!(!key_live(&db, "party:a", 11).await);
    assert!(jobs::lease(&db.queue, 10, 60.0).await.unwrap().is_empty());
}

#[tokio::test]
async fn t_27_a_lease_settles_only_in_its_owners_transaction() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    tx.enqueue_job(&NewJob {
        id: JobId::from_bytes(id(60).into_bytes()).unwrap(),
        kind: JobKind::Export,
        idempotency_key: &[60; 32],
        permission_id: None,
        delay_secs: 0.0,
        payload: None,
    })
    .await
    .unwrap();
    tx.commit().await.unwrap();
    let leased = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    let mut other = scoped(&db, "party:b").await;
    assert!(matches!(
        other.finish_job(&leased[0]).await,
        Err(one_store::StoreError::Owner)
    ));
}
