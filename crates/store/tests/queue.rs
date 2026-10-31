//! The outbox, idempotency and job queue against a real database: one transaction for the record and its effects, the same key with other content is an error, dispatchers and workers never share a row, and only the lease holder finishes a job (OP-3, T-27 (6, 7), OP-12).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_proto::{EventId, JobId};
use one_store::idempotency::Claim;
use one_store::jobs::{self, JobKind, NewJob};
use one_store::outbox::{Batch, NewEvent};
use one_store::scope::{Owner, OwnerTx};
use one_store::testing::{TestDb, fresh};
use one_store::{StoreError, Uuid};

fn id(n: u8) -> Uuid {
    Uuid::from_bytes([0x01, 0x9a, 0, 0, 0, 0, 0x70, n, 0x80, 0, 0, 0, 0, 0, 0, n])
}

fn event_id(n: u8) -> EventId {
    EventId::from_bytes(id(n).into_bytes()).unwrap()
}

fn job_id(n: u8) -> JobId {
    JobId::from_bytes(id(n).into_bytes()).unwrap()
}

async fn scoped(db: &TestDb, owner: &str) -> OwnerTx {
    let owner = Owner::new(owner).unwrap();
    let mut tx = OwnerTx::begin(&db.app, &owner).await.unwrap();
    tx.open_account("tr").await.unwrap();
    tx
}

fn event<'a>(n: u8, key: &'a [u8; 32], payload: &'a [u8]) -> NewEvent<'a> {
    NewEvent {
        id: event_id(n),
        event_type: "one.test",
        idempotency_key: key,
        payload,
    }
}

fn job(n: u8, key: &[u8; 32], kind: JobKind) -> NewJob<'_> {
    NewJob {
        id: job_id(n),
        kind,
        idempotency_key: key,
        permission_id: None,
        delay_secs: 0.0,
        payload: None,
    }
}

#[tokio::test]
async fn op_3_the_same_key_with_other_content_is_an_error() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    tx.enqueue_event(&event(1, &[1; 32], b"body"))
        .await
        .unwrap();
    tx.enqueue_event(&event(2, &[1; 32], b"body"))
        .await
        .unwrap();
    let e = tx
        .enqueue_event(&event(3, &[1; 32], b"other"))
        .await
        .unwrap_err();
    assert!(matches!(e, StoreError::Conflict), "{e}");
}

#[tokio::test]
async fn op_3_an_event_leaves_only_after_its_transaction_commits() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    tx.enqueue_event(&event(1, &[1; 32], b"body"))
        .await
        .unwrap();
    let early = Batch::claim(&db.queue, 10).await.unwrap();
    assert!(early.events.is_empty());
    early.commit().await.unwrap();
    tx.commit().await.unwrap();

    let mut first = Batch::claim(&db.queue, 10).await.unwrap();
    assert_eq!(first.events.len(), 1);
    let second = Batch::claim(&db.queue, 10).await.unwrap();
    assert!(second.events.is_empty());
    second.commit().await.unwrap();
    let (owner, row) = (first.events[0].owner.clone(), first.events[0].id);
    assert_eq!(owner, "party:a");
    assert_eq!(first.events[0].payload, b"body");
    first.sent(&owner, row).await.unwrap();
    first.commit().await.unwrap();
    let after = Batch::claim(&db.queue, 10).await.unwrap();
    assert!(after.events.is_empty());
}

#[tokio::test]
async fn op_3_a_failed_delivery_waits_and_counts() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    tx.enqueue_event(&event(1, &[1; 32], b"body"))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let mut batch = Batch::claim(&db.queue, 10).await.unwrap();
    batch.retry("party:a", event_id(1), 3600.0).await.unwrap();
    batch.commit().await.unwrap();
    let later = Batch::claim(&db.queue, 10).await.unwrap();
    assert!(later.events.is_empty());
}

#[tokio::test]
async fn t_27_idempotency_replays_the_same_request_and_rejects_another() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    assert_eq!(
        tx.claim_idempotency(&[1; 32], &[9; 32]).await.unwrap(),
        Claim::New
    );
    assert_eq!(
        tx.claim_idempotency(&[1; 32], &[9; 32]).await.unwrap(),
        Claim::Replay(None)
    );
    tx.record_response(&[1; 32], b"sealed").await.unwrap();
    assert_eq!(
        tx.claim_idempotency(&[1; 32], &[9; 32]).await.unwrap(),
        Claim::Replay(Some(b"sealed".to_vec()))
    );
    let e = tx.claim_idempotency(&[1; 32], &[8; 32]).await.unwrap_err();
    assert!(matches!(e, StoreError::Conflict), "{e}");
}

#[tokio::test]
async fn t_27_jobs_deduplicate_and_only_the_lease_holder_finishes() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    assert!(
        tx.enqueue_job(&job(1, &[1; 32], JobKind::Shred))
            .await
            .unwrap()
    );
    assert!(
        !tx.enqueue_job(&job(2, &[1; 32], JobKind::Export))
            .await
            .unwrap()
    );
    tx.commit().await.unwrap();

    let leased = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    assert_eq!(leased.len(), 1);
    assert_eq!(leased[0].kind, JobKind::Shred);
    assert_eq!(leased[0].attempt, 1);
    assert!(jobs::lease(&db.queue, 10, 60.0).await.unwrap().is_empty());

    assert!(
        jobs::release(&db.queue, &leased[0], Some(0.0))
            .await
            .unwrap()
    );
    assert!(!jobs::finish(&db.queue, &leased[0]).await.unwrap());
    let again = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    assert_eq!(again.len(), 1);
    assert_eq!(again[0].attempt, 2);
    assert!(jobs::finish(&db.queue, &again[0]).await.unwrap());
    assert!(jobs::lease(&db.queue, 10, 60.0).await.unwrap().is_empty());
}

#[tokio::test]
async fn t_27_an_expired_lease_is_taken_over_and_a_failed_job_stays() {
    let db = fresh().await.unwrap();
    let mut tx = scoped(&db, "party:a").await;
    tx.enqueue_job(&job(1, &[1; 32], JobKind::Consolidation))
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let first = jobs::lease(&db.queue, 10, 0.0).await.unwrap();
    assert_eq!(first.len(), 1);
    let taken = jobs::lease(&db.queue, 10, 60.0).await.unwrap();
    assert_eq!(taken.len(), 1);
    assert_eq!(taken[0].attempt, 2);
    assert!(!jobs::finish(&db.queue, &first[0]).await.unwrap());
    assert!(jobs::release(&db.queue, &taken[0], None).await.unwrap());
    assert!(jobs::lease(&db.queue, 10, 60.0).await.unwrap().is_empty());
}

#[test]
fn t_27_job_kinds_are_the_closed_list() {
    for kind in JobKind::ALL {
        assert_eq!(JobKind::from_name(kind.as_str()), Some(kind));
    }
    assert_eq!(JobKind::from_name("analytics"), None);
}
