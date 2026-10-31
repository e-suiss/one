//! The outbox (OP-3): every outbound effect is written in the transaction of the record it rests on, with an idempotency key; the dispatcher claims due rows with `FOR UPDATE SKIP LOCKED` as a `one_queue` member and marks them sent in the same transaction.

use one_proto::EventId;
use sqlx::{PgPool, Postgres, Transaction};
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;

/// An event to send once the transaction commits.
pub struct NewEvent<'a> {
    /// Row id.
    pub id: EventId,
    /// `CloudEvent` type.
    pub event_type: &'a str,
    /// SHA-256 of the idempotency key.
    pub idempotency_key: &'a [u8; 32],
    /// The event body.
    pub payload: &'a [u8],
}

impl OwnerTx {
    /// Adds `event` to the outbox; the same key with the same type and body is a no-op.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when the key was used with another type or body, [`StoreError::Db`].
    pub async fn enqueue_event(&mut self, event: &NewEvent<'_>) -> Result<(), StoreError> {
        let inserted = sqlx::query!(
            "INSERT INTO one.outbox (owner, id, event_type, idempotency_key, ciphertext)
             VALUES ($1, $2, $3, $4, $5)
             ON CONFLICT (owner, idempotency_key) DO NOTHING",
            self.owner.as_str(),
            Uuid::from_bytes(event.id.to_bytes()),
            event.event_type,
            event.idempotency_key.as_slice(),
            event.payload
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(());
        }
        let stored = sqlx::query!(
            "SELECT event_type, ciphertext FROM one.outbox WHERE owner = $1 AND idempotency_key = $2",
            self.owner.as_str(),
            event.idempotency_key.as_slice()
        )
        .fetch_one(&mut *self.tx)
        .await?;
        if stored.event_type == event.event_type && stored.ciphertext == event.payload {
            Ok(())
        } else {
            Err(StoreError::Conflict)
        }
    }
}

/// A claimed event awaiting delivery.
pub struct Delivery {
    /// Owner of the row.
    pub owner: String,
    /// Row id.
    pub id: EventId,
    /// `CloudEvent` type.
    pub event_type: String,
    /// SHA-256 of the idempotency key, sent with the event.
    pub idempotency_key: Vec<u8>,
    /// The event body.
    pub payload: Vec<u8>,
    /// Earlier failed attempts.
    pub attempts: i32,
}

/// Due events locked by one dispatcher until [`Batch::commit`].
pub struct Batch {
    tx: Transaction<'static, Postgres>,
    /// The claimed events, oldest first.
    pub events: Vec<Delivery>,
}

impl Batch {
    /// Locks up to `limit` due events that no other dispatcher holds.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn claim(queue: &PgPool, limit: i64) -> Result<Self, StoreError> {
        let mut tx = queue.begin().await?;
        let rows = sqlx::query!(
            "SELECT owner, id, event_type, idempotency_key, ciphertext AS payload, attempts
               FROM one.outbox
              WHERE state = 'pending' AND run_after <= now()
              ORDER BY run_after, id
              LIMIT $1
                FOR UPDATE SKIP LOCKED",
            limit
        )
        .fetch_all(&mut *tx)
        .await?;
        let events = rows
            .into_iter()
            .map(|r| {
                Ok(Delivery {
                    id: EventId::from_bytes(r.id.into_bytes()).map_err(|_| StoreError::Corrupt)?,
                    owner: r.owner,
                    event_type: r.event_type,
                    idempotency_key: r.idempotency_key,
                    payload: r.payload,
                    attempts: r.attempts,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
        Ok(Self { tx, events })
    }

    /// Marks an event delivered.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn sent(&mut self, owner: &str, id: EventId) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE one.outbox SET state = 'sent' WHERE owner = $1 AND id = $2 AND state = 'pending'",
            owner,
            Uuid::from_bytes(id.to_bytes())
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Counts a failed attempt and moves the event `delay_secs` into the future.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn retry(
        &mut self,
        owner: &str,
        id: EventId,
        delay_secs: f64,
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE one.outbox
                SET attempts = attempts + 1, run_after = now() + make_interval(secs => $3)
              WHERE owner = $1 AND id = $2 AND state = 'pending'",
            owner,
            Uuid::from_bytes(id.to_bytes()),
            delay_secs
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Commits the marks and releases the locks.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }
}
