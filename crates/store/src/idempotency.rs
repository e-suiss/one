//! Idempotent requests (T-27 (6), OP-3): the first use of a key records the request digest; a repeat with the same digest replays the stored response and a repeat with another digest is an error.

use crate::StoreError;
use crate::scope::OwnerTx;

/// What a key's use means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Claim {
    /// First use; run the request and call [`OwnerTx::record_response`].
    New,
    /// Seen before with the same request; the stored encrypted response, if it was recorded.
    Replay(Option<Vec<u8>>),
}

impl OwnerTx {
    /// Records the first use of `key` for `request_digest`, or judges a repeat.
    ///
    /// # Errors
    /// [`StoreError::Conflict`] when the key was used for another request, [`StoreError::Db`].
    pub async fn claim_idempotency(
        &mut self,
        key: &[u8; 32],
        request_digest: &[u8; 32],
    ) -> Result<Claim, StoreError> {
        let inserted = sqlx::query!(
            "INSERT INTO one.idempotency (owner, idempotency_key, request_digest) VALUES ($1, $2, $3)
             ON CONFLICT (owner, idempotency_key) DO NOTHING",
            self.owner.as_str(),
            key.as_slice(),
            request_digest.as_slice()
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if inserted == 1 {
            return Ok(Claim::New);
        }
        let stored = sqlx::query!(
            "SELECT request_digest, ciphertext FROM one.idempotency WHERE owner = $1 AND idempotency_key = $2",
            self.owner.as_str(),
            key.as_slice()
        )
        .fetch_one(&mut *self.tx)
        .await?;
        if stored.request_digest == request_digest.as_slice() {
            Ok(Claim::Replay(stored.ciphertext))
        } else {
            Err(StoreError::Conflict)
        }
    }

    /// Stores the encrypted response of the request `key` was claimed for.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn record_response(
        &mut self,
        key: &[u8; 32],
        response: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "UPDATE one.idempotency SET ciphertext = $3 WHERE owner = $1 AND idempotency_key = $2",
            self.owner.as_str(),
            key.as_slice(),
            response
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }
}
