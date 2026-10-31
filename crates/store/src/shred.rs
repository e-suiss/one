//! Crypto-shred in the database (OP-6, OP-9 (1), M-25, OP-30): a shred clears the wrapped key copies and marks every row it made unreadable, in every record-bearing table, as a deleted skeleton in one statement; no row is removed and the ciphertext stays, now without a key. A class under a legal hold is not shredded; the caller keeps the request as a held job.

use one_proto::data_class::RetentionClass;
use one_proto::{DekId, RecordKeyId};
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;

/// What a shred request came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Shred {
    /// The key copies are gone, now or earlier.
    Done,
    /// A legal hold covers the class; nothing changed (OP-30 (1)).
    Held,
    /// The owner has no such key.
    Missing,
}

impl OwnerTx {
    async fn class_held(&mut self, class: &str) -> Result<bool, StoreError> {
        let held = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT FROM one.legal_hold
                               WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL) AS "held!""#,
            self.owner.as_str(),
            class
        )
        .fetch_one(&mut *self.tx)
        .await?;
        Ok(held)
    }

    /// Destroys record key `id`: the record and every derived part sealed under it become unreadable, while the class DEK and other records stay (M-25).
    ///
    /// # Errors
    /// [`StoreError::NoAccount`], [`StoreError::Db`].
    pub async fn shred_record_key(&mut self, id: RecordKeyId) -> Result<Shred, StoreError> {
        self.lock_account(false).await?;
        let key = Uuid::from_bytes(id.to_bytes());
        let Some(class) = sqlx::query_scalar!(
            r#"SELECT d.retention_class AS "retention_class!" FROM one.record_key k
               JOIN one.class_dek d ON d.owner = k.owner AND d.dek_id = k.dek_id
              WHERE k.owner = $1 AND k.record_key_id = $2"#,
            self.owner.as_str(),
            key
        )
        .fetch_optional(&mut *self.tx)
        .await?
        else {
            return Ok(Shred::Missing);
        };
        if self.class_held(&class).await? {
            return Ok(Shred::Held);
        }
        sqlx::query!(
            "WITH r AS (UPDATE one.record SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND record_key_id = $2 AND deleted_at IS NULL),
                  m AS (UPDATE one.memory_record SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND record_key_id = $2 AND deleted_at IS NULL),
                  e AS (UPDATE one.memory_edge SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND record_key_id = $2 AND deleted_at IS NULL),
                  p AS (UPDATE one.episode SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND record_key_id = $2 AND deleted_at IS NULL),
                  i AS (UPDATE one.index_part SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND record_key_id = $2 AND deleted_at IS NULL)
             UPDATE one.record_key SET wrapped_record_key = NULL, deleted_at = now()
              WHERE owner = $1 AND record_key_id = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            key
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(Shred::Done)
    }

    /// Destroys class DEK `id` with every record key it wraps, such as a sensitive field's own DEK on consent withdrawal (PV-22 (5)).
    ///
    /// # Errors
    /// [`StoreError::NoAccount`], [`StoreError::Db`].
    pub async fn shred_dek(&mut self, id: DekId) -> Result<Shred, StoreError> {
        self.lock_account(false).await?;
        let dek = Uuid::from_bytes(id.to_bytes());
        let Some(class) = sqlx::query_scalar!(
            r#"SELECT retention_class AS "retention_class!" FROM one.class_dek WHERE owner = $1 AND dek_id = $2"#,
            self.owner.as_str(),
            dek
        )
        .fetch_optional(&mut *self.tx)
        .await?
        else {
            return Ok(Shred::Missing);
        };
        if self.class_held(&class).await? {
            return Ok(Shred::Held);
        }
        sqlx::query!(
            "WITH r AS (UPDATE one.record SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL),
                  m AS (UPDATE one.memory_record SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL),
                  e AS (UPDATE one.memory_edge SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL),
                  p AS (UPDATE one.episode SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL),
                  i AS (UPDATE one.index_part SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL),
                  k AS (UPDATE one.record_key SET wrapped_record_key = NULL, deleted_at = now()
                         WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL)
             UPDATE one.class_dek SET wrapped_dek = NULL, deleted_at = now()
              WHERE owner = $1 AND dek_id = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            dek
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(Shred::Done)
    }

    /// Destroys every DEK of `class` with the record keys they wrap: retention expiry, model reset or one class of an account deletion (OP-11, OP-12).
    ///
    /// # Errors
    /// [`StoreError::NoAccount`], [`StoreError::Db`].
    pub async fn shred_class(&mut self, class: RetentionClass) -> Result<Shred, StoreError> {
        self.lock_account(false).await?;
        if self.class_held(class.as_str()).await? {
            return Ok(Shred::Held);
        }
        sqlx::query!(
            "WITH r AS (UPDATE one.record SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL),
                  m AS (UPDATE one.memory_record SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL),
                  e AS (UPDATE one.memory_edge SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL),
                  p AS (UPDATE one.episode SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL),
                  i AS (UPDATE one.index_part SET status = 'deleted', deleted_at = now()
                         WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL),
                  k AS (UPDATE one.record_key k SET wrapped_record_key = NULL, deleted_at = now()
                          FROM one.class_dek d
                         WHERE k.owner = $1 AND d.owner = k.owner AND d.dek_id = k.dek_id
                           AND d.retention_class = $2 AND k.deleted_at IS NULL)
             UPDATE one.class_dek SET wrapped_dek = NULL, deleted_at = now()
              WHERE owner = $1 AND retention_class = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            class.as_str()
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(Shred::Done)
    }
}
