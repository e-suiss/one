//! Legal hold orders (OP-30): an order suspends crypto-shred and retention expiry in the classes it covers, never opens data; requests made under it are kept as held shred jobs and run again when the last covering order lifts. Hold changes take the account row lock that every shred takes, so an order and a shred never interleave.

use one_proto::LegalHoldId;
use one_proto::data_class::RetentionClass;
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;

impl OwnerTx {
    /// Locks the owner's account row against hold changes until the transaction ends.
    pub(crate) async fn lock_account(&mut self, exclusive: bool) -> Result<(), StoreError> {
        let found = if exclusive {
            sqlx::query_scalar!(
                r#"SELECT owner AS "owner!" FROM one.account WHERE owner = $1 FOR UPDATE"#,
                self.owner.as_str()
            )
            .fetch_optional(&mut *self.tx)
            .await?
        } else {
            sqlx::query_scalar!(
                r#"SELECT owner AS "owner!" FROM one.account WHERE owner = $1 FOR SHARE"#,
                self.owner.as_str()
            )
            .fetch_optional(&mut *self.tx)
            .await?
        };
        found.map(drop).ok_or(StoreError::NoAccount)
    }

    /// Places order `id` over `class`; placing the same order again changes nothing.
    ///
    /// # Errors
    /// [`StoreError::NoAccount`], [`StoreError::Db`].
    pub async fn place_hold(
        &mut self,
        id: LegalHoldId,
        class: RetentionClass,
    ) -> Result<(), StoreError> {
        self.lock_account(true).await?;
        sqlx::query!(
            "INSERT INTO one.legal_hold (owner, id, retention_class) VALUES ($1, $2, $3)
             ON CONFLICT (owner, id) DO NOTHING",
            self.owner.as_str(),
            Uuid::from_bytes(id.to_bytes()),
            class.as_str()
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Lifts order `id` and makes the held shred jobs due again; those still under another order are held again when they run. Returns `false` when the order is not in force.
    ///
    /// # Errors
    /// [`StoreError::NoAccount`], [`StoreError::Db`].
    pub async fn lift_hold(&mut self, id: LegalHoldId) -> Result<bool, StoreError> {
        self.lock_account(true).await?;
        let lifted = sqlx::query!(
            "UPDATE one.legal_hold SET deleted_at = now()
              WHERE owner = $1 AND id = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            Uuid::from_bytes(id.to_bytes())
        )
        .execute(&mut *self.tx)
        .await?
        .rows_affected();
        if lifted == 0 {
            return Ok(false);
        }
        sqlx::query!(
            "UPDATE one.job SET state = 'pending', run_after = now()
              WHERE owner = $1 AND job_kind = 'shred' AND state = 'held'",
            self.owner.as_str()
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(true)
    }

    /// The classes under an order in force.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for an unknown class, [`StoreError::Db`].
    pub async fn held_classes(&mut self) -> Result<Vec<RetentionClass>, StoreError> {
        let rows = sqlx::query_scalar!(
            r#"SELECT DISTINCT retention_class AS "retention_class!" FROM one.legal_hold
              WHERE owner = $1 AND deleted_at IS NULL ORDER BY 1"#,
            self.owner.as_str()
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.iter()
            .map(|c| RetentionClass::from_name(c).ok_or(StoreError::Corrupt))
            .collect()
    }
}
