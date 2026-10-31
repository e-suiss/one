//! Owner scope (T-32 (3)): an application transaction carries its owner from `BEGIN` through `set_config(…, true)`, so a statement cannot run unscoped and row-level security limits it to that owner's rows.

use sqlx::{PgPool, Postgres, Transaction};

use crate::StoreError;

/// Longest owner identifier, the `CHECK` of `one.account.owner`.
pub const OWNER_MAX_LEN: usize = 200;

/// An account identifier (`PartyRef` id), the scope prefix of every key. Deliberately without `Debug`.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Owner(String);

impl Owner {
    /// Checks `id` against the column `CHECK`: 1 to 200 of `A–Z a–z 0–9 _ : . -`.
    ///
    /// # Errors
    /// [`StoreError::Owner`].
    pub fn new(id: &str) -> Result<Self, StoreError> {
        let ok = !id.is_empty()
            && id.len() <= OWNER_MAX_LEN
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b':' | b'.' | b'-'));
        if ok {
            Ok(Self(id.to_owned()))
        } else {
            Err(StoreError::Owner)
        }
    }

    /// The identifier.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A transaction scoped to one owner, opened on a pool of `one_app` members.
pub struct OwnerTx {
    pub(crate) tx: Transaction<'static, Postgres>,
    pub(crate) owner: Owner,
}

impl OwnerTx {
    /// Opens a transaction and sets `app.owner` for it only.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn begin(pool: &PgPool, owner: &Owner) -> Result<Self, StoreError> {
        let mut tx = pool.begin().await?;
        sqlx::query!("SELECT set_config('app.owner', $1, true)", owner.as_str())
            .fetch_one(&mut *tx)
            .await?;
        Ok(Self {
            tx,
            owner: owner.clone(),
        })
    }

    /// The scope.
    #[must_use]
    pub const fn owner(&self) -> &Owner {
        &self.owner
    }

    /// Creates the owner's account row in `region` if it does not exist yet.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn open_account(&mut self, region: &str) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO one.account (owner, region) VALUES ($1, $2) ON CONFLICT (owner) DO NOTHING",
            self.owner.as_str(),
            region
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Commits.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn commit(self) -> Result<(), StoreError> {
        self.tx.commit().await?;
        Ok(())
    }
}
