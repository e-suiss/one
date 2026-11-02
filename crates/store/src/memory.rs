//! Memory versions and episodes (M-6, M-24, M-25, C-20): a record is never edited in place, a correction or a change of use is a new row that supersedes the head of its chain under the same record key, so permanent forgetting shreds every version at once; episodes are written before the records that cite them, and every row is ciphertext.

use one_proto::{EpisodeId, MemoryRecordId, RecordKeyId};
use uuid::Uuid;

use crate::StoreError;
use crate::keyring::Sealing;
use crate::scope::OwnerTx;

/// One stored memory row, as the export and the view read it.
#[derive(Clone, PartialEq, Eq)]
pub struct MemoryRow {
    /// The row's record identifier.
    pub id: MemoryRecordId,
    /// Its version in the chain, from 1.
    pub version: i32,
    /// The row it supersedes.
    pub supersedes: Option<MemoryRecordId>,
    /// Whether it is the head of its chain.
    pub head: bool,
    /// The retention class name.
    pub retention_class: String,
    /// The record key the chain is sealed under.
    pub record_key: RecordKeyId,
    /// The ciphertext, or `None` once the row is a forgotten skeleton.
    pub ciphertext: Option<Vec<u8>>,
    /// Transaction time, Unix milliseconds.
    pub recorded_at_ms: i64,
    /// When it was forgotten, Unix milliseconds.
    pub deleted_at_ms: Option<i64>,
}

/// One stored episode.
#[derive(Clone, PartialEq, Eq)]
pub struct EpisodeRow {
    /// The episode.
    pub id: EpisodeId,
    /// The retention class name.
    pub retention_class: String,
    /// The record key it is sealed under.
    pub record_key: RecordKeyId,
    /// The ciphertext, or `None` once forgotten.
    pub ciphertext: Option<Vec<u8>>,
    /// Transaction time, Unix milliseconds.
    pub recorded_at_ms: i64,
    /// When it was forgotten, Unix milliseconds.
    pub deleted_at_ms: Option<i64>,
}

impl core::fmt::Debug for EpisodeRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpisodeRow")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl core::fmt::Debug for MemoryRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("MemoryRow")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

fn uuid(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

fn len(bytes: &[u8]) -> Result<i32, StoreError> {
    i32::try_from(bytes.len()).map_err(|_| StoreError::Range)
}

impl OwnerTx {
    /// Writes episode `id` as `ciphertext` in the account's region.
    ///
    /// # Errors
    /// [`StoreError::Range`], [`StoreError::Db`].
    pub async fn put_episode(
        &mut self,
        id: EpisodeId,
        sealing: &Sealing,
        ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO one.episode (owner, id, status, retention_class, region, record_key_id, dek_id,
                                      ciphertext, ciphertext_len, promise_version)
             SELECT $1, $2, 'active', $3, a.region, $4, $5, $6, $7, $8
               FROM one.account a WHERE a.owner = $1",
            self.owner.as_str(),
            uuid(id.to_bytes()),
            sealing.class.as_str(),
            uuid(sealing.record_key.to_bytes()),
            uuid(sealing.dek.to_bytes()),
            ciphertext,
            len(ciphertext)?,
            sealing.promise_version
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Whether every episode in `ids` exists and is not forgotten (M-6).
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn episodes_exist(&mut self, ids: &[EpisodeId]) -> Result<bool, StoreError> {
        let ids: Vec<Uuid> = ids.iter().map(|e| uuid(e.to_bytes())).collect();
        let found = sqlx::query_scalar!(
            r#"SELECT count(DISTINCT id) AS "found!" FROM one.episode
                WHERE owner = $1 AND id = ANY($2) AND deleted_at IS NULL"#,
            self.owner.as_str(),
            &ids
        )
        .fetch_one(&mut *self.tx)
        .await?;
        let mut distinct = ids;
        distinct.sort_unstable();
        distinct.dedup();
        Ok(usize::try_from(found).is_ok_and(|n| n == distinct.len()))
    }

    /// Writes row `id` as the next version after the head `supersedes`, sealed under the head's own record key, and makes it the head; the old row stays.
    ///
    /// # Errors
    /// [`StoreError::NoRow`] when `supersedes` is not a live head, [`StoreError::Range`], [`StoreError::Db`].
    pub async fn put_memory_version(
        &mut self,
        id: MemoryRecordId,
        supersedes: MemoryRecordId,
        ciphertext: &[u8],
    ) -> Result<i32, StoreError> {
        let version = sqlx::query_scalar!(
            "WITH old AS (UPDATE one.memory_record SET status = 'superseded'
                           WHERE owner = $1 AND id = $2 AND status = 'active'
                       RETURNING owner, version, retention_class, region, record_key_id, dek_id, promise_version)
             INSERT INTO one.memory_record (owner, id, version, supersedes, status, retention_class, region,
                                            record_key_id, dek_id, ciphertext, ciphertext_len, promise_version)
             SELECT owner, $3, version + 1, $2, 'active', retention_class, region, record_key_id, dek_id, $4, $5,
                    promise_version
               FROM old
             RETURNING version",
            self.owner.as_str(),
            uuid(supersedes.to_bytes()),
            uuid(id.to_bytes()),
            ciphertext,
            len(ciphertext)?
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        version.ok_or(StoreError::NoRow)
    }

    /// Every memory row of the owner, forgotten ones without ciphertext, oldest first.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn memory_rows(&mut self) -> Result<Vec<MemoryRow>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT id, version, supersedes, status, retention_class, record_key_id,
                      CASE WHEN deleted_at IS NULL THEN ciphertext END AS ciphertext,
                      (extract(epoch FROM recorded_at) * 1000)::bigint AS "recorded_at_ms!",
                      (extract(epoch FROM deleted_at) * 1000)::bigint AS deleted_at_ms
                 FROM one.memory_record WHERE owner = $1
                ORDER BY recorded_at, id"#,
            self.owner.as_str()
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                let id = |u: Uuid| {
                    MemoryRecordId::from_bytes(u.into_bytes()).map_err(|_| StoreError::Corrupt)
                };
                Ok(MemoryRow {
                    id: id(r.id)?,
                    version: r.version,
                    supersedes: r.supersedes.map(id).transpose()?,
                    head: r.status == "active",
                    retention_class: r.retention_class,
                    record_key: RecordKeyId::from_bytes(r.record_key_id.into_bytes())
                        .map_err(|_| StoreError::Corrupt)?,
                    ciphertext: r.ciphertext,
                    recorded_at_ms: r.recorded_at_ms,
                    deleted_at_ms: r.deleted_at_ms,
                })
            })
            .collect()
    }

    /// Every episode of the owner, forgotten ones without ciphertext, oldest first.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn episode_rows(&mut self) -> Result<Vec<EpisodeRow>, StoreError> {
        let rows = sqlx::query!(
            r#"SELECT id, retention_class, record_key_id,
                      CASE WHEN deleted_at IS NULL THEN ciphertext END AS ciphertext,
                      (extract(epoch FROM recorded_at) * 1000)::bigint AS "recorded_at_ms!",
                      (extract(epoch FROM deleted_at) * 1000)::bigint AS deleted_at_ms
                 FROM one.episode WHERE owner = $1
                ORDER BY recorded_at, id"#,
            self.owner.as_str()
        )
        .fetch_all(&mut *self.tx)
        .await?;
        rows.into_iter()
            .map(|r| {
                Ok(EpisodeRow {
                    id: EpisodeId::from_bytes(r.id.into_bytes())
                        .map_err(|_| StoreError::Corrupt)?,
                    retention_class: r.retention_class,
                    record_key: RecordKeyId::from_bytes(r.record_key_id.into_bytes())
                        .map_err(|_| StoreError::Corrupt)?,
                    ciphertext: r.ciphertext,
                    recorded_at_ms: r.recorded_at_ms,
                    deleted_at_ms: r.deleted_at_ms,
                })
            })
            .collect()
    }

    /// The live class DEK of `class` and its wrapped bytes, if the class has one.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn live_class_dek(
        &mut self,
        class: one_proto::data_class::RetentionClass,
    ) -> Result<Option<(one_proto::DekId, Vec<u8>)>, StoreError> {
        let row = sqlx::query!(
            r#"SELECT dek_id, wrapped_dek AS "wrapped_dek!" FROM one.class_dek
                WHERE owner = $1 AND retention_class = $2 AND wrapped_dek IS NOT NULL
                ORDER BY recorded_at DESC LIMIT 1"#,
            self.owner.as_str(),
            class.as_str()
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            let id = one_proto::DekId::from_bytes(r.dek_id.into_bytes())
                .map_err(|_| StoreError::Corrupt)?;
            Ok((id, r.wrapped_dek))
        })
        .transpose()
    }
}
