//! Derivation links (C-21, OP-5): every derived row (a consolidated record, a summary record, an index part) is linked to each source row and the source version it was built from, so permanent forgetting can follow the links to every derivative, however deep; a derivative is never in a less strict class than a source (M-38).

use one_proto::data_class::RetentionClass;
use one_proto::{EpisodeId, IndexPartId, MemoryRecordId, RecordKeyId};
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;
use crate::shred::Shred;

/// A row that can be a source or a derivative.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Row {
    /// A memory record or relationship edge.
    Memory(MemoryRecordId),
    /// An episode.
    Episode(EpisodeId),
    /// An encrypted index part.
    IndexPart(IndexPartId),
}

impl Row {
    fn uuid(self) -> Uuid {
        Uuid::from_bytes(match self {
            Self::Memory(id) => id.to_bytes(),
            Self::Episode(id) => id.to_bytes(),
            Self::IndexPart(id) => id.to_bytes(),
        })
    }
}

impl OwnerTx {
    async fn class_of(&mut self, row: Row) -> Result<Option<RetentionClass>, StoreError> {
        let id = row.uuid();
        let owner = self.owner.as_str();
        let name = match row {
            Row::Memory(_) => {
                sqlx::query_scalar!(
                    r#"SELECT retention_class AS "retention_class!" FROM one.memory_record WHERE owner = $1 AND id = $2
                       UNION SELECT retention_class FROM one.memory_edge WHERE owner = $1 AND id = $2
                       LIMIT 1"#,
                    owner,
                    id
                )
                .fetch_optional(&mut *self.tx)
                .await?
            }
            Row::Episode(_) => {
                sqlx::query_scalar!(
                    "SELECT retention_class FROM one.episode WHERE owner = $1 AND id = $2",
                    owner,
                    id
                )
                .fetch_optional(&mut *self.tx)
                .await?
            }
            Row::IndexPart(_) => {
                sqlx::query_scalar!(
                    "SELECT retention_class FROM one.index_part WHERE owner = $1 AND id = $2 LIMIT 1",
                    owner,
                    id
                )
                .fetch_optional(&mut *self.tx)
                .await?
            }
        };
        name.map(|n| RetentionClass::from_name(&n).ok_or(StoreError::Corrupt))
            .transpose()
    }

    /// Records that `derived` was built from version `source_version` of `source`.
    ///
    /// # Errors
    /// [`StoreError::NoRow`] when either row is missing, [`StoreError::Class`] when `derived` is in a less strict class than `source`, [`StoreError::Db`].
    pub async fn link_derivation(
        &mut self,
        derived: Row,
        source: Row,
        source_version: i32,
    ) -> Result<(), StoreError> {
        let (Some(to), Some(from)) = (self.class_of(derived).await?, self.class_of(source).await?)
        else {
            return Err(StoreError::NoRow);
        };
        if RetentionClass::for_derivative([to, from]) != Some(to) {
            return Err(StoreError::Class);
        }
        sqlx::query!(
            "INSERT INTO one.derivation (owner, id, source_id, source_version) VALUES ($1, $2, $3, $4)
             ON CONFLICT (owner, id, source_id, source_version) DO NOTHING",
            self.owner.as_str(),
            derived.uuid(),
            source.uuid(),
            source_version
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The record keys of every row derived from `source`, directly or through other derivatives, that are not shredded yet.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for a stored key that is not a `UUIDv7`, [`StoreError::Db`].
    pub async fn derived_keys(&mut self, source: Row) -> Result<Vec<RecordKeyId>, StoreError> {
        let keys = sqlx::query_scalar!(
            r#"WITH RECURSIVE d(id) AS (
                 SELECT id FROM one.derivation WHERE owner = $1 AND source_id = $2
                 UNION
                 SELECT x.id FROM one.derivation x JOIN d ON x.source_id = d.id WHERE x.owner = $1
               ), k(record_key_id) AS (
                 SELECT record_key_id FROM one.memory_record WHERE owner = $1 AND id IN (SELECT id FROM d)
                 UNION SELECT record_key_id FROM one.memory_edge WHERE owner = $1 AND id IN (SELECT id FROM d)
                 UNION SELECT record_key_id FROM one.episode WHERE owner = $1 AND id IN (SELECT id FROM d)
                 UNION SELECT record_key_id FROM one.index_part WHERE owner = $1 AND id IN (SELECT id FROM d)
               )
               SELECT k.record_key_id AS "record_key_id!" FROM k
                 JOIN one.record_key r ON r.owner = $1 AND r.record_key_id = k.record_key_id
                WHERE r.deleted_at IS NULL
                ORDER BY 1"#,
            self.owner.as_str(),
            source.uuid()
        )
        .fetch_all(&mut *self.tx)
        .await?;
        keys.into_iter()
            .map(|k| RecordKeyId::from_bytes(k.into_bytes()).map_err(|_| StoreError::Corrupt))
            .collect()
    }

    async fn key_of(&mut self, row: Row) -> Result<Option<RecordKeyId>, StoreError> {
        let key = sqlx::query_scalar!(
            r#"SELECT record_key_id AS "record_key_id!" FROM one.memory_record WHERE owner = $1 AND id = $2
               UNION SELECT record_key_id FROM one.memory_edge WHERE owner = $1 AND id = $2
               UNION SELECT record_key_id FROM one.episode WHERE owner = $1 AND id = $2
               UNION SELECT record_key_id FROM one.index_part WHERE owner = $1 AND id = $2
               LIMIT 1"#,
            self.owner.as_str(),
            row.uuid()
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        key.map(|k| RecordKeyId::from_bytes(k.into_bytes()).map_err(|_| StoreError::Corrupt))
            .transpose()
    }

    /// Permanent forgetting (M-25, C-21): destroys the record key of `row` and of every row derived from it, however deep; the skeletons stay and the class DEKs and other records are untouched. Nothing changes when a legal hold covers the class of any of those keys (OP-30 (1)).
    ///
    /// # Errors
    /// [`StoreError::NoAccount`], [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn forget(&mut self, row: Row) -> Result<Shred, StoreError> {
        self.lock_account(false).await?;
        let Some(own) = self.key_of(row).await? else {
            return Ok(Shred::Missing);
        };
        let mut keys = self.derived_keys(row).await?;
        keys.push(own);
        let ids: Vec<Uuid> = keys
            .iter()
            .map(|k| Uuid::from_bytes(k.to_bytes()))
            .collect();
        let held = sqlx::query_scalar!(
            r#"SELECT EXISTS (SELECT FROM one.record_key k
                                JOIN one.class_dek d ON d.owner = k.owner AND d.dek_id = k.dek_id
                                JOIN one.legal_hold h ON h.owner = k.owner AND h.retention_class = d.retention_class
                               WHERE k.owner = $1 AND k.record_key_id = ANY($2) AND h.deleted_at IS NULL) AS "held!""#,
            self.owner.as_str(),
            &ids
        )
        .fetch_one(&mut *self.tx)
        .await?;
        if held {
            return Ok(Shred::Held);
        }
        for key in keys {
            self.shred_record_key(key).await?;
        }
        Ok(Shred::Done)
    }
}
