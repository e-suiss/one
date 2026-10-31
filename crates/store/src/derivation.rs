//! Derivation links (C-21, OP-5): every derived row (a consolidated record, a summary record, an index part) is linked to each source row and the source version it was built from, so permanent forgetting can follow the links to every derivative, however deep.

use one_proto::{EpisodeId, IndexPartId, MemoryRecordId, RecordKeyId};
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;

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
    /// Records that `derived` was built from version `source_version` of `source`.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn link_derivation(
        &mut self,
        derived: Row,
        source: Row,
        source_version: i32,
    ) -> Result<(), StoreError> {
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
}
