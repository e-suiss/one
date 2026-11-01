//! Wrapped keys and encrypted rows (OP-4 (1, 2), PV-4): a class DEK wrapped to the user's KEK, a record key wrapped to its class DEK, memory records and index parts written only as ciphertext and object rows naming ciphertext in the object store; a TEE job reads a record key's chain and unwraps it there, and a shredded key has no chain.

use one_proto::data_class::RetentionClass;
use one_proto::recovery::KekId;
use one_proto::{DekId, IndexPartId, MemoryRecordId, ObjectId, RecordKeyId};
use uuid::Uuid;

use crate::StoreError;
use crate::scope::OwnerTx;

/// The wrapped keys above one record key, as the key layer unwraps them: KEK → class DEK → record key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyChain {
    /// The class DEK the record key is wrapped to.
    pub dek: DekId,
    /// The DEK's retention class.
    pub class: RetentionClass,
    /// The KEK the DEK is wrapped to.
    pub kek: KekId,
    /// The DEK wrapped to the KEK.
    pub wrapped_dek: Vec<u8>,
    /// The record key wrapped to the DEK.
    pub wrapped_record_key: Vec<u8>,
}

/// Where an encrypted row's ciphertext and keys belong.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Sealing {
    /// The row's retention class, the class of its DEK.
    pub class: RetentionClass,
    /// The record key the row is sealed under.
    pub record_key: RecordKeyId,
    /// The class DEK that wraps the record key.
    pub dek: DekId,
    /// The privacy promise version the row was written under (OD-68).
    pub promise_version: i32,
}

fn uuid(bytes: [u8; 16]) -> Uuid {
    Uuid::from_bytes(bytes)
}

fn len(bytes: &[u8]) -> Result<i32, StoreError> {
    i32::try_from(bytes.len()).map_err(|_| StoreError::Range)
}

impl OwnerTx {
    /// Stores class DEK `dek` of `class`, wrapped to KEK `kek`; outside `one_sensitive` a class has one live DEK.
    ///
    /// # Errors
    /// [`StoreError::Db`], also for a second live DEK of a class.
    pub async fn put_class_dek(
        &mut self,
        dek: DekId,
        class: RetentionClass,
        kek: &KekId,
        wrapped: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO one.class_dek (owner, dek_id, retention_class, kek_id, wrapped_dek)
             VALUES ($1, $2, $3, $4, $5)",
            self.owner.as_str(),
            uuid(dek.to_bytes()),
            class.as_str(),
            kek.as_str(),
            wrapped
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// Stores record key `key`, wrapped to class DEK `dek`.
    ///
    /// # Errors
    /// [`StoreError::Db`].
    pub async fn put_record_key(
        &mut self,
        key: RecordKeyId,
        dek: DekId,
        wrapped: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO one.record_key (owner, record_key_id, dek_id, wrapped_record_key)
             VALUES ($1, $2, $3, $4)",
            self.owner.as_str(),
            uuid(key.to_bytes()),
            uuid(dek.to_bytes()),
            wrapped
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The chain above record key `key`, or `None` once the key or its DEK is shredded.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`] for a stored row that does not match the model, [`StoreError::Db`].
    pub async fn key_chain(&mut self, key: RecordKeyId) -> Result<Option<KeyChain>, StoreError> {
        let row = sqlx::query!(
            r#"SELECT d.dek_id, d.retention_class, d.kek_id,
                      d.wrapped_dek AS "wrapped_dek!", k.wrapped_record_key AS "wrapped_record_key!"
                 FROM one.record_key k
                 JOIN one.class_dek d ON d.owner = k.owner AND d.dek_id = k.dek_id
                WHERE k.owner = $1 AND k.record_key_id = $2
                  AND k.wrapped_record_key IS NOT NULL AND d.wrapped_dek IS NOT NULL"#,
            self.owner.as_str(),
            uuid(key.to_bytes())
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            Ok(KeyChain {
                dek: DekId::from_bytes(r.dek_id.into_bytes()).map_err(|_| StoreError::Corrupt)?,
                class: RetentionClass::from_name(&r.retention_class).ok_or(StoreError::Corrupt)?,
                kek: KekId::parse(&r.kek_id).map_err(|_| StoreError::Corrupt)?,
                wrapped_dek: r.wrapped_dek,
                wrapped_record_key: r.wrapped_record_key,
            })
        })
        .transpose()
    }

    /// Writes version 1 of memory record `id` as `ciphertext` in the account's region.
    ///
    /// # Errors
    /// [`StoreError::Range`] for a ciphertext over 2 GiB, [`StoreError::Db`].
    pub async fn put_memory_record(
        &mut self,
        id: MemoryRecordId,
        sealing: &Sealing,
        ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        sqlx::query!(
            "INSERT INTO one.memory_record (owner, id, version, status, retention_class, region, record_key_id,
                                            dek_id, ciphertext, ciphertext_len, promise_version)
             SELECT $1, $2, 1, 'active', $3, a.region, $4, $5, $6, $7, $8
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

    /// The record key and ciphertext of memory record `id`, or `None` when it is missing or a deleted skeleton.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn memory_ciphertext(
        &mut self,
        id: MemoryRecordId,
    ) -> Result<Option<(RecordKeyId, Vec<u8>)>, StoreError> {
        let row = sqlx::query!(
            "SELECT record_key_id, ciphertext FROM one.memory_record
              WHERE owner = $1 AND id = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            uuid(id.to_bytes())
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            let key = RecordKeyId::from_bytes(r.record_key_id.into_bytes())
                .map_err(|_| StoreError::Corrupt)?;
            Ok((key, r.ciphertext))
        })
        .transpose()
    }

    /// Writes version 1 of index part `id`, number `part_no`, built by `embedding` (model, version) when it holds vectors (M-12).
    ///
    /// # Errors
    /// [`StoreError::Range`], [`StoreError::Db`].
    pub async fn put_index_part(
        &mut self,
        id: IndexPartId,
        part_no: i32,
        embedding: Option<(&str, &str)>,
        sealing: &Sealing,
        ciphertext: &[u8],
    ) -> Result<(), StoreError> {
        let (model, version) = embedding.unzip();
        sqlx::query!(
            "INSERT INTO one.index_part (owner, id, version, status, retention_class, index_part_no, embedding_model,
                                         embedding_model_version, record_key_id, dek_id, ciphertext, ciphertext_len)
             VALUES ($1, $2, 1, 'active', $3, $4, $5, $6, $7, $8, $9, $10)",
            self.owner.as_str(),
            uuid(id.to_bytes()),
            sealing.class.as_str(),
            part_no,
            model,
            version,
            uuid(sealing.record_key.to_bytes()),
            uuid(sealing.dek.to_bytes()),
            ciphertext,
            len(ciphertext)?
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The record key and ciphertext of index part `id`, or `None` when it is missing or a deleted skeleton.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn index_part_ciphertext(
        &mut self,
        id: IndexPartId,
    ) -> Result<Option<(RecordKeyId, Vec<u8>)>, StoreError> {
        let row = sqlx::query!(
            "SELECT record_key_id, ciphertext FROM one.index_part
              WHERE owner = $1 AND id = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            uuid(id.to_bytes())
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        row.map(|r| {
            let key = RecordKeyId::from_bytes(r.record_key_id.into_bytes())
                .map_err(|_| StoreError::Corrupt)?;
            Ok((key, r.ciphertext))
        })
        .transpose()
    }

    /// Records object `id`, whose `ciphertext_len` bytes of ciphertext are in the object store under the owner's prefix.
    ///
    /// # Errors
    /// [`StoreError::Range`], [`StoreError::Db`].
    pub async fn put_object(
        &mut self,
        id: ObjectId,
        sealing: &Sealing,
        ciphertext_len: u64,
    ) -> Result<(), StoreError> {
        let n = i32::try_from(ciphertext_len).map_err(|_| StoreError::Range)?;
        sqlx::query!(
            "INSERT INTO one.object (owner, id, status, retention_class, region, record_key_id, dek_id,
                                     ciphertext_len, promise_version)
             SELECT $1, $2, 'active', $3, a.region, $4, $5, $6, $7
               FROM one.account a WHERE a.owner = $1",
            self.owner.as_str(),
            uuid(id.to_bytes()),
            sealing.class.as_str(),
            uuid(sealing.record_key.to_bytes()),
            uuid(sealing.dek.to_bytes()),
            n,
            sealing.promise_version
        )
        .execute(&mut *self.tx)
        .await?;
        Ok(())
    }

    /// The record key of object `id`, or `None` when it is missing or a deleted skeleton.
    ///
    /// # Errors
    /// [`StoreError::Corrupt`], [`StoreError::Db`].
    pub async fn object_key(&mut self, id: ObjectId) -> Result<Option<RecordKeyId>, StoreError> {
        let key = sqlx::query_scalar!(
            "SELECT record_key_id FROM one.object WHERE owner = $1 AND id = $2 AND deleted_at IS NULL",
            self.owner.as_str(),
            uuid(id.to_bytes())
        )
        .fetch_optional(&mut *self.tx)
        .await?;
        key.map(|k| RecordKeyId::from_bytes(k.into_bytes()).map_err(|_| StoreError::Corrupt))
            .transpose()
    }
}
