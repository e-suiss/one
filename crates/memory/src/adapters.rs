//! The memory component's adapters: the vault over the owner-scoped PostgreSQL transaction and the OP-4 key hierarchy, run inside the attested job; a class DEK is wrapped to the KEK in the token, a record key to its class DEK, every version of a chain is sealed under the chain's record key and opened only through the TEE frame, so a forgotten chain never opens again (OP-4, OP-5, M-25).

use one_keys::hsm::Kek;
use one_keys::seal::{Part, PartRef, from_stored, open_part, seal_part, to_stored, unwrap, wrap};
use one_proto::data_class::RetentionClass;
use one_proto::id::uuid_v7;
use one_proto::ontology::time::Instant;
use one_proto::recovery::KekId;
use one_proto::{DekId, EpisodeId, MemoryRecordId, RecordKeyId};
use one_store::derivation::Row as StoreRow;
use one_store::keyring::{KeyChain, Sealing};
use one_store::scope::{Owner, OwnerTx};
use one_store::shred::Shred;
use one_store::{Pool, StoreError};
use one_tee::frame::unseal;
use one_tee::ports::{OpenError, Opener};
use one_tee::{RecordKeyId as TeeKeyId, Sealed};
use suiss_crypto::envelope::Dek;
use suiss_crypto::secret::Secret;

use crate::ports::{EpisodeRow, Forgot, Row, Vault, VaultError};

/// The vault of one owner within one transaction; [`PgVault::commit`] makes its writes durable.
pub struct PgVault<'k, K: Kek> {
    tx: OwnerTx,
    owner: String,
    kek: &'k K,
    promise_version: i32,
    clock_ms: u64,
}

impl<K: Kek> core::fmt::Debug for PgVault<'_, K> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PgVault").finish_non_exhaustive()
    }
}

struct TeeKeys<'a, K: Kek> {
    kek: &'a K,
    chain: Option<KeyChain>,
    part: PartRef<'a>,
}

impl<K: Kek> Opener for TeeKeys<'_, K> {
    fn open(
        &self,
        _: TeeKeyId,
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), OpenError> {
        let chain = self.chain.as_ref().ok_or(OpenError::NoKey)?;
        if aad != self.part.context() {
            return Err(OpenError::Tag);
        }
        let dek = self
            .kek
            .unwrap(&chain.wrapped_dek)
            .map_err(|_| OpenError::NoKey)?;
        let record_key =
            unwrap(dek.secret(), &chain.wrapped_record_key).map_err(|_| OpenError::NoKey)?;
        let sealed = from_stored(ciphertext).map_err(|_| OpenError::Tag)?;
        let plain = open_part(&record_key, &self.part, &sealed).map_err(|_| OpenError::Tag)?;
        out.extend_from_slice(&plain);
        Ok(())
    }
}

fn instant(ms: i64) -> Instant {
    Instant::from_unix(ms.div_euclid(1000))
}

fn class(name: &str) -> Result<RetentionClass, VaultError> {
    RetentionClass::from_name(name).ok_or(VaultError::Store(StoreError::Corrupt))
}

fn fresh_id() -> Result<[u8; 10], VaultError> {
    let dek = Dek::generate().map_err(|_| VaultError::Key)?;
    let mut out = [0_u8; 10];
    out.copy_from_slice(dek.secret().expose().get(..10).ok_or(VaultError::Key)?);
    Ok(out)
}

impl<'k, K: Kek> PgVault<'k, K> {
    /// Opens the vault of `owner` in a new transaction; keys are wrapped to `kek`, rows carry `promise_version`, and new key identifiers take their time from `clock_ms`.
    ///
    /// # Errors
    /// [`VaultError::Store`].
    pub async fn begin(
        pool: &Pool,
        owner: &Owner,
        kek: &'k K,
        promise_version: i32,
        clock_ms: u64,
    ) -> Result<Self, VaultError> {
        Ok(Self {
            tx: OwnerTx::begin(pool, owner).await?,
            owner: owner.as_str().to_owned(),
            kek,
            promise_version,
            clock_ms,
        })
    }

    /// Commits the transaction.
    ///
    /// # Errors
    /// [`VaultError::Store`].
    pub async fn commit(self) -> Result<(), VaultError> {
        Ok(self.tx.commit().await?)
    }

    fn part<'a>(&'a self, record: &'a str, class: RetentionClass) -> PartRef<'a> {
        PartRef {
            owner: &self.owner,
            record,
            class,
            part: Part::Content,
            version: 1,
        }
    }

    async fn class_dek(&mut self, class: RetentionClass) -> Result<(DekId, Dek), VaultError> {
        if let Some((id, wrapped)) = self.tx.live_class_dek(class).await? {
            let dek = self.kek.unwrap(&wrapped).map_err(|_| VaultError::Key)?;
            return Ok((id, dek));
        }
        let dek = Dek::generate().map_err(|_| VaultError::Key)?;
        let wrapped = self.kek.wrap(&dek).map_err(|_| VaultError::Key)?;
        let id =
            DekId::from_bytes(uuid_v7(self.clock_ms, fresh_id()?)).map_err(|_| VaultError::Key)?;
        let kek = KekId::parse(self.kek.id()).map_err(|_| VaultError::Key)?;
        self.tx.put_class_dek(id, class, &kek, &wrapped).await?;
        Ok((id, dek))
    }

    async fn new_record_key(
        &mut self,
        class: RetentionClass,
    ) -> Result<(Sealing, Secret<[u8; 32]>), VaultError> {
        let (dek_id, dek) = self.class_dek(class).await?;
        let key = Dek::generate().map_err(|_| VaultError::Key)?;
        let value = Secret::new(*key.secret().expose());
        let id = RecordKeyId::from_bytes(uuid_v7(self.clock_ms, fresh_id()?))
            .map_err(|_| VaultError::Key)?;
        let wrapped = wrap(dek.secret(), &value).map_err(|_| VaultError::Key)?;
        self.tx.put_record_key(id, dek_id, &wrapped).await?;
        Ok((
            Sealing {
                class,
                record_key: id,
                dek: dek_id,
                promise_version: self.promise_version,
            },
            value,
        ))
    }

    fn seal(
        &self,
        key: &Secret<[u8; 32]>,
        record: &str,
        class: RetentionClass,
        body: &[u8],
    ) -> Result<Vec<u8>, VaultError> {
        let sealed =
            seal_part(key, &self.part(record, class), body).map_err(|_| VaultError::Key)?;
        Ok(to_stored(&sealed))
    }

    async fn open(
        &mut self,
        key: RecordKeyId,
        record: &str,
        class: RetentionClass,
        stored: Vec<u8>,
    ) -> Result<Option<Vec<u8>>, VaultError> {
        let chain = self.tx.key_chain(key).await?;
        if chain.is_none() {
            return Ok(None);
        }
        let part = self.part(record, class);
        let opener = TeeKeys {
            kek: self.kek,
            chain,
            part,
        };
        let sealed: Sealed<Vec<u8>> =
            Sealed::from_parts(TeeKeyId(key.to_bytes()), part.context(), stored);
        let unsealed =
            unseal(&opener, &sealed, |b| Some(b.to_vec())).map_err(|_| VaultError::Open)?;
        Ok(Some(unsealed.expose().clone()))
    }
}

fn forgot(shred: Shred) -> Forgot {
    match shred {
        Shred::Done => Forgot::Done,
        Shred::Held => Forgot::Held,
        Shred::Missing => Forgot::Missing,
    }
}

impl<K: Kek> Vault for PgVault<'_, K> {
    async fn put_episode(
        &mut self,
        id: EpisodeId,
        class: RetentionClass,
        body: &[u8],
    ) -> Result<(), VaultError> {
        let (sealing, key) = self.new_record_key(class).await?;
        let stored = self.seal(&key, &id.to_string(), class, body)?;
        self.tx.put_episode(id, &sealing, &stored).await?;
        Ok(())
    }

    async fn episodes_exist(&mut self, ids: &[EpisodeId]) -> Result<bool, VaultError> {
        Ok(self.tx.episodes_exist(ids).await?)
    }

    async fn put_first(
        &mut self,
        id: MemoryRecordId,
        class: RetentionClass,
        body: &[u8],
    ) -> Result<(), VaultError> {
        let (sealing, key) = self.new_record_key(class).await?;
        let stored = self.seal(&key, &id.to_string(), class, body)?;
        self.tx.put_memory_record(id, &sealing, &stored).await?;
        Ok(())
    }

    async fn put_next(
        &mut self,
        id: MemoryRecordId,
        supersedes: MemoryRecordId,
        body: &[u8],
    ) -> Result<(), VaultError> {
        let (key_id, _) = self
            .tx
            .memory_ciphertext(supersedes)
            .await?
            .ok_or(VaultError::NotHead)?;
        let chain = self
            .tx
            .key_chain(key_id)
            .await?
            .ok_or(VaultError::NotHead)?;
        let dek = self
            .kek
            .unwrap(&chain.wrapped_dek)
            .map_err(|_| VaultError::Key)?;
        let key = unwrap(dek.secret(), &chain.wrapped_record_key).map_err(|_| VaultError::Key)?;
        let stored = self.seal(&key, &id.to_string(), chain.class, body)?;
        match self.tx.put_memory_version(id, supersedes, &stored).await {
            Err(StoreError::NoRow) => Err(VaultError::NotHead),
            other => other.map(|_| ()).map_err(VaultError::Store),
        }
    }

    async fn rows(&mut self) -> Result<Vec<Row>, VaultError> {
        let stored = self.tx.memory_rows().await?;
        let mut out = Vec::with_capacity(stored.len());
        for r in stored {
            let class = class(&r.retention_class)?;
            let body = match r.ciphertext {
                Some(c) => self.open(r.record_key, &r.id.to_string(), class, c).await?,
                None => None,
            };
            out.push(Row {
                id: r.id,
                version: u32::try_from(r.version).map_err(|_| StoreError::Corrupt)?,
                supersedes: r.supersedes,
                head: r.head,
                class,
                body,
                recorded_at: instant(r.recorded_at_ms),
                deleted_at: r.deleted_at_ms.map(instant),
            });
        }
        Ok(out)
    }

    async fn episodes(&mut self) -> Result<Vec<EpisodeRow>, VaultError> {
        let stored = self.tx.episode_rows().await?;
        let mut out = Vec::with_capacity(stored.len());
        for e in stored {
            let class = class(&e.retention_class)?;
            let body = match e.ciphertext {
                Some(c) => self.open(e.record_key, &e.id.to_string(), class, c).await?,
                None => None,
            };
            out.push(EpisodeRow {
                id: e.id,
                class,
                body,
                recorded_at: instant(e.recorded_at_ms),
                deleted_at: e.deleted_at_ms.map(instant),
            });
        }
        Ok(out)
    }

    async fn forget(&mut self, id: MemoryRecordId) -> Result<Forgot, VaultError> {
        Ok(forgot(self.tx.forget(StoreRow::Memory(id)).await?))
    }

    async fn forget_episode(&mut self, id: EpisodeId) -> Result<Forgot, VaultError> {
        Ok(forgot(self.tx.forget(StoreRow::Episode(id)).await?))
    }
}
