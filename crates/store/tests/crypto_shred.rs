//! Crypto-shred end to end against a real database, object store and `SoftHSM` token: a record is sealed under the OP-4 key hierarchy with the class DEK wrapped inside the token, opens in the TEE frame, and once forgotten neither it, its object, its derived summary nor its index part opens again while the other records do; withdrawing consent shreds a sensitive field's own DEK, account deletion leaves only the training lineage readable and a legal hold keeps everything as it was (OP-4, OP-5, OP-9, OP-11, OP-30, M-25, PV-22 (5), T-37 (4), T-51).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use std::path::PathBuf;

use one_keys::hsm::{HsmKek, Kek as _, KeyStore};
use one_keys::seal::{Part, PartRef, from_stored, open_part, seal_part, to_stored, unwrap, wrap};
use one_objects::{Objects, Settings};
use one_proto::data_class::RetentionClass;
use one_proto::id::uuid_v7;
use one_proto::recovery::KekId;
use one_proto::{DekId, IndexPartId, LegalHoldId, MemoryRecordId, ObjectId, RecordKeyId};
use one_store::Uuid;
use one_store::derivation::Row;
use one_store::keyring::{KeyChain, Sealing};
use one_store::scope::{Owner, OwnerTx};
use one_store::shred::Shred;
use one_store::testing::{TestDb, fresh};
use one_tee::frame::unseal;
use one_tee::ports::{OpenError, Opener};
use one_tee::{RecordKeyId as TeeKeyId, Sealed};
use suiss_crypto::envelope::Dek;
use suiss_crypto::secret::Secret;

const OWNER: &str = "party:a";

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; the test job provides it"))
}

fn bytes(tag: u8) -> [u8; 16] {
    let pid = std::process::id().to_be_bytes();
    uuid_v7(
        1_791_504_000_000,
        [tag, pid[0], pid[1], pid[2], pid[3], 0, 0, 0, 0, tag],
    )
}

fn text(tag: u8) -> String {
    Uuid::from_bytes(bytes(tag)).to_string()
}

fn secret(tag: u8) -> Secret<[u8; 32]> {
    let mut key = [tag; 32];
    key[..4].copy_from_slice(&std::process::id().to_be_bytes());
    Secret::new(key)
}

struct World {
    db: TestDb,
    objects: Objects,
    kek: HsmKek,
    kek_id: KekId,
}

impl World {
    async fn new(label: &str) -> Self {
        let db = fresh().await.unwrap();
        let store = KeyStore::open(
            &PathBuf::from(var("ONE_TEST_PKCS11_MODULE")),
            &var("ONE_TEST_PKCS11_TOKEN"),
            &Secret::new(var("ONE_TEST_PKCS11_PIN")),
        )
        .unwrap();
        let name = format!("{label}-{}", std::process::id());
        let kek = store.generate_kek(&name).unwrap();
        let endpoint = var("ONE_TEST_S3_ENDPOINT");
        let objects = Objects::s3(&Settings {
            allow_http: endpoint.starts_with("http://"),
            endpoint: &endpoint,
            bucket: &var("ONE_TEST_S3_BUCKET"),
            region: "us-east-1",
            access_key: &var("ONE_TEST_S3_ACCESS_KEY"),
            secret_key: &var("ONE_TEST_S3_SECRET_KEY"),
        })
        .unwrap();
        let world = Self {
            db,
            objects,
            kek,
            kek_id: KekId::parse(&name).unwrap(),
        };
        let mut tx = world.tx().await;
        tx.open_account("tr").await.unwrap();
        tx.commit().await.unwrap();
        world
    }

    async fn tx(&self) -> OwnerTx {
        OwnerTx::begin(&self.db.app, &Owner::new(OWNER).unwrap())
            .await
            .unwrap()
    }

    /// A class DEK made in software and wrapped inside the token.
    async fn dek(&self, tag: u8, class: RetentionClass) -> (DekId, Secret<[u8; 32]>) {
        let id = DekId::from_bytes(bytes(tag)).unwrap();
        let value = secret(tag);
        let wrapped = self
            .kek
            .wrap(&Dek::from_secret(Secret::new(*value.expose())))
            .unwrap();
        let mut tx = self.tx().await;
        tx.put_class_dek(id, class, &self.kek_id, &wrapped)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        (id, value)
    }

    /// A record key wrapped to `dek`, and the sealing of a row under it.
    async fn record_key(
        &self,
        tag: u8,
        class: RetentionClass,
        dek: &(DekId, Secret<[u8; 32]>),
    ) -> (Sealing, Secret<[u8; 32]>) {
        let key = RecordKeyId::from_bytes(bytes(tag)).unwrap();
        let value = secret(tag);
        let mut tx = self.tx().await;
        tx.put_record_key(key, dek.0, &wrap(&dek.1, &value).unwrap())
            .await
            .unwrap();
        tx.commit().await.unwrap();
        let sealing = Sealing {
            class,
            record_key: key,
            dek: dek.0,
            promise_version: 1,
        };
        (sealing, value)
    }

    async fn memory(
        &self,
        tag: u8,
        key: &(Sealing, Secret<[u8; 32]>),
        content: &[u8],
    ) -> MemoryRecordId {
        let id = MemoryRecordId::from_bytes(bytes(tag)).unwrap();
        let record = text(tag);
        let part = content_part(&record, key.0.class);
        let stored = to_stored(&seal_part(&key.1, &part, content).unwrap());
        let mut tx = self.tx().await;
        tx.put_memory_record(id, &key.0, &stored).await.unwrap();
        tx.commit().await.unwrap();
        id
    }

    async fn index_part(
        &self,
        tag: u8,
        key: &(Sealing, Secret<[u8; 32]>),
        content: &[u8],
    ) -> IndexPartId {
        let id = IndexPartId::from_bytes(bytes(tag)).unwrap();
        let record = text(tag);
        let part = PartRef {
            owner: OWNER,
            record: &record,
            class: key.0.class,
            part: Part::Embedding,
            version: 1,
        };
        let stored = to_stored(&seal_part(&key.1, &part, content).unwrap());
        let mut tx = self.tx().await;
        tx.put_index_part(id, 0, Some(("embeddinggemma-2", "2.0")), &key.0, &stored)
            .await
            .unwrap();
        tx.commit().await.unwrap();
        id
    }

    async fn object(&self, tag: u8, key: &(Sealing, Secret<[u8; 32]>), content: &[u8]) -> ObjectId {
        let id = ObjectId::from_bytes(bytes(tag)).unwrap();
        let record = text(tag);
        let stored =
            to_stored(&seal_part(&key.1, &object_part(&record, key.0.class), content).unwrap());
        let len = u64::try_from(stored.len()).unwrap();
        self.objects.put(OWNER, id, stored).await.unwrap();
        let mut tx = self.tx().await;
        tx.put_object(id, &key.0, len).await.unwrap();
        tx.commit().await.unwrap();
        id
    }

    /// Opens a sealed part in the TEE frame with the chain the store hands out now.
    fn open_in_tee(
        &self,
        chain: Option<KeyChain>,
        key: RecordKeyId,
        part: PartRef<'_>,
        stored: Vec<u8>,
    ) -> Option<Vec<u8>> {
        let opener = TeeKeys {
            kek: &self.kek,
            chain,
            part,
        };
        let sealed: Sealed<Vec<u8>> =
            Sealed::from_parts(TeeKeyId(key.to_bytes()), part.context(), stored);
        let unsealed = unseal(&opener, &sealed, |b| Some(b.to_vec())).ok()?;
        Some(unsealed.expose().clone())
    }

    async fn read_memory(&self, tag: u8, class: RetentionClass) -> Option<Vec<u8>> {
        let id = MemoryRecordId::from_bytes(bytes(tag)).unwrap();
        let mut tx = self.tx().await;
        let (key, stored) = tx.memory_ciphertext(id).await.unwrap()?;
        let chain = tx.key_chain(key).await.unwrap();
        tx.commit().await.unwrap();
        let record = text(tag);
        self.open_in_tee(chain, key, content_part(&record, class), stored)
    }

    async fn read_index_part(&self, tag: u8, class: RetentionClass) -> Option<Vec<u8>> {
        let id = IndexPartId::from_bytes(bytes(tag)).unwrap();
        let mut tx = self.tx().await;
        let (key, stored) = tx.index_part_ciphertext(id).await.unwrap()?;
        let chain = tx.key_chain(key).await.unwrap();
        tx.commit().await.unwrap();
        let record = text(tag);
        let part = PartRef {
            owner: OWNER,
            record: &record,
            class,
            part: Part::Embedding,
            version: 1,
        };
        self.open_in_tee(chain, key, part, stored)
    }

    async fn read_object(&self, tag: u8, class: RetentionClass) -> Option<Vec<u8>> {
        let id = ObjectId::from_bytes(bytes(tag)).unwrap();
        let mut tx = self.tx().await;
        let key = tx.object_key(id).await.unwrap()?;
        let chain = tx.key_chain(key).await.unwrap();
        tx.commit().await.unwrap();
        let stored = self.objects.get(OWNER, id).await.unwrap();
        let record = text(tag);
        self.open_in_tee(chain, key, object_part(&record, class), stored)
    }

    /// The ciphertext still in the database, read past the skeleton filter: shred never removes it.
    async fn raw_ciphertext(&self, table: &str, tag: u8) -> Vec<u8> {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
            "SELECT ciphertext FROM one.{table} WHERE owner = $1 AND id = $2"
        )))
        .bind(OWNER)
        .bind(Uuid::from_bytes(bytes(tag)))
        .fetch_one(&self.db.owner)
        .await
        .unwrap()
    }
}

fn content_part(record: &str, class: RetentionClass) -> PartRef<'_> {
    PartRef {
        owner: OWNER,
        record,
        class,
        part: Part::Content,
        version: 1,
    }
}

fn object_part(record: &str, class: RetentionClass) -> PartRef<'_> {
    PartRef {
        owner: OWNER,
        record,
        class,
        part: Part::Object,
        version: 1,
    }
}

/// The TEE side of the key layer: KEK in the token → class DEK → record key → part key.
struct TeeKeys<'a> {
    kek: &'a HsmKek,
    chain: Option<KeyChain>,
    part: PartRef<'a>,
}

impl Opener for TeeKeys<'_> {
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

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

#[tokio::test]
async fn m_25_a_forgotten_record_and_every_derivative_no_longer_open() {
    let w = World::new("shred-forget").await;
    let memory = RetentionClass::OneMemory;
    let dek = w.dek(1, memory).await;
    let source = w.record_key(10, memory, &dek).await;
    let summary = w.record_key(20, memory, &dek).await;
    let index = w.record_key(30, memory, &dek).await;
    let other = w.record_key(40, memory, &dek).await;
    let content = b"meeting with the notary on friday";
    let a = w.memory(10, &source, content).await;
    w.object(11, &source, b"scan of the contract").await;
    let b = w.memory(20, &summary, b"notary meeting").await;
    let c = w.index_part(30, &index, &[7_u8; 64]).await;
    w.memory(40, &other, b"buy bread").await;
    let mut tx = w.tx().await;
    tx.link_derivation(Row::Memory(b), Row::Memory(a), 1)
        .await
        .unwrap();
    tx.link_derivation(Row::IndexPart(c), Row::Memory(b), 1)
        .await
        .unwrap();
    tx.commit().await.unwrap();

    assert!(!contains(
        &w.raw_ciphertext("memory_record", 10).await,
        content
    ));
    assert_eq!(w.read_memory(10, memory).await.unwrap(), content);
    assert_eq!(
        w.read_object(11, memory).await.unwrap(),
        b"scan of the contract"
    );
    assert_eq!(w.read_memory(20, memory).await.unwrap(), b"notary meeting");
    assert_eq!(w.read_index_part(30, memory).await.unwrap(), [7_u8; 64]);

    let mut tx = w.tx().await;
    assert_eq!(tx.forget(Row::Memory(a)).await.unwrap(), Shred::Done);
    for key in [&source, &summary, &index] {
        assert_eq!(tx.key_chain(key.0.record_key).await.unwrap(), None);
    }
    tx.commit().await.unwrap();

    assert_eq!(w.read_memory(10, memory).await, None);
    assert_eq!(w.read_object(11, memory).await, None);
    assert_eq!(w.read_memory(20, memory).await, None);
    assert_eq!(w.read_index_part(30, memory).await, None);
    assert_ne!(w.raw_ciphertext("memory_record", 10).await, [] as [u8; 0]);
    let id = ObjectId::from_bytes(bytes(11)).unwrap();
    assert_ne!(w.objects.get(OWNER, id).await.unwrap(), [] as [u8; 0]);
    assert_eq!(w.read_memory(40, memory).await.unwrap(), b"buy bread");
}

#[tokio::test]
async fn m_25_the_old_wrapped_key_is_gone_not_hidden() {
    let w = World::new("shred-gone").await;
    let memory = RetentionClass::OneMemory;
    let dek = w.dek(1, memory).await;
    let key = w.record_key(10, memory, &dek).await;
    let a = w.memory(10, &key, b"private").await;
    let mut tx = w.tx().await;
    assert_eq!(tx.forget(Row::Memory(a)).await.unwrap(), Shred::Done);
    tx.commit().await.unwrap();
    let wrapped: Option<Vec<u8>> = sqlx::query_scalar(
        "SELECT wrapped_record_key FROM one.record_key WHERE owner = $1 AND record_key_id = $2",
    )
    .bind(OWNER)
    .bind(Uuid::from_bytes(bytes(10)))
    .fetch_one(&w.db.owner)
    .await
    .unwrap();
    assert_eq!(wrapped, None);
    let stale = KeyChain {
        dek: dek.0,
        class: memory,
        kek: w.kek_id.clone(),
        wrapped_dek: w
            .kek
            .wrap(&Dek::from_secret(Secret::new(*dek.1.expose())))
            .unwrap(),
        wrapped_record_key: vec![0; 40],
    };
    let record = text(10);
    let stored = w.raw_ciphertext("memory_record", 10).await;
    assert_eq!(
        w.open_in_tee(
            Some(stale),
            key.0.record_key,
            content_part(&record, memory),
            stored
        ),
        None
    );
}

#[tokio::test]
async fn pv_22_withdrawing_consent_shreds_only_that_fields_dek() {
    let w = World::new("shred-sensitive").await;
    let sensitive = RetentionClass::OneSensitive;
    let health = w.dek(1, sensitive).await;
    let faith = w.dek(2, sensitive).await;
    let h = w.record_key(10, sensitive, &health).await;
    let f = w.record_key(20, sensitive, &faith).await;
    w.memory(10, &h, b"health note").await;
    w.memory(20, &f, b"faith note").await;
    let mut tx = w.tx().await;
    assert_eq!(tx.shred_dek(health.0).await.unwrap(), Shred::Done);
    tx.commit().await.unwrap();
    assert_eq!(w.read_memory(10, sensitive).await, None);
    assert_eq!(w.read_memory(20, sensitive).await.unwrap(), b"faith note");
}

#[tokio::test]
async fn op_11_account_deletion_leaves_only_the_training_lineage_readable() {
    let w = World::new("shred-account").await;
    let classes = [
        RetentionClass::OneMemory,
        RetentionClass::OneModel,
        RetentionClass::OneObservation,
        RetentionClass::OneTrainingLineage,
    ];
    for (n, class) in (1_u8..).zip(classes) {
        let dek = w.dek(n, class).await;
        let key = w.record_key(n.saturating_mul(10), class, &dek).await;
        w.memory(n.saturating_mul(10), &key, class.as_str().as_bytes())
            .await;
    }
    let mut tx = w.tx().await;
    let done = tx.shred_account().await.unwrap();
    assert!(done.iter().all(|(_, s)| *s == Shred::Done));
    tx.commit().await.unwrap();
    for (n, class) in (1_u8..).zip(classes) {
        let read = w.read_memory(n.saturating_mul(10), class).await;
        if class == RetentionClass::OneTrainingLineage {
            assert_eq!(read.unwrap(), class.as_str().as_bytes());
        } else {
            assert_eq!(read, None, "{}", class.as_str());
        }
    }
}

#[tokio::test]
async fn op_30_a_legal_hold_keeps_the_record_and_its_derivatives_readable() {
    let w = World::new("shred-hold").await;
    let memory = RetentionClass::OneMemory;
    let dek = w.dek(1, memory).await;
    let source = w.record_key(10, memory, &dek).await;
    let summary = w.record_key(20, memory, &dek).await;
    let a = w.memory(10, &source, b"held content").await;
    let b = w.memory(20, &summary, b"held summary").await;
    let mut tx = w.tx().await;
    tx.link_derivation(Row::Memory(b), Row::Memory(a), 1)
        .await
        .unwrap();
    tx.place_hold(LegalHoldId::from_bytes(bytes(90)).unwrap(), memory)
        .await
        .unwrap();
    assert_eq!(tx.forget(Row::Memory(a)).await.unwrap(), Shred::Held);
    tx.commit().await.unwrap();
    assert_eq!(w.read_memory(10, memory).await.unwrap(), b"held content");
    assert_eq!(w.read_memory(20, memory).await.unwrap(), b"held summary");
}
