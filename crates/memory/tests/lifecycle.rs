//! The Stage 4 closing condition end to end against a real database and `SoftHSM` token: the user sees a remembered record, corrects it, stops and resumes using it and permanently forgets it, and the full export package is written, read back and imported; One alone cannot forget, an export waits while Access cannot be read, and a forgotten chain never opens again (M-6, M-15, M-24, M-25, M-39, M-40, M-43, INV-24, INV-27).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use std::path::PathBuf;

use one_keys::hsm::{HsmKek, KeyStore};
use one_memory::adapters::PgVault;
use one_memory::app::{
    Export, MemoryAppError, Use, correct, export, forget, record_episode, records, remember,
    set_use, view,
};
use one_memory::domain::write::{Moment, Session, WritePath};
use one_memory::ports::Projections;
use one_proto::MemoryRecordId;
use one_proto::id::uuid_v7;
use one_proto::memory::export::{AccessE65, AccessProjection, ExportDocument, Generator, import};
use one_proto::memory::fields::{EpistemicState, LiveStatus};
use one_proto::memory::forget::{Confirmation, ForgetError, Initiator};
use one_proto::memory::record::{LiveMemoryRecord, MemoryRecord};
use one_proto::ontology::episode::Episode;
use one_proto::ontology::reference::PartyRef;
use one_proto::ontology::time::Instant;
use one_store::scope::{Owner, OwnerTx};
use one_store::testing::{TestDb, fresh};
use serde_json::{Value, json};
use suiss_crypto::secret::Secret;

const OWNER: &str = "party:a";
const PARTY: &str = "pty_01k742sgz8ea9tc04vraj0cqss";
const EPISODE: &str = "epi_01k742sgz8fpbvee16bvnbpem8";

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; the test job provides it"))
}

fn at(text: &str) -> Instant {
    Instant::parse(text).unwrap()
}

fn id(tag: u8) -> MemoryRecordId {
    let pid = std::process::id().to_be_bytes();
    MemoryRecordId::from_bytes(uuid_v7(
        1_793_000_000_000,
        [tag, pid[0], pid[1], pid[2], pid[3], 7, 7, 7, 7, tag],
    ))
    .unwrap()
}

fn owner() -> PartyRef {
    serde_json::from_value(json!({ "ref": "PartyRef", "id": PARTY })).unwrap()
}

fn episode() -> Episode {
    serde_json::from_value(json!({
        "type": "Episode", "id": EPISODE, "owner": { "ref": "PartyRef", "id": PARTY },
        "domain": { "areas": ["leisure"], "project": null },
        "data_class": { "kinds": ["personal"], "sensitive": [] },
        "retention_class": "one_memory", "provenance": "user.direct",
        "recorded_at": "2026-11-03T08:00:00Z", "version": 1, "promise_version": 1,
        "status": "active", "deleted_at": null, "supersedes": null,
        "produced_by": { "actor": "one", "instance": { "ref": "InstanceRef", "id": "ins_01k742sgz8ezrvb1ad5hsd1p0p" },
                         "model_version": "mdl_01k742sgz8fpttyr5nkb810tbn", "config_version": "one-2026.11.1" },
        "kind": "conversation", "modes": ["text"],
        "started_at": "2026-11-03T08:00:00Z", "ended_at": "2026-11-03T08:01:00Z",
        "entries": [{ "seq": 0, "at": "2026-11-03T08:00:00Z", "actor": "one", "mode": "text",
                      "kind": "conversation_turn", "content": { "text": "Not ettim.", "lang": "tr" } }]
    }))
    .unwrap()
}

fn record(id: MemoryRecordId, text: &str) -> LiveMemoryRecord {
    let mut v: Value = serde_json::from_value(json!({
        "type": "MemoryRecord", "owner": { "ref": "PartyRef", "id": PARTY },
        "domain": { "areas": ["leisure"], "project": null },
        "data_class": { "kinds": ["personal"], "sensitive": [] },
        "retention_class": "one_memory", "provenance": "user.direct",
        "recorded_at": "2026-11-03T08:01:00Z", "version": 1, "promise_version": 1,
        "supersedes": null, "status": "active", "deleted_at": null,
        "produced_by": { "actor": "one", "instance": { "ref": "InstanceRef", "id": "ins_01k742sgz8ezrvb1ad5hsd1p0p" },
                         "model_version": "mdl_01k742sgz8fpttyr5nkb810tbn", "config_version": "one-2026.11.1" },
        "content_type": "preference", "epistemic_state": "stated", "layer": "consolidated_fact",
        "time_kind": "permanent", "valid_from": "2026-11-03T08:00:00Z", "valid_to": null,
        "superseded_at": null, "source_episodes": [EPISODE], "source_kind": "user_statement",
        "evidence": { "observation_count": 1, "supporting_count": 1,
                      "first_observed_at": "2026-11-03T08:00:00Z", "last_observed_at": "2026-11-03T08:00:00Z",
                      "contradicting_records": [], "user_confirmed_at": null },
        "trust": { "value": 0.954_545, "formula": "trust/v1", "computed_at": "2026-11-03T08:01:00Z" },
        "alternative_explanations": [], "usage_restriction": null,
        "statement": { "text": text, "lang": "tr" }
    }))
    .unwrap();
    v["id"] = json!(id.to_string());
    serde_json::from_value(v).unwrap()
}

struct Access(bool);

impl Projections for Access {
    fn read(
        &mut self,
        at: Instant,
    ) -> impl Future<Output = Option<(AccessProjection, AccessProjection)>> {
        let projection = |schema: &str| AccessProjection {
            source: AccessE65,
            read_at: at,
            schema: schema.to_owned(),
            items: Vec::new(),
        };
        std::future::ready(
            self.0
                .then(|| (projection("grants/v1"), projection("connections/v1"))),
        )
    }
}

struct World {
    db: TestDb,
    kek: HsmKek,
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
        let kek = store
            .generate_kek(&format!("{label}-{}", std::process::id()))
            .unwrap();
        let mut tx = OwnerTx::begin(&db.app, &Owner::new(OWNER).unwrap())
            .await
            .unwrap();
        tx.open_account("tr").await.unwrap();
        tx.commit().await.unwrap();
        Self { db, kek }
    }

    async fn vault(&self) -> PgVault<'_, HsmKek> {
        PgVault::begin(
            &self.db.app,
            &Owner::new(OWNER).unwrap(),
            &self.kek,
            1,
            1_793_000_000_000,
        )
        .await
        .unwrap()
    }

    async fn view_text(&self) -> String {
        let mut v = self.vault().await;
        let text = view(&mut v, &owner(), at("2026-11-03T12:00:00Z"))
            .await
            .unwrap()
            .text;
        v.commit().await.unwrap();
        text
    }
}

async fn remembered(w: &World, tag: u8, text: &str) -> MemoryRecordId {
    let mut v = w.vault().await;
    record_episode(&mut v, &episode()).await.unwrap();
    let rid = remember(
        &mut v,
        at("2026-11-03T08:01:00Z"),
        record(id(tag), text),
        WritePath::ExplicitRemember,
        Moment::Conversation,
        Session::Normal,
    )
    .await
    .unwrap();
    v.commit().await.unwrap();
    rid
}

#[tokio::test]
async fn m_24_see_correct_suppress_resume() {
    let w = World::new("memory-verbs").await;
    let first = remembered(&w, 1, "Kahveyi sütlü içerim.").await;
    assert!(w.view_text().await.contains("Kahveyi sütlü içerim."));

    let mut v = w.vault().await;
    let fixed = correct(
        &mut v,
        at("2026-11-03T09:00:00Z"),
        first,
        record(id(2), "Kahveyi sütsüz içerim."),
    )
    .await
    .unwrap();
    v.commit().await.unwrap();
    let text = w.view_text().await;
    assert!(text.contains("Kahveyi sütsüz içerim."));
    assert!(!text.contains("sütlü"));

    let mut v = w.vault().await;
    let heads = records(&mut v, &owner()).await.unwrap();
    v.commit().await.unwrap();
    assert_eq!(heads.len(), 1);
    let MemoryRecord::Live(head) = &heads[0] else {
        panic!("head is live");
    };
    assert_eq!(
        (head.id, head.supersedes, head.header.version.get()),
        (fixed, Some(first), 2)
    );

    let mut v = w.vault().await;
    let set_aside = set_use(
        &mut v,
        at("2026-11-03T10:00:00Z"),
        fixed,
        id(3),
        Use::Suppress,
    )
    .await
    .unwrap();
    v.commit().await.unwrap();
    assert!(!w.view_text().await.contains("sütsüz"));

    let mut v = w.vault().await;
    assert!(matches!(
        set_use(
            &mut v,
            at("2026-11-03T10:30:00Z"),
            set_aside,
            id(4),
            Use::Suppress
        )
        .await,
        Err(MemoryAppError::State)
    ));
    drop(v);
    let mut v = w.vault().await;
    set_use(
        &mut v,
        at("2026-11-03T11:00:00Z"),
        set_aside,
        id(5),
        Use::Resume,
    )
    .await
    .unwrap();
    v.commit().await.unwrap();
    assert!(w.view_text().await.contains("Kahveyi sütsüz içerim."));

    let mut v = w.vault().await;
    assert!(matches!(
        correct(
            &mut v,
            at("2026-11-03T11:30:00Z"),
            first,
            record(id(6), "x")
        )
        .await,
        Err(MemoryAppError::NotFound)
    ));
}

#[tokio::test]
async fn m_25_only_the_user_forgets_and_the_whole_chain_stops_opening() {
    let w = World::new("memory-forget").await;
    let first = remembered(&w, 1, "Doktor randevum salı.").await;
    let mut v = w.vault().await;
    let head = correct(
        &mut v,
        at("2026-11-03T09:00:00Z"),
        first,
        record(id(2), "Doktor randevum çarşamba."),
    )
    .await
    .unwrap();
    v.commit().await.unwrap();

    for (initiator, confirmation, error) in [
        (
            Initiator::One,
            Some(Confirmation::InApp),
            ForgetError::UserOnly,
        ),
        (
            Initiator::Trigger,
            Some(Confirmation::InApp),
            ForgetError::UserOnly,
        ),
        (Initiator::User, None, ForgetError::ConfirmationRequired),
    ] {
        let mut v = w.vault().await;
        assert!(matches!(
            forget(&mut v, at("2026-11-03T10:00:00Z"), head, initiator, confirmation).await,
            Err(MemoryAppError::Forget(e)) if e == error
        ));
    }
    assert!(w.view_text().await.contains("çarşamba"));

    let mut v = w.vault().await;
    let effects = forget(
        &mut v,
        at("2026-11-03T10:00:00Z"),
        head,
        Initiator::User,
        Some(Confirmation::InApp),
    )
    .await
    .unwrap();
    v.commit().await.unwrap();
    assert_eq!(effects.shredded_record_keys, vec![head]);
    assert!(effects.user_notice.tr.contains("okunamaz"));
    assert!(!w.view_text().await.contains("randevum"));

    let mut v = w.vault().await;
    let rows = one_memory::ports::Vault::rows(&mut v).await.unwrap();
    v.commit().await.unwrap();
    assert_eq!(rows.len(), 2);
    assert!(
        rows.iter()
            .all(|r| r.body.is_none() && r.deleted_at.is_some())
    );
    let mut v = w.vault().await;
    let heads = records(&mut v, &owner()).await.unwrap();
    assert!(matches!(heads.as_slice(), [MemoryRecord::Forgotten(s)] if s.id == head));
}

#[tokio::test]
async fn m_39_the_full_package_is_written_read_back_and_imported() {
    let w = World::new("memory-export").await;
    let old = remembered(&w, 1, "Kahveyi sütlü içerim.").await;
    let mut v = w.vault().await;
    let kept = correct(
        &mut v,
        at("2026-11-03T08:01:30Z"),
        old,
        record(id(3), "Kahveyi sütsüz içerim."),
    )
    .await
    .unwrap();
    let gone = remember(
        &mut v,
        at("2026-11-03T08:02:00Z"),
        record(id(2), "Eski adresim."),
        WritePath::ExplicitRemember,
        Moment::Conversation,
        Session::Normal,
    )
    .await
    .unwrap();
    forget(
        &mut v,
        at("2026-11-03T09:00:00Z"),
        gone,
        Initiator::User,
        Some(Confirmation::InApp),
    )
    .await
    .unwrap();
    v.commit().await.unwrap();

    let generator = Generator {
        name: "one-server".to_owned(),
        version: "0.0.0".to_owned(),
    };
    let mut v = w.vault().await;
    let waiting = export(
        &mut v,
        &mut Access(false),
        &owner(),
        at("2026-11-03T12:00:00Z"),
        false,
        generator.clone(),
    )
    .await
    .unwrap();
    assert_eq!(waiting, Export::Waiting);

    let Export::Ready(document) = export(
        &mut v,
        &mut Access(true),
        &owner(),
        at("2026-11-03T12:00:00Z"),
        false,
        generator,
    )
    .await
    .unwrap() else {
        panic!("Access answered");
    };
    v.commit().await.unwrap();
    let bytes = serde_json::to_vec(&*document).unwrap();
    let read: ExportDocument = serde_json::from_slice(&bytes).unwrap();
    read.validate().unwrap();
    assert_eq!(read, *document);
    assert!(read.text_view.contains("Kahveyi sütsüz içerim."));
    assert!(!String::from_utf8_lossy(&bytes).contains("Eski adresim"));
    let ids: Vec<MemoryRecordId> = read.memory.records.iter().map(MemoryRecord::id).collect();
    assert!(ids.contains(&kept) && ids.contains(&gone));
    assert!(matches!(
        read.memory.records.iter().find(|r| r.id() == gone),
        Some(MemoryRecord::Forgotten(_))
    ));
    let superseded = read
        .memory
        .records
        .iter()
        .find(|r| r.id() == old)
        .and_then(MemoryRecord::live)
        .unwrap();
    assert_eq!(superseded.epistemic_state, EpistemicState::Invalidated);
    assert!(superseded.superseded_at.is_some());
    assert!(!read.text_view.contains("sütlü"));
    assert_eq!(read.memory.episodes.len(), 1);

    let imported = import(&read);
    assert!(!imported.training_eligible);
    assert_eq!(imported.imported.len(), 2);
    assert!(
        imported
            .imported
            .iter()
            .all(|r| r.status == LiveStatus::Candidate)
    );
}
