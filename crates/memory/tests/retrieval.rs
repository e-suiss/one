//! The retrieval pipeline over an in-memory vault: a General record serves every area, a "use only for" restriction keeps a record out of other areas and projects, a record that no longer holds is marked instead of dropped, opinions stay out of factual questions and nothing is retrieved with personalisation off (M-11, M-28, M-30, M-32, M-34).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use std::future::{Future, ready};

use one_memory::app::retrieve;
use one_memory::domain::retrieval::{Query, QueryKind};
use one_memory::ports::{
    EpisodeRow, Forgot, Hit, Policy, Row, Search, SearchError, Vault, VaultError,
};
use one_proto::data_class::{LifeArea, RetentionClass};
use one_proto::memory::record::LiveMemoryRecord;
use one_proto::ontology::reference::PartyRef;
use one_proto::ontology::time::Instant;
use one_proto::{EpisodeId, MemoryRecordId, ProjectId};
use serde_json::{Value, json};

const PARTY: &str = "pty_01k742sgz8ea9tc04vraj0cqss";
const PROJECT: &str = "prj_01k742sgz8fyn90pgkmp7p24ym";
const IDS: [&str; 6] = [
    "mem_01k742szm0fcqs2ar1rjs1vt00",
    "mem_01k742szm0fcqs2ar1rjs1vt01",
    "mem_01k742szm0fcqs2ar1rjs1vt02",
    "mem_01k742szm0fcqs2ar1rjs1vt03",
    "mem_01k742szm0fcqs2ar1rjs1vt04",
    "mem_01k742szm0fcqs2ar1rjs1vt05",
];

fn at(text: &str) -> Instant {
    Instant::parse(text).unwrap()
}

fn owner() -> PartyRef {
    serde_json::from_value(json!({ "ref": "PartyRef", "id": PARTY })).unwrap()
}

fn record(n: usize, text: &str, edit: impl FnOnce(&mut Value)) -> LiveMemoryRecord {
    let mut v = json!({
        "type": "MemoryRecord", "id": IDS[n], "owner": { "ref": "PartyRef", "id": PARTY },
        "domain": { "areas": ["leisure"], "project": null },
        "data_class": { "kinds": ["personal"], "sensitive": [] },
        "retention_class": "one_memory", "provenance": "user.memory",
        "recorded_at": "2026-11-03T08:01:00Z", "version": 1, "promise_version": 1,
        "supersedes": null, "status": "active", "deleted_at": null,
        "produced_by": { "actor": "user" },
        "content_type": "preference", "epistemic_state": "stated", "layer": "consolidated_fact",
        "time_kind": "permanent", "valid_from": "2026-09-01T00:00:00Z", "valid_to": null,
        "superseded_at": null, "source_episodes": ["epi_01k742sgz8fpbvee16bvnbpem8"],
        "source_kind": "user_statement",
        "evidence": { "observation_count": 1, "supporting_count": 1,
                      "first_observed_at": "2026-09-01T08:00:00Z", "last_observed_at": "2026-10-01T08:00:00Z",
                      "contradicting_records": [], "user_confirmed_at": null },
        "trust": { "value": 0.954_545, "formula": "trust/v1", "computed_at": "2026-11-03T08:01:00Z" },
        "alternative_explanations": [], "usage_restriction": null,
        "statement": { "text": text, "lang": "tr" }
    });
    edit(&mut v);
    let r: LiveMemoryRecord = serde_json::from_value(v).unwrap();
    r.validate().unwrap();
    r
}

struct Memory(Vec<LiveMemoryRecord>);

impl Vault for Memory {
    fn put_episode(
        &mut self,
        _: EpisodeId,
        _: RetentionClass,
        _: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>> {
        ready(Err(VaultError::Key))
    }

    fn episodes_exist(
        &mut self,
        _: &[EpisodeId],
    ) -> impl Future<Output = Result<bool, VaultError>> {
        ready(Ok(true))
    }

    fn put_first(
        &mut self,
        _: MemoryRecordId,
        _: RetentionClass,
        _: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>> {
        ready(Err(VaultError::Key))
    }

    fn put_next(
        &mut self,
        _: MemoryRecordId,
        _: MemoryRecordId,
        _: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>> {
        ready(Err(VaultError::Key))
    }

    fn rows(&mut self) -> impl Future<Output = Result<Vec<Row>, VaultError>> {
        ready(Ok(self
            .0
            .iter()
            .map(|r| Row {
                id: r.id,
                version: 1,
                supersedes: None,
                head: true,
                class: r.header.retention_class,
                body: Some(serde_json::to_vec(r).unwrap()),
                recorded_at: r.header.recorded_at,
                deleted_at: None,
            })
            .collect()))
    }

    fn episodes(&mut self) -> impl Future<Output = Result<Vec<EpisodeRow>, VaultError>> {
        ready(Ok(Vec::new()))
    }

    fn forget(&mut self, _: MemoryRecordId) -> impl Future<Output = Result<Forgot, VaultError>> {
        ready(Ok(Forgot::Missing))
    }

    fn forget_episode(&mut self, _: EpisodeId) -> impl Future<Output = Result<Forgot, VaultError>> {
        ready(Ok(Forgot::Missing))
    }
}

struct Open;

impl Policy for Open {
    fn allows(&self, _: &LiveMemoryRecord, _: &Query) -> bool {
        true
    }
}

#[derive(Default)]
struct Exact {
    seen: Vec<MemoryRecordId>,
}

impl Search for Exact {
    fn search(
        &mut self,
        _: &Query,
        eligible: &[MemoryRecordId],
    ) -> impl Future<Output = Result<Vec<Hit>, SearchError>> {
        self.seen = eligible.to_vec();
        ready(Ok(eligible
            .iter()
            .map(|id| Hit {
                id: *id,
                lexical: 1.0,
                similarity: 1.0,
            })
            .collect()))
    }
}

fn query(area: Option<LifeArea>, kind: QueryKind) -> Query {
    Query {
        text: "kahve".to_owned(),
        area,
        project: None,
        kind,
        valid_at: at("2026-11-03T12:00:00Z"),
        unpersonalised: false,
    }
}

fn id(n: usize) -> MemoryRecordId {
    MemoryRecordId::parse(IDS[n]).unwrap()
}

fn records() -> Vec<LiveMemoryRecord> {
    vec![
        record(0, "Bana siz diye hitap et.", |v| {
            v["domain"]["areas"] = json!(["general"]);
        }),
        record(1, "Toplantı notlarını kısa tut.", |v| {
            v["domain"]["areas"] = json!(["work", "leisure"]);
            v["usage_restriction"] = json!({ "areas": ["work"], "projects": [] });
        }),
        record(2, "Bu projede İngilizce yaz.", |v| {
            v["domain"] = json!({ "areas": ["work"], "project": PROJECT });
            v["usage_restriction"] = json!({ "areas": [], "projects": [PROJECT] });
        }),
        record(3, "Geçen yaz Ayvalık'taydım.", |v| {
            v["time_kind"] = json!("one_off");
            v["valid_from"] = json!("2026-06-01T00:00:00Z");
            v["valid_to"] = json!("2026-09-01T00:00:00Z");
        }),
        record(4, "Caz sıkıcı bence.", |v| {
            v["content_type"] = json!("opinion");
        }),
        record(5, "Eski kahve tercihim.", |v| {
            v["status"] = json!("suppressed");
        }),
    ]
}

async fn run(q: &Query) -> (Vec<MemoryRecordId>, String) {
    let mut vault = Memory(records());
    let mut search = Exact::default();
    let view = retrieve(&mut vault, &Open, &mut search, &owner(), q)
        .await
        .unwrap();
    assert!(view.records.iter().all(|r| search.seen.contains(r)));
    (view.records, view.text)
}

#[tokio::test]
async fn m_28_a_general_record_serves_every_area() {
    for area in [LifeArea::Work, LifeArea::Health, LifeArea::Leisure] {
        let (got, _) = run(&query(Some(area), QueryKind::Factual)).await;
        assert!(got.contains(&id(0)), "{area:?}");
    }
}

#[tokio::test]
async fn m_30_a_use_only_for_restriction_keeps_a_record_in_its_areas_and_projects() {
    let (work, _) = run(&query(Some(LifeArea::Work), QueryKind::Factual)).await;
    assert!(work.contains(&id(1)));
    assert!(!work.contains(&id(2)));
    let (leisure, _) = run(&query(Some(LifeArea::Leisure), QueryKind::Factual)).await;
    assert!(!leisure.contains(&id(1)));
    let (none, _) = run(&query(None, QueryKind::Factual)).await;
    assert!(!none.contains(&id(1)));
    assert!(!none.contains(&id(2)));
    let in_project = Query {
        project: Some(ProjectId::parse(PROJECT).unwrap()),
        ..query(Some(LifeArea::Work), QueryKind::Factual)
    };
    let (project, _) = run(&in_project).await;
    assert!(project.contains(&id(1)));
    assert!(project.contains(&id(2)));
}

#[tokio::test]
async fn m_30_a_record_that_no_longer_holds_is_marked_not_dropped() {
    let (got, text) = run(&query(Some(LifeArea::Leisure), QueryKind::Factual)).await;
    assert!(got.contains(&id(3)));
    let line = text.lines().find(|l| l.contains("Ayvalık")).unwrap();
    assert!(line.contains("|not_current"), "{line}");
    let line = text.lines().find(|l| l.contains("siz diye")).unwrap();
    assert!(!line.contains("|not_current"), "{line}");
}

#[tokio::test]
async fn m_32_opinions_stay_out_of_factual_questions() {
    let (factual, _) = run(&query(Some(LifeArea::Leisure), QueryKind::Factual)).await;
    assert!(!factual.contains(&id(4)));
    for kind in [
        QueryKind::OwnOpinion,
        QueryKind::Style,
        QueryKind::Suggestion,
    ] {
        let (got, _) = run(&query(Some(LifeArea::Leisure), kind)).await;
        assert!(got.contains(&id(4)), "{kind:?}");
    }
}

#[tokio::test]
async fn m_24_a_suppressed_record_is_never_retrieved() {
    let (got, _) = run(&query(None, QueryKind::Suggestion)).await;
    assert!(!got.contains(&id(5)));
}

#[tokio::test]
async fn m_34_nothing_is_retrieved_with_personalisation_off() {
    let q = Query {
        unpersonalised: true,
        ..query(None, QueryKind::Suggestion)
    };
    let (got, _) = run(&q).await;
    assert_eq!(got, Vec::new());
}

#[test]
fn t_37_a_query_debug_never_shows_its_text() {
    let shown = format!("{:?}", query(None, QueryKind::Factual));
    assert!(!shown.contains("kahve"), "{shown}");
}
