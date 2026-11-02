//! The memory component's pure rules: every vector of `trust-class-v1.json`, `decay-v1.json` and `rank-v1.json`, the M-15 write paths and the fixed retrieval order (M-14, M-15, M-16, M-18, M-23, M-30, M-32, M-33).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    reason = "T-38"
)]

use one_memory::domain::classes::trust_class;
use one_memory::domain::decay::{DecayError, DecayInput, priority};
use one_memory::domain::rank::{Ranked, score, smallest_subset};
use one_memory::domain::retrieval::{ORDER, QueryKind, Step, opinion_allowed};
use one_memory::domain::write::{Admitted, Moment, Session, WriteError, WritePath, admit};
use one_proto::memory::fields::{EpistemicState, Layer, LiveStatus, SourceKind, TimeKind};
use one_proto::ontology::time::Instant;
use serde_json::Value;

fn vectors(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../conformance/memory/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn word<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).unwrap()
}

fn instant(v: &Value) -> Option<Instant> {
    v.as_str().map(|s| Instant::parse(s).unwrap())
}

#[test]
fn m_14_trust_class_vectors() {
    for v in vectors("trust-class-v1.json") {
        let i = &v["input"];
        let got = trust_class(
            word::<SourceKind>(&i["source_kind"]),
            i["user_confirmed"].as_bool().unwrap(),
            i["trust"].as_f64().unwrap(),
        );
        assert_eq!(
            got.name(),
            v["expected"]["trust_class"].as_str().unwrap(),
            "{}",
            v["description"]
        );
    }
}

#[test]
fn m_23_decay_vectors() {
    for v in vectors("decay-v1.json") {
        let i = &v["input"];
        let input = DecayInput {
            time_kind: word::<TimeKind>(&i["time_kind"]),
            as_of: instant(&i["as_of"]).unwrap(),
            last_used_at: instant(&i["last_used_at"]).unwrap(),
            use_count: u32::try_from(i["use_count"].as_u64().unwrap()).unwrap(),
            last_confirmed_at: instant(&i["last_confirmed_at"]),
        };
        let d = v["description"].as_str().unwrap();
        match v["expected"].get("priority").and_then(Value::as_f64) {
            Some(p) => assert_eq!(priority(&input).unwrap(), p, "{d}"),
            None => assert_eq!(priority(&input), Err(DecayError::FutureEvidence), "{d}"),
        }
    }
}

#[test]
fn m_30_rank_vectors() {
    for v in vectors("rank-v1.json") {
        let d = v["description"].as_str().unwrap();
        let ranked: Vec<Ranked<String>> = v["input"]["candidates"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| Ranked {
                id: c["id"].as_str().unwrap().to_owned(),
                lexical: c["lexical"].as_f64().unwrap(),
                similarity: c["similarity"].as_f64().unwrap(),
                trust: c["trust"].as_f64().unwrap(),
                priority: c["priority"].as_f64().unwrap(),
                in_area: c["in_area"].as_bool().unwrap(),
                contradicts: word(&c["contradicts"]),
            })
            .collect();
        for r in &ranked {
            assert_eq!(
                score(r),
                v["expected"]["scores"][&r.id].as_f64().unwrap(),
                "{d}: {}",
                r.id
            );
        }
        let kept: Vec<String> = word(&v["expected"]["kept"]);
        assert_eq!(smallest_subset(&ranked), kept, "{d}");
    }
}

#[test]
fn m_15_write_paths() {
    let normal =
        |path, layer, sensitive| admit(Session::Normal, Moment::Background, path, layer, sensitive);
    let fact = Layer::ConsolidatedFact;
    let rule = Layer::BehaviourRule;
    let at = |status, epistemic_state| {
        Ok(Admitted {
            status,
            epistemic_state,
        })
    };
    assert_eq!(
        normal(WritePath::ExplicitRemember, fact, true),
        at(LiveStatus::Active, EpistemicState::Stated)
    );
    assert_eq!(
        normal(WritePath::BackgroundInference, fact, false),
        at(LiveStatus::Active, EpistemicState::Inferred)
    );
    assert_eq!(
        normal(WritePath::BackgroundInference, fact, true),
        at(LiveStatus::Candidate, EpistemicState::Inferred)
    );
    assert_eq!(
        normal(WritePath::BackgroundInference, rule, false),
        at(LiveStatus::Candidate, EpistemicState::Inferred)
    );
    for path in [WritePath::ExternalContent, WritePath::Import] {
        assert_eq!(
            normal(path, fact, false),
            at(LiveStatus::Candidate, EpistemicState::Hypothesis)
        );
        assert_eq!(normal(path, rule, false), Err(WriteError::OutsideRule));
    }
}

#[test]
fn m_16_m_33_only_explicit_remember_on_the_hot_path_and_nothing_when_ephemeral() {
    let fact = Layer::ConsolidatedFact;
    assert!(
        admit(
            Session::Normal,
            Moment::Conversation,
            WritePath::ExplicitRemember,
            fact,
            false
        )
        .is_ok()
    );
    for path in [
        WritePath::BackgroundInference,
        WritePath::ExternalContent,
        WritePath::Import,
    ] {
        assert_eq!(
            admit(Session::Normal, Moment::Conversation, path, fact, false),
            Err(WriteError::HotPath)
        );
    }
    for moment in [Moment::Conversation, Moment::Background] {
        assert_eq!(
            admit(
                Session::Ephemeral,
                moment,
                WritePath::ExplicitRemember,
                fact,
                false
            ),
            Err(WriteError::Ephemeral)
        );
    }
}

#[test]
fn m_30_m_32_the_order_is_fixed_and_opinions_stay_out_of_factual_questions() {
    assert_eq!(
        ORDER,
        [
            Step::Area,
            Step::Status,
            Step::Policy,
            Step::Opinion,
            Step::Search,
            Step::Rank,
            Step::Subset,
            Step::Present
        ]
    );
    assert!(!opinion_allowed(QueryKind::Factual));
    for kind in [
        QueryKind::OwnOpinion,
        QueryKind::Style,
        QueryKind::Suggestion,
    ] {
        assert!(opinion_allowed(kind));
    }
}
