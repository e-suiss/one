//! Ontology schema and behaviour vectors against the one-proto types: identifiers, references, the canonical records, relations, extensions and layer conversions (C-1…C-29, M-1).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::path::Path;

use one_proto::memory::fields::{EpistemicState, LiveStatus};
use one_proto::memory::record::LiveMemoryRecord;
use one_proto::memory::record::MemoryRecord;
use one_proto::ontology::concept::{AnyId, Concept};
use one_proto::ontology::concept::{CanonicalId, CanonicalNode};
use one_proto::ontology::episode::Episode;
use one_proto::ontology::extension::ExtensionDeclaration;
use one_proto::ontology::goal::Goal;
use one_proto::ontology::layers::{
    ConfirmationEvidence, Conversion, LayerError, OntologyLayer, confirm, conversion, correct,
    infer, layer_of, record_observed, remember_explicit, suggest,
};
use one_proto::ontology::observation::Observation;
use one_proto::ontology::personality::PersonalityProfile;
use one_proto::ontology::provenance::ProvenanceLabel;
use one_proto::ontology::reference::AnyRef;
use one_proto::ontology::relation::RelationEdge;
use one_proto::ontology::routine::Routine;
use one_proto::ontology::time::Instant;
use one_proto::ontology::validate::ContractViolation;
use one_proto::{InteractionId, MemoryRecordId};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn vectors(rel: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn round_trip<T: DeserializeOwned + Serialize>(rel: &str, v: &Value) {
    let input = &v["input"];
    let value: T = serde_json::from_value(input.clone())
        .unwrap_or_else(|e| panic!("{rel}: {}: {e}", v["description"]));
    assert_eq!(
        &serde_json::to_value(&value).unwrap(),
        input,
        "{rel}: {}",
        v["description"]
    );
}

fn valid_round_trips<T: DeserializeOwned + Serialize>(rel: &str) -> usize {
    let valid: Vec<Value> = vectors(rel)
        .into_iter()
        .filter(|v| v["valid"] == json!(true))
        .collect();
    for v in &valid {
        round_trip::<T>(rel, v);
    }
    valid.len()
}

fn strict<T: DeserializeOwned + Serialize>(
    rel: &str,
    validate: impl Fn(&T) -> Result<(), ContractViolation>,
) -> (usize, usize) {
    let (mut valid, mut invalid) = (0, 0);
    for v in vectors(rel) {
        let parsed = serde_json::from_value::<T>(v["input"].clone());
        if v["valid"] == json!(true) {
            round_trip::<T>(rel, &v);
            validate(&parsed.unwrap())
                .unwrap_or_else(|e| panic!("{rel}: {}: {e}", v["description"]));
            valid += 1;
        } else {
            let refused = parsed.map_or(true, |t| validate(&t).is_err());
            assert!(refused, "{rel}: accepted {}", v["description"]);
            invalid += 1;
        }
    }
    (valid, invalid)
}

fn rejected<T: DeserializeOwned>(rel: &str) -> (usize, usize) {
    let invalid: Vec<Value> = vectors(rel)
        .into_iter()
        .filter(|v| v["valid"] == json!(false))
        .collect();
    let n = invalid
        .iter()
        .filter(|v| serde_json::from_value::<T>(v["input"].clone()).is_err())
        .count();
    (n, invalid.len())
}

#[test]
fn c_19_identifier_vectors() {
    assert_eq!(valid_round_trips::<AnyId>("ontology/vectors/id.json"), 2);
    assert_eq!(rejected::<AnyId>("ontology/vectors/id.json"), (9, 9));
}

#[test]
fn c_24_reference_vectors() {
    assert_eq!(
        valid_round_trips::<AnyRef>("ontology/vectors/reference.json"),
        7
    );
}

#[test]
fn c_10_observation_vectors() {
    assert_eq!(
        strict("ontology/vectors/observation.json", Observation::validate),
        (6, 15)
    );
}

#[test]
fn c_11_episode_vectors() {
    assert_eq!(
        strict("ontology/vectors/episode.json", Episode::validate),
        (9, 13)
    );
}

#[test]
fn c_13_goal_vectors() {
    assert_eq!(strict("ontology/vectors/goal.json", Goal::validate), (1, 5));
}

#[test]
fn c_14_routine_vectors() {
    assert_eq!(
        strict("ontology/vectors/routine.json", Routine::validate),
        (2, 12)
    );
}

#[test]
fn c_14_routine_cannot_carry_authority() {
    for v in vectors("ontology/vectors/routine.json") {
        if v["valid"] == json!(true) {
            let mut input = v["input"].clone();
            input["authority"] = json!("GRANT");
            assert!(serde_json::from_value::<Routine>(input).is_err());
        }
    }
}

#[test]
fn c_23_relation_vectors() {
    assert_eq!(
        strict("ontology/vectors/relation.json", |_: &RelationEdge| Ok(())),
        (12, 15)
    );
}

#[test]
fn c_23_relation_has_no_authority_field() {
    for v in vectors("ontology/vectors/relation.json") {
        if v["valid"] == json!(true) {
            let edge: RelationEdge = serde_json::from_value(v["input"].clone()).unwrap();
            let out = serde_json::to_value(&edge).unwrap();
            assert!(out.get("authority").is_none());
        }
    }
}

#[test]
fn c_28_personality_profile_vectors() {
    assert_eq!(
        strict(
            "ontology/vectors/personality-profile.json",
            |_: &PersonalityProfile| Ok(())
        ),
        (1, 7)
    );
}

#[test]
fn c_7_extension_vectors() {
    assert_eq!(
        strict(
            "ontology/vectors/extension.json",
            ExtensionDeclaration::validate
        ),
        (5, 12)
    );
}

fn concept_check(v: &Value) -> Result<(), String> {
    fn one<T: DeserializeOwned>(
        input: &Value,
        validate: impl Fn(&T) -> Result<(), ContractViolation>,
    ) -> Result<(), String> {
        let t: T = serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
        validate(&t).map_err(|e| e.to_string())
    }
    let input = &v["input"];
    match input.get("type").and_then(Value::as_str) {
        Some("Observation") => one(input, Observation::validate),
        Some("Episode") => one(input, Episode::validate),
        Some("MemoryRecord") => one(input, MemoryRecord::validate),
        Some("Goal") => one(input, Goal::validate),
        Some("Routine") => one(input, Routine::validate),
        other => serde_json::from_value::<Concept>(json!(other))
            .map(|c| panic!("{c:?} is owned by another module"))
            .map_err(|e| e.to_string()),
    }
}

#[test]
fn c_2_concept_vectors() {
    let rel = "ontology/vectors/concept.json";
    let all = vectors(rel);
    for v in &all {
        let valid = v["valid"] == json!(true);
        assert_eq!(concept_check(v).is_ok(), valid, "{}", v["description"]);
        if valid {
            match v["input"]["type"].as_str().unwrap() {
                "Observation" => round_trip::<Observation>(rel, v),
                "Episode" => round_trip::<Episode>(rel, v),
                "MemoryRecord" => round_trip::<MemoryRecord>(rel, v),
                "Goal" => round_trip::<Goal>(rel, v),
                _ => round_trip::<Routine>(rel, v),
            }
        }
    }
    assert_eq!(all.len(), 10);
}

#[test]
fn c_8_layer_conversion_vectors() {
    let rel = "ontology/vectors/layers.json";
    let all = vectors(rel);
    for v in &all {
        let from = serde_json::from_value::<OntologyLayer>(v["input"]["from"].clone());
        let to = serde_json::from_value::<OntologyLayer>(v["input"]["to"].clone());
        let asked = v["input"]["user_asked"].as_bool().unwrap();
        let found = match (from, to) {
            (Ok(f), Ok(t)) => conversion(f, t, asked),
            _ => None,
        };
        let actual = found.map_or(
            json!("rejected"),
            |c| json!({ "function": serde_json::to_value(c).unwrap() }),
        );
        assert_eq!(actual, v["expected"], "{}", v["description"]);
    }
    assert_eq!(all.len(), 12);
}

#[test]
fn m_15_user_asked_flags_match_layers_toml() {
    let text = std::fs::read_to_string(format!(
        "{}/../../conformance/ontology/layers.toml",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    for block in text.split("[[conversion]]").skip(1) {
        let field = |key: &str| {
            block
                .lines()
                .find_map(|l| l.strip_prefix(&format!("{key} = ")))
                .map(|v| v.trim_matches('"').to_owned())
        };
        let name = field("name").unwrap();
        let c: Conversion = serde_json::from_value(json!(name)).unwrap();
        assert_eq!(
            c.user_asked(),
            field("user_asked").map(|v| v == "true"),
            "{name}"
        );
    }
}

#[test]
fn c_8_no_conversion_reaches_authority() {
    for c in Conversion::ALL {
        assert_ne!(c.to_layer(), OntologyLayer::Authority);
    }
}

fn first_valid<T: DeserializeOwned>(rel: &str, pick: impl Fn(&Value) -> bool) -> T {
    let v = vectors(rel)
        .into_iter()
        .find(|v| v["valid"] == json!(true) && pick(&v["input"]))
        .unwrap();
    serde_json::from_value(v["input"].clone()).unwrap()
}

fn utterance() -> Observation {
    first_valid("ontology/vectors/observation.json", |i| {
        i["source_kind"] == json!("user_utterance")
    })
}

fn record_for(observation: &Observation) -> LiveMemoryRecord {
    let mut r: LiveMemoryRecord = first_valid("memory/vectors/memory-record.json", |i| {
        i["epistemic_state"] == json!("inferred")
    });
    r.source_episodes = vec![observation.episode];
    r
}

#[test]
fn c_8_named_conversions_set_the_yielded_states() {
    let obs = utterance();
    let stated = remember_explicit(&obs, record_for(&obs)).unwrap();
    assert_eq!(
        (stated.epistemic_state, stated.status),
        (EpistemicState::Stated, LiveStatus::Active)
    );
    assert_eq!(layer_of(&stated), OntologyLayer::Memory);

    let hypothesis = infer(record_for(&obs), true);
    assert_eq!(
        (hypothesis.epistemic_state, hypothesis.status),
        (EpistemicState::Hypothesis, LiveStatus::Candidate)
    );
    assert_eq!(layer_of(&hypothesis), OntologyLayer::Inference);
    assert_eq!(hypothesis.header.provenance, ProvenanceLabel::OneInferred);

    let at: Instant = serde_json::from_value(json!("2026-10-20T09:00:00Z")).unwrap();
    let verified = confirm(hypothesis, ConfirmationEvidence::User(at)).unwrap();
    assert_eq!(verified.epistemic_state, EpistemicState::Verified);
    assert_eq!(verified.header.provenance, ProvenanceLabel::UserMemory);
    assert_eq!(
        confirm(verified.clone(), ConfirmationEvidence::SecondEvidence),
        Err(LayerError::NotAnInference)
    );

    let mut next = stated.clone();
    next.id = MemoryRecordId::parse("mem_01m5104ew8esb9cnjpasb5cnjp").unwrap();
    let (old, new) = correct(stated.clone(), next, at).unwrap();
    assert_eq!(
        (old.epistemic_state, old.superseded_at),
        (EpistemicState::Invalidated, Some(at))
    );
    assert_eq!(new.supersedes, Some(stated.id));
    assert_eq!(new.header.version.get(), stated.header.version.get() + 1);

    assert_eq!(
        record_observed(&obs, record_for(&obs), true).map(|r| r.status),
        Ok(LiveStatus::Candidate)
    );
}

#[test]
fn c_14_suggestion_is_an_approval_interaction() {
    let interaction = InteractionId::parse("int_01m5104gtrexvvexvqexvqexvq").unwrap();
    let routine = CanonicalNode(CanonicalId::parse("rtn_01m5104cxreh288h248h248h24").unwrap());
    let at: Instant = serde_json::from_value(json!("2026-10-20T09:00:00Z")).unwrap();
    let s = serde_json::to_value(suggest(interaction, routine, at).unwrap()).unwrap();
    assert_eq!(s["interaction_kind"], json!("approval"));
    assert_eq!(s["concerns"]["relation"], json!("concerns"));
    let obs = CanonicalNode(CanonicalId::parse("obs_01m5104a00e48s248h248h248h").unwrap());
    assert_eq!(
        suggest(interaction, obs, at),
        Err(LayerError::NotSuggestible)
    );
}
