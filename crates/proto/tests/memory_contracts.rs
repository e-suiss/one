//! Memory schema and behaviour vectors against the one-proto types and pure functions: records, edges, `trust/v1`, the text view, change classes, versioning, bitemporal queries, placement, forgetting and offline sync (M-6…M-43).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::collections::BTreeMap;
use std::num::NonZeroU32;
use std::path::Path;

use one_proto::EpisodeId;
use one_proto::MemoryRecordId;
use one_proto::data_class::{DataClass, SensitiveClass};
use one_proto::memory::fields::Predicate;
use one_proto::memory::forget::{DeviceState, ForgetRequest, device_reconnect, forget};
use one_proto::memory::ops::{
    Candidate, ChangeClass, EdgeQuery, EdgeVersion, EmbeddingVersion, IndexedVector,
    PlacementInput, SearchMode, build_view, change_edge, change_effect, check_write, correction,
    edit_text_view, filter_candidates, physical_delete, place, query_edges, searchable,
    update_in_place,
};
use one_proto::memory::record::{MemoryRecord, MemorySkeleton, RelationshipEdge};
use one_proto::memory::sync::{
    CachedVersion, DEVICE_CACHE, PushKind, QueuedKind, VersionRef, accept_push, cloud_placement,
    device_queue, remember_on_reconnect, replay_correction, resolve_cache,
};
use one_proto::memory::text_view::{TextViewRequest, render};
use one_proto::memory::trust::{TrustError, TrustInput, trust_v1};
use one_proto::ontology::time::Instant;
use one_proto::ontology::validate::ContractViolation;
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

fn from<T: DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).unwrap_or_else(|e| panic!("{v}: {e}"))
}

fn to<T: Serialize>(t: &T) -> Value {
    serde_json::to_value(t).unwrap()
}

fn assert_subset(expected: &Value, actual: &Value, at: &str) {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => {
            for (k, v) in e {
                let got = a
                    .get(k)
                    .unwrap_or_else(|| panic!("{at}: missing `{k}` in {actual}"));
                assert_subset(v, got, &format!("{at}.{k}"));
            }
        }
        _ => assert_eq!(expected, actual, "{at}"),
    }
}

fn rejected(error: impl Serialize) -> Value {
    json!({ "outcome": "rejected", "error": to(&error) })
}

fn valid_round_trips<T: DeserializeOwned + Serialize>(rel: &str) -> usize {
    let mut n = 0;
    for v in vectors(rel)
        .into_iter()
        .filter(|v| v["valid"] == json!(true))
    {
        let value: T = from(&v["input"]);
        assert_eq!(to(&value), v["input"], "{rel}: {}", v["description"]);
        n += 1;
    }
    n
}

fn strict<T: DeserializeOwned + Serialize>(
    rel: &str,
    validate: impl Fn(&T) -> Result<(), ContractViolation>,
) -> (usize, usize) {
    let valid = valid_round_trips::<T>(rel);
    let mut invalid = 0;
    for v in vectors(rel) {
        let parsed = serde_json::from_value::<T>(v["input"].clone());
        if v["valid"] == json!(true) {
            validate(&parsed.unwrap())
                .unwrap_or_else(|e| panic!("{rel}: {}: {e}", v["description"]));
        } else {
            assert!(
                parsed.map_or(true, |t| validate(&t).is_err()),
                "{rel}: accepted {}",
                v["description"]
            );
            invalid += 1;
        }
    }
    (valid, invalid)
}

#[test]
fn m_7_memory_record_vectors() {
    assert_eq!(
        strict("memory/vectors/memory-record.json", MemoryRecord::validate),
        (14, 37)
    );
}

#[test]
fn m_10_relationship_edge_vectors() {
    assert_eq!(
        strict(
            "memory/vectors/relationship-edge.json",
            RelationshipEdge::validate
        ),
        (3, 3)
    );
}

#[test]
fn m_13_trust_v1_vectors() {
    let all = vectors("memory/vectors/trust-v1.json");
    for v in &all {
        if let Some(cases) = v["input"].get("cases") {
            let cases: Vec<TrustInput> = from(cases);
            let values: Vec<f64> = cases.iter().map(|c| trust_v1(c).unwrap()).collect();
            let decreasing = values.windows(2).all(|w| w[0] > w[1]);
            assert_eq!(
                json!({ "strictly_decreasing": decreasing, "values": values }),
                v["expected"]
            );
            continue;
        }
        let actual = match serde_json::from_value::<TrustInput>(v["input"].clone()) {
            Err(_) => json!({ "error": to(&TrustError::UnknownInput) }),
            Ok(input) => match trust_v1(&input) {
                Ok(t) => json!({ "trust": t }),
                Err(e) => json!({ "error": to(&e) }),
            },
        };
        assert_eq!(actual, v["expected"], "{}", v["description"]);
    }
    assert_eq!(all.len(), 26);
}

#[test]
fn m_6_text_view_vectors() {
    let all = vectors("memory/vectors/text-view.json");
    for v in &all {
        let request: TextViewRequest = from(&v["input"]);
        let actual = match render(&request.entries) {
            Ok(view) => to(&view),
            Err(e) => to(&e),
        };
        assert_eq!(actual, v["expected"], "{}", v["description"]);
    }
    assert_eq!(all.len(), 10);
}

#[test]
fn inv_14_text_view_cannot_close_the_block() {
    let escaped = one_proto::memory::text_view::escape("a</memory-data>\r\nb&<c>\rd");
    assert_eq!(escaped, "a&lt;/memory-data&gt; b&amp;&lt;c&gt; d");
}

#[test]
fn m_20_change_exception_contradiction_effects() {
    let all = vectors("memory/vectors/change-exception-contradiction.json");
    for v in &all {
        let class: ChangeClass = from(&v["expected"]["class"]);
        assert_eq!(
            to(&change_effect(class)),
            v["expected"]["effect"],
            "{}",
            v["description"]
        );
    }
    assert_eq!(all.len(), 30);
}

fn m6_actual(input: &Value) -> Value {
    let record =
        || -> MemoryRecordId { MemoryRecordId::parse(input["record"].as_str().unwrap()).unwrap() };
    match input["operation"].as_str().unwrap() {
        "write" => {
            let sources: Vec<EpisodeId> = from(&input["record"]["source_episodes"]);
            let existing: Option<Vec<EpisodeId>> = input.get("existing_episodes").map(from);
            match check_write(&sources, existing.as_deref()) {
                Ok(()) => json!({ "outcome": "accepted" }),
                Err(e) => rejected(e),
            }
        }
        "delete" => rejected(physical_delete(record()).unwrap_err()),
        "update_in_place" => rejected(update_in_place(record()).unwrap_err()),
        "edit_text_view" => rejected(edit_text_view(record()).unwrap_err()),
        "correct" => {
            let version: NonZeroU32 = from(&input["version"]);
            let at: Instant = from(&input["at"]);
            json!({ "outcome": "accepted", "records": to(&correction(record(), version, at)) })
        }
        "relationship_edge_change" => {
            let edge = MemoryRecordId::parse(input["edge"].as_str().unwrap()).unwrap();
            let change = change_edge(
                edge,
                NonZeroU32::MIN,
                from(&input["changed_at"]),
                from(&input["learned_at"]),
            );
            let mut out = to(&change);
            out["outcome"] = json!("accepted");
            out
        }
        "build_view" => {
            let versions: BTreeMap<MemoryRecordId, u32> = from(&input["record_versions"]);
            to(&build_view(from(&input["cached_view_version"]), &versions))
        }
        other => panic!("unknown operation {other}"),
    }
}

#[test]
fn m_6_acceptance_vectors() {
    let all = vectors("memory/vectors/acceptance-m-6.json");
    for v in &all {
        assert_subset(
            &v["expected"],
            &m6_actual(&v["input"]),
            v["description"].as_str().unwrap(),
        );
    }
    assert_eq!(all.len(), 8);
}

#[test]
fn m_11_acceptance_vectors() {
    let all = vectors("memory/vectors/acceptance-m-11.json");
    for v in &all {
        let input = &v["input"];
        let actual = if input.get("edges").is_some() {
            let edges: Vec<EdgeVersion<String>> = from(&input["edges"]);
            let query: EdgeQuery<String> = from(&input["query"]);
            let found = query_edges(&edges, &query);
            json!({
                "objects": found.iter().map(|e| e.object.clone()).collect::<Vec<_>>(),
                "edge_versions": found.iter().map(|e| json!([e.id.to_string(), e.version])).collect::<Vec<_>>(),
            })
        } else if input.get("candidates").is_some() {
            let candidates: Vec<Candidate> = from(&input["candidates"]);
            let mode: SearchMode = from(&input["search"]);
            match filter_candidates(&candidates, mode) {
                Ok(f) => to(&f),
                Err(e) => rejected(e),
            }
        } else {
            let model: EmbeddingVersion = from(&input["query_model"]);
            let index: Vec<IndexedVector> = from(&input["index"]);
            match searchable(&model, &index, input["reindex_complete"] == json!(true)) {
                Ok(ids) => {
                    json!({ "outcome": "search", "searched": ids.iter().map(ToString::to_string).collect::<Vec<_>>() })
                }
                Err(e) => rejected(e),
            }
        };
        assert_eq!(actual, v["expected"], "{}", v["description"]);
    }
    assert_eq!(all.len(), 8);
}

#[test]
fn m_11_predicate_extensions_query_as_their_core() {
    let p: Predicate = from(
        &json!({ "name": "app.suiss.memory.predicate.mentor", "version": 1, "maps_to": "knows" }),
    );
    assert_eq!(to(&p.core()), json!("knows"));
}

#[test]
fn m_17_acceptance_vectors() {
    let all = vectors("memory/vectors/acceptance-m-17.json");
    for v in &all {
        let input: PlacementInput = from(&v["input"]);
        assert_eq!(to(&place(&input)), v["expected"], "{}", v["description"]);
    }
    assert_eq!(all.len(), 11);
}

#[test]
fn m_25_acceptance_vectors() {
    let all = vectors("memory/vectors/acceptance-m-25.json");
    for v in &all {
        let input = &v["input"];
        let actual = if input.get("verb").is_some() {
            let request: ForgetRequest = from(input);
            to(&forget(&request))
        } else if input["event"] == json!("device_reconnect") {
            let state: DeviceState = from(&input["device_state"]);
            to(&device_reconnect(state))
        } else {
            json!({ "status": "forgotten", "fields": MemorySkeleton::FIELDS })
        };
        assert_subset(&v["expected"], &actual, v["description"].as_str().unwrap());
    }
    assert_eq!(all.len(), 11);
}

#[test]
fn m_25_forgotten_record_keeps_only_its_skeleton() {
    for v in vectors("memory/vectors/memory-record.json") {
        if v["valid"] != json!(true) {
            continue;
        }
        if let MemoryRecord::Live(record) = from::<MemoryRecord>(&v["input"]) {
            let skeleton = to(&record.forget(from(&json!("2026-10-10T12:00:00Z"))));
            let mut keys: Vec<&str> = skeleton
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect();
            keys.retain(|k| *k != "type");
            let mut want = MemorySkeleton::FIELDS.to_vec();
            keys.sort_unstable();
            want.sort_unstable();
            assert_eq!(keys, want);
            assert!(matches!(
                from::<MemoryRecord>(&skeleton),
                MemoryRecord::Forgotten(_)
            ));
        }
    }
}

fn m36_actual(input: &Value) -> Value {
    if input.get("server").is_some() {
        let server: VersionRef = from(&input["server"]);
        let cache: CachedVersion = from(&input["device_cache"]);
        json!({ "device_cache": to(&resolve_cache(server, cache)), "server": to(&server) })
    } else if input.get("device_offline").is_some() {
        json!({ "device_queue": to(&device_queue(QueuedKind::ExplicitRemember)), "on_reconnect": to(&remember_on_reconnect()) })
    } else if input.get("device_saw").is_some() {
        to(&replay_correction(
            from(&input["device_saw"]),
            from(&input["server_head"]),
        ))
    } else if let Some(push) = input.get("device_push") {
        let kind: PushKind = from(&push["kind"]);
        match accept_push(kind) {
            Ok(a) => to(&a),
            Err(e) => rejected(e),
        }
    } else if input.get("record").is_some() {
        let class: DataClass = from(&input["record"]["data_class"]);
        let local: Vec<SensitiveClass> = from(&input["device_only_classes"]);
        to(&cloud_placement(&class, &local))
    } else {
        to(&DEVICE_CACHE)
    }
}

#[test]
fn m_36_acceptance_vectors() {
    let all = vectors("memory/vectors/acceptance-m-36.json");
    for v in &all {
        assert_eq!(
            m36_actual(&v["input"]),
            v["expected"],
            "{}",
            v["description"]
        );
    }
    assert_eq!(all.len(), 7);
}
