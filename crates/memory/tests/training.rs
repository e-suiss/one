//! The training-data filter: every vector of `training-filter-v1.json`, the fixed check order and an example's debug output that never shows its text (MF-33, MF-32, MF-36, MF-37, T-35 (2)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_memory::domain::training::{Excluded, Profile, example, mask, suspicious};
use one_proto::memory::record::LiveMemoryRecord;
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

fn record(v: &Value) -> LiveMemoryRecord {
    let record: LiveMemoryRecord = serde_json::from_value(v.clone()).unwrap();
    record.validate().unwrap();
    record
}

fn profile(v: &Value) -> Profile {
    if v.as_bool().unwrap() {
        Profile::Child
    } else {
        Profile::Adult
    }
}

#[test]
fn mf_33_training_filter_vectors() {
    let all = vectors("training-filter-v1.json");
    assert!(!all.is_empty());
    for v in all {
        let i = &v["input"];
        let r = record(&i["record"]);
        let got = example(&r, profile(&i["child"]));
        let want = &v["expected"];
        match (got, want["excluded"].as_str(), want["text"].as_str()) {
            (Ok(e), None, Some(text)) => {
                assert_eq!(e.text(), text, "{}", v["description"]);
                assert_eq!(e.record(), r.id, "{}", v["description"]);
            }
            (Err(e), Some(reason), None) => {
                assert_eq!(e.name(), reason, "{}", v["description"]);
            }
            (got, _, _) => panic!("{}: got {got:?}", v["description"]),
        }
    }
}

#[test]
fn mf_33_every_reason_has_a_distinct_name() {
    let names: Vec<&str> = Excluded::ORDER.into_iter().map(Excluded::name).collect();
    let mut sorted = names.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(sorted.len(), names.len());
    assert_eq!(names.first(), Some(&"child_profile"));
    assert_eq!(names.last(), Some(&"suspicious"));
}

#[test]
fn mf_33_masking_is_idempotent_and_leaves_no_digit() {
    for text in [
        "Call +90 532 123 45 67 or write to a.b@example.com.",
        "See https://example.com/1234 and www.example.org.",
        "Between 2026-11-03 and 2026/12/06.",
    ] {
        let once = mask(text);
        assert_eq!(mask(&once), once);
        assert!(!once.chars().any(|c| c.is_ascii_digit()), "{once}");
    }
    assert!(suspicious("Ask Ali first."));
    assert!(!suspicious("Ask first. Then wait."));
}

#[test]
fn t_37_debug_never_shows_the_text() {
    let v = vectors("training-filter-v1.json");
    let first = v
        .iter()
        .find(|v| v["expected"]["text"].is_string())
        .unwrap();
    let r = record(&first["input"]["record"]);
    let e = example(&r, Profile::Adult).unwrap();
    let shown = format!("{e:?}");
    assert!(!shown.contains(e.text()), "{shown}");
    assert!(shown.contains(".."), "{shown}");
}
