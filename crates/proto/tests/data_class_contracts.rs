//! Data class, sensitive class, retention class, life area and provenance label vectors against the one-proto types (PV-16, PV-20, M-28, SEC-14).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::path::Path;

use one_proto::data_class::{DataClass, DataKind, LifeArea, RetentionClass, SensitiveClass};
use one_proto::ontology::concept::Concept;
use one_proto::ontology::provenance::ProvenanceLabel;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

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

fn check_all<T: DeserializeOwned + Serialize>(rel: &str) -> usize {
    let mut n = 0;
    for v in vectors(rel) {
        let input = &v["input"];
        let parsed = serde_json::from_value::<T>(input.clone());
        if v["valid"] == Value::Bool(true) {
            let value = parsed.unwrap_or_else(|e| panic!("{rel}: {}: {e}", v["description"]));
            assert_eq!(
                &serde_json::to_value(&value).unwrap(),
                input,
                "{rel}: {}",
                v["description"]
            );
        } else {
            assert!(parsed.is_err(), "{rel}: accepted {}", v["description"]);
        }
        n += 1;
    }
    n
}

#[test]
fn pv_20_data_class_vectors() {
    assert_eq!(check_all::<DataClass>("memory/vectors/data-class.json"), 16);
}

#[test]
fn pv_20_sensitive_class_vectors() {
    assert_eq!(
        check_all::<SensitiveClass>("memory/vectors/sensitive-class.json"),
        2
    );
    assert_eq!(SensitiveClass::ALL.len(), 13);
}

#[test]
fn pv_16_retention_class_vectors() {
    assert_eq!(
        check_all::<RetentionClass>("memory/vectors/retention-class.json"),
        8
    );
    assert_eq!(RetentionClass::ALL.len(), 7);
}

#[test]
fn m_28_life_area_vectors() {
    assert_eq!(check_all::<LifeArea>("memory/vectors/life-area.json"), 2);
}

#[test]
fn sec_14_provenance_label_vectors() {
    assert_eq!(
        check_all::<ProvenanceLabel>("memory/vectors/provenance-label.json"),
        4
    );
}

#[test]
fn c_19_retention_class_follows_the_data_class() {
    let plain = DataClass::new(vec![DataKind::Personal], vec![]).unwrap();
    let health = DataClass::new(vec![DataKind::Personal], vec![SensitiveClass::Health]).unwrap();
    assert_eq!(
        RetentionClass::for_record(Concept::MemoryRecord, &plain, false),
        RetentionClass::OneMemory
    );
    assert_eq!(
        RetentionClass::for_record(Concept::MemoryRecord, &health, false),
        RetentionClass::OneSensitive
    );
    assert_eq!(
        RetentionClass::for_record(Concept::Observation, &health, true),
        RetentionClass::OneObservation
    );
    assert_eq!(
        RetentionClass::for_record(Concept::Observation, &health, false),
        RetentionClass::OneSensitive
    );
}

#[test]
fn pv_20_combined_data_takes_the_union() {
    let a = DataClass::new(vec![DataKind::Personal], vec![SensitiveClass::Health]).unwrap();
    let b = DataClass::new(
        vec![DataKind::Location],
        vec![SensitiveClass::PreciseLocationHistory],
    )
    .unwrap();
    let general = DataClass::new(vec![DataKind::General], vec![]).unwrap();
    let u = a.union(&b).union(&general);
    assert_eq!(u.kinds(), &[DataKind::Personal, DataKind::Location]);
    assert_eq!(
        u.sensitive(),
        &[
            SensitiveClass::Health,
            SensitiveClass::PreciseLocationHistory
        ]
    );
    assert_eq!(general.union(&general).kinds(), &[DataKind::General]);
}
