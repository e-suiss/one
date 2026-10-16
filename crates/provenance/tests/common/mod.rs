//! Loading the golden vectors under `conformance/`.

#![allow(clippy::unwrap_used, reason = "T-38")]
#![allow(dead_code, unreachable_pub, reason = "T-38")]

use std::path::Path;

use one_provenance::{Label, LabelKind, Source};
use serde_json::Value;

pub fn load(rel: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .join(rel);
    let text = std::fs::read_to_string(&path).unwrap();
    let vectors: Vec<Value> = serde_json::from_str(&text).unwrap();
    assert!(!vectors.is_empty(), "{rel} has no vectors");
    vectors
}

pub fn kind(v: &Value) -> LabelKind {
    LabelKind::parse(v.as_str().unwrap()).unwrap()
}

pub fn label(entry: &Value) -> Label {
    let sources: Option<Vec<Source>> = entry
        .get("sources")
        .map(|s| serde_json::from_value(s.clone()).unwrap());
    Label::from_wire(kind(&entry["label"]), sources.as_deref()).unwrap()
}

pub fn labels(entries: &Value) -> Vec<Label> {
    entries.as_array().unwrap().iter().map(label).collect()
}

pub fn expected_label(expected: &Value) -> Label {
    label(expected)
}

pub fn description(v: &Value) -> &str {
    v["description"].as_str().unwrap()
}
