//! Export package vectors: CDDL validity, decode(encode) identity, unknown-field skipping and import as unverified candidates (M-39, M-40, M-43, INV-27).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::path::Path;

use one_proto::memory::export::{ExportDocument, import};
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

fn decode(document: &Value) -> Option<ExportDocument> {
    let text = serde_json::to_string(document).unwrap();
    let doc: ExportDocument = serde_json::from_str(&text).ok()?;
    doc.validate().ok()?;
    Some(doc)
}

#[test]
fn m_40_export_schema_vectors() {
    let all = vectors("export/vectors/export-schema.json");
    for v in &all {
        assert_eq!(v["input"]["cddl"], json!("export.cddl"));
        let valid = decode(&v["input"]["document"]).is_some();
        assert_eq!(
            json!({ "valid": valid }),
            v["expected"],
            "{}",
            v["description"]
        );
    }
    assert_eq!(all.len(), 18);
}

#[test]
fn m_40_round_trip_vectors() {
    let all = vectors("export/vectors/round-trip.json");
    for v in &all {
        let doc = decode(&v["input"]["document"]).unwrap_or_else(|| panic!("{}", v["description"]));
        if v["expected"].get("imported").is_some() {
            assert_eq!(
                serde_json::to_value(import(&doc)).unwrap(),
                v["expected"],
                "{}",
                v["description"]
            );
            continue;
        }
        let bytes = serde_json::to_vec(&doc).unwrap();
        let again: ExportDocument = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(again, doc);
        let encoded = serde_json::to_value(&again).unwrap();
        assert_eq!(
            json!({ "equal": encoded == v["input"]["document"], "document": encoded }),
            v["expected"],
            "{}",
            v["description"]
        );
    }
    assert_eq!(all.len(), 4);
}

fn non_ascii_strings(v: &Value, out: &mut Vec<String>) {
    match v {
        Value::String(s) if !s.is_ascii() => out.push(s.clone()),
        Value::Array(items) => items.iter().for_each(|i| non_ascii_strings(i, out)),
        Value::Object(map) => map.values().for_each(|i| non_ascii_strings(i, out)),
        _ => {}
    }
}

#[test]
fn m_40_turkish_text_is_kept_byte_for_byte() {
    let v = &vectors("export/vectors/round-trip.json")[2];
    let doc = decode(&v["input"]["document"]).unwrap();
    let encoded = serde_json::to_string(&doc).unwrap();
    let mut texts = Vec::new();
    non_ascii_strings(&v["input"]["document"], &mut texts);
    assert_ne!(texts, Vec::<String>::new());
    for t in texts {
        assert!(encoded.contains(&t), "{t}");
    }
}

#[test]
fn inv_27_unknown_fields_are_skipped() {
    let all = vectors("export/vectors/unknown-fields.json");
    for v in &all {
        let actual = match decode(&v["input"]["document"]) {
            Some(doc) => json!({ "valid": true, "read": serde_json::to_value(&doc).unwrap() }),
            None => json!({ "valid": false }),
        };
        assert_eq!(actual, v["expected"], "{}", v["description"]);
    }
    assert_eq!(all.len(), 3);
}
