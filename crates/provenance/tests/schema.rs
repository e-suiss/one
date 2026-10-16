//! Every schema vector of `conformance/provenance`: valid inputs round-trip through serde unchanged, invalid ones are rejected or open as `external.unknown` (SEC-14, T-36 (4, 5)).

#![allow(clippy::unwrap_used, reason = "T-38")]

mod common;

use common::{description, load};
use one_provenance::{AccessMapping, Label, Labelled, Opened, ParameterProvenance};
use serde_json::Value;

#[test]
fn t_36_labelled_value_schema_vectors() {
    let vectors = load("provenance/vectors/labelled-value.schema.json");
    for v in &vectors {
        let input = &v["input"];
        let valid = v["valid"].as_bool().unwrap();
        let opened: Opened<Value> = serde_json::from_value(input.clone()).unwrap();
        assert_eq!(opened.conforms(), valid, "{}", description(v));
        if valid {
            let back = serde_json::to_value(opened.labelled()).unwrap();
            assert_eq!(&back, input, "{}", description(v));
            let again: Labelled<Value> = serde_json::from_value(back).unwrap();
            assert!(again == *opened.labelled(), "{}", description(v));
        } else {
            assert_eq!(
                opened.labelled().label(),
                Label::UNKNOWN,
                "{}",
                description(v)
            );
        }
    }
    assert_eq!(vectors.len(), 18);
}

#[test]
fn t_36_access_mapping_schema_vectors() {
    let vectors = load("provenance/vectors/access-mapping.schema.json");
    for v in &vectors {
        let input = &v["input"];
        let parsed = serde_json::from_value::<AccessMapping>(input.clone());
        assert_eq!(
            parsed.is_ok(),
            v["valid"].as_bool().unwrap(),
            "{}",
            description(v)
        );
        if let Ok(pair) = parsed {
            assert_eq!(
                &serde_json::to_value(pair).unwrap(),
                input,
                "{}",
                description(v)
            );
        }
    }
    assert_eq!(vectors.len(), 25);
}

#[test]
fn sec_14_access_parameter_provenance_schema_vectors() {
    let vectors = load("provenance/vectors/access-parameter-provenance.schema.json");
    for v in &vectors {
        let input = &v["input"];
        let parsed = serde_json::from_value::<ParameterProvenance>(input.clone());
        assert_eq!(
            parsed.is_ok(),
            v["valid"].as_bool().unwrap(),
            "{}",
            description(v)
        );
        if let Ok(map) = parsed {
            assert_eq!(
                &serde_json::to_value(&map).unwrap(),
                input,
                "{}",
                description(v)
            );
        }
    }
    assert_eq!(vectors.len(), 4);
}

#[test]
fn t_36_variable_references_of_the_intent_schema_vectors() {
    let vectors = load("intent/vectors/intent-model-output.schema.json");
    let mut seen = 0;
    for v in &vectors {
        let Some(inputs) = v["input"].get("inputs").and_then(Value::as_object) else {
            continue;
        };
        for input in inputs.values() {
            let Some(obj) = input.as_object().filter(|o| o.len() == 1) else {
                continue;
            };
            let Some(text) = obj.get("ref").and_then(Value::as_str) else {
                continue;
            };
            assert_eq!(
                one_provenance::VarRef::parse(text).is_some(),
                v["valid"].as_bool().unwrap(),
                "{}",
                description(v)
            );
            seen += 1;
        }
    }
    assert_eq!(seen, 6);
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code, reason = "T-38")]
struct UpgradeRequest {
    op: String,
    label: one_provenance::LabelKind,
    via: one_provenance::confirm::Via,
    surface: one_provenance::confirm::Surface,
    shown: bool,
    target: one_provenance::confirm::Target,
}

#[test]
fn t_36_upgrade_schema_vectors() {
    let vectors = load("provenance/vectors/upgrade.schema.json");
    for v in &vectors {
        let parsed = serde_json::from_value::<UpgradeRequest>(v["input"].clone());
        let accepted = parsed.is_ok_and(|r| r.op == "upgrade" && r.label.trusted().is_none());
        assert_eq!(
            accepted,
            v["valid"].as_bool().unwrap(),
            "{}",
            description(v)
        );
    }
    assert_eq!(vectors.len(), 8);
}
