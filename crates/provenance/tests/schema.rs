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
    assert_eq!(vectors.len(), 12);
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
