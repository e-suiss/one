//! Every schema and behaviour vector of `conformance/capability` through the typed names, negotiation, registry entries, surfaces, autonomy rules, triggers and the purchase intent, and the embedded tables against their TOML files (CP-15, CP-16, CP-23, A-1, A-14, A-24, A-42).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use one_proto::capability::{
    AutonomyRule, CATEGORIES, CapabilityDefinition, CapabilityName, CapabilityVersion, Declaration,
    NameKind, PurchaseInput, RESERVED_SEGMENTS, SurfaceCapability, TAXONOMY, Trigger,
    TriggerRejection, TriggerRun, TypedSchema, check_trigger_bounds, effective_reversibility,
    is_forbidden_field_name, is_safe_property_name, negotiate,
};
use one_proto::interaction_types::Reversibility;
use one_proto::ontology::JsonObject;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

fn read(path: &str) -> String {
    let full = format!(
        "{}/../../conformance/capability/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(full).unwrap()
}

fn load(path: &str) -> Vec<Value> {
    serde_json::from_str::<Value>(&read(path))
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn schema_vectors<T: DeserializeOwned + Serialize>(path: &str) -> (usize, usize) {
    let (mut valid, mut invalid) = (0, 0);
    for v in load(path) {
        let input = &v["input"];
        let description = v["description"].as_str().unwrap();
        let parsed = serde_json::from_value::<T>(input.clone());
        if v["valid"].as_bool().unwrap() {
            let typed = parsed.unwrap_or_else(|e| panic!("{path}: rejected: {description}: {e}"));
            assert_eq!(
                &serde_json::to_value(&typed).unwrap(),
                input,
                "{path}: round trip: {description}"
            );
            valid += 1;
        } else {
            assert!(parsed.is_err(), "{path}: accepted: {description}");
            invalid += 1;
        }
    }
    (valid, invalid)
}

#[test]
fn cp_16_definition_schema_vectors() {
    assert_eq!(
        schema_vectors::<CapabilityDefinition>("vectors/definition.json"),
        (6, 40)
    );
}

#[test]
fn c_18_surface_capability_schema_vectors() {
    assert_eq!(
        schema_vectors::<SurfaceCapability>("vectors/surface-capability.json"),
        (3, 15)
    );
}

#[test]
fn a_1_autonomy_rule_schema_vectors() {
    assert_eq!(
        schema_vectors::<AutonomyRule>("vectors/autonomy-rule.json"),
        (4, 10)
    );
}

#[test]
fn a_14_trigger_schema_vectors() {
    assert_eq!(schema_vectors::<Trigger>("vectors/trigger.json"), (2, 14));
}

#[test]
fn a_49_purchase_input_schema_vectors() {
    assert_eq!(
        schema_vectors::<PurchaseInput>("vectors/commerce-purchase-input.json"),
        (1, 7)
    );
}

#[test]
fn cp_15_name_vectors() {
    let all = load("vectors/name.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let input = v["input"].as_str().unwrap();
        let expected = &v["expected"];
        let valid = expected["valid"].as_bool().unwrap();
        if expected["kind"] == "version" {
            assert_eq!(
                CapabilityVersion::parse(input).is_ok(),
                valid,
                "{description}"
            );
            continue;
        }
        match CapabilityName::parse(input) {
            Ok(name) => {
                assert!(valid, "{description}: accepted");
                let kind = match name.kind() {
                    NameKind::Suiss => "suiss",
                    NameKind::ThirdParty => "third_party",
                };
                assert_eq!(expected["kind"], kind, "{description}");
                let segments: Vec<&str> = name.segments().collect();
                assert_eq!(expected["segments"], json!(segments), "{description}");
                assert_eq!(
                    expected.get("category").and_then(Value::as_str),
                    name.category(),
                    "{description}"
                );
            }
            Err(e) => {
                assert!(!valid, "{description}: rejected {e}");
                assert_eq!(expected["error"], e.code(), "{description}");
            }
        }
    }
    assert_eq!(all.len(), 23);
}

fn offer(side: &Value) -> Vec<Declaration> {
    side.as_array()
        .unwrap()
        .iter()
        .filter_map(|d| serde_json::from_value(d.clone()).ok())
        .collect()
}

#[test]
fn cp_15_negotiation_vectors() {
    let all = load("vectors/negotiation.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let kept = negotiate(&offer(&v["input"]["local"]), &offer(&v["input"]["remote"]));
        assert_eq!(
            serde_json::to_value(&kept).unwrap(),
            v["expected"],
            "{description}"
        );
    }
    assert_eq!(all.len(), 10);
}

#[test]
fn cp_15_extension_cycle_without_a_suiss_parent_is_dropped() {
    let cycle = json!([
        {"name": "com.example.a.b", "versions": ["2026-01-01"], "extends": "com.example.c.d"},
        {"name": "com.example.c.d", "versions": ["2026-01-01"], "extends": "com.example.a.b"}
    ]);
    assert_eq!(negotiate(&offer(&cycle), &offer(&cycle)), Vec::new());
}

#[test]
fn a_24_reversibility_vectors() {
    let all = load("vectors/reversibility.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let declared = v["input"]["declared"]
            .as_str()
            .map(|d| Reversibility::from_wire(d).unwrap());
        let effective =
            effective_reversibility(declared, v["input"]["verified"].as_bool().unwrap());
        assert_eq!(
            effective.as_str(),
            v["expected"]["effective"],
            "{description}"
        );
    }
    assert_eq!(all.len(), 5);
}

#[test]
fn a_14_trigger_bounds_vectors() {
    let all = load("vectors/trigger-bounds.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let trigger: Trigger = serde_json::from_value(v["input"].clone()).unwrap();
        let expected = &v["expected"];
        match check_trigger_bounds(&trigger) {
            Ok(run) => {
                assert_eq!(expected["accepted"], true, "{description}");
                let run = match run {
                    TriggerRun::DecidesOnFire => "decides_on_fire",
                    TriggerRun::AsksOnFire => "asks_on_fire",
                    TriggerRun::HandsOffOnFire => "hands_off_on_fire",
                };
                assert_eq!(expected["runs"], run, "{description}");
            }
            Err(e) => {
                let code = match e {
                    TriggerRejection::EndsAfterMandate => "ends_after_mandate",
                    TriggerRejection::BudgetExceedsMandate => "budget_exceeds_mandate",
                    TriggerRejection::CurrencyMismatch => "currency_mismatch",
                };
                assert_eq!(expected["rejected"], code, "{description}");
            }
        }
    }
    assert_eq!(all.len(), 6);
}

#[test]
fn cp_23_secret_like_field_names_are_forbidden() {
    for name in [
        "password",
        "access_token",
        "card_number",
        "cvv",
        "session_cookie",
        "my_api_key",
        "otp",
    ] {
        assert!(is_forbidden_field_name(name), "{name}");
        assert!(!is_safe_property_name(name), "{name}");
    }
    for name in [
        "pickup",
        "spinner",
        "cardinal",
        "tokenless",
        "destination",
        "pinned_at",
    ] {
        assert!(is_safe_property_name(name), "{name}");
    }
}

#[test]
fn cp_23_nested_secret_field_in_a_typed_schema_is_rejected() {
    let schema = |field: &str| -> JsonObject {
        serde_json::from_value(json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "trip": {
                    "type": "object",
                    "additionalProperties": false,
                    "properties": { field: {"type": "string"} }
                }
            }
        }))
        .unwrap()
    };
    assert!(TypedSchema::new(schema("pickup")).is_ok());
    assert!(TypedSchema::new(schema("loyalty_pin")).is_err());
}

fn toml_values(text: &str, header: &str, key: &str) -> Vec<String> {
    text.split("[[")
        .skip(1)
        .filter_map(|b| b.split_once("]]"))
        .filter(|(n, _)| *n == header)
        .filter_map(|(_, body)| {
            body.lines().find_map(|l| {
                l.strip_prefix(&format!("{key} = "))
                    .map(|v| v.trim_matches('"').to_owned())
            })
        })
        .collect()
}

#[test]
fn cp_15_taxonomy_matches_taxonomy_toml_and_parses() {
    let text = read("taxonomy.toml");
    assert_eq!(
        CATEGORIES,
        toml_values(&text, "category", "name").as_slice()
    );
    assert_eq!(
        TAXONOMY,
        toml_values(&text, "capability", "name").as_slice()
    );
    for name in TAXONOMY {
        let parsed = CapabilityName::parse(name).unwrap();
        assert_eq!(parsed.kind(), NameKind::Suiss);
        assert!(CATEGORIES.contains(&parsed.category().unwrap()), "{name}");
    }
}

#[test]
fn cp_15_reserved_segments_match_naming_toml() {
    let text = read("naming.toml");
    assert_eq!(
        RESERVED_SEGMENTS,
        toml_values(&text, "reserved_segment", "segment").as_slice()
    );
    for segment in RESERVED_SEGMENTS {
        assert!(CapabilityName::parse(&format!("app.suiss.{segment}.thing.do")).is_err());
    }
}

#[test]
fn a_42_category_wide_or_wildcard_capability_is_not_a_name() {
    assert!(CapabilityName::parse("app.suiss.commerce").is_err());
    assert!(CapabilityName::parse("app.suiss.commerce.*").is_err());
    assert!(CapabilityName::parse("*").is_err());
}
