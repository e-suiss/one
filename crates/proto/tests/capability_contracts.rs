//! Every schema and behaviour vector of `conformance/capability` through the typed names, negotiation, registry entries, surfaces, autonomy rules, triggers and the purchase intent, and the embedded tables against their TOML files (CP-15, CP-16, CP-23, A-1, A-14, A-24, A-42).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

#[allow(dead_code, reason = "T-38")]
#[path = "federation_support/mod.rs"]
mod support;

use one_proto::capability::{
    AndroidAppFunction, AppleAppSchema, AutonomyRule, CATEGORIES, CapabilityDefinition,
    CapabilityName, CapabilityVersion, Declaration, MAX_NAME_LENGTH, NameError, NameKind,
    Projections, PurchaseInput, RESERVED_SEGMENTS, SurfaceCapability, TAXONOMY, ThirdPartyName,
    Trigger, TriggerRejection, TriggerRun, TypedSchema, check_trigger_bounds,
    effective_reversibility, is_forbidden_field_name, is_safe_property_name, negotiate,
};
use one_proto::interaction_types::Reversibility;
use one_proto::ontology::JsonObject;
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use support::{TomlValue, get_bool, get_str, toml_tables};

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
    assert_eq!(all.len(), 26);
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
    assert_eq!(all.len(), 12);
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
                assert_eq!(expected["runs"], run.as_str(), "{description}");
            }
            Err(e) => assert_eq!(expected["rejected"], e.as_str(), "{description}"),
        }
    }
    assert_eq!(all.len(), 10);
}

#[test]
fn a_15_trigger_outcomes_match_trigger_bounds_toml() {
    let text = read("trigger-bounds.toml");
    let codes: Vec<&str> = TriggerRejection::ALL.iter().map(|c| c.as_str()).collect();
    assert_eq!(codes, toml_values(&text, "check", "code"));
    let runs = toml_values(&text, "run", "runs");
    for (behaviour, runs) in toml_values(&text, "run", "behaviour").iter().zip(&runs) {
        let mut trigger: Value = load("vectors/trigger-bounds.json")[0]["input"].clone();
        trigger["mandate"]["behaviour"] = json!(behaviour);
        let trigger: Trigger = serde_json::from_value(trigger).unwrap();
        assert_eq!(
            check_trigger_bounds(&trigger).unwrap().as_str(),
            runs,
            "{behaviour}"
        );
    }
    let mut named: Vec<&str> = runs.iter().map(String::as_str).collect();
    named.dedup();
    let all: Vec<&str> = TriggerRun::ALL.iter().map(|r| r.as_str()).collect();
    assert_eq!(named, all);
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
fn cp_15_name_errors_match_naming_toml() {
    let text = read("naming.toml");
    let field = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key} = ")))
            .unwrap()
            .to_owned()
    };
    let listed: Vec<String> = field("codes")
        .trim_matches(['[', ']'])
        .split(", ")
        .map(|c| c.trim_matches('"').to_owned())
        .collect();
    let codes: Vec<&str> = NameError::ALL.iter().map(|e| e.code()).collect();
    assert_eq!(codes, listed);
    assert_eq!(field("max_length"), MAX_NAME_LENGTH.to_string());
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

fn projection_targets() -> Vec<String> {
    read("projections.toml")
        .lines()
        .filter_map(|l| l.strip_prefix("[target.")?.strip_suffix(']'))
        .map(str::to_owned)
        .collect()
}

fn target_keys(target: &str) -> Vec<String> {
    let header = format!("[target.{target}]");
    read("projections.toml")
        .lines()
        .skip_while(|l| *l != header)
        .skip(1)
        .take_while(|l| !l.starts_with('['))
        .filter_map(|l| l.split_once(" = ").map(|(k, _)| k.to_owned()))
        .collect()
}

fn is_mcp_tool_name(name: &str) -> bool {
    (1..=128).contains(&name.len())
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn projections(value: &Value) -> Projections {
    serde_json::from_value(value.clone()).unwrap_or_else(|e| panic!("{value}: {e}"))
}

#[test]
fn cp_15_projection_targets_are_the_projection_fields() {
    let name = "app.suiss.assistant.task.submit";
    let full = Projections {
        mcp_tool: Some(CapabilityName::parse(name).unwrap()),
        a2a_skill: Some(CapabilityName::parse(name).unwrap()),
        apple_app_schema: Some(AppleAppSchema::parse(".mail.createDraft").unwrap()),
        android_app_function: Some(AndroidAppFunction::parse(name).unwrap()),
        ucp: Some(serde_json::from_value(json!("dev.ucp.shopping.checkout")).unwrap()),
    };
    let mut fields: Vec<String> = serde_json::to_value(&full)
        .unwrap()
        .as_object()
        .unwrap()
        .keys()
        .cloned()
        .collect();
    let mut targets = projection_targets();
    fields.sort();
    targets.sort();
    assert_eq!(fields, targets);
    let text = read("projections.toml");
    assert!(text.contains("direction = \"outbound_only\""));
}

#[test]
fn cp_15_projection_rows_map_registry_capabilities_to_well_formed_targets() {
    let rows = toml_tables("capability/projections.toml", "row");
    assert_eq!(rows.len(), 13);
    let mut seen = Vec::new();
    for row in &rows {
        let name = get_str(row, "capability").unwrap();
        assert!(!seen.contains(&name), "{name} mapped twice");
        seen.push(name);
        let parsed = CapabilityName::parse(name).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(parsed.kind(), NameKind::Suiss, "{name}");
        assert!(TAXONOMY.contains(&name), "{name} is not in the registry");
        let mut targets = 0;
        for (key, value) in row {
            match (key.as_str(), value) {
                ("capability", _) => {}
                ("apple_app_schema", TomlValue::Str(schema)) => {
                    targets += 1;
                    assert!(AppleAppSchema::parse(schema).is_ok(), "{name}: {schema}");
                    let p = projections(&json!({ "apple_app_schema": schema }));
                    assert_eq!(p.apple_app_schema.unwrap().as_str(), schema);
                }
                ("ucp", TomlValue::Str(ucp)) => {
                    targets += 1;
                    assert_eq!(parsed.category(), Some("commerce"), "{name}: {ucp}");
                    let third: ThirdPartyName = serde_json::from_value(json!(ucp))
                        .unwrap_or_else(|e| panic!("{name}: {ucp}: {e}"));
                    let segments: Vec<&str> = third.name().segments().collect();
                    assert_eq!(segments[..3], ["dev", "ucp", "shopping"], "{ucp}");
                    assert_eq!(segments.len(), 4, "{ucp}");
                    assert_eq!(projections(&json!({ "ucp": ucp })).ucp, Some(third));
                }
                ("mcp_tool_exposed" | "a2a_skill_exposed", TomlValue::Bool(true)) => {
                    targets += 1;
                    let field = key.trim_end_matches("_exposed");
                    assert!(is_mcp_tool_name(name), "{name}");
                    let p = serde_json::to_value(projections(&json!({ field: name }))).unwrap();
                    assert_eq!(p[field], json!(name));
                    assert!(AndroidAppFunction::parse(name).is_ok(), "{name}");
                }
                other => panic!("{name}: unknown projection {other:?}"),
            }
        }
        assert!(targets > 0, "{name} projects nowhere");
    }
    for name in [
        "app.suiss.assistant.task.submit",
        "app.suiss.assistant.task.status",
    ] {
        let row = rows
            .iter()
            .find(|r| get_str(r, "capability") == Some(name))
            .unwrap();
        assert_eq!(get_bool(row, "mcp_tool_exposed"), Some(true), "{name}");
        assert_eq!(get_bool(row, "a2a_skill_exposed"), Some(true), "{name}");
    }
}

#[test]
fn cp_15_projection_targets_reject_malformed_names() {
    for bad in [
        "mail.createDraft",
        ".Mail.createDraft",
        ".mail.",
        ".mail",
        ".mail.create-draft",
    ] {
        assert!(AppleAppSchema::parse(bad).is_err(), "{bad}");
        assert!(serde_json::from_value::<Projections>(json!({ "apple_app_schema": bad })).is_err());
    }
    for bad in [
        "app.suiss.commerce.purchase",
        "ucp",
        "dev.ucp",
        "Dev.ucp.shopping.checkout",
    ] {
        assert!(
            serde_json::from_value::<Projections>(json!({ "ucp": bad })).is_err(),
            "{bad}"
        );
    }
    for bad in ["", "App.Suiss.x.y", "tool name"] {
        assert!(
            serde_json::from_value::<Projections>(json!({ "mcp_tool": bad })).is_err(),
            "{bad}"
        );
    }
    assert!(serde_json::from_value::<Projections>(json!({ "openai_function": "x" })).is_err());
    assert!(AndroidAppFunction::parse("").is_err());
    let long = "a".repeat(129);
    assert!(!is_mcp_tool_name(&long));
    for name in TAXONOMY {
        assert!(is_mcp_tool_name(name), "{name}");
    }
}

fn hints_definition(definitions: &[Value], input: &Value) -> CapabilityDefinition {
    let base = input["base"].as_str().unwrap();
    let mut def = definitions
        .iter()
        .find(|v| v["valid"] == json!(true) && v["description"] == json!(base))
        .unwrap_or_else(|| panic!("{base}"))["input"]
        .clone();
    if let Some(tier) = input.get("consequence_tier") {
        def["authority"]["consequence_tier"] = tier.clone();
    }
    if let Some(writes) = input.get("writes") {
        def["data_access"]["writes"] = writes.clone();
    }
    if let Some(reversibility) = input.get("reversibility") {
        def["reversibility"] = reversibility.clone();
    }
    let primary = def["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["role"] == "primary")
        .unwrap()
        .clone();
    let second = match def["reversibility"].as_str().unwrap() {
        "reversible" => Some("undo"),
        "compensable" => Some("compensate"),
        _ => None,
    };
    def["actions"] = std::iter::once(primary.clone())
        .chain(second.map(|role| {
            let mut a = primary.clone();
            a["role"] = json!(role);
            a["action_ref"]["name"] = json!(role);
            a
        }))
        .collect();
    if second.is_none()
        || matches!(
            def["authority"]["consequence_tier"].as_str(),
            Some("CT2" | "CT3")
        )
    {
        def["surface"]["approval_ceiling"] =
            json!({ "surface_classes": ["phone", "desktop"], "min_assurance": "passkey" });
    }
    if let Some(paths) = input.get("path_types") {
        def["providers"] = paths
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .map(|(i, p)| json!({ "provider_ref": format!("provider:p{i}"), "path_type": p }))
            .collect();
    }
    serde_json::from_value(def).unwrap()
}

#[test]
fn c_27_mcp_tool_hints_vectors() {
    let definitions = load("vectors/definition.json");
    let hint_keys: Vec<String> = target_keys("mcp_tool")
        .into_iter()
        .filter(|k| k.ends_with("_hint"))
        .collect();
    assert_eq!(
        hint_keys,
        [
            "read_only_hint",
            "destructive_hint",
            "idempotent_hint",
            "open_world_hint"
        ]
    );
    let all = load("vectors/mcp-tool-hints.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let hints = hints_definition(&definitions, &v["input"]).mcp_tool_hints();
        let got = json!({
            "read_only_hint": hints.read_only,
            "destructive_hint": hints.destructive,
            "idempotent_hint": hints.idempotent,
            "open_world_hint": hints.open_world,
        });
        let mut expected_keys: Vec<&String> = v["expected"].as_object().unwrap().keys().collect();
        expected_keys.sort();
        let mut table_keys: Vec<&String> = hint_keys.iter().collect();
        table_keys.sort();
        assert_eq!(expected_keys, table_keys, "{description}");
        assert_eq!(got, v["expected"], "{description}");
    }
    assert_eq!(all.len(), 13);
}
