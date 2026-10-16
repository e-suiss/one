//! Every behaviour vector of `conformance/interaction`: kind resolution, projection budgets and response processing (X-12, X-13, X-22, C-7, C-26, T-31).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

mod common;

use one_interaction::common::Timestamp;
use one_interaction::projection::live_update_chip;
use one_interaction::{
    Interaction, InteractionResponse, Kind, KindRegistry, ResponseOutcome, ResponseProcessor,
    SurfaceClass, SurfaceTarget, project,
};
use serde_json::{Map, Value, json};

#[test]
fn x_12_kind_resolution_vectors() {
    let vectors = common::vectors("vectors/kind-resolution.json");
    for v in &vectors {
        let registry: KindRegistry =
            serde_json::from_value(v["input"]["registry"].clone()).unwrap();
        let kind: Kind = serde_json::from_value(v["input"]["kind"].clone()).unwrap();
        let actual = match registry.resolve(&kind) {
            Ok(core) => json!({"valid": true, "core_kind": core}),
            Err(e) => json!({"valid": false, "error": e}),
        };
        assert_eq!(actual, v["expected"], "{}", v["description"]);
    }
    assert_eq!(vectors.len(), 5);
}

#[test]
fn x_13_budget_vectors() {
    let vectors = common::vectors("vectors/budgets.json");
    for v in &vectors {
        let input = &v["input"];
        let registry: KindRegistry = serde_json::from_value(input["registry"].clone()).unwrap();
        let i: Interaction = serde_json::from_value(input["interaction"].clone()).unwrap();
        one_interaction::validate_interaction(&i).unwrap();
        let kind = registry.resolve(&i.kind).unwrap();
        let class: SurfaceClass = serde_json::from_value(input["surface_class"].clone()).unwrap();
        let target: SurfaceTarget = serde_json::from_value(input["target"].clone()).unwrap();
        let declared: Vec<SurfaceTarget> =
            serde_json::from_value(input["declared_targets"].clone()).unwrap();
        let mut actual = serde_json::to_value(project(&i, kind, class, target, &declared)).unwrap();
        actual["valid"] = Value::Bool(true);
        if target == SurfaceTarget::LiveUpdate && actual["projection"] == "full" {
            let max = usize::try_from(target.budget().chip_max_chars.unwrap()).unwrap();
            let chip = live_update_chip(&i, max);
            assert_eq!(
                v["expected"]["chip"].as_str(),
                chip.as_deref(),
                "{}",
                v["description"]
            );
            actual["chip"] = json!(chip);
        }
        assert!(
            common::subset(&v["expected"], &actual),
            "{}: expected {} got {actual}",
            v["description"],
            v["expected"]
        );
    }
    assert_eq!(vectors.len(), 26);
}

fn merge(into: &mut Map<String, Value>, key: &str, value: Value) {
    into.entry(key.to_owned()).or_insert(value);
}

#[test]
fn x_22_response_processing_vectors() {
    let vectors = common::vectors("vectors/response-processing.json");
    for v in &vectors {
        let input = &v["input"];
        let i: Interaction = serde_json::from_value(input["interaction"].clone()).unwrap();
        one_interaction::validate_interaction(&i).unwrap();
        let state = &input["state"];
        let now: Timestamp = serde_json::from_value(state["now"].clone()).unwrap();
        let verified = state["signature_valid"].as_bool().unwrap();
        let current = u32::try_from(state["current_version"].as_u64().unwrap()).unwrap();
        let mut processor = ResponseProcessor::new(&i, current);
        let mut outcomes = Vec::new();
        let mut approvals = 0_u64;
        let mut actual = Map::new();
        for r in input["responses"].as_array().unwrap() {
            let response: InteractionResponse = serde_json::from_value(r.clone()).unwrap();
            one_interaction::validate_response(&response).unwrap();
            let processed = processor.process(&response, &now, verified);
            if processed.outcome == ResponseOutcome::Accepted && processed.aas.is_some() {
                approvals += 1;
            }
            outcomes.push(processed.outcome);
            if let Value::Object(fields) = serde_json::to_value(&processed).unwrap() {
                for (k, value) in fields {
                    if k != "outcome" {
                        merge(&mut actual, &k, value);
                    }
                }
            }
        }
        actual.insert("valid".to_owned(), Value::Bool(true));
        actual.insert(
            "outcomes".to_owned(),
            serde_json::to_value(&outcomes).unwrap(),
        );
        actual.insert("approvals_created".to_owned(), json!(approvals));
        let actual = Value::Object(actual);
        assert!(
            common::subset(&v["expected"], &actual),
            "{}: expected {} got {actual}",
            v["description"],
            v["expected"]
        );
    }
    assert_eq!(vectors.len(), 13);
}
