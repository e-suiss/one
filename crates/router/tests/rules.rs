//! The router's pure rules against every vector of `difficulty-v1.json`, `personality-regression-v1.json` and `adapter-v1.json` (MF-21, MF-31, MF-34, MF-35, MF-48).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    reason = "T-38"
)]

use one_router::domain::adapter::{Gates, Outcome, Versions, first_training_due};
use one_router::domain::difficulty::{
    Signals, short_answer_allowed, small_enough, small_sufficient,
};
use one_router::domain::personality::{Scores, compare};
use serde_json::Value;

fn vectors(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../conformance/model/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

#[test]
fn mf_21_difficulty_vectors() {
    for v in vectors("difficulty-v1.json") {
        let i = &v["input"];
        let d = v["description"].as_str().unwrap();
        let caps: Vec<&str> = i["capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| c.as_str().unwrap())
            .collect();
        let s = Signals {
            planning: caps.contains(&"multi_step_planning"),
            long_context: caps.contains(&"long_context"),
            tools: i["tool_count"].as_u64().unwrap(),
            plan_depth: i.get("plan_depth").and_then(Value::as_u64),
            expected_output_tokens: i.get("expected_output_tokens").and_then(Value::as_u64),
            task_kind: i
                .get("task_kind")
                .and_then(Value::as_str)
                .map(str::to_owned),
        };
        let p = small_sufficient(&s);
        let e = &v["expected"];
        assert_eq!(p, e["small_sufficient"].as_f64().unwrap(), "{d}");
        let role = if small_enough(p) {
            "small_lm"
        } else {
            "large_lm"
        };
        assert_eq!(role, e["role"].as_str().unwrap(), "{d}");
        assert_eq!(
            short_answer_allowed(&s, p),
            e["short_answer_allowed"].as_bool().unwrap(),
            "{d}"
        );
    }
}

fn scores(v: &Value) -> Scores {
    let f = |k: &str| v[k].as_f64().unwrap();
    Scores {
        address: f("address"),
        tone: f("tone"),
        length: f("length"),
        rules: f("rules"),
        bilingual: f("bilingual"),
    }
}

#[test]
fn mf_48_personality_regression_vectors() {
    for v in vectors("personality-regression-v1.json") {
        let d = v["description"].as_str().unwrap();
        let active = v["input"].get("active").map(scores);
        let got = compare(&scores(&v["input"]["candidate"]), active.as_ref());
        let e = &v["expected"];
        assert_eq!(got.passes, e["passes"].as_bool().unwrap(), "{d}");
        assert_eq!(got.significant, e["significant"].as_bool().unwrap(), "{d}");
        assert_eq!(got.delta, e.get("delta").map(scores), "{d}");
    }
}

fn opt(v: &Value) -> Option<String> {
    v.as_str().map(str::to_owned)
}

#[test]
fn mf_34_mf_35_adapter_vectors() {
    for v in vectors("adapter-v1.json") {
        let d = v["description"].as_str().unwrap();
        let i = &v["input"];
        let e = &v["expected"];
        if i["event"] == "first_training" {
            assert_eq!(
                first_training_due(i["examples"].as_u64().unwrap(), i["days"].as_u64().unwrap()),
                e["due"].as_bool().unwrap(),
                "{d}"
            );
            continue;
        }
        let state = Versions {
            active: opt(&i["state"]["active"]),
            previous: opt(&i["state"]["previous"]),
        };
        let step = match i["event"].as_str().unwrap() {
            "candidate" => {
                let g = &i["gates"];
                state.offer(
                    i["version"].as_str().unwrap().to_owned(),
                    Gates {
                        personality: g.get("personality").and_then(Value::as_bool),
                        held_out: g.get("held_out").and_then(Value::as_bool),
                        safety: g.get("safety").and_then(Value::as_bool),
                    },
                )
            }
            "revert" => state.revert(),
            "forget" => state.forget(),
            "reset" => state.reset(),
            other => panic!("{other}"),
        };
        assert_eq!(step.versions.active, opt(&e["active"]), "{d}");
        assert_eq!(step.versions.previous, opt(&e["previous"]), "{d}");
        let shredded: Vec<String> = serde_json::from_value(e["shredded"].clone()).unwrap();
        assert_eq!(step.shredded, shredded, "{d}");
        let outcome = match e["outcome"].as_str().unwrap() {
            "activated" => Outcome::Activated,
            "rejected" => Outcome::Rejected,
            "reverted" => Outcome::Reverted,
            "unchanged" => Outcome::Unchanged,
            "retrain" => Outcome::Retrain,
            "reset" => Outcome::Reset,
            other => panic!("{other}"),
        };
        assert_eq!(step.outcome, outcome, "{d}");
    }
}
