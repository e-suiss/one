//! Attention decision records, decision head, calibration, output types and the Relay mapping against `conformance/attention/` (AT-1, AT-9, AT-24, AT-42).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    reason = "T-38"
)]

#[allow(dead_code, reason = "T-38")]
#[path = "federation_support/mod.rs"]
mod support;

use one_proto::attention::calibration::bin_of;
use one_proto::attention::catalog::{CRITICAL_GRANT, Delivery, MuteScope, relay_row};
use one_proto::attention::{
    Arm, DecisionRecord, ECE_GATE, HeadInput, OUTPUT_TYPES, OneRelayClass, Prediction, Probability,
    Propensity, RELAY_ROWS, RelayCandidate, Route, RowId, Thresholds, Timing, clamp_to_ceiling,
    decide, expected_calibration_error, map_to_relay, output_type, passes_calibration_gate,
    reliability_curve,
};
use one_proto::interaction_types::Interruption;
use serde_json::{Value, json};
use support::{TomlValue, check_schema_vectors, get, get_bool, get_str, toml_tables, vectors};

fn p(v: &Value) -> Probability {
    Probability::try_from(v.as_f64().unwrap()).unwrap()
}

fn wire<T: serde::Serialize>(value: &T) -> Value {
    serde_json::to_value(value).unwrap()
}

#[test]
fn at_24_decision_record_schema_vectors() {
    let n = check_schema_vectors::<DecisionRecord, _>(
        "attention/vectors/decision-record.json",
        DecisionRecord::validate,
    );
    assert_eq!((n.valid, n.invalid), (11, 30));
}

#[test]
fn at_24_selection_probability_is_in_the_open_unit_interval_and_forced_is_one() {
    assert!(Propensity::try_from(0.0).is_err());
    assert!(Propensity::try_from(1.000_001).is_err());
    assert!(Propensity::try_from(f64::NAN).is_err());
    assert_eq!(Propensity::FORCED.get(), 1.0);
    assert_eq!(Propensity::try_from(1.0).unwrap(), Propensity::FORCED);
}

#[test]
fn at_1_decision_head_vectors() {
    let all = vectors("attention/vectors/decision-head.json");
    for v in &all {
        let i = &v["input"];
        let input = HeadInput {
            value_probability: p(&i["value_probability"]),
            thresholds: Thresholds {
                lower: p(&i["thresholds"]["lower"]),
                upper: p(&i["thresholds"]["upper"]),
            },
            urgent: i["urgent"].as_bool().unwrap(),
            cloud_available: i["cloud_available"].as_bool().unwrap(),
            type_muted: i["type_muted"].as_bool().unwrap(),
            budget_remaining: u8::try_from(i["budget_remaining"].as_u64().unwrap()).unwrap(),
            critical_grant: i["critical_grant"].as_bool().unwrap(),
        };
        let decision = decide(&input).unwrap();
        let e = &v["expected"];
        let route = match e["route"].as_str().unwrap() {
            "notify" => Route::Notify,
            "no_notification" => Route::NoNotification,
            "cloud_estimate" => Route::CloudEstimate,
            other => panic!("{other}"),
        };
        let what = v["description"].as_str().unwrap();
        assert_eq!(decision.route, route, "{what}");
        let arm = e
            .get("chosen_arm")
            .map(|a| serde_json::from_value::<Arm>(a.clone()).unwrap());
        assert_eq!(decision.chosen_arm, arm, "{what}");
        let level = e
            .get("interruption")
            .map(|l| serde_json::from_value::<Interruption>(l.clone()).unwrap());
        assert_eq!(decision.interruption, level, "{what}");
    }
    assert_eq!(all.len(), 13);
}

#[test]
fn at_9_critical_grant_overrides_mute_but_nothing_else_does() {
    let base = HeadInput {
        value_probability: Probability::try_from(0.99).unwrap(),
        thresholds: Thresholds {
            lower: Probability::try_from(0.3).unwrap(),
            upper: Probability::try_from(0.7).unwrap(),
        },
        urgent: true,
        cloud_available: true,
        type_muted: true,
        budget_remaining: 3,
        critical_grant: false,
    };
    assert_eq!(decide(&base).unwrap().route, Route::NoNotification);
    let granted = HeadInput {
        critical_grant: true,
        ..base
    };
    let decision = decide(&granted).unwrap();
    assert_eq!(decision.route, Route::Notify);
    assert_eq!(decision.interruption, Some(Interruption::Critical));
    let crossed = HeadInput {
        thresholds: Thresholds {
            lower: Probability::try_from(0.8).unwrap(),
            upper: Probability::try_from(0.2).unwrap(),
        },
        ..base
    };
    assert!(decide(&crossed).is_err());
}

#[test]
fn at_1_calibration_vectors() {
    let all = vectors("attention/vectors/calibration.json");
    for v in &all {
        let i = &v["input"];
        assert_eq!(i["bins"], 10);
        assert_eq!(i["binning"], "equal_width_upper_bin_closed");
        let predictions: Vec<Prediction> = i["predictions"]
            .as_array()
            .unwrap()
            .iter()
            .map(|x| Prediction {
                probability: p(&x["probability"]),
                outcome: x["outcome"].as_u64().unwrap() == 1,
            })
            .collect();
        let e = &v["expected"];
        let ece = expected_calibration_error(&predictions).unwrap();
        assert!((ece - e["expected_calibration_error"].as_f64().unwrap()).abs() < 1e-6);
        let curve = reliability_curve(&predictions);
        let want = e["reliability_curve"].as_array().unwrap();
        assert_eq!(curve.len(), want.len());
        for (got, want) in curve.iter().zip(want) {
            assert_eq!(
                got.bin,
                usize::try_from(want["bin"].as_u64().unwrap()).unwrap()
            );
            assert_eq!(
                got.count,
                usize::try_from(want["count"].as_u64().unwrap()).unwrap()
            );
            assert!(
                (got.mean_probability - want["mean_probability"].as_f64().unwrap()).abs() < 1e-6
            );
            assert!((got.observed_rate - want["observed_rate"].as_f64().unwrap()).abs() < 1e-6);
        }
        assert_eq!(passes_calibration_gate(&predictions), ece <= ECE_GATE);
    }
    assert_eq!(all.len(), 2);
}

#[test]
fn at_1_calibration_gate_is_ece_at_most_five_hundredths_with_closed_last_bin() {
    assert_eq!(ECE_GATE, 0.05);
    assert_eq!(bin_of(Probability::try_from(1.0).unwrap()), 9);
    assert_eq!(bin_of(Probability::try_from(0.0).unwrap()), 0);
    assert_eq!(bin_of(Probability::try_from(0.1).unwrap()), 1);
    assert!(expected_calibration_error(&[]).is_none());
    assert!(!passes_calibration_gate(&[]));
}

#[test]
fn at_42_relay_mapping_vectors() {
    let all = vectors("attention/vectors/relay-mapping.json");
    for v in &all {
        let i = &v["input"];
        let candidate = RelayCandidate {
            output_type: i["output_type"].as_str().unwrap(),
            interruption: serde_json::from_value(i["interruption"].clone()).unwrap(),
            urgent: i["urgent"].as_bool().unwrap(),
            critical_grant: i["critical_grant"].as_bool().unwrap(),
            personal_agent_registered: i["personal_agent_registered"].as_bool().unwrap(),
        };
        let what = v["description"].as_str().unwrap();
        let e = &v["expected"];
        let sent = map_to_relay(&candidate);
        if !e["send"].as_bool().unwrap() {
            assert!(sent.is_none(), "{what}");
            continue;
        }
        let sent = sent.unwrap();
        assert_eq!(wire(&sent.relay_class), e["relay_class"], "{what}");
        assert_eq!(wire(&sent.interruption), e["interruption"], "{what}");
        assert_eq!(wire(&sent.timing), e["timing"], "{what}");
        assert_eq!(
            json!(sent.max_defer_required),
            e["max_defer_required"],
            "{what}"
        );
    }
    assert_eq!(all.len(), 14);
}

#[test]
fn at_42_level_is_clamped_to_the_type_ceiling_and_never_critical_without_grant() {
    let bill = output_type("app.suiss.one.output.bill.reminder").unwrap();
    assert_eq!(
        clamp_to_ceiling(bill, Interruption::Critical, true),
        Some(Interruption::Active)
    );
    let travel = output_type("app.suiss.one.output.travel.change").unwrap();
    assert_eq!(
        clamp_to_ceiling(travel, Interruption::Critical, true),
        Some(Interruption::TimeSensitive)
    );
    let progress = output_type("app.suiss.one.output.task.progress").unwrap();
    assert_eq!(
        clamp_to_ceiling(progress, Interruption::TimeSensitive, true),
        Some(Interruption::Passive)
    );
    let in_app = output_type("app.suiss.one.output.session.ai_disclosure").unwrap();
    assert_eq!(clamp_to_ceiling(in_app, Interruption::Active, true), None);
}

fn interruption(s: &str) -> Interruption {
    serde_json::from_value(json!(s)).unwrap()
}

#[test]
fn at_42_output_type_constants_match_output_types_toml() {
    let rows = toml_tables("attention/output-types.toml", "output_type");
    assert_eq!(rows.len(), OUTPUT_TYPES.len());
    for (row, t) in rows.iter().zip(OUTPUT_TYPES) {
        assert_eq!(get_str(row, "id"), Some(t.id.as_str()));
        assert_eq!(get_str(row, "title"), Some(t.title));
        let delivery = match get_str(row, "delivery").unwrap() {
            "relay" => Delivery::Relay,
            "in_app" => Delivery::InApp,
            other => panic!("{other}"),
        };
        assert_eq!(delivery, t.delivery, "{}", t.id);
        assert_eq!(
            get_str(row, "row").map(|r| serde_json::from_value::<RowId>(json!(r)).unwrap()),
            t.row,
            "{}",
            t.id
        );
        assert_eq!(
            get_str(row, "interruption_ceiling").map(interruption),
            t.interruption_ceiling,
            "{}",
            t.id
        );
        let scope = match get_str(row, "mute_scope").unwrap() {
            "type_and_capability" => MuteScope::TypeAndCapability,
            "type" => MuteScope::Type,
            "task" => MuteScope::Task,
            "none" => MuteScope::None,
            other => panic!("{other}"),
        };
        assert_eq!(scope, t.mute_scope, "{}", t.id);
        assert_eq!(get_bool(row, "mutable"), Some(t.mutable), "{}", t.id);
        assert_eq!(
            get_bool(row, "budget_exempt"),
            Some(t.budget_exempt),
            "{}",
            t.id
        );
        assert!(t.id.as_str().starts_with("app.suiss.one.output."));
    }
}

#[test]
fn at_42_relay_row_constants_match_relay_mapping_toml() {
    let rows = toml_tables("attention/relay-mapping.toml", "row");
    assert_eq!(rows.len(), RELAY_ROWS.len() + 1);
    for row in &rows {
        let id: RowId = serde_json::from_value(json!(get_str(row, "id").unwrap())).unwrap();
        if id == RowId::CriticalGrant {
            assert_eq!(get_str(row, "relay_class"), Some("inherit"));
            assert_eq!(
                get_str(row, "interruption").map(interruption),
                Some(CRITICAL_GRANT.interruption)
            );
            assert_eq!(
                wire(&CRITICAL_GRANT.timing),
                json!(get_str(row, "timing").unwrap())
            );
            let overlays: Vec<Value> = CRITICAL_GRANT.overlays.iter().map(wire).collect();
            let Some(TomlValue::List(want)) = get(row, "overlays") else {
                panic!("overlays")
            };
            assert_eq!(overlays, want.iter().map(|w| json!(w)).collect::<Vec<_>>());
            assert_eq!(
                get_bool(row, "requires_access_grant"),
                Some(CRITICAL_GRANT.requires_access_grant)
            );
            assert_eq!(
                get_bool(row, "counts_toward_budget"),
                Some(CRITICAL_GRANT.counts_toward_budget)
            );
            continue;
        }
        let r = relay_row(id).unwrap();
        let class: OneRelayClass =
            serde_json::from_value(json!(get_str(row, "relay_class").unwrap())).unwrap();
        assert_eq!(class, r.relay_class);
        assert_eq!(
            get_str(row, "interruption_ceiling").map(interruption),
            Some(r.interruption_ceiling)
        );
        assert_eq!(
            get_bool(row, "requires_personal_agent").unwrap_or(false),
            r.requires_personal_agent
        );
        let timing: Timing =
            serde_json::from_value(json!(get_str(row, "timing_default").unwrap())).unwrap();
        assert_eq!(timing, r.timing_default);
        assert_eq!(
            get_bool(row, "timing_immediate_only_if_urgent"),
            Some(r.timing_immediate_only_if_urgent)
        );
        assert_eq!(
            get_bool(row, "max_defer_required_on_next_break"),
            Some(r.max_defer_required_on_next_break)
        );
        assert_eq!(get_bool(row, "critical_overlay"), Some(r.critical_overlay));
    }
    let text =
        std::fs::read_to_string(support::conformance("attention/relay-mapping.toml")).unwrap();
    assert!(text.contains("forbidden_classes = [\"security\"]"));
    assert!(text.contains("unlisted_output_type = \"never_send\""));
    assert!(serde_json::from_value::<OneRelayClass>(json!("security")).is_err());
}
