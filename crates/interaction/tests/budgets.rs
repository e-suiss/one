//! The embedded budget table against `surfaces/budgets.toml`, the canonical JSON size against an independent encoder, and an exhaustive projection sweep over every kind, surface class and target (X-13, X-6, X-19, X-20).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

mod common;

use one_interaction::budget::{
    self, MINIMAL, NEUTRAL, ORDER, OUTCOMES, REDIRECT, SENSITIVE_VOICE_TARGETS,
};
use one_interaction::common::Locale;
use one_interaction::projection::{
    approval_within_ceiling, fits_budget, is_sensitive, live_activity_bytes, live_activity_payload,
};
use one_interaction::surface::ClassRow;
use one_interaction::{
    CoreKind, Interaction, ProjectionOutcome, Rule, SurfaceClass, SurfaceTarget, project,
};
use serde_json::{Value, json};

#[test]
fn x_13_budget_table_matches_budgets_toml() {
    let table = common::toml("surfaces/budgets.toml");
    assert_eq!(table["version"], budget::VERSION);
    assert_eq!(table["schema"], budget::SCHEMA);
    assert_eq!(table["text_unit"], budget::TEXT_UNIT);
    assert_eq!(table["byte_unit"], budget::BYTE_UNIT);
    assert_eq!(table["outcomes"], serde_json::to_value(OUTCOMES).unwrap());
    assert_eq!(table["order"], serde_json::to_value(ORDER).unwrap());
    assert_eq!(table["minimal"], serde_json::to_value(MINIMAL).unwrap());
    let rules = table["rule"].as_object().unwrap();
    assert_eq!(rules.len(), ORDER.len());
    for rule in ORDER {
        let name = serde_json::to_value(rule).unwrap();
        let row = &rules[name.as_str().unwrap()];
        assert_eq!(
            row["outcome"],
            serde_json::to_value(rule.outcome()).unwrap()
        );
    }
    assert_eq!(
        rules["sensitive_on_voice"]["targets"],
        serde_json::to_value(SENSITIVE_VOICE_TARGETS).unwrap()
    );
    assert_eq!(
        rules["sensitive_on_voice"]["neutral"],
        serde_json::to_value(NEUTRAL).unwrap()
    );
    assert_eq!(
        rules["approval_above_ceiling"]["redirect"],
        serde_json::to_value(REDIRECT).unwrap()
    );
    let targets = table["target"].as_object().unwrap();
    assert_eq!(targets.len(), SurfaceTarget::ALL.len());
    for target in SurfaceTarget::ALL {
        assert_eq!(
            &serde_json::to_value(target.budget()).unwrap(),
            &targets[target.as_str()],
            "{}",
            target.as_str()
        );
    }
}

fn independent_payload(i: &Value, locale: &str) -> Value {
    let det = &i["details"];
    let mut state = serde_json::Map::new();
    state.insert("version".into(), i["version"].clone());
    state.insert("title".into(), i["subject"]["title"][locale].clone());
    state.insert(
        "status".into(),
        i["minimal_projection"]["sentence"][locale].clone(),
    );
    for (from, to) in [
        ("phase", "phase"),
        ("fraction", "fraction"),
        ("step_label", "step"),
    ] {
        if let Some(v) = det["progress"].get(from) {
            state.insert(to.into(), v.clone());
        }
    }
    if let Some(steps) = det["steps"].as_array() {
        let steps: Vec<Value> = steps
            .iter()
            .map(|s| json!({"label": s["label"], "status": s["status"]}))
            .collect();
        state.insert("steps".into(), Value::Array(steps));
    }
    if let Some(link) = i.get("deep_link") {
        state.insert("deep_link".into(), link.clone());
    }
    json!({
        "attributes": {"interaction_id": i["id"], "task": i["subject"]["ref"]["id"], "kind": i["kind"]},
        "content_state": state,
    })
}

#[test]
fn x_13_live_activity_size_is_the_canonical_json_length_of_each_locale() {
    let mut checked = 0;
    for v in common::vectors("vectors/budgets.json") {
        let raw = &v["input"]["interaction"];
        let i: Interaction = serde_json::from_value(raw.clone()).unwrap();
        if i.kind.declared_core() != CoreKind::Progress {
            continue;
        }
        let mut largest = 0;
        for (locale, name) in [(Locale::Tr, "tr"), (Locale::En, "en")] {
            let expected = serde_json::to_string(&independent_payload(raw, name)).unwrap();
            assert_eq!(
                live_activity_payload(&i, locale).canonical_len(),
                expected.len(),
                "{}",
                v["description"]
            );
            largest = largest.max(expected.len());
        }
        assert_eq!(live_activity_bytes(&i), largest);
        checked += 1;
    }
    assert!(checked >= 3);
}

fn fixtures() -> Vec<Value> {
    common::vectors("vectors/fixtures.json")
        .into_iter()
        .chain(
            common::vectors("vectors/budgets.json")
                .into_iter()
                .map(|v| json!({"input": v["input"]["interaction"]})),
        )
        .map(|v| v["input"].clone())
        .collect()
}

fn stretched(base: &Value) -> Vec<Value> {
    let mut out = vec![base.clone()];
    let mut long = base.clone();
    long["subject"]["title"] = json!({"tr": "ş".repeat(60), "en": "e".repeat(60)});
    long["minimal_projection"]["sentence"] = json!({"tr": "ğ".repeat(120), "en": "s".repeat(120)});
    out.push(long);
    let mut sensitive = base.clone();
    sensitive["sensitive"] = json!(true);
    out.push(sensitive);
    if base["details"].get("options").is_some() && base["kind"] == "choice" {
        let mut many = base.clone();
        let options: Vec<Value> = (0..10)
            .map(|n| json!({"id": format!("o{n}"), "title": format!("Option number {n} with a long title here")}))
            .collect();
        many["details"]["options"] = Value::Array(options);
        out.push(many);
    }
    if base["details"].get("steps").is_some() {
        let mut steps = base.clone();
        let list: Vec<Value> = (0..100)
            .map(|n| json!({"label": format!("Adım {n:02}: paket aktarma merkezinden çıkış"), "status": "done"}))
            .collect();
        steps["details"]["steps"] = Value::Array(list);
        out.push(steps);
    }
    out
}

fn chars(s: &str) -> usize {
    s.chars().count()
}

fn assert_full_is_within_budget(
    i: &Interaction,
    kind: CoreKind,
    class: SurfaceClass,
    target: SurfaceTarget,
) {
    let b = target.budget();
    assert!(b.kinds.contains(&kind));
    assert_ne!(b.always_minimal, Some(true));
    assert!(!(SENSITIVE_VOICE_TARGETS.contains(&target) && is_sensitive(i)));
    assert!(kind != CoreKind::Approval || approval_within_ceiling(i, class));
    assert!(fits_budget(i, kind, class, target).0);
    let title = i.subject.title.max_chars();
    let sentence = i.minimal_projection.sentence.max_chars();
    if let Some(max) = b.max_title_chars {
        assert!(title <= usize::try_from(max).unwrap());
    }
    if let Some(max) = b.max_body_chars.or(b.max_status_chars) {
        assert!(sentence <= usize::try_from(max).unwrap());
    }
    if let Some(max) = b.max_bytes {
        assert!(live_activity_bytes(i) <= usize::try_from(max).unwrap());
    }
    let options = i.details.options.as_ref().map_or(0, Vec::len);
    if let (Some(max), CoreKind::Choice) = (b.max_spoken_options, kind) {
        assert!(options <= usize::try_from(max).unwrap());
    }
    if let Some(max) = b.max_list_items {
        let items = match kind {
            CoreKind::Choice | CoreKind::Comparison => options,
            _ => i.details.steps.as_ref().map_or(0, Vec::len),
        };
        assert!(items <= usize::try_from(max).unwrap());
        if let (Some(item_max), Some(list)) = (b.max_list_item_chars, i.details.options.as_ref()) {
            assert!(
                list.iter()
                    .all(|o| chars(&o.title) <= usize::try_from(item_max).unwrap())
            );
        }
    }
    if let (Some(max), CoreKind::Choice) = (b.max_choice_options, kind) {
        assert!(options <= usize::try_from(max).unwrap());
    }
}

#[test]
fn x_13_every_kind_class_and_target_projects_to_one_outcome_never_full_over_budget() {
    let mut cases = 0;
    let mut seen = std::collections::BTreeSet::new();
    let mut kinds = std::collections::BTreeSet::new();
    for base in fixtures() {
        for raw in stretched(&base) {
            let i: Interaction = serde_json::from_value(raw).unwrap();
            let kind = i.kind.declared_core();
            kinds.insert(kind);
            for class in SurfaceClass::ALL {
                for target in SurfaceTarget::ALL {
                    for declared in [&SurfaceTarget::ALL[..], &[]] {
                        let p = project(&i, kind, class, target, declared);
                        assert!(OUTCOMES.contains(&p.projection));
                        assert_eq!(p.projection, p.reason.outcome());
                        let undeclared = !declared.contains(&target) || !class.has_target(target);
                        assert_eq!(undeclared, p.reason == Rule::UndeclaredTarget);
                        if p.projection == ProjectionOutcome::Full {
                            assert_full_is_within_budget(&i, kind, class, target);
                        }
                        if !undeclared && !fits_budget(&i, kind, class, target).0 {
                            assert_ne!(p.projection, ProjectionOutcome::Full);
                        }
                        seen.insert(format!("{:?}", p.reason));
                        cases += 1;
                    }
                }
            }
        }
    }
    assert_eq!(kinds.len(), CoreKind::ALL.len());
    assert_eq!(seen.len(), ORDER.len(), "{seen:?}");
    assert!(cases > 5000);
}
