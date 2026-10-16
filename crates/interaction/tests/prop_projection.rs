//! Property tests of the projection decision over arbitrary Interactions within the schema limits: one of five outcomes from the first applicable rule, never full over a budget (X-13, X-6, X-19, X-20, T-38 (3)).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    reason = "T-38"
)]

mod common;

use one_interaction::budget::{OUTCOMES, SENSITIVE_VOICE_TARGETS};
use one_interaction::projection::{fits_budget, is_sensitive, live_activity_bytes};
use one_interaction::surface::ClassRow;
use one_interaction::{
    Interaction, ProjectionOutcome, Rule, SurfaceClass, SurfaceTarget, project,
    validate_interaction,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};
use serde_json::{Value, json};

fn config() -> Config {
    Config {
        cases: 192,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(13),
        ..Config::default()
    }
}

fn bases() -> Vec<Value> {
    common::vectors("vectors/fixtures.json")
        .into_iter()
        .map(|v| v["input"].clone())
        .chain(
            common::vectors("vectors/budgets.json")
                .into_iter()
                .map(|v| v["input"]["interaction"].clone()),
        )
        .collect()
}

fn text(max: usize) -> impl Strategy<Value = String> {
    proptest::string::string_regex(&format!("[a-zA-Z0-9çğıöşüÇĞİÖŞÜ .,!?]{{1,{max}}}"))
        .unwrap()
        .prop_filter("not blank", |s| !s.trim().is_empty())
}

fn localized(max: usize) -> impl Strategy<Value = Value> {
    (text(max), text(max)).prop_map(|(tr, en)| json!({"tr": tr, "en": en}))
}

#[derive(Debug, Clone)]
struct Edits {
    base: usize,
    title: Option<Value>,
    sentence: Option<Value>,
    sensitive: Option<bool>,
    steps: Option<Vec<String>>,
    extra_options: Vec<String>,
    step_label: Option<String>,
    fraction: Option<f64>,
    tighten: Option<(usize, u32, u32)>,
}

fn edits(count: usize) -> impl Strategy<Value = Edits> {
    (
        0..count,
        proptest::option::of(localized(60)),
        proptest::option::of(localized(120)),
        proptest::option::of(any::<bool>()),
        proptest::option::of(proptest::collection::vec(text(80), 1..=100)),
        proptest::collection::vec(text(40), 0..=7),
        proptest::option::of(text(60)),
        proptest::option::of(0.0..=1.0_f64),
        proptest::option::of((0..SurfaceClass::ALL.len(), 8_u32..=64, 16_u32..=180)),
    )
        .prop_map(
            |(
                base,
                title,
                sentence,
                sensitive,
                steps,
                extra_options,
                step_label,
                fraction,
                tighten,
            )| Edits {
                base,
                title,
                sentence,
                sensitive,
                steps,
                extra_options,
                step_label,
                fraction,
                tighten,
            },
        )
}

fn apply(base: &Value, e: &Edits) -> Value {
    let mut v = base.clone();
    if let Some(t) = &e.title {
        v["subject"]["title"] = t.clone();
    }
    if let Some(s) = &e.sentence {
        v["minimal_projection"]["sentence"] = s.clone();
    }
    if let Some(s) = e.sensitive {
        v["sensitive"] = json!(s);
    }
    let details = &mut v["details"];
    if let (Some(labels), Some(_)) = (&e.steps, details.get("steps")) {
        details["steps"] = labels
            .iter()
            .map(|l| json!({"label": l, "status": "done"}))
            .collect();
    }
    if let Some(Value::Array(options)) = details.get_mut("options") {
        for (n, title) in e.extra_options.iter().enumerate() {
            options.push(json!({"id": format!("extra{n}"), "title": title}));
        }
    }
    if let Some(Value::Object(progress)) = details.get_mut("progress") {
        if let Some(l) = &e.step_label {
            progress.insert("step_label".into(), json!(l));
        }
        if let Some(f) = e.fraction {
            progress.insert("fraction".into(), json!(f));
        }
    }
    if let Some((class, title, body)) = e.tighten {
        let name = serde_json::to_value(SurfaceClass::ALL[class]).unwrap();
        v["surface_budgets"]["tighten"] = json!({
            name.as_str().unwrap(): {"max_title_chars": title, "max_body_chars": body}
        });
    }
    v
}

fn interaction() -> impl Strategy<Value = Interaction> {
    let all = bases();
    edits(all.len()).prop_filter_map("outside the schema limits", move |e| {
        let i: Interaction = serde_json::from_value(apply(&all[e.base], &e)).ok()?;
        validate_interaction(&i).is_ok().then_some(i)
    })
}

fn over(value: usize, max: Option<u32>) -> bool {
    max.is_some_and(|m| value > usize::try_from(m).unwrap())
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn x_13_projection_is_one_of_five_outcomes_never_full_over_budget(
        i in interaction(),
        declared in proptest::sample::subsequence(SurfaceTarget::ALL.to_vec(), 0..=SurfaceTarget::ALL.len()),
    ) {
        let kind = i.kind.declared_core();
        for class in SurfaceClass::ALL {
            for target in SurfaceTarget::ALL {
                let p = project(&i, kind, class, target, &declared);
                prop_assert_eq!(p, project(&i, kind, class, target, &declared));
                prop_assert!(OUTCOMES.contains(&p.projection));
                prop_assert_eq!(p.projection, p.reason.outcome());
                let undeclared = !declared.contains(&target) || !class.has_target(target);
                if undeclared {
                    prop_assert_eq!(p.projection, ProjectionOutcome::None);
                }
                if SENSITIVE_VOICE_TARGETS.contains(&target) && is_sensitive(&i) && !undeclared {
                    prop_assert!(matches!(p.projection, ProjectionOutcome::Neutral | ProjectionOutcome::None));
                }
                let (fits, bytes) = fits_budget(&i, kind, class, target);
                if matches!(p.reason, Rule::OverBudget | Rule::Fits) {
                    prop_assert_eq!(p.projected_bytes, bytes);
                    prop_assert_eq!(p.reason == Rule::Fits, fits);
                }
                if p.projection != ProjectionOutcome::Full {
                    continue;
                }
                prop_assert!(fits);
                let b = target.budget();
                let tighten = i.tighten(class);
                let title = i.subject.title.max_chars();
                let sentence = i.minimal_projection.sentence.max_chars();
                prop_assert!(!over(title, b.max_title_chars));
                prop_assert!(!over(title, tighten.and_then(|t| t.max_title_chars)));
                prop_assert!(!over(sentence, b.max_body_chars.or(b.max_status_chars)));
                prop_assert!(!over(sentence, tighten.and_then(|t| t.max_body_chars)));
                if target == SurfaceTarget::LiveActivity {
                    prop_assert!(!over(live_activity_bytes(&i), b.max_bytes));
                }
                if target == SurfaceTarget::Complication {
                    prop_assert!(!over(title, b.max_chars));
                }
            }
        }
    }
}
