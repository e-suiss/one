//! Every schema vector of `conformance/interaction` through the typed forms, and the embedded kind, catalog and surface tables against their TOML files (X-12, X-14, X-22, C-25, C-26, T-31).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

mod common;

use one_interaction::catalog::Component;
use one_interaction::surface::{Ceiling, ClassRow};
use one_interaction::{
    CoreKind, Interaction, InteractionResponse, KindRegistry, SurfaceClass, validate_interaction,
    validate_response,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn accepts<T: DeserializeOwned + Serialize>(input: &Value, check: impl Fn(&T) -> bool) -> bool {
    serde_json::from_value::<T>(input.clone()).is_ok_and(|typed| check(&typed))
}

fn round_trips<T: DeserializeOwned + Serialize>(input: &Value) -> Value {
    let typed: T = serde_json::from_value(input.clone()).unwrap();
    serde_json::to_value(&typed).unwrap()
}

fn run<T: DeserializeOwned + Serialize>(file: &str, check: impl Fn(&T) -> bool) -> (usize, usize) {
    let (mut valid, mut invalid) = (0, 0);
    for v in common::vectors(file) {
        let input = &v["input"];
        let description = v["description"].as_str().unwrap();
        if v["valid"].as_bool().unwrap() {
            assert!(
                accepts::<T>(input, &check),
                "{file}: rejected: {description}"
            );
            assert_eq!(
                &round_trips::<T>(input),
                input,
                "{file}: round trip: {description}"
            );
            valid += 1;
        } else {
            assert!(
                !accepts::<T>(input, &check),
                "{file}: accepted: {description}"
            );
            invalid += 1;
        }
    }
    (valid, invalid)
}

#[test]
fn c_25_interaction_vectors_round_trip_and_invalid_ones_are_rejected() {
    let check = |i: &Interaction| validate_interaction(i).is_ok();
    assert_eq!(run("vectors/fixtures.json", check), (10, 0));
    assert_eq!(run("vectors/interaction.json", check), (25, 108));
}

#[test]
fn x_22_response_vectors_round_trip_and_invalid_ones_are_rejected() {
    let check = |r: &InteractionResponse| validate_response(r).is_ok();
    assert_eq!(run("vectors/interaction-response.json", check), (2, 19));
}

#[test]
fn x_12_kind_extension_registry_vectors_round_trip() {
    assert_eq!(
        run::<KindRegistry>("vectors/kind-extension.json", |_| true),
        (2, 4)
    );
}

#[test]
fn x_12_the_committed_extension_registry_is_empty() {
    let registry: KindRegistry =
        serde_json::from_value(common::toml("kind-extensions.toml")).unwrap();
    assert_eq!(registry.version, 1);
    assert_eq!(registry.extension.len(), 0);
}

#[test]
fn x_12_kind_rules_match_kinds_toml() {
    let table = common::toml("kinds.toml");
    let kinds = table["kind"].as_object().unwrap();
    assert_eq!(kinds.len(), CoreKind::ALL.len());
    for kind in CoreKind::ALL {
        let row = &kinds[kind.as_str()];
        assert_eq!(
            &serde_json::to_value(kind.rule()).unwrap(),
            row,
            "{}",
            kind.as_str()
        );
    }
}

#[test]
fn x_14_catalog_matches_components_toml() {
    let table = common::toml("catalog/components.toml");
    assert_eq!(table["catalog_version"], 1);
    assert_eq!(table["free_ui"], false);
    assert_eq!(table["generated_markup"], false);
    let components = table["component"].as_object().unwrap();
    assert_eq!(components.len(), Component::ALL.len());
    for c in Component::ALL {
        assert_eq!(
            &serde_json::to_value(c.spec()).unwrap(),
            &components[c.as_str()],
            "{}",
            c.as_str()
        );
    }
}

#[test]
fn x_3_surface_classes_match_surface_classes_toml() {
    let table = common::toml("surfaces/surface-classes.toml");
    assert_eq!(
        table["chat_is_canonical_unit"],
        one_interaction::surface::CHAT_IS_CANONICAL_UNIT
    );
    let classes = table["class"].as_object().unwrap();
    assert_eq!(classes.len(), SurfaceClass::ALL.len());
    for class in SurfaceClass::ALL {
        assert_eq!(
            &serde_json::to_value(class.spec()).unwrap(),
            &classes[class.as_str()],
            "{}",
            class.as_str()
        );
    }
    let ceilings = table["ceiling"].as_object().unwrap();
    for (name, ceiling) in [
        ("low_risk", Ceiling::LowRisk),
        ("full_with_strong_auth", Ceiling::FullWithStrongAuth),
    ] {
        assert_eq!(
            &serde_json::to_value(ceiling.spec()).unwrap(),
            &ceilings[name],
            "{name}"
        );
    }
    assert_eq!(ceilings["stop"]["effect"], "stop");
    assert_eq!(ceilings["stop"]["all_classes"], true);
    for (mode, projection) in [
        ("presence", "minimal"),
        ("workspace", "full"),
        ("control", "full"),
    ] {
        assert_eq!(table["mode"][mode]["projection"], projection);
    }
}

#[test]
fn x_22_response_check_order_matches_approval_act_statement_toml() {
    let table = common::toml("projection/approval-act-statement.toml");
    assert_eq!(
        table["processing"]["check_order"],
        serde_json::to_value(one_interaction::processing::CHECK_ORDER).unwrap()
    );
    assert_eq!(table["processing"]["first_failing_check_decides"], true);
}
