//! Every behaviour vector of `conformance/intent`: intent acceptance in contract order, labelling of planner proposals and control separation of model contexts (SEC-2, SEC-4, SEC-12, SEC-14, SEC-19, SEC-21 (1), CP-5, T-36 (2)).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::unreachable,
    reason = "T-38"
)]

mod intent_common;

use intent_common::{Boon, description, fixture, json, registry, vectors};
use one_proto::TaskId;
use one_proto::ontology::JsonValue;
use one_provenance::intent::{
    BindError, BoundCapability, Control, IntentModelOutput, ModelContext, OriginSet,
    QuarantineModelOutput, QuarantineOutput, Rejection, SummaryLangMismatch, TypedIntent,
    accept_intent,
};
use one_provenance::{
    AccessMapping, Label, LabelKind, Labelled, Transform, TrustedLabel, VarRef, VariableTable,
};
use serde_json::Value;

fn kind(v: &Value) -> LabelKind {
    LabelKind::parse(v.as_str().unwrap()).unwrap()
}

#[test]
fn sec_4_intent_acceptance_vectors() {
    let all = vectors("vectors/intent-acceptance.json");
    let registry = registry();
    for v in &all {
        let got = accept_intent(json(&v["input"]), &registry, &Boon);
        let expected = &v["expected"];
        assert_eq!(
            got.is_ok(),
            expected["accepted"].as_bool().unwrap(),
            "{}: {got:?}",
            description(v)
        );
        if let Err(reason) = got {
            assert_eq!(
                reason.code(),
                expected["reason"].as_str().unwrap(),
                "{}",
                description(v)
            );
            assert_eq!(serde_json::to_value(reason).unwrap(), expected["reason"]);
        }
    }
    assert_eq!(all.len(), 13);
}

fn acceptance_check_order() -> Vec<String> {
    let text = std::fs::read_to_string(intent_common::path("acceptance.toml")).unwrap();
    let line = |key: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(&format!("{key} = ")))
            .unwrap()
            .to_owned()
    };
    assert_eq!(line("first_failing_check_decides"), "true");
    line("check_order")
        .trim_matches(['[', ']'])
        .split(", ")
        .map(|c| c.trim_matches('"').to_owned())
        .collect()
}

#[test]
fn sec_4_check_order_matches_acceptance_toml() {
    let codes: Vec<&str> = Rejection::CHECK_ORDER.iter().map(|r| r.code()).collect();
    assert_eq!(codes, acceptance_check_order());
    let position = |code: &str| codes.iter().position(|c| *c == code).unwrap();
    assert!(position("input_schema") < position("summary_mismatch"));
    let all = vectors("vectors/intent-acceptance.json");
    let both = all
        .iter()
        .find(|v| {
            description(v).starts_with("inputs that fail the capability input schema and a summary")
        })
        .unwrap();
    let intent: TypedIntent = serde_json::from_value(both["input"].clone()).unwrap();
    let rebuilt = TypedIntent::new(
        intent.task_id(),
        intent.capability().clone(),
        intent.inputs().clone(),
        intent.origin_set().clone(),
    );
    assert_ne!(rebuilt.summary(), intent.summary());
    assert_eq!(
        intent.accept(&registry(), &Boon),
        Err(Rejection::InputSchema)
    );
}

#[test]
fn sec_14_intent_built_from_its_inputs_carries_the_summary_acceptance_expects() {
    let all = vectors("vectors/intent-acceptance.json");
    let accepted = all
        .iter()
        .find(|v| v["expected"]["accepted"] == Value::Bool(true))
        .unwrap();
    let wire: TypedIntent = serde_json::from_value(accepted["input"].clone()).unwrap();
    let rebuilt = TypedIntent::new(
        wire.task_id(),
        wire.capability().clone(),
        wire.inputs().clone(),
        wire.origin_set().clone(),
    );
    assert_eq!(rebuilt, wire);
    assert_eq!(rebuilt.accept(&registry(), &Boon), Ok(()));
    let unpinned = std::collections::BTreeMap::new();
    assert_eq!(
        rebuilt.accept(&unpinned, &Boon),
        Err(Rejection::UnknownInputSchema)
    );
}

fn table(variables: &Value) -> VariableTable<JsonValue> {
    let mut table = VariableTable::new();
    for (name, entry) in variables.as_object().unwrap() {
        let label = kind(&entry["label"]).single().unwrap();
        table.insert(
            VarRef::parse(name).unwrap(),
            Labelled::derive(
                Transform::Combine,
                [&label],
                JsonValue::String(name.clone()),
            )
            .unwrap(),
        );
    }
    table
}

#[test]
fn t_36_intent_labelling_vectors() {
    let all = vectors("vectors/intent-labelling.json");
    for v in &all {
        let input = &v["input"];
        let output: IntentModelOutput =
            serde_json::from_value(input["model_output"].clone()).unwrap();
        let variables = table(&input["variables"]);
        let context = input["planner_context_labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| kind(l).trusted().unwrap())
            .reduce(TrustedLabel::join)
            .unwrap();
        let labels = output.input_labels(&variables, context);
        let expected = &v["expected"];
        let want = expected["inputs"].as_object().unwrap();
        assert_eq!(labels.inputs.len(), want.len(), "{}", description(v));
        for (name, label) in &labels.inputs {
            assert_eq!(
                label.kind(),
                kind(&want[name.as_str()]),
                "{}: {}",
                description(v),
                name.as_str()
            );
        }
        assert_eq!(
            labels.worst.as_ref().map(Label::kind),
            Some(kind(&expected["worst"])),
            "{}",
            description(v)
        );

        let capability = BoundCapability::bind(output.capability.clone(), &fixture());
        let task = TaskId::parse("task_01m43k40v4f7zsqnydqk8x21v3").unwrap();
        match output.bind(task, capability, &variables, context, OriginSet::default()) {
            Ok(intent) => {
                for (name, value) in intent.inputs().iter() {
                    assert_eq!(value.label(), labels.inputs[name], "{}", description(v));
                }
                assert_eq!(
                    intent.summary().worst.map(AccessMapping::label),
                    labels.worst.as_ref().map(Label::kind)
                );
            }
            Err(BindError::UnknownVariable(var)) => {
                assert_eq!(variables.label(var), Label::UNKNOWN, "{}", description(v));
            }
            Err(e) => unreachable!("{}: {e:?}", description(v)),
        }
    }
    assert_eq!(all.len(), 4);
}

fn replace_data_text(context: &mut Value, text: &str) {
    for part in context["data"].as_array_mut().unwrap() {
        if part.get("text").is_some() {
            part["text"] = Value::String(text.to_owned());
        }
    }
}

#[test]
fn sec_2_control_separation_vectors() {
    let all = vectors("vectors/control-separation.json");
    for v in &all {
        let input = &v["input"];
        let with_injection: ModelContext =
            serde_json::from_value(input["context"].clone()).unwrap();
        let mut variant = input["context"].clone();
        replace_data_text(&mut variant, input["variant_data_text"].as_str().unwrap());
        let plain: ModelContext = serde_json::from_value(variant).unwrap();
        assert_ne!(with_injection, plain, "{}", description(v));
        assert_eq!(
            with_injection.control(),
            plain.control(),
            "{}",
            description(v)
        );
        assert_eq!(
            serde_json::to_value(with_injection.control()).unwrap(),
            v["expected"]["control"],
            "{}",
            description(v)
        );
        let role_matches = matches!(
            (&with_injection, with_injection.control()),
            (ModelContext::Planner(_), Control::Planner(_))
                | (ModelContext::Quarantine(_), Control::Quarantine(_))
        );
        assert!(role_matches, "{}", description(v));
    }
    assert_eq!(all.len(), 2);
}

#[test]
fn t_36_planner_literal_label_is_the_join_of_request_memory_and_records() {
    let all = vectors("vectors/model-context.schema.json");
    let context: ModelContext = serde_json::from_value(all[0]["input"].clone()).unwrap();
    let ModelContext::Planner(planner) = context else {
        unreachable!("first model-context vector is a planner context");
    };
    assert_eq!(planner.literal_label(), TrustedLabel::RecordTrusted);
    let mut only_memory = planner.clone();
    only_memory
        .data
        .retain(|p| matches!(p, one_provenance::intent::PlannerData::MemoryData(_)));
    assert_eq!(only_memory.literal_label(), TrustedLabel::UserMemory);
    only_memory.data.clear();
    assert_eq!(only_memory.literal_label(), TrustedLabel::UserDirect);
}

#[test]
fn sec_13_quarantine_output_takes_the_content_label() {
    let contexts = vectors("vectors/model-context.schema.json");
    let ModelContext::Quarantine(context) =
        serde_json::from_value::<ModelContext>(contexts[1]["input"].clone()).unwrap()
    else {
        unreachable!("second model-context vector is a quarantine context");
    };
    let outputs = vectors("vectors/quarantine-model-output.schema.json");
    let model: QuarantineModelOutput = serde_json::from_value(outputs[0]["input"].clone()).unwrap();
    let field_count = model.fields.len();
    let labelled = context.label_output(model).unwrap();
    assert_eq!(labelled.label.kind().as_str(), "external.email");
    assert!(labelled.fields.values().all(|f| f.label == labelled.label));
    let summary = labelled.display_summary.clone().unwrap();
    assert_eq!(summary.label, labelled.label);
    let wire = serde_json::to_value(&labelled).unwrap();
    assert_eq!(wire["display_summary"]["display_only"], Value::Bool(true));
    let back: QuarantineOutput = serde_json::from_value(wire).unwrap();
    assert_eq!(back, labelled);
    let values = labelled.into_untrusted();
    assert_eq!(values.len(), field_count);
    assert!(
        values
            .values()
            .all(|u| u.label().kind().as_str() == "external.email")
    );
}

#[test]
fn sec_13_quarantine_labelling_vectors() {
    let all = vectors("vectors/quarantine-labelling.json");
    for v in &all {
        let input = &v["input"];
        let ModelContext::Quarantine(context) =
            serde_json::from_value::<ModelContext>(input["context"].clone()).unwrap()
        else {
            unreachable!("{}: not a quarantine context", description(v));
        };
        let model: QuarantineModelOutput =
            serde_json::from_value(input["model_output"].clone()).unwrap();
        let expected = &v["expected"];
        let got = context.label_output(model);
        assert_eq!(
            Value::Bool(got.is_ok()),
            expected["accepted"],
            "{}",
            description(v)
        );
        let Ok(output) = got else {
            assert_eq!(got, Err(SummaryLangMismatch));
            assert_eq!(expected["reason"], "summary_lang", "{}", description(v));
            continue;
        };
        assert_eq!(
            serde_json::to_value(&output).unwrap(),
            expected["output"],
            "{}",
            description(v)
        );
        let sources = context.content().label.untrusted().external_sources();
        for value in output.into_untrusted().values() {
            assert_eq!(
                value.label().external_sources(),
                sources,
                "{}",
                description(v)
            );
        }
    }
    assert_eq!(all.len(), 5);
}
