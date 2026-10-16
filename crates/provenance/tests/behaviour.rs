//! Every behaviour vector of `conformance/provenance` and the labelling vectors of `conformance/intent` (SEC-14, SEC-31 (5), T-36).

#![allow(
    clippy::unwrap_used,
    clippy::unreachable,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

mod common;

use std::cmp::Ordering;

use common::{description, expected_label, kind, label, labels, load};
use one_provenance::confirm::{
    Evidence, SecondEvidence, ShownConfirmation, Surface, Target, Via, corroborate, upgrade_label,
};
use one_provenance::{
    AccessMapping, AccessProvenance, ExternalSource, Label, Labelled, Opened, ParameterName,
    ParameterProvenance, ProposedInput, Transform, Untrusted, VarRef, VariableTable,
};
use serde_json::{Value, json};

fn wire(label: &Label) -> Value {
    let mut v =
        serde_json::to_value(Labelled::derive(Transform::Combine, [label], 0).unwrap()).unwrap();
    v.as_object_mut().unwrap().remove("value");
    v
}

#[test]
fn sec_14_order_vectors() {
    let vectors = load("provenance/vectors/order.json");
    for v in &vectors {
        let input = &v["input"];
        match input["op"].as_str().unwrap() {
            "rank" => {
                let k = kind(&input["label"]);
                let rank = u64::from(k.rank());
                assert_eq!(
                    rank,
                    v["expected"]["rank"].as_u64().unwrap(),
                    "{}",
                    description(v)
                );
                if let Some(single) = k.single() {
                    assert_eq!(u64::from(single.rank()), rank, "{}", description(v));
                }
            }
            "compare" => {
                let a = kind(&input["a"]);
                let b = kind(&input["b"]);
                let order = match a.rank().cmp(&b.rank()) {
                    Ordering::Less => "less",
                    Ordering::Equal => "equal",
                    Ordering::Greater => "greater",
                };
                assert_eq!(order, v["expected"]["order"], "{}", description(v));
                if let (Some(a), Some(b)) = (a.single(), b.single()) {
                    assert_eq!(
                        a.cmp_trust(&b).reverse(),
                        b.cmp_trust(&a),
                        "{}",
                        description(v)
                    );
                }
            }
            op => unreachable!("unknown op {op}"),
        }
    }
    assert_eq!(vectors.len(), 30);
}

#[test]
fn sec_14_join_vectors() {
    let vectors = load("provenance/vectors/join.json");
    for v in &vectors {
        assert_eq!(v["input"]["op"], "join");
        let inputs = labels(&v["input"]["inputs"]);
        let joined = Label::join_all(&inputs).unwrap();
        assert_eq!(joined, expected_label(&v["expected"]), "{}", description(v));
        assert_eq!(wire(&joined), v["expected"], "{}", description(v));
        let reversed = Label::join_all(inputs.iter().rev()).unwrap();
        assert_eq!(reversed, joined, "{}", description(v));
    }
    assert_eq!(vectors.len(), 18);
}

#[test]
fn t_36_open_vectors() {
    let vectors = load("provenance/vectors/open.json");
    for v in &vectors {
        assert_eq!(v["input"]["op"], "open");
        let encoded = &v["input"]["encoded"];
        let opened: Labelled<Value> = serde_json::from_value(encoded.clone()).unwrap();
        let expected = &v["expected"];
        assert_eq!(
            opened.label().kind(),
            kind(&expected["label"]),
            "{}",
            description(v)
        );
        let provenance: AccessProvenance =
            serde_json::from_value(expected["access_provenance"].clone()).unwrap();
        assert_eq!(opened.access_provenance(), provenance, "{}", description(v));
        let value = encoded.get("value").unwrap_or(encoded);
        assert_eq!(opened.expose(), value, "{}", description(v));
        let checked: Opened<Value> = serde_json::from_value(encoded.clone()).unwrap();
        if checked.conforms() {
            assert_eq!(
                &serde_json::to_value(&opened).unwrap(),
                encoded,
                "{}",
                description(v)
            );
        } else {
            assert_eq!(opened.label(), Label::UNKNOWN, "{}", description(v));
        }
    }
    assert_eq!(vectors.len(), 14);
}

#[test]
fn t_36_access_mapping_vectors() {
    let vectors = load("provenance/vectors/access-mapping.json");
    for v in &vectors {
        assert_eq!(v["input"]["op"], "map");
        let k = kind(&v["input"]["label"]);
        let expected: AccessProvenance =
            serde_json::from_value(v["expected"]["provenance"].clone()).unwrap();
        assert_eq!(k.access_provenance(), expected, "{}", description(v));
        assert_eq!(
            AccessMapping::of(k).provenance(),
            expected,
            "{}",
            description(v)
        );
        if let Some(full) = k.single() {
            assert_eq!(full.access_provenance(), expected, "{}", description(v));
        }
    }
    assert_eq!(vectors.len(), 19);
}

#[test]
fn sec_14_transform_vectors() {
    let vectors = load("provenance/vectors/transform.json");
    for v in &vectors {
        let inputs = labels(&v["input"]["inputs"]);
        let expected = expected_label(&v["expected"]);
        let derived = match v["input"]["op"].as_str().unwrap() {
            "summarise" => Transform::Summarise.label(&inputs),
            "translate" => Transform::Translate.label(&inputs),
            "quarantine_extract" => Transform::QuarantineExtract.label(&inputs),
            "normalise_text" => Transform::NormaliseText.label(&inputs),
            "memory_write" => Transform::MemoryWrite.label(&inputs),
            "serialise_roundtrip" => {
                let value = Labelled::derive(Transform::Combine, &inputs, json!("x")).unwrap();
                let text = serde_json::to_string(&value).unwrap();
                let back: Opened<Value> = serde_json::from_str(&text).unwrap();
                assert!(back.conforms(), "{}", description(v));
                Some(back.labelled().label())
            }
            op => unreachable!("unknown op {op}"),
        };
        assert_eq!(derived.unwrap(), expected, "{}", description(v));
    }
    assert_eq!(vectors.len(), 14);
}

fn evidence(input: &Value) -> Evidence {
    let via: Via = serde_json::from_value(input["via"].clone()).unwrap();
    let surface: Surface = serde_json::from_value(input["surface"].clone()).unwrap();
    Evidence::new(via, surface, input["shown"].as_bool().unwrap())
}

fn typed_upgrade(input: &Value, target: Target) -> Label {
    let Labelled::Untrusted(value) =
        Labelled::derive(Transform::Combine, [&label(input)], ()).unwrap()
    else {
        unreachable!("upgrade vectors start untrusted");
    };
    match evidence(input) {
        Evidence::UserConfirmation { surface, shown } => {
            match ShownConfirmation::new(surface, shown, target) {
                Some(proof) => {
                    let (trusted, record) = proof.confirm(value).into_parts();
                    assert_eq!(record.to(), trusted.label());
                    assert_eq!(record.target(), target);
                    Label::Trusted(trusted.label())
                }
                None => Label::Untrusted(value.label().clone()),
            }
        }
        Evidence::SecondIndependentEvidence if target == Target::Memory => Label::Untrusted(
            corroborate(value, SecondEvidence::Independent)
                .label()
                .clone(),
        ),
        Evidence::SameSourceSecondCopy => Label::Untrusted(
            corroborate(value, SecondEvidence::SameSource)
                .label()
                .clone(),
        ),
        _ => Label::Untrusted(value.label().clone()),
    }
}

#[test]
fn sec_14_upgrade_vectors() {
    let vectors = load("provenance/vectors/upgrade.json");
    for v in &vectors {
        let input = &v["input"];
        assert_eq!(input["op"], "upgrade");
        let target: Target = serde_json::from_value(input["target"].clone()).unwrap();
        let expected = expected_label(&v["expected"]);
        let pure = upgrade_label(&label(input), evidence(input), target);
        assert_eq!(pure, expected, "{}", description(v));
        assert_eq!(typed_upgrade(input, target), expected, "{}", description(v));
    }
    assert_eq!(vectors.len(), 14);
}

#[test]
fn t_36_intent_labelling_vectors() {
    let vectors = load("intent/vectors/intent-labelling.json");
    for v in &vectors {
        let input = &v["input"];
        let mut table: VariableTable<()> = VariableTable::new();
        for (name, entry) in input["variables"].as_object().unwrap() {
            let var = VarRef::parse(name).unwrap();
            table.insert(
                var,
                Labelled::derive(Transform::Combine, [&label(entry)], ()).unwrap(),
            );
        }
        let context = input["planner_context_labels"]
            .as_array()
            .unwrap()
            .iter()
            .map(|l| kind(l).trusted().unwrap())
            .reduce(one_provenance::TrustedLabel::join)
            .unwrap();
        let mut got = Vec::new();
        for (name, raw) in input["model_output"]["inputs"].as_object().unwrap() {
            let proposed: ProposedInput<Value> = serde_json::from_value(raw.clone()).unwrap();
            assert_eq!(&serde_json::to_value(&proposed).unwrap(), raw);
            let l = proposed.label(&table, context);
            assert_eq!(
                l.kind(),
                kind(&v["expected"]["inputs"][name]),
                "{}: {name}",
                description(v)
            );
            got.push(l);
        }
        let worst = Label::join_all(&got).unwrap();
        assert_eq!(
            worst.kind(),
            kind(&v["expected"]["worst"]),
            "{}",
            description(v)
        );
    }
    assert_eq!(vectors.len(), 4);
}

fn summary_labels_consistent(input: &Value) -> bool {
    let mut opened = Vec::new();
    let mut params = ParameterProvenance::new();
    for (name, raw) in input["inputs"].as_object().unwrap() {
        let checked: Opened<Value> = serde_json::from_value(raw.clone()).unwrap();
        if !checked.conforms() {
            return false;
        }
        let l = checked.labelled().label();
        params.insert(ParameterName::new(name).unwrap(), &l);
        opened.push((name.clone(), l));
    }
    let summary = &input["summary"];
    let Some(summary_inputs) = summary["inputs"].as_object() else {
        return false;
    };
    if summary_inputs.len() != opened.len() {
        return false;
    }
    for (name, l) in &opened {
        let Some(pair) = summary_inputs.get(name) else {
            return false;
        };
        let Ok(pair) = serde_json::from_value::<AccessMapping>(pair.clone()) else {
            return false;
        };
        if pair != AccessMapping::from(l)
            || params.get(&ParameterName::new(name).unwrap()) != Some(pair.provenance())
        {
            return false;
        }
    }
    let worst = Label::join_all(opened.iter().map(|(_, l)| l)).unwrap();
    serde_json::from_value::<AccessMapping>(summary["worst"].clone())
        .is_ok_and(|w| w == AccessMapping::from(&worst))
}

#[test]
fn sec_14_intent_acceptance_label_summary() {
    let vectors = load("intent/vectors/intent-acceptance.json");
    let mut checked = 0;
    for v in &vectors {
        let input = &v["input"];
        let expected = &v["expected"];
        let label_case = match expected["reason"].as_str() {
            None | Some("envelope_schema") => true,
            Some("summary_mismatch") => input["summary"]["origin_set"] == input["origin_set"],
            Some(_) => false,
        };
        if !label_case {
            continue;
        }
        let accepted = expected["accepted"].as_bool().unwrap();
        assert_eq!(
            summary_labels_consistent(input),
            accepted,
            "{}",
            description(v)
        );
        checked += 1;
    }
    assert_eq!(vectors.len(), 12);
    assert_eq!(checked, 5);
}

#[test]
fn t_36_unknown_variable_is_external_unknown() {
    let table: VariableTable<()> = VariableTable::new();
    assert_eq!(table.label(VarRef::parse("var_9").unwrap()), Label::UNKNOWN);
    assert_eq!(
        Label::UNKNOWN,
        Label::Untrusted(one_provenance::UntrustedLabel::External(
            ExternalSource::Unknown
        ))
    );
    let _ = Untrusted::unknown(());
}
