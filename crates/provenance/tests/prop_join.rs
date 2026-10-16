//! Property tests over arbitrary label multisets, transforms, wire values and variable references (INV-15, SEC-14 (1, 2), T-36 (3, 4), T-38 (3)).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::needless_pass_by_value,
    reason = "T-38"
)]

use std::collections::BTreeSet;

use one_provenance::{
    ExternalSource, Label, LabelKind, Labelled, MixedSources, Opened, Transform, TrustedLabel,
    UntrustedLabel, VarRef,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};
use serde_json::{Map, Value, json};

fn config() -> Config {
    Config {
        cases: 256,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(15),
        ..Config::default()
    }
}

fn label() -> impl Strategy<Value = Label> {
    let single = proptest::sample::select(
        LabelKind::ALL
            .iter()
            .filter_map(|k| k.single())
            .collect::<Vec<_>>(),
    );
    let mixed = proptest::sample::subsequence(ExternalSource::ALL.to_vec(), 2..=5)
        .prop_map(|s| Label::Untrusted(UntrustedLabel::Mixed(MixedSources::new(s).unwrap())));
    prop_oneof![3 => single, 1 => mixed]
}

fn labels() -> impl Strategy<Value = Vec<Label>> {
    proptest::collection::vec(label(), 1..24)
}

fn transform() -> impl Strategy<Value = Transform> {
    proptest::sample::select(vec![
        Transform::Combine,
        Transform::Summarise,
        Transform::Translate,
        Transform::QuarantineExtract,
        Transform::NormaliseText,
        Transform::MemoryWrite,
    ])
}

fn externals(labels: &[Label]) -> BTreeSet<ExternalSource> {
    labels
        .iter()
        .filter_map(|l| match l {
            Label::Untrusted(u) => Some(u.external_sources().iter().copied()),
            Label::Trusted(_) => None,
        })
        .flatten()
        .collect()
}

fn min_rank(labels: &[Label]) -> u8 {
    labels.iter().map(Label::rank).min().unwrap()
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn inv_15_join_is_commutative_and_associative(a in label(), b in label(), c in label()) {
        prop_assert_eq!(a.join(&b), b.join(&a));
        prop_assert_eq!(a.join(&b).join(&c), a.join(&b.join(&c)));
        prop_assert_eq!(a.join(&a), a);
    }

    #[test]
    fn inv_15_join_all_ignores_order_and_repetition(
        (list, shuffled) in labels().prop_flat_map(|l| (Just(l.clone()), Just(l).prop_shuffle()))
    ) {
        let joined = Label::join_all(&list).unwrap();
        prop_assert_eq!(&Label::join_all(&shuffled).unwrap(), &joined);
        let doubled: Vec<Label> = list.iter().chain(&list).cloned().collect();
        prop_assert_eq!(&Label::join_all(&doubled).unwrap(), &joined);
        prop_assert_eq!(&joined.join(&joined), &joined);
    }

    #[test]
    fn inv_15_join_never_improves_trust(list in labels()) {
        let joined = Label::join_all(&list).unwrap();
        prop_assert!(joined.rank() <= min_rank(&list));
        prop_assert_eq!(joined.rank(), min_rank(&list));
        prop_assert_eq!(joined.is_trusted(), list.iter().all(Label::is_trusted));
        let sources = externals(&list);
        match &joined {
            Label::Trusted(_) => prop_assert!(sources.is_empty()),
            Label::Untrusted(u) => {
                let got: BTreeSet<ExternalSource> = u.external_sources().iter().copied().collect();
                prop_assert_eq!(got, sources);
            }
        }
    }

    #[test]
    fn sec_14_transforms_never_clear_a_label(t in transform(), list in labels()) {
        let derived = t.label(&list).unwrap();
        let joined = Label::join_all(&list).unwrap();
        prop_assert!(derived.rank() <= min_rank(&list));
        prop_assert_eq!(derived.is_trusted(), joined.is_trusted());
        let promoted = t == Transform::MemoryWrite
            && joined == Label::Trusted(TrustedLabel::UserDirect);
        if promoted {
            prop_assert_eq!(&derived, &Label::Trusted(TrustedLabel::UserMemory));
        } else {
            prop_assert_eq!(&derived, &joined);
        }
        let value = Labelled::derive(t, &list, 0_u8).unwrap();
        prop_assert_eq!(value.label(), t.label(&list).unwrap());
    }
}

fn leaf() -> impl Strategy<Value = Value> {
    let words: Vec<Value> = LabelKind::ALL
        .iter()
        .map(|k| json!(k.as_str()))
        .chain([json!("User.Direct"), json!("user.direct "), json!("")])
        .collect();
    prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        any::<i64>().prop_map(Value::from),
        "[a-z._ ]{0,12}".prop_map(Value::String),
        proptest::sample::select(words),
    ]
}

fn json_value() -> impl Strategy<Value = Value> {
    leaf().prop_recursive(3, 24, 4, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
            proptest::collection::btree_map(
                proptest::sample::select(vec!["value", "label", "sources", "x", "kind"]),
                inner,
                0..4
            )
            .prop_map(|m| Value::Object(m.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())),
        ]
    })
}

fn wrapper() -> impl Strategy<Value = Value> {
    (
        json_value(),
        proptest::option::of(leaf()),
        proptest::option::of(prop_oneof![
            proptest::collection::vec(leaf(), 0..4).prop_map(Value::Array),
            leaf(),
        ]),
        proptest::option::of(leaf()),
    )
        .prop_map(|(value, label, sources, extra)| {
            let mut m = Map::new();
            m.insert("value".into(), value);
            if let Some(l) = label {
                m.insert("label".into(), l);
            }
            if let Some(s) = sources {
                m.insert("sources".into(), s);
            }
            if let Some(e) = extra {
                m.insert("note".into(), e);
            }
            Value::Object(m)
        })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn sec_14_opening_arbitrary_json_is_trusted_only_by_a_valid_trusted_label(
        input in prop_oneof![json_value(), wrapper()]
    ) {
        let Ok(opened) = serde_json::from_value::<Opened<Value>>(input.clone()) else {
            return Ok(());
        };
        let label = opened.labelled().label();
        if !opened.conforms() {
            prop_assert_eq!(&label, &Label::UNKNOWN);
        }
        if let Label::Trusted(trusted) = label {
            let object = input.as_object().unwrap();
            let wire = object["label"].as_str().unwrap();
            prop_assert_eq!(LabelKind::parse(wire), Some(LabelKind::Trusted(trusted)));
            prop_assert_eq!(wire, trusted.as_str());
            prop_assert!(opened.conforms());
            prop_assert!(!object["value"].is_null());
            prop_assert!(object.keys().all(|k| ["value", "label", "sources"].contains(&k.as_str())));
        }
    }

    #[test]
    fn t_36_var_ref_prints_what_it_parses(n in 0_u32..=999_999, junk in "var_[0-9]{0,8}|[a-z_0-9]{0,10}") {
        let text = format!("var_{n}");
        let var = VarRef::parse(&text).unwrap();
        prop_assert_eq!(var.to_string(), text.clone());
        prop_assert_eq!(serde_json::to_value(var).unwrap(), json!(text));
        if let Some(v) = VarRef::parse(&junk) {
            prop_assert_eq!(v.to_string(), junk);
        }
    }
}
