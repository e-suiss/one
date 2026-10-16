//! Property tests of capability names and negotiation: parse and print round-trip, and the negotiated set is within both offers, symmetric and a fixpoint (CP-15, OO-9, T-38 (3)).

#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "T-38")]

use std::collections::BTreeSet;

use one_proto::capability::{
    CapabilityName, CapabilityRef, CapabilityVersion, Declaration, Extends, NameKind,
    RESERVED_SEGMENTS, negotiate,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn config() -> Config {
    Config {
        cases: 512,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(15),
        ..Config::default()
    }
}

fn suiss_name() -> impl Strategy<Value = String> {
    proptest::collection::vec("[a-z][a-z0-9]{0,9}", 2..=5)
        .prop_filter("reserved first segment", |s| {
            !RESERVED_SEGMENTS.contains(&s[0].as_str())
        })
        .prop_map(|s| format!("app.suiss.{}", s.join(".")))
}

fn third_party_name() -> impl Strategy<Value = String> {
    (
        "[a-z]{2,6}",
        proptest::collection::vec("[a-z0-9]([a-z0-9_-]{0,6}[a-z0-9])?", 2..=9),
    )
        .prop_filter("app.suiss is the Suiss root", |(tld, labels)| {
            !(tld == "app" && labels[0] == "suiss")
        })
        .prop_map(|(tld, labels)| format!("{tld}.{}", labels.join(".")))
        .prop_filter("128 characters at most", |s| s.len() <= 128)
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn cp_15_names_print_what_they_parse(text in prop_oneof![suiss_name(), third_party_name()]) {
        let name = CapabilityName::parse(&text).unwrap();
        prop_assert_eq!(name.to_string(), text.clone());
        prop_assert_eq!(name.as_str(), text.as_str());
        prop_assert_eq!(name.kind() == NameKind::Suiss, text.starts_with("app.suiss."));
        let wire = serde_json::to_value(&name).unwrap();
        prop_assert_eq!(serde_json::from_value::<CapabilityName>(wire).unwrap(), name);
    }

    #[test]
    fn cp_15_any_accepted_text_round_trips(text in "[a-zA-Z0-9._-]{0,40}|app\\.suiss\\.[a-z0-9.]{0,30}") {
        if let Ok(name) = CapabilityName::parse(&text) {
            prop_assert_eq!(name.to_string(), text.clone());
            prop_assert_eq!(CapabilityName::parse(name.as_str()).unwrap(), name);
        }
    }
}

const POOL: usize = 8;
const VERSIONS: [&str; 4] = ["2026-01-01", "2026-03-15", "2026-06-01", "2026-09-30"];

fn pool_name(i: usize) -> CapabilityName {
    CapabilityName::parse(&format!("app.suiss.pool.cap{i}")).unwrap()
}

fn declaration() -> impl Strategy<Value = Declaration> {
    (
        0..POOL,
        proptest::sample::subsequence(VERSIONS.to_vec(), 1..=VERSIONS.len()).prop_shuffle(),
        proptest::option::weighted(
            0.4,
            proptest::sample::subsequence((0..POOL).collect::<Vec<_>>(), 1..=3),
        ),
    )
        .prop_map(|(i, versions, parents)| Declaration {
            name: pool_name(i),
            versions: versions
                .iter()
                .map(|v| CapabilityVersion::parse(v).unwrap())
                .collect(),
            extends: parents.map(|p| {
                let names: Vec<CapabilityName> = p.into_iter().map(pool_name).collect();
                if names.len() == 1 {
                    Extends::one(names[0].clone())
                } else {
                    Extends::many(names).unwrap()
                }
            }),
        })
}

fn first<'a>(side: &'a [Declaration], name: &CapabilityName) -> Option<&'a Declaration> {
    side.iter().find(|d| &d.name == name)
}

fn redeclare(result: &[CapabilityRef], side: &[Declaration]) -> Vec<Declaration> {
    result
        .iter()
        .map(|r| Declaration {
            name: r.name.clone(),
            versions: vec![r.version.clone()],
            extends: first(side, &r.name).unwrap().extends.clone(),
        })
        .collect()
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn cp_15_negotiation_is_within_both_offers_and_a_fixpoint(
        local in proptest::collection::vec(declaration(), 0..12),
        remote in proptest::collection::vec(declaration(), 0..12),
    ) {
        let result = negotiate(&local, &remote);
        let names: BTreeSet<&str> = result.iter().map(|r| r.name.as_str()).collect();
        prop_assert_eq!(names.len(), result.len());
        prop_assert!(result.windows(2).all(|w| w[0].name.as_str() < w[1].name.as_str()));
        for r in &result {
            let (mine, theirs) = (first(&local, &r.name).unwrap(), first(&remote, &r.name).unwrap());
            prop_assert!(mine.versions.contains(&r.version) && theirs.versions.contains(&r.version));
            let higher_common = mine
                .versions
                .iter()
                .any(|v| v > &r.version && theirs.versions.contains(v));
            prop_assert!(!higher_common);
            if let Some(extends) = &mine.extends {
                prop_assert!(extends.parents().iter().any(|p| names.contains(p.as_str())));
            }
        }
        prop_assert_eq!(&negotiate(&remote, &local), &result);
        let again = redeclare(&result, &local);
        prop_assert_eq!(&negotiate(&again, &again), &result);
        prop_assert_eq!(&negotiate(&again, &remote), &result);
    }
}
