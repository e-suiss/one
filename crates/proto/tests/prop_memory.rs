//! Property tests of `trust/v1`: the result is in [0, 1], a user confirmation never lowers it and each contradiction halves the ceiling (M-13, M-14, M-8, T-38 (3)).

#![allow(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    clippy::float_cmp,
    reason = "T-38"
)]

use one_proto::memory::SourceKind;
use one_proto::memory::trust::{TrustError, TrustInput, round6, source_ceiling, trust_v1};
use one_proto::ontology::time::Instant;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn config() -> Config {
    Config {
        cases: 512,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(13),
        ..Config::default()
    }
}

const AS_OF: i64 = 1_792_108_800;
const TEN_YEARS: i64 = 10 * 366 * 86_400;

fn source_kind() -> impl Strategy<Value = SourceKind> {
    proptest::sample::select(vec![
        SourceKind::UserStatement,
        SourceKind::UserBehaviour,
        SourceKind::ConnectedSource,
        SourceKind::ExternalContent,
        SourceKind::Import,
    ])
}

fn input() -> impl Strategy<Value = TrustInput> {
    (
        source_kind(),
        (1_u32..500).prop_flat_map(|o| (Just(o), 0..=o)),
        0..TEN_YEARS,
        proptest::option::of(0..TEN_YEARS),
        prop_oneof![Just(0_u32), 0_u32..40],
    )
        .prop_map(
            |(kind, (observations, supporting), age, confirmed, contradicting)| TrustInput {
                source_kind: kind,
                observation_count: observations,
                supporting_count: supporting,
                last_observed_at: Instant::from_unix(AS_OF - age),
                user_confirmed_at: confirmed.map(|c| Instant::from_unix(AS_OF - c)),
                contradicting_count: contradicting,
                as_of: Instant::from_unix(AS_OF),
            },
        )
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn m_13_trust_is_within_zero_and_one(i in input()) {
        let t = trust_v1(&i).unwrap();
        prop_assert!((0.0..=1.0).contains(&t), "{t}");
        prop_assert_eq!(round6(t), t);
        if i.user_confirmed_at.is_none() {
            prop_assert!(t <= round6(source_ceiling(i.source_kind)));
        }
    }

    #[test]
    fn m_13_a_confirmation_never_lowers_trust(i in input(), earlier in 0..TEN_YEARS) {
        let unconfirmed = TrustInput { user_confirmed_at: None, ..i.clone() };
        let base = trust_v1(&unconfirmed).unwrap();
        let confirmed = trust_v1(&i).unwrap();
        prop_assert!(confirmed >= base, "{confirmed} < {base}");
        if let Some(at) = i.user_confirmed_at {
            let older = TrustInput {
                user_confirmed_at: Some(Instant::from_unix(at.unix_secs().min(AS_OF - earlier))),
                ..i.clone()
            };
            prop_assert!(trust_v1(&older).unwrap() <= confirmed);
        }
    }

    #[test]
    fn m_13_each_contradiction_halves_the_ceiling(i in input()) {
        let t = trust_v1(&i).unwrap();
        let mut cap = 1.0_f64;
        for _ in 0..i.contradicting_count {
            cap *= 0.5;
        }
        prop_assert!(t <= round6(cap), "{t} > {cap}");
        let more = TrustInput { contradicting_count: i.contradicting_count + 1, ..i.clone() };
        prop_assert!(trust_v1(&more).unwrap() <= t);
        let none = TrustInput { contradicting_count: 0, ..i.clone() };
        prop_assert_eq!(t, round6(trust_v1(&none).unwrap().min(cap)));
    }

    #[test]
    fn m_13_impossible_or_future_evidence_is_refused(i in input(), ahead in 1..TEN_YEARS) {
        let too_many = TrustInput { supporting_count: i.observation_count + 1, ..i.clone() };
        prop_assert_eq!(trust_v1(&too_many), Err(TrustError::InvalidEvidence));
        let future = TrustInput { last_observed_at: Instant::from_unix(AS_OF + ahead), ..i.clone() };
        prop_assert_eq!(trust_v1(&future), Err(TrustError::FutureEvidence));
    }
}
