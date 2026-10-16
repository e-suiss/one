//! Property tests of the attention decision head and Relay mapping: the critical Grant, mute, the daily budget and the interruption ceilings always hold, and the calibration error stays in [0, 1] (AT-1, AT-2, AT-5, AT-6, AT-42, AT-24, T-38 (3)).

#![allow(clippy::unwrap_used, reason = "T-38")]

use one_proto::attention::catalog::relay_row;
use one_proto::attention::{
    Arm, BINS, HeadInput, OUTPUT_TYPES, Prediction, Probability, RelayCandidate, Route, Thresholds,
    clamp_to_ceiling, decide, expected_calibration_error, map_to_relay, output_type,
    passes_calibration_gate, reliability_curve,
};
use one_proto::interaction_types::Interruption;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn config() -> Config {
    Config {
        cases: 512,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(1),
        ..Config::default()
    }
}

fn probability() -> impl Strategy<Value = Probability> {
    prop_oneof![
        1 => proptest::sample::select(vec![0.0, 0.1, 0.5, 0.9, 1.0]),
        4 => 0.0..=1.0_f64,
    ]
    .prop_map(|p| Probability::try_from(p).unwrap())
}

fn interruption() -> impl Strategy<Value = Interruption> {
    proptest::sample::select(vec![
        Interruption::Passive,
        Interruption::Active,
        Interruption::TimeSensitive,
        Interruption::Critical,
    ])
}

fn head_input() -> impl Strategy<Value = HeadInput> {
    (
        probability(),
        probability(),
        probability(),
        any::<[bool; 4]>(),
        prop_oneof![Just(0_u8), any::<u8>()],
    )
        .prop_map(
            |(p, a, b, [urgent, cloud, muted, grant], budget)| HeadInput {
                value_probability: p,
                thresholds: Thresholds { lower: a, upper: b },
                urgent,
                cloud_available: cloud,
                type_muted: muted,
                budget_remaining: budget,
                critical_grant: grant,
            },
        )
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn at_1_decision_head_respects_hard_constraints(input in head_input()) {
        let crossed = input.thresholds.lower.get() > input.thresholds.upper.get();
        let Ok(decision) = decide(&input) else {
            prop_assert!(crossed);
            return Ok(());
        };
        prop_assert!(!crossed);
        prop_assert_eq!(decision.interruption == Some(Interruption::Critical), input.critical_grant);
        if input.critical_grant {
            prop_assert_eq!(decision.route, Route::Notify);
            prop_assert_eq!(decision.chosen_arm, Some(Arm::InterruptNow));
            return Ok(());
        }
        prop_assert_eq!(decision.interruption, None);
        if input.type_muted || input.budget_remaining == 0 {
            prop_assert_eq!(decision.route, Route::NoNotification);
            prop_assert_eq!(decision.chosen_arm, Some(Arm::Digest));
            return Ok(());
        }
        let p = input.value_probability.get();
        if decision.route == Route::Notify {
            prop_assert!(p >= input.thresholds.upper.get());
        }
        if p < input.thresholds.lower.get() {
            prop_assert_ne!(decision.route, Route::Notify);
        }
        if decision.route == Route::CloudEstimate {
            prop_assert!(input.cloud_available);
        }
        let interrupts = decision.chosen_arm == Some(Arm::InterruptNow);
        prop_assert!(!interrupts || input.urgent);
    }

    #[test]
    fn at_42_relay_level_never_exceeds_the_ceilings(
        index in 0..OUTPUT_TYPES.len(),
        requested in interruption(),
        urgent in any::<bool>(),
        grant in any::<bool>(),
        registered in any::<bool>(),
    ) {
        let output = &OUTPUT_TYPES[index];
        if let Some(level) = clamp_to_ceiling(output, requested, registered) {
            let row = relay_row(output.row.unwrap()).unwrap();
            prop_assert!(level <= requested);
            prop_assert!(level <= output.interruption_ceiling.unwrap());
            prop_assert!(level <= row.interruption_ceiling);
            prop_assert_ne!(level, Interruption::Critical);
            if row.requires_personal_agent && !registered {
                prop_assert!(level <= Interruption::Active);
            }
        }
        let candidate = RelayCandidate {
            output_type: output.id.as_str(),
            interruption: requested,
            urgent,
            critical_grant: grant,
            personal_agent_registered: registered,
        };
        prop_assert_eq!(output_type(output.id.as_str()), Some(output));
        if let Some(send) = map_to_relay(&candidate) {
            if send.interruption == Interruption::Critical {
                prop_assert!(grant);
            } else {
                prop_assert_eq!(
                    Some(send.interruption),
                    clamp_to_ceiling(output, requested, registered)
                );
            }
        }
        let unlisted = RelayCandidate { output_type: "app.suiss.one.output.unlisted", ..candidate };
        prop_assert_eq!(map_to_relay(&unlisted), None);
    }

    #[test]
    fn at_24_calibration_error_is_within_zero_and_one(
        predictions in proptest::collection::vec(
            (probability(), any::<bool>()).prop_map(|(probability, outcome)| Prediction { probability, outcome }),
            0..64,
        )
    ) {
        let curve = reliability_curve(&predictions);
        prop_assert_eq!(curve.iter().map(|b| b.count).sum::<usize>(), predictions.len());
        prop_assert!(curve.iter().all(|b| b.bin < BINS && b.count > 0));
        prop_assert!(curve.windows(2).all(|w| w[0].bin < w[1].bin));
        match expected_calibration_error(&predictions) {
            None => {
                prop_assert!(predictions.is_empty());
                prop_assert!(!passes_calibration_gate(&predictions));
            }
            Some(ece) => {
                prop_assert!((0.0..=1.0).contains(&ece), "{ece}");
                prop_assert!(!predictions.is_empty());
            }
        }
    }
}
