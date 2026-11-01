//! The plan, decide and execute gate: only an accepted intent with an allow outside `check` mode becomes a permit, and every other decision stops the step with its reason; acceptance is checked before the decision (CP-5, SEC-1, A-2, A-6, E-14, E-36).

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use std::cell::RefCell;

use one_access_client::access_kernel::combinator::Mode;
use one_access_client::decision::{Decision, NoAllow, decide};
use one_provenance::intent::Rejection;
use one_task::gate::{Executor, Permit, Stop, gate};
use suiss_crypto::digest::Digest;

fn allow() -> Decision {
    Decision::Allow {
        exercise: Some(Digest([7; 32])),
        advisory: false,
        basis_ref: None,
        consistency_token: None,
    }
}

#[derive(Default)]
struct Recorder(RefCell<Vec<Digest>>);

impl Executor<&'static str> for Recorder {
    type Error = ();

    fn execute(&self, permit: &Permit<&'static str>) -> Result<(), ()> {
        self.0.borrow_mut().push(*permit.exercise());
        Ok(())
    }
}

#[test]
fn cp_5_only_an_allowed_accepted_intent_reaches_the_executor() {
    let executor = Recorder::default();
    let permit = gate(Ok("order"), &allow()).unwrap();
    assert_eq!(*permit.intent(), "order");
    executor.execute(&permit).unwrap();
    assert_eq!(*executor.0.borrow(), [Digest([7; 32])]);
}

#[test]
fn a_6_a_rejected_intent_stops_before_any_decision() {
    for reason in Rejection::CHECK_ORDER {
        assert_eq!(
            gate::<&str>(Err(reason), &allow()),
            Err(Stop::Rejected(reason))
        );
    }
}

#[test]
fn a_2_nothing_but_an_allow_opens_the_gate() {
    let advisory = Decision::Allow {
        exercise: None,
        advisory: true,
        basis_ref: None,
        consistency_token: None,
    };
    let cases = [
        (advisory, Stop::Advisory),
        (
            Decision::Deny {
                blockers: Vec::new(),
            },
            Stop::Denied,
        ),
        (
            Decision::RequireAction {
                blockers: Vec::new(),
                unmet: Vec::new(),
            },
            Stop::ActionRequired,
        ),
        (
            Decision::NoAllow(NoAllow::Unreachable),
            Stop::NoAllow(NoAllow::Unreachable),
        ),
        (
            decide(Mode::Commit, 503, b"{}"),
            Stop::NoAllow(NoAllow::Status(503, None)),
        ),
        (
            decide(
                Mode::Commit,
                200,
                br#"{"decision":true,"context":{"outcome":"allow"}}"#,
            ),
            Stop::NoAllow(NoAllow::Malformed),
        ),
    ];
    for (decision, stop) in cases {
        assert_eq!(gate(Ok("order"), &decision), Err(stop));
    }
}
