//! The plan, decide and execute gate (CP-5, SEC-1, A-2, A-6, E-14): an intent reaches the Executor port only as a [`Permit`], and a permit is made only from an accepted typed intent with an Access allow outside `check` mode; an intent that fails acceptance is dropped and the user is asked, the model is not retried, and a deny, a `require_action`, an advisory allow or any no-allow stops the step. No One signal, confidence or chat "yes" enters the gate.
//!
//! A permit cannot be made outside this module:
//!
//! ```compile_fail,E0451
//! let permit = one_task::gate::Permit { intent: 1_u8, exercise: suiss_crypto::digest::Digest([0; 32]) };
//! ```

use one_access_client::decision::{Decision, NoAllow};
use one_provenance::intent::Rejection;
use suiss_crypto::digest::Digest;

/// An intent Access allowed: the only thing the Executor port takes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permit<T> {
    intent: T,
    exercise: Digest,
}

impl<T> Permit<T> {
    /// The accepted intent.
    #[must_use]
    pub const fn intent(&self) -> &T {
        &self.intent
    }

    /// The Exercise Access recorded for it; every effect binds to it (INV-10).
    #[must_use]
    pub const fn exercise(&self) -> &Digest {
        &self.exercise
    }
}

/// Why a step stops at the gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Stop {
    /// The intent failed acceptance; it is dropped and the user is asked (A-6).
    Rejected(Rejection),
    /// Access denied it.
    Denied,
    /// Access needs an approval, proof or step-up the user gives on a trusted surface (A-2).
    ActionRequired,
    /// An advisory `check` allow, which is never a go.
    Advisory,
    /// Access gave no decision that allows anything (E-36).
    NoAllow(NoAllow),
}

/// The gate: a permit for `intent` when it was accepted and `decision` allows it.
///
/// # Errors
/// The [`Stop`] that applies; acceptance is checked first.
pub fn gate<T>(intent: Result<T, Rejection>, decision: &Decision) -> Result<Permit<T>, Stop> {
    let intent = intent.map_err(Stop::Rejected)?;
    match decision {
        Decision::Allow {
            exercise: Some(exercise),
            advisory: false,
            ..
        } => Ok(Permit {
            intent,
            exercise: *exercise,
        }),
        Decision::Allow { .. } => Err(Stop::Advisory),
        Decision::Deny { .. } => Err(Stop::Denied),
        Decision::RequireAction { .. } => Err(Stop::ActionRequired),
        Decision::NoAllow(reason) => Err(Stop::NoAllow(reason.clone())),
    }
}

/// The Executor port: it takes only a permit, so nothing reaches it without an Access allow (E-14, CP-7).
pub trait Executor<T> {
    /// Why the Executor did not take the step.
    type Error;

    /// Hands the allowed step to the Executor.
    ///
    /// # Errors
    /// The Executor did not take it; its outcome is unknown until it reports (E-18).
    fn execute(&self, permit: &Permit<T>) -> Result<(), Self::Error>;
}
