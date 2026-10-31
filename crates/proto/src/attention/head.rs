//! The decision head route: the calibrated probability against two adjustable thresholds, the cloud estimate between them, hard constraints to the digest, and the user's critical Grant above every constraint including mute (AT-1, AT-2, AT-8, AT-9, AT-10, AT-12).

use super::record::{Arm, Probability, Thresholds};
use crate::interaction_types::Interruption;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;

/// What the decision head decided for a candidate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Route {
    /// Notify through Relay.
    Notify,
    /// Do not notify.
    NoNotification,
    /// Ask the cloud for a value estimate (AT-2).
    CloudEstimate,
}

/// The inputs of one decision.
#[derive(Clone, Copy, Debug, PartialEq)]
#[allow(clippy::struct_excessive_bools, reason = "mirrors the contract")]
pub struct HeadInput {
    /// The calibrated value probability.
    pub value_probability: Probability,
    /// The person's and channel's thresholds.
    pub thresholds: Thresholds,
    /// The output needs action now.
    pub urgent: bool,
    /// The cloud value estimate is reachable.
    pub cloud_available: bool,
    /// The user muted the output type.
    pub type_muted: bool,
    /// The remaining daily budget.
    pub budget_remaining: u8,
    /// The user's critical Grant covers the output.
    pub critical_grant: bool,
}

/// The decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeadDecision {
    /// The route.
    pub route: Route,
    /// The arm when the route fixes one; the learned policy chooses otherwise.
    pub chosen_arm: Option<Arm>,
    /// `critical` when the user's Grant decided.
    pub interruption: Option<Interruption>,
}

impl Thresholds {
    /// Checks `lower ≤ upper`.
    ///
    /// # Errors
    /// Rejects crossed thresholds.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require(self.lower.get() <= self.upper.get(), "lower above upper")
    }
}

const fn fixed(route: Route, arm: Option<Arm>) -> HeadDecision {
    HeadDecision {
        route,
        chosen_arm: arm,
        interruption: None,
    }
}

/// Routes a candidate (AT-1).
///
/// # Errors
/// Rejects crossed thresholds.
pub fn decide(input: &HeadInput) -> Result<HeadDecision, ContractViolation> {
    input.thresholds.validate()?;
    if input.critical_grant {
        return Ok(HeadDecision {
            route: Route::Notify,
            chosen_arm: Some(Arm::InterruptNow),
            interruption: Some(Interruption::Critical),
        });
    }
    if input.type_muted || input.budget_remaining == 0 {
        return Ok(fixed(Route::NoNotification, Some(Arm::Digest)));
    }
    let p = input.value_probability.get();
    Ok(if p >= input.thresholds.upper.get() {
        let arm = if input.urgent {
            Arm::InterruptNow
        } else {
            Arm::NextBreak
        };
        fixed(Route::Notify, Some(arm))
    } else if p < input.thresholds.lower.get() {
        fixed(Route::NoNotification, None)
    } else if input.cloud_available {
        fixed(Route::CloudEstimate, None)
    } else {
        fixed(Route::NoNotification, Some(Arm::Digest))
    })
}
