//! Sub-agent authority (CP-46, CP-47): the world sees one One, while every sub-agent is its own Access `AgentInstance` whose authority only narrows One's: its capabilities are a subset of One's, its step and amount budgets are no larger, and a sub-agent can never grant itself anything; a user who steers a sub-agent narrows it the same way and cannot lift it past One.

use core::cmp::Ordering;
use core::num::NonZeroU32;
use std::collections::BTreeSet;

use one_proto::capability::CapabilityName;
use one_proto::money::Money;

/// An authority scope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    /// The capabilities it may use.
    pub capabilities: BTreeSet<CapabilityName>,
    /// Its step budget.
    pub steps: NonZeroU32,
    /// Its amount budget, if it may spend.
    pub amount: Option<Money>,
}

/// Who asks for the scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Asker {
    /// One, for a sub-agent it starts.
    One,
    /// The user, steering a sub-agent.
    User,
    /// The sub-agent itself.
    SubAgent,
}

/// Why a scope is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A sub-agent asked for authority for itself.
    SelfGrant,
    /// It names a capability One does not hold.
    Capability,
    /// Its step budget is larger than One's.
    Steps,
    /// It may spend more than One, in another currency, or where One may not spend at all.
    Amount,
}

/// The sub-agent's scope when `asked` fits inside `parent`.
///
/// # Errors
/// [`Refused`] with the first part that does not fit.
pub fn narrow(parent: &Scope, asked: Scope, by: Asker) -> Result<Scope, Refused> {
    if by == Asker::SubAgent {
        return Err(Refused::SelfGrant);
    }
    if !asked.capabilities.is_subset(&parent.capabilities) {
        return Err(Refused::Capability);
    }
    if asked.steps > parent.steps {
        return Err(Refused::Steps);
    }
    match (&parent.amount, &asked.amount) {
        (_, None) => {}
        (None, Some(_)) => return Err(Refused::Amount),
        (Some(p), Some(a)) => match a.compare(p) {
            Some(Ordering::Less | Ordering::Equal) => {}
            _ => return Err(Refused::Amount),
        },
    }
    Ok(asked)
}
