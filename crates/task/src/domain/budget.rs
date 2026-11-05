//! The step budget of a browser or computer agent (CP-36, CP-4): a task asks for [`DEFAULT_STEPS`] unless it asks for fewer, the Mandate's budget wins when it is narrower, and when the budget is spent the task stops and asks the user instead of taking another step.

use core::num::NonZeroU32;

use one_proto::task::{BudgetRejection, effective_steps};

/// The steps a task asks for when nothing narrower applies.
pub const DEFAULT_STEPS: NonZeroU32 = NonZeroU32::MIN.saturating_add(49);

/// What the next step may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Spend {
    /// Take the step; `left` steps remain after it.
    Go {
        /// The steps left after this one.
        left: u32,
    },
    /// The budget is spent: stop and ask the user.
    AskUser,
}

/// The budget a task runs with: the narrower of the Mandate's budget and its request, which defaults to [`DEFAULT_STEPS`].
///
/// # Errors
/// Never in practice, since the request is always set; kept for [`effective_steps`].
pub fn budget(
    mandate: Option<NonZeroU32>,
    requested: Option<NonZeroU32>,
) -> Result<NonZeroU32, BudgetRejection> {
    effective_steps(mandate, Some(requested.unwrap_or(DEFAULT_STEPS)))
}

/// Whether a step may be taken after `used` steps under `budget`.
#[must_use]
pub const fn next(used: u32, budget: NonZeroU32) -> Spend {
    match budget.get().checked_sub(used) {
        Some(room) if room > 0 => Spend::Go {
            left: room.saturating_sub(1),
        },
        _ => Spend::AskUser,
    }
}
