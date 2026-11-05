//! Handing a step to the Executor (CP-5, CP-9, CP-10, CP-12, CP-36, E-14): [`prepare`] decides, before any Access request, whether the step can go at all (connected, budget left, a path, the user present when the path needs them) and which route it takes; [`submit`] then runs the gate for the intent built on that route and its Access decision, and only the gate's permit reaches the Executor port.

use core::num::NonZeroU32;

use one_access_client::decision::Decision;
use one_proto::task::{Route, RoutePath};
use one_provenance::intent::Rejection;

use crate::domain::budget::{Spend, next};
use crate::domain::gate::{Stop, gate};
use crate::domain::path::{Choice, Handoff, Offer, Site, Situation, choose};
use crate::ports::Executor;

/// Where the step stands before its Access request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Before<'a> {
    /// One reaches Access; offline, no effect happens (CP-10).
    pub online: bool,
    /// Steps already taken.
    pub used: u32,
    /// The task's step budget.
    pub budget: NonZeroU32,
    /// The capability's offers.
    pub offers: &'a [Offer],
    /// The site of a browser offer.
    pub site: Site,
    /// The user's platform, session need and presence.
    pub situation: Situation,
}

/// What [`prepare`] found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Prepared {
    /// Offline: the command stays a pending task and asks Access in order once connected (CP-10).
    Held,
    /// The step budget is spent: the task stops and asks the user (CP-36).
    BudgetSpent,
    /// The step needs the user's session and the user is away: the task waits as `waiting_user` (CP-9).
    WaitForUser {
        /// The offer.
        offer: usize,
        /// Its path.
        path: RoutePath,
    },
    /// The user does it (CP-12, CP-14).
    Handoff {
        /// Why.
        why: Handoff,
        /// The route written to the step.
        route: Route,
    },
    /// Ask Access for the intent built on this route.
    Ready {
        /// The offer.
        offer: usize,
        /// The route written to the step.
        route: Route,
    },
}

/// Prepares a step in `before`.
///
/// # Errors
/// [`one_proto::ontology::validate::ContractViolation`] only if a fixed route reason broke its contract.
pub fn prepare(
    before: &Before<'_>,
) -> Result<Prepared, one_proto::ontology::validate::ContractViolation> {
    if !before.online {
        return Ok(Prepared::Held);
    }
    if next(before.used, before.budget) == Spend::AskUser {
        return Ok(Prepared::BudgetSpent);
    }
    Ok(
        match choose(before.offers, before.site, before.situation)? {
            Choice::Run { offer, route } => Prepared::Ready { offer, route },
            Choice::WaitForUser { offer, path } => Prepared::WaitForUser { offer, path },
            Choice::Handoff { why, route } => Prepared::Handoff { why, route },
        },
    )
}

/// Why a step was not handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submit<E> {
    /// The gate stopped it.
    Stopped(Stop),
    /// The Executor did not take it.
    Executor(E),
}

/// Runs the gate for `intent` and `decision`, and hands an allowed step to `executor`.
///
/// # Errors
/// [`Submit::Stopped`] with the gate's reason, or [`Submit::Executor`].
pub fn submit<T, X: Executor<T>>(
    executor: &X,
    intent: Result<T, Rejection>,
    decision: &Decision,
) -> Result<(), Submit<X::Error>> {
    let permit = gate(intent, decision).map_err(Submit::Stopped)?;
    executor.execute(&permit).map_err(Submit::Executor)
}
