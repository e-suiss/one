//! Batch semantics: stop at the first failed or unknown step, the rest are not run, a continuation is a new decision (CP-6) and the effective budget is the narrower of Mandate and request (CP-4, CP-36).

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::num::NonZeroU32;

use super::outcome::{StepReason, StepStatus};
use super::record::StepId;
use crate::money::Money;

/// What the Executor reported for a batch step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reported {
    /// Done.
    Done,
    /// Failed.
    Failed,
    /// Unknown.
    Unknown,
}

/// One batch step as shown to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BatchEntry {
    /// The step.
    pub step: StepId,
    /// Its status.
    pub status: StepStatus,
    /// Why it did not run.
    pub reason: Option<StepReason>,
}

/// A report that breaks the batch rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BatchRejection {
    /// A step reported after the batch stopped.
    RanAfterHalt(StepId),
    /// A step that is not in the batch.
    NotInBatch(StepId),
}

/// Lays out a batch: reported steps keep their status up to the first failed or unknown one, every later step is not run; unreported steps before it are still open and left out.
///
/// # Errors
/// Rejects a step reported after the halt or one outside the batch.
pub fn batch(
    order: &[StepId],
    reported: &[(StepId, Reported)],
) -> Result<Vec<BatchEntry>, BatchRejection> {
    if let Some((step, _)) = reported.iter().find(|(s, _)| !order.contains(s)) {
        return Err(BatchRejection::NotInBatch(step.clone()));
    }
    let mut out = Vec::new();
    let mut halt: Option<StepReason> = None;
    for step in order {
        let report = reported.iter().find(|(s, _)| s == step).map(|(_, r)| *r);
        if let Some(reason) = halt {
            if report.is_some() {
                return Err(BatchRejection::RanAfterHalt(step.clone()));
            }
            out.push(BatchEntry {
                step: step.clone(),
                status: StepStatus::NotRun,
                reason: Some(reason),
            });
            continue;
        }
        let status = match report {
            None => continue,
            Some(Reported::Done) => StepStatus::Done,
            Some(Reported::Failed) => {
                halt = Some(StepReason::EarlierStepFailed);
                StepStatus::Failed
            }
            Some(Reported::Unknown) => {
                halt = Some(StepReason::EarlierStepUnknown);
                StepStatus::Unknown
            }
        };
        out.push(BatchEntry {
            step: step.clone(),
            status,
            reason: None,
        });
    }
    Ok(out)
}

/// Why no effective budget exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudgetRejection {
    /// Neither the Mandate nor the request sets a budget: the task cannot start.
    NoBudget,
    /// The amounts are in different currencies.
    CurrencyMismatch,
}

/// The effective step budget: the narrower of the Mandate's and the request's.
///
/// # Errors
/// Returns [`BudgetRejection::NoBudget`] when neither is set.
pub fn effective_steps(
    mandate: Option<NonZeroU32>,
    requested: Option<NonZeroU32>,
) -> Result<NonZeroU32, BudgetRejection> {
    match (mandate, requested) {
        (Some(m), Some(r)) => Ok(m.min(r)),
        (Some(one), None) | (None, Some(one)) => Ok(one),
        (None, None) => Err(BudgetRejection::NoBudget),
    }
}

/// The effective amount budget: the narrower of the Mandate's and the request's.
///
/// # Errors
/// Rejects a missing budget or two currencies.
pub fn effective_amount(
    mandate: Option<&Money>,
    requested: Option<&Money>,
) -> Result<Money, BudgetRejection> {
    match (mandate, requested) {
        (Some(m), Some(r)) => match m.compare(r) {
            None => Err(BudgetRejection::CurrencyMismatch),
            Some(Ordering::Greater) => Ok(r.clone()),
            Some(_) => Ok(m.clone()),
        },
        (Some(one), None) | (None, Some(one)) => Ok(one.clone()),
        (None, None) => Err(BudgetRejection::NoBudget),
    }
}
