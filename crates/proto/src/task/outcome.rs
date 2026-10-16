//! Outcomes and step results: unknown is first class, and stopped, undone or approved exist only with the reference that confirms them (INV-30, CP-6, CP-7, CP-43).

use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::common::{ExecutorEvidence, wire_enum};
use crate::ontology::ClaimRef;
use crate::ontology::DecisionRecordRef;
use crate::ontology::ExecutionReportRef;
use crate::ontology::Instant;
use crate::ontology::WaitpointRef;
use crate::ontology::reference::ref_union;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;

wire_enum!(
    /// What an outcome is about.
    OutcomeSubject {
        /// An execution.
        Execution = "execution",
        /// A stop.
        Stop = "stop",
        /// An effect in the world.
        Effect = "effect",
        /// An undo.
        Undo = "undo",
        /// An approval.
        Approval = "approval",
    }
);

wire_enum!(
    /// Whether an outcome is confirmed.
    Certainty {
        /// Confirmed by a record that can confirm it.
        Confirmed = "confirmed",
        /// Not known.
        Unknown = "unknown",
    }
);

ref_union!(
    /// Evidence of an approval result: an Access decision or a Relay wait result.
    ApprovalEvidence {
        /// An Access decision or approval act.
        Decision(DecisionRecordRef),
        /// A Relay wait result.
        Waitpoint(WaitpointRef),
    }
);

ref_union!(
    /// Any record that can confirm an outcome.
    ConfirmationRef {
        /// An Executor report.
        ExecutionReport(ExecutionReportRef),
        /// An Executor Claim.
        Claim(ClaimRef),
        /// An Access decision.
        Decision(DecisionRecordRef),
        /// A Relay wait result.
        Waitpoint(WaitpointRef),
    }
);

/// A confirmed approval outcome; `Approved` exists only with an Access approval act.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApprovalOutcome {
    /// Approved by the Access approval act.
    Approved(DecisionRecordRef),
    /// Declined.
    Declined(ApprovalEvidence),
    /// Expired without an answer.
    Expired(ApprovalEvidence),
}

/// A confirmed outcome: each value carries the reference kind that can confirm it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfirmedOutcome {
    /// The execution succeeded.
    ExecutionSucceeded(ExecutorEvidence),
    /// The execution failed.
    ExecutionFailed(ExecutorEvidence),
    /// The Executor confirmed the stop.
    Stopped(ExecutionReportRef),
    /// The Executor confirmed it did not stop.
    NotStopped(ExecutionReportRef),
    /// The effect occurred.
    EffectOccurred(ExecutorEvidence),
    /// The effect did not occur.
    EffectNotOccurred(ExecutorEvidence),
    /// The undo took effect.
    Undone(ExecutorEvidence),
    /// The undo did not take effect.
    NotUndone(ExecutorEvidence),
    /// An approval result.
    Approval(ApprovalOutcome),
}

impl ConfirmedOutcome {
    /// What the outcome is about.
    #[must_use]
    pub const fn subject(&self) -> OutcomeSubject {
        match self {
            Self::ExecutionSucceeded(_) | Self::ExecutionFailed(_) => OutcomeSubject::Execution,
            Self::Stopped(_) | Self::NotStopped(_) => OutcomeSubject::Stop,
            Self::EffectOccurred(_) | Self::EffectNotOccurred(_) => OutcomeSubject::Effect,
            Self::Undone(_) | Self::NotUndone(_) => OutcomeSubject::Undo,
            Self::Approval(_) => OutcomeSubject::Approval,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn value(&self) -> &'static str {
        match self {
            Self::ExecutionSucceeded(_) => "succeeded",
            Self::ExecutionFailed(_) => "failed",
            Self::Stopped(_) => "stopped",
            Self::NotStopped(_) => "not_stopped",
            Self::EffectOccurred(_) => "occurred",
            Self::EffectNotOccurred(_) => "not_occurred",
            Self::Undone(_) => "undone",
            Self::NotUndone(_) => "not_undone",
            Self::Approval(ApprovalOutcome::Approved(_)) => "approved",
            Self::Approval(ApprovalOutcome::Declined(_)) => "declined",
            Self::Approval(ApprovalOutcome::Expired(_)) => "expired",
        }
    }

    fn confirmation(&self) -> ConfirmationRef {
        let executor = |e: &ExecutorEvidence| match e {
            ExecutorEvidence::Claim(c) => ConfirmationRef::Claim(c.clone()),
            ExecutorEvidence::ExecutionReport(r) => ConfirmationRef::ExecutionReport(r.clone()),
        };
        let approval = |e: &ApprovalEvidence| match e {
            ApprovalEvidence::Decision(d) => ConfirmationRef::Decision(d.clone()),
            ApprovalEvidence::Waitpoint(w) => ConfirmationRef::Waitpoint(w.clone()),
        };
        match self {
            Self::ExecutionSucceeded(e)
            | Self::ExecutionFailed(e)
            | Self::EffectOccurred(e)
            | Self::EffectNotOccurred(e)
            | Self::Undone(e)
            | Self::NotUndone(e) => executor(e),
            Self::Stopped(r) | Self::NotStopped(r) => ConfirmationRef::ExecutionReport(r.clone()),
            Self::Approval(ApprovalOutcome::Approved(d)) => ConfirmationRef::Decision(d.clone()),
            Self::Approval(ApprovalOutcome::Declined(e) | ApprovalOutcome::Expired(e)) => {
                approval(e)
            }
        }
    }

    fn from_parts(
        subject: OutcomeSubject,
        value: &str,
        confirmation: ConfirmationRef,
    ) -> Result<Self, ContractViolation> {
        let bad = ContractViolation("outcome value or confirmation");
        let executor = |c: ConfirmationRef| match c {
            ConfirmationRef::Claim(r) => Ok(ExecutorEvidence::Claim(r)),
            ConfirmationRef::ExecutionReport(r) => Ok(ExecutorEvidence::ExecutionReport(r)),
            ConfirmationRef::Decision(_) | ConfirmationRef::Waitpoint(_) => Err(bad),
        };
        let report = |c: ConfirmationRef| match c {
            ConfirmationRef::ExecutionReport(r) => Ok(r),
            _ => Err(bad),
        };
        let approval = |c: ConfirmationRef| match c {
            ConfirmationRef::Decision(r) => Ok(ApprovalEvidence::Decision(r)),
            ConfirmationRef::Waitpoint(r) => Ok(ApprovalEvidence::Waitpoint(r)),
            _ => Err(bad),
        };
        Ok(match (subject, value) {
            (OutcomeSubject::Execution, "succeeded") => {
                Self::ExecutionSucceeded(executor(confirmation)?)
            }
            (OutcomeSubject::Execution, "failed") => Self::ExecutionFailed(executor(confirmation)?),
            (OutcomeSubject::Stop, "stopped") => Self::Stopped(report(confirmation)?),
            (OutcomeSubject::Stop, "not_stopped") => Self::NotStopped(report(confirmation)?),
            (OutcomeSubject::Effect, "occurred") => Self::EffectOccurred(executor(confirmation)?),
            (OutcomeSubject::Effect, "not_occurred") => {
                Self::EffectNotOccurred(executor(confirmation)?)
            }
            (OutcomeSubject::Undo, "undone") => Self::Undone(executor(confirmation)?),
            (OutcomeSubject::Undo, "not_undone") => Self::NotUndone(executor(confirmation)?),
            (OutcomeSubject::Approval, "approved") => match confirmation {
                ConfirmationRef::Decision(d) => Self::Approval(ApprovalOutcome::Approved(d)),
                _ => return Err(bad),
            },
            (OutcomeSubject::Approval, "declined") => {
                Self::Approval(ApprovalOutcome::Declined(approval(confirmation)?))
            }
            (OutcomeSubject::Approval, "expired") => {
                Self::Approval(ApprovalOutcome::Expired(approval(confirmation)?))
            }
            _ => return Err(bad),
        })
    }
}

/// The result of an execution, stop, effect, undo or approval (INV-30).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "OutcomeWire", into = "OutcomeWire")]
pub enum Outcome {
    /// Confirmed by a record that can confirm it.
    Confirmed {
        /// The confirmed value with its confirmation.
        outcome: ConfirmedOutcome,
        /// When it was reported.
        reported_at: Option<Instant>,
    },
    /// Not known; carries no value and no confirmation.
    Unknown {
        /// What is unknown.
        subject: OutcomeSubject,
        /// When it was reported.
        reported_at: Option<Instant>,
    },
}

impl Outcome {
    /// What the outcome is about.
    #[must_use]
    pub const fn subject(&self) -> OutcomeSubject {
        match self {
            Self::Confirmed { outcome, .. } => outcome.subject(),
            Self::Unknown { subject, .. } => *subject,
        }
    }

    /// Whether it is confirmed.
    #[must_use]
    pub const fn certainty(&self) -> Certainty {
        match self {
            Self::Confirmed { .. } => Certainty::Confirmed,
            Self::Unknown { .. } => Certainty::Unknown,
        }
    }

    /// The confirmed value, if any.
    #[must_use]
    pub const fn confirmed(&self) -> Option<&ConfirmedOutcome> {
        match self {
            Self::Confirmed { outcome, .. } => Some(outcome),
            Self::Unknown { .. } => None,
        }
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OutcomeWire {
    subject: OutcomeSubject,
    certainty: Certainty,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    confirmation: Option<ConfirmationRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reported_at: Option<Instant>,
}

impl TryFrom<OutcomeWire> for Outcome {
    type Error = ContractViolation;

    fn try_from(wire: OutcomeWire) -> Result<Self, ContractViolation> {
        match wire.certainty {
            Certainty::Unknown => {
                require(
                    wire.value.is_none() && wire.confirmation.is_none(),
                    "unknown outcome has no value or confirmation",
                )?;
                Ok(Self::Unknown {
                    subject: wire.subject,
                    reported_at: wire.reported_at,
                })
            }
            Certainty::Confirmed => {
                let value = wire
                    .value
                    .ok_or(ContractViolation("confirmed outcome needs a value"))?;
                let confirmation = wire
                    .confirmation
                    .ok_or(ContractViolation("confirmed outcome needs a confirmation"))?;
                Ok(Self::Confirmed {
                    outcome: ConfirmedOutcome::from_parts(wire.subject, &value, confirmation)?,
                    reported_at: wire.reported_at,
                })
            }
        }
    }
}

impl From<Outcome> for OutcomeWire {
    fn from(outcome: Outcome) -> Self {
        match outcome {
            Outcome::Confirmed {
                outcome,
                reported_at,
            } => Self {
                subject: outcome.subject(),
                certainty: Certainty::Confirmed,
                value: Some(String::from(outcome.value())),
                confirmation: Some(outcome.confirmation()),
                reported_at,
            },
            Outcome::Unknown {
                subject,
                reported_at,
            } => Self {
                subject,
                certainty: Certainty::Unknown,
                value: None,
                confirmation: None,
                reported_at,
            },
        }
    }
}

wire_enum!(
    /// The status of one plan step, shown separately to the user (CP-6).
    StepStatus {
        /// Done.
        Done = "done",
        /// Failed.
        Failed = "failed",
        /// Not run.
        NotRun = "not_run",
        /// Unknown.
        Unknown = "unknown",
    }
);

wire_enum!(
    /// Why a step failed or did not run.
    StepReason {
        /// The input did not validate.
        SchemaRejected = "schema_rejected",
        /// Access denied it.
        AccessDenied = "access_denied",
        /// The provider failed.
        ProviderError = "provider_error",
        /// The site blocked it.
        BlockedBySite = "blocked_by_site",
        /// The site's terms forbid agents.
        TermsForbidAgents = "terms_forbid_agents",
        /// A wait expired.
        WaitExpired = "wait_expired",
        /// The budget ran out.
        BudgetExhausted = "budget_exhausted",
        /// Authority was revoked.
        AuthorityRevoked = "authority_revoked",
        /// An earlier step failed.
        EarlierStepFailed = "earlier_step_failed",
        /// An earlier step's outcome is unknown.
        EarlierStepUnknown = "earlier_step_unknown",
        /// A crash left the outcome unverified.
        CrashUnverified = "crash_unverified",
        /// The task was cancelled.
        Cancelled = "cancelled",
    }
);

impl StepReason {
    const fn allowed_for_failed(self) -> bool {
        !matches!(
            self,
            Self::EarlierStepFailed | Self::EarlierStepUnknown | Self::CrashUnverified
        )
    }

    const fn allowed_for_not_run(self) -> bool {
        matches!(
            self,
            Self::EarlierStepFailed
                | Self::EarlierStepUnknown
                | Self::AuthorityRevoked
                | Self::BudgetExhausted
                | Self::Cancelled
                | Self::AccessDenied
                | Self::SchemaRejected
        )
    }
}

/// The result of one plan step: done, failed, not run or unknown (CP-6).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "StepResultWire", into = "StepResultWire")]
pub struct StepResult {
    status: StepStatus,
    outcome: Option<Outcome>,
    reason: Option<StepReason>,
}

fn executes(outcome: &Outcome) -> bool {
    matches!(
        outcome.subject(),
        OutcomeSubject::Execution | OutcomeSubject::Effect
    )
}

impl StepResult {
    /// A done step: a confirmed successful execution or an occurred effect.
    ///
    /// # Errors
    /// Rejects any other outcome.
    pub fn done(outcome: Outcome) -> Result<Self, ContractViolation> {
        require(
            matches!(
                outcome.confirmed(),
                Some(ConfirmedOutcome::ExecutionSucceeded(_) | ConfirmedOutcome::EffectOccurred(_))
            ),
            "done needs a confirmed success",
        )?;
        Ok(Self {
            status: StepStatus::Done,
            outcome: Some(outcome),
            reason: None,
        })
    }

    /// A failed step: a confirmed failure and its own reason.
    ///
    /// # Errors
    /// Rejects any other outcome or a reason that names an earlier step or a crash.
    pub fn failed(outcome: Outcome, reason: StepReason) -> Result<Self, ContractViolation> {
        require(
            matches!(
                outcome.confirmed(),
                Some(ConfirmedOutcome::ExecutionFailed(_) | ConfirmedOutcome::EffectNotOccurred(_))
            ),
            "failed needs a confirmed failure",
        )?;
        require(reason.allowed_for_failed(), "failed reason")?;
        Ok(Self {
            status: StepStatus::Failed,
            outcome: Some(outcome),
            reason: Some(reason),
        })
    }

    /// A step that did not run.
    ///
    /// # Errors
    /// Rejects a reason that cannot explain a step that never ran.
    pub fn not_run(reason: StepReason) -> Result<Self, ContractViolation> {
        require(reason.allowed_for_not_run(), "not run reason")?;
        Ok(Self {
            status: StepStatus::NotRun,
            outcome: None,
            reason: Some(reason),
        })
    }

    /// A step whose outcome is unknown.
    ///
    /// # Errors
    /// Rejects a confirmed outcome or one about a stop, undo or approval.
    pub fn unknown(
        outcome: Outcome,
        reason: Option<StepReason>,
    ) -> Result<Self, ContractViolation> {
        require(
            outcome.certainty() == Certainty::Unknown && executes(&outcome),
            "unknown needs an unknown execution or effect",
        )?;
        Ok(Self {
            status: StepStatus::Unknown,
            outcome: Some(outcome),
            reason,
        })
    }

    /// The status.
    #[must_use]
    pub const fn status(&self) -> StepStatus {
        self.status
    }

    /// The outcome.
    #[must_use]
    pub const fn outcome(&self) -> Option<&Outcome> {
        self.outcome.as_ref()
    }

    /// The reason.
    #[must_use]
    pub const fn reason(&self) -> Option<StepReason> {
        self.reason
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StepResultWire {
    status: StepStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<StepReason>,
}

impl TryFrom<StepResultWire> for StepResult {
    type Error = ContractViolation;

    fn try_from(wire: StepResultWire) -> Result<Self, ContractViolation> {
        let missing = ContractViolation("step result outcome or reason");
        match wire.status {
            StepStatus::Done => {
                require(wire.reason.is_none(), "done carries no reason")?;
                Self::done(wire.outcome.ok_or(missing)?)
            }
            StepStatus::Failed => {
                Self::failed(wire.outcome.ok_or(missing)?, wire.reason.ok_or(missing)?)
            }
            StepStatus::NotRun => {
                require(wire.outcome.is_none(), "not run carries no outcome")?;
                Self::not_run(wire.reason.ok_or(missing)?)
            }
            StepStatus::Unknown => Self::unknown(wire.outcome.ok_or(missing)?, wire.reason),
        }
    }
}

impl From<StepResult> for StepResultWire {
    fn from(result: StepResult) -> Self {
        Self {
            status: result.status,
            outcome: result.outcome,
            reason: result.reason,
        }
    }
}
