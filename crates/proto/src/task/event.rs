//! Task events: one entry of a task's history, each kind with the only source that may write it (CP-3, CP-11, CP-42, CP-44, INV-30).

use alloc::string::String;
use core::num::{NonZeroU32, NonZeroU64};

use serde::{Deserialize, Serialize};

use super::common::{ExecutorEvidence, wire_enum};
use super::outcome::{Certainty, Outcome, StepResult};
use super::record::StepId;
use crate::id::TaskId;
use crate::ontology::CheckpointRef;
use crate::ontology::DecisionRecordRef;
use crate::ontology::ExecutionReportRef;
use crate::ontology::ExerciseRef;
use crate::ontology::Instant;
use crate::ontology::WaitpointRef;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;

wire_enum!(
    /// Who wrote an event.
    EventSource {
        /// The user.
        User = "user",
        /// One.
        One = "one",
        /// The Executor.
        Executor = "executor",
        /// Access.
        Access = "access",
        /// Relay.
        Relay = "relay",
    }
);

wire_enum!(
    /// The event alphabet of the task state machine.
    EventKind {
        /// The task was created.
        TaskCreated = "task_created",
        /// A step started.
        StepStarted = "step_started",
        /// A step finished.
        StepFinished = "step_finished",
        /// A late report turned an unknown outcome into a confirmed one.
        StepOutcomeReported = "step_outcome_reported",
        /// A Relay waitpoint opened.
        WaitOpened = "wait_opened",
        /// The open waitpoint was answered.
        WaitResolved = "wait_resolved",
        /// The open waitpoint expired.
        WaitExpired = "wait_expired",
        /// A pause was requested.
        PauseRequested = "pause_requested",
        /// The Executor confirmed the pause.
        PauseConfirmed = "pause_confirmed",
        /// The task resumed.
        Resumed = "resumed",
        /// The Executor recorded a checkpoint.
        CheckpointRecorded = "checkpoint_recorded",
        /// The completion criterion was verified.
        CompletionVerified = "completion_verified",
        /// The task failed.
        TaskFailed = "task_failed",
        /// The task was cancelled.
        TaskCancelled = "task_cancelled",
    }
);

wire_enum!(
    /// Who a wait is for.
    WaitKind {
        /// The user.
        User = "user",
        /// An external event.
        External = "external",
    }
);

wire_enum!(
    /// Why a task waits.
    WaitReason {
        /// The user's approval.
        Approval = "approval",
        /// The user's input.
        Input = "input",
        /// The user's takeover.
        Takeover = "takeover",
        /// The user's authentication.
        Authentication = "authentication",
        /// A peer One's reply.
        PeerReply = "peer_reply",
        /// A price threshold.
        PriceThreshold = "price_threshold",
        /// A site.
        Site = "site",
        /// A trigger event.
        TriggerEvent = "trigger_event",
        /// The user is absent for a session-bound step.
        UserAbsent = "user_absent",
    }
);

impl WaitReason {
    /// Who the reason waits for.
    #[must_use]
    pub const fn kind(self) -> WaitKind {
        match self {
            Self::Approval
            | Self::Input
            | Self::Takeover
            | Self::Authentication
            | Self::UserAbsent => WaitKind::User,
            Self::PeerReply | Self::PriceThreshold | Self::Site | Self::TriggerEvent => {
                WaitKind::External
            }
        }
    }
}

wire_enum!(
    /// Why a task failed.
    FailureReason {
        /// The completion criterion cannot be reached.
        CriterionUnreachable = "criterion_unreachable",
        /// A step failed.
        StepFailed = "step_failed",
        /// A step's outcome is unknown.
        StepUnknown = "step_unknown",
        /// The budget ran out.
        BudgetExhausted = "budget_exhausted",
        /// The site blocked it.
        BlockedBySite = "blocked_by_site",
        /// The site's terms forbid agents.
        TermsForbidAgents = "terms_forbid_agents",
    }
);

wire_enum!(
    /// Who cancelled.
    CancelCause {
        /// The user gave up; written by the user.
        User = "user",
        /// Authority was removed; written by Access.
        AuthorityRevoked = "authority_revoked",
    }
);

wire_enum!(
    /// Who created the task.
    CreatedBy {
        /// One.
        One = "one",
        /// The user.
        User = "user",
    }
);

wire_enum!(
    /// Who requested a pause.
    PauseRequestedBy {
        /// The user.
        User = "user",
        /// One.
        One = "one",
    }
);

wire_enum!(
    /// Who declared the task failed.
    FailedBy {
        /// One.
        One = "one",
        /// The Executor.
        Executor = "executor",
    }
);

/// The Access decision and Exercise an effectful step starts under.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StepAuthority {
    /// The decision.
    pub decision_ref: Option<DecisionRecordRef>,
    /// The Exercise.
    pub exercise_ref: Option<ExerciseRef>,
}

/// What happened, with the fields its kind carries; the source is implied where only one may write it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventBody {
    /// The task was created.
    TaskCreated {
        /// Who created it.
        source: CreatedBy,
        /// The plan version.
        plan_version: NonZeroU32,
    },
    /// The Executor started a step; an effectful step carries both references.
    StepStarted {
        /// The step.
        step_id: StepId,
        /// Whether the step changes the world.
        effectful: bool,
        /// The Access references.
        authority: StepAuthority,
    },
    /// The Executor finished a step.
    StepFinished {
        /// The step.
        step_id: StepId,
        /// Its result.
        result: StepResult,
    },
    /// A late confirmed outcome from the Executor.
    StepOutcomeReported {
        /// The step.
        step_id: StepId,
        /// The confirmed outcome.
        outcome: Outcome,
    },
    /// One opened a Relay waitpoint.
    WaitOpened {
        /// The waitpoint.
        waitpoint_ref: WaitpointRef,
        /// Why; the reason fixes who the wait is for.
        reason: WaitReason,
    },
    /// Relay resolved the waitpoint with a continuation decision.
    WaitResolved {
        /// The waitpoint.
        waitpoint_ref: WaitpointRef,
        /// The continuation decision.
        continuation_ref: DecisionRecordRef,
    },
    /// Relay expired the waitpoint.
    WaitExpired {
        /// The waitpoint.
        waitpoint_ref: WaitpointRef,
    },
    /// A pause was requested.
    PauseRequested {
        /// Who asked.
        source: PauseRequestedBy,
    },
    /// The Executor confirmed the pause.
    PauseConfirmed {
        /// The Executor report.
        execution_report_ref: ExecutionReportRef,
    },
    /// One resumed with a continuation decision.
    Resumed {
        /// The continuation decision.
        continuation_ref: DecisionRecordRef,
    },
    /// The Executor recorded a checkpoint.
    CheckpointRecorded {
        /// The checkpoint.
        checkpoint_ref: CheckpointRef,
    },
    /// One verified completion.
    CompletionVerified {
        /// The evidence.
        evidence_ref: ExecutorEvidence,
    },
    /// The task failed.
    TaskFailed {
        /// Who declared it.
        source: FailedBy,
        /// Why.
        reason: FailureReason,
    },
    /// The task was cancelled; the cause fixes the source.
    TaskCancelled {
        /// Why.
        cause: CancelCause,
    },
}

impl EventBody {
    /// The event kind.
    #[must_use]
    pub const fn kind(&self) -> EventKind {
        match self {
            Self::TaskCreated { .. } => EventKind::TaskCreated,
            Self::StepStarted { .. } => EventKind::StepStarted,
            Self::StepFinished { .. } => EventKind::StepFinished,
            Self::StepOutcomeReported { .. } => EventKind::StepOutcomeReported,
            Self::WaitOpened { .. } => EventKind::WaitOpened,
            Self::WaitResolved { .. } => EventKind::WaitResolved,
            Self::WaitExpired { .. } => EventKind::WaitExpired,
            Self::PauseRequested { .. } => EventKind::PauseRequested,
            Self::PauseConfirmed { .. } => EventKind::PauseConfirmed,
            Self::Resumed { .. } => EventKind::Resumed,
            Self::CheckpointRecorded { .. } => EventKind::CheckpointRecorded,
            Self::CompletionVerified { .. } => EventKind::CompletionVerified,
            Self::TaskFailed { .. } => EventKind::TaskFailed,
            Self::TaskCancelled { .. } => EventKind::TaskCancelled,
        }
    }

    /// Who wrote the event.
    #[must_use]
    pub const fn source(&self) -> EventSource {
        match self {
            Self::TaskCreated {
                source: CreatedBy::One,
                ..
            }
            | Self::PauseRequested {
                source: PauseRequestedBy::One,
            }
            | Self::TaskFailed {
                source: FailedBy::One,
                ..
            }
            | Self::WaitOpened { .. }
            | Self::Resumed { .. }
            | Self::CompletionVerified { .. } => EventSource::One,
            Self::TaskCreated {
                source: CreatedBy::User,
                ..
            }
            | Self::PauseRequested {
                source: PauseRequestedBy::User,
            }
            | Self::TaskCancelled {
                cause: CancelCause::User,
            } => EventSource::User,
            Self::StepStarted { .. }
            | Self::StepFinished { .. }
            | Self::StepOutcomeReported { .. }
            | Self::PauseConfirmed { .. }
            | Self::CheckpointRecorded { .. }
            | Self::TaskFailed {
                source: FailedBy::Executor,
                ..
            } => EventSource::Executor,
            Self::TaskCancelled {
                cause: CancelCause::AuthorityRevoked,
            } => EventSource::Access,
            Self::WaitResolved { .. } | Self::WaitExpired { .. } => EventSource::Relay,
        }
    }
}

/// One entry of a task's event history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "EventWire", into = "EventWire")]
pub struct TaskEvent {
    /// The task.
    pub task_id: TaskId,
    /// The position in the history, from 1.
    pub seq: NonZeroU64,
    /// When it happened.
    pub at: Instant,
    /// What happened.
    pub body: EventBody,
}

#[derive(Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EventWire {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task_id: Option<TaskId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    seq: Option<NonZeroU64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    at: Option<Instant>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    source: Option<EventSource>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kind: Option<EventKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    plan_version: Option<NonZeroU32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    step_id: Option<StepId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    effectful: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision_ref: Option<DecisionRecordRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    exercise_ref: Option<ExerciseRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    result: Option<StepResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    wait: Option<WaitKind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    waitpoint_ref: Option<WaitpointRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    continuation_ref: Option<DecisionRecordRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    execution_report_ref: Option<ExecutionReportRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint_ref: Option<CheckpointRef>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    evidence_ref: Option<ExecutorEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cause: Option<CancelCause>,
}

impl EventWire {
    const fn extra_fields(&self) -> [bool; 15] {
        [
            self.plan_version.is_some(),
            self.step_id.is_some(),
            self.effectful.is_some(),
            self.decision_ref.is_some(),
            self.exercise_ref.is_some(),
            self.result.is_some(),
            self.outcome.is_some(),
            self.wait.is_some(),
            self.waitpoint_ref.is_some(),
            self.reason.is_some(),
            self.continuation_ref.is_some(),
            self.execution_report_ref.is_some(),
            self.checkpoint_ref.is_some(),
            self.evidence_ref.is_some(),
            self.cause.is_some(),
        ]
    }
}

const PLAN_VERSION: usize = 0;
const STEP_ID: usize = 1;
const EFFECTFUL: usize = 2;
const DECISION: usize = 3;
const EXERCISE: usize = 4;
const RESULT: usize = 5;
const OUTCOME: usize = 6;
const WAIT: usize = 7;
const WAITPOINT: usize = 8;
const REASON: usize = 9;
const CONTINUATION: usize = 10;
const REPORT: usize = 11;
const CHECKPOINT: usize = 12;
const EVIDENCE: usize = 13;
const CAUSE: usize = 14;

const fn allowed(kind: EventKind) -> &'static [usize] {
    match kind {
        EventKind::TaskCreated => &[PLAN_VERSION],
        EventKind::StepStarted => &[STEP_ID, EFFECTFUL, DECISION, EXERCISE],
        EventKind::StepFinished => &[STEP_ID, RESULT],
        EventKind::StepOutcomeReported => &[STEP_ID, OUTCOME],
        EventKind::WaitOpened => &[WAIT, WAITPOINT, REASON],
        EventKind::WaitResolved => &[WAITPOINT, CONTINUATION],
        EventKind::WaitExpired => &[WAITPOINT],
        EventKind::PauseRequested => &[],
        EventKind::PauseConfirmed => &[REPORT],
        EventKind::Resumed => &[CONTINUATION],
        EventKind::CheckpointRecorded => &[CHECKPOINT],
        EventKind::CompletionVerified => &[EVIDENCE],
        EventKind::TaskFailed => &[REASON],
        EventKind::TaskCancelled => &[CAUSE],
    }
}

fn source_is(wire: &EventWire, source: EventSource) -> Result<(), ContractViolation> {
    require(wire.source == Some(source), "event source")
}

fn need<T>(field: Option<T>) -> Result<T, ContractViolation> {
    field.ok_or(ContractViolation("event field"))
}

const fn created_by(source: EventSource) -> Result<CreatedBy, ContractViolation> {
    match source {
        EventSource::One => Ok(CreatedBy::One),
        EventSource::User => Ok(CreatedBy::User),
        _ => Err(ContractViolation("event source")),
    }
}

const fn pause_requested_by(source: EventSource) -> Result<PauseRequestedBy, ContractViolation> {
    match source {
        EventSource::User => Ok(PauseRequestedBy::User),
        EventSource::One => Ok(PauseRequestedBy::One),
        _ => Err(ContractViolation("event source")),
    }
}

const fn failed_by(source: EventSource) -> Result<FailedBy, ContractViolation> {
    match source {
        EventSource::One => Ok(FailedBy::One),
        EventSource::Executor => Ok(FailedBy::Executor),
        _ => Err(ContractViolation("event source")),
    }
}

fn step_body(kind: EventKind, wire: EventWire) -> Result<EventBody, ContractViolation> {
    Ok(match kind {
        EventKind::StepStarted => {
            source_is(&wire, EventSource::Executor)?;
            let effectful = need(wire.effectful)?;
            if effectful {
                require(
                    wire.decision_ref.is_some() && wire.exercise_ref.is_some(),
                    "effectful step starts under an Access decision and Exercise",
                )?;
            }
            EventBody::StepStarted {
                step_id: need(wire.step_id)?,
                effectful,
                authority: StepAuthority {
                    decision_ref: wire.decision_ref,
                    exercise_ref: wire.exercise_ref,
                },
            }
        }
        EventKind::StepFinished => {
            source_is(&wire, EventSource::Executor)?;
            EventBody::StepFinished {
                step_id: need(wire.step_id)?,
                result: need(wire.result)?,
            }
        }
        EventKind::StepOutcomeReported => {
            source_is(&wire, EventSource::Executor)?;
            let outcome = need(wire.outcome)?;
            require(
                outcome.certainty() == Certainty::Confirmed,
                "late report is confirmed",
            )?;
            EventBody::StepOutcomeReported {
                step_id: need(wire.step_id)?,
                outcome,
            }
        }
        _ => return Err(ContractViolation("event kind")),
    })
}

fn body_of(wire: EventWire) -> Result<EventBody, ContractViolation> {
    let kind = need(wire.kind)?;
    let present = wire.extra_fields();
    let permitted = allowed(kind);
    require(
        present
            .iter()
            .enumerate()
            .all(|(i, p)| !*p || permitted.contains(&i)),
        "field not allowed for this event kind",
    )?;
    let source = need(wire.source)?;
    let body = match kind {
        EventKind::TaskCreated => EventBody::TaskCreated {
            source: created_by(source)?,
            plan_version: need(wire.plan_version)?,
        },
        EventKind::StepStarted | EventKind::StepFinished | EventKind::StepOutcomeReported => {
            step_body(kind, wire)?
        }
        EventKind::WaitOpened => {
            source_is(&wire, EventSource::One)?;
            let reason = WaitReason::from_wire(&need(wire.reason)?)
                .ok_or(ContractViolation("wait reason"))?;
            require(
                Some(reason.kind()) == wire.wait,
                "wait reason matches wait kind",
            )?;
            EventBody::WaitOpened {
                waitpoint_ref: need(wire.waitpoint_ref)?,
                reason,
            }
        }
        EventKind::WaitResolved => {
            source_is(&wire, EventSource::Relay)?;
            EventBody::WaitResolved {
                waitpoint_ref: need(wire.waitpoint_ref)?,
                continuation_ref: need(wire.continuation_ref)?,
            }
        }
        EventKind::WaitExpired => {
            source_is(&wire, EventSource::Relay)?;
            EventBody::WaitExpired {
                waitpoint_ref: need(wire.waitpoint_ref)?,
            }
        }
        EventKind::PauseRequested => EventBody::PauseRequested {
            source: pause_requested_by(source)?,
        },
        EventKind::PauseConfirmed => {
            source_is(&wire, EventSource::Executor)?;
            EventBody::PauseConfirmed {
                execution_report_ref: need(wire.execution_report_ref)?,
            }
        }
        EventKind::Resumed => {
            source_is(&wire, EventSource::One)?;
            EventBody::Resumed {
                continuation_ref: need(wire.continuation_ref)?,
            }
        }
        EventKind::CheckpointRecorded => {
            source_is(&wire, EventSource::Executor)?;
            EventBody::CheckpointRecorded {
                checkpoint_ref: need(wire.checkpoint_ref)?,
            }
        }
        EventKind::CompletionVerified => {
            source_is(&wire, EventSource::One)?;
            EventBody::CompletionVerified {
                evidence_ref: need(wire.evidence_ref)?,
            }
        }
        EventKind::TaskFailed => EventBody::TaskFailed {
            source: failed_by(source)?,
            reason: FailureReason::from_wire(&need(wire.reason)?)
                .ok_or(ContractViolation("failure reason"))?,
        },
        EventKind::TaskCancelled => {
            let cause = need(wire.cause)?;
            let wanted = match cause {
                CancelCause::User => EventSource::User,
                CancelCause::AuthorityRevoked => EventSource::Access,
            };
            source_is(&wire, wanted)?;
            EventBody::TaskCancelled { cause }
        }
    };
    Ok(body)
}

impl TryFrom<EventWire> for TaskEvent {
    type Error = ContractViolation;

    fn try_from(mut wire: EventWire) -> Result<Self, ContractViolation> {
        let task_id = need(wire.task_id.take())?;
        let seq = need(wire.seq.take())?;
        let at = need(wire.at.take())?;
        Ok(Self {
            task_id,
            seq,
            at,
            body: body_of(wire)?,
        })
    }
}

impl From<TaskEvent> for EventWire {
    fn from(event: TaskEvent) -> Self {
        let mut wire = Self {
            task_id: Some(event.task_id),
            seq: Some(event.seq),
            at: Some(event.at),
            source: Some(event.body.source()),
            kind: Some(event.body.kind()),
            ..Self::default()
        };
        match event.body {
            EventBody::TaskCreated { plan_version, .. } => wire.plan_version = Some(plan_version),
            EventBody::StepStarted {
                step_id,
                effectful,
                authority,
            } => {
                wire.step_id = Some(step_id);
                wire.effectful = Some(effectful);
                wire.decision_ref = authority.decision_ref;
                wire.exercise_ref = authority.exercise_ref;
            }
            EventBody::StepFinished { step_id, result } => {
                wire.step_id = Some(step_id);
                wire.result = Some(result);
            }
            EventBody::StepOutcomeReported { step_id, outcome } => {
                wire.step_id = Some(step_id);
                wire.outcome = Some(outcome);
            }
            EventBody::WaitOpened {
                waitpoint_ref,
                reason,
            } => {
                wire.wait = Some(reason.kind());
                wire.waitpoint_ref = Some(waitpoint_ref);
                wire.reason = Some(String::from(reason.as_str()));
            }
            EventBody::WaitResolved {
                waitpoint_ref,
                continuation_ref,
            } => {
                wire.waitpoint_ref = Some(waitpoint_ref);
                wire.continuation_ref = Some(continuation_ref);
            }
            EventBody::WaitExpired { waitpoint_ref } => wire.waitpoint_ref = Some(waitpoint_ref),
            EventBody::PauseRequested { .. } => {}
            EventBody::TaskCancelled { cause } => wire.cause = Some(cause),
            EventBody::PauseConfirmed {
                execution_report_ref,
            } => {
                wire.execution_report_ref = Some(execution_report_ref);
            }
            EventBody::Resumed { continuation_ref } => {
                wire.continuation_ref = Some(continuation_ref);
            }
            EventBody::CheckpointRecorded { checkpoint_ref } => {
                wire.checkpoint_ref = Some(checkpoint_ref);
            }
            EventBody::CompletionVerified { evidence_ref } => {
                wire.evidence_ref = Some(evidence_ref);
            }
            EventBody::TaskFailed { reason, .. } => {
                wire.reason = Some(String::from(reason.as_str()));
            }
        }
        wire
    }
}
