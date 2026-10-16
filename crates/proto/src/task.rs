//! The task record and its event-derived state machine with protocol projections, batch and budget rules (CP-3, CP-4, CP-6, INV-30).

mod batch;
pub mod common;
mod event;
mod outcome;
mod projection;
mod record;
mod state;

pub use batch::{
    BatchEntry, BatchRejection, BudgetRejection, Reported, batch, effective_amount, effective_steps,
};
pub use event::{
    CancelCause, CreatedBy, EventBody, EventKind, EventSource, FailedBy, FailureReason,
    PauseRequestedBy, StepAuthority, TaskEvent, WaitKind, WaitReason,
};
pub use outcome::{
    ApprovalEvidence, ApprovalOutcome, Certainty, ConfirmationRef, ConfirmedOutcome, Outcome,
    OutcomeSubject, StepReason, StepResult, StepStatus,
};
pub use projection::{
    A2aTaskState, McpTaskStatus, Projection, RefusedSubmission, project, refused_submission,
};
pub use record::{
    AmountBudget, Authority, Budget, CompletionCheck, CompletionCriterion, CriterionStatement,
    IdempotencyKey, Origin, OriginSet, Plan, Purpose, Route, RouteLocation, RoutePath, RouteReason,
    Step, StepBudget, StepId, StepState, Task, TaskType, TypedInput,
};
pub use state::{
    Derived, Guard, HistoryEntry, RejectCode, Rejection, STAYS, Stay, StopCommand, TRANSITIONS,
    TaskState, Transition, derive, derive_events, stop_command,
};
