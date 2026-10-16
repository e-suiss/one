//! Outbound MCP Tasks and A2A Task projections of the task state; a protocol state is never written into a task (CP-3, C-6, C-27).

use super::common::wire_enum;
use super::event::WaitReason;
use super::state::TaskState;

wire_enum!(
    /// MCP Tasks status.
    McpTaskStatus {
        /// Working.
        Working = "working",
        /// Input required.
        InputRequired = "input_required",
        /// Completed.
        Completed = "completed",
        /// Failed.
        Failed = "failed",
        /// Cancelled.
        Cancelled = "cancelled",
    }
);

wire_enum!(
    /// A2A 1.0.0 `TaskState`; `TASK_STATE_UNSPECIFIED` is never projected.
    A2aTaskState {
        /// Submitted.
        Submitted = "TASK_STATE_SUBMITTED",
        /// Working.
        Working = "TASK_STATE_WORKING",
        /// Input required.
        InputRequired = "TASK_STATE_INPUT_REQUIRED",
        /// Authentication required.
        AuthRequired = "TASK_STATE_AUTH_REQUIRED",
        /// Completed.
        Completed = "TASK_STATE_COMPLETED",
        /// Failed.
        Failed = "TASK_STATE_FAILED",
        /// Canceled.
        Canceled = "TASK_STATE_CANCELED",
        /// Rejected; only for a submission refused before a task exists.
        Rejected = "TASK_STATE_REJECTED",
    }
);

/// A task state as MCP and A2A callers see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Projection {
    /// The MCP Tasks status.
    pub mcp_tasks: McpTaskStatus,
    /// The A2A task state.
    pub a2a_task: A2aTaskState,
    /// The One state, carried as the status message.
    pub status_message: TaskState,
    /// For a user wait: whether the calling assistant may answer it; always false.
    pub caller_answer_accepted: Option<bool>,
}

/// Projects a task state; `wait_reason` picks between input and authentication for a user wait.
#[must_use]
pub const fn project(state: TaskState, wait_reason: Option<WaitReason>) -> Projection {
    let (mcp_tasks, a2a_task) = match state {
        TaskState::Pending => (McpTaskStatus::Working, A2aTaskState::Submitted),
        TaskState::Running | TaskState::WaitingExternal | TaskState::Paused => {
            (McpTaskStatus::Working, A2aTaskState::Working)
        }
        TaskState::WaitingUser => match wait_reason {
            Some(WaitReason::Authentication) => {
                (McpTaskStatus::InputRequired, A2aTaskState::AuthRequired)
            }
            _ => (McpTaskStatus::InputRequired, A2aTaskState::InputRequired),
        },
        TaskState::Completed => (McpTaskStatus::Completed, A2aTaskState::Completed),
        TaskState::Failed => (McpTaskStatus::Failed, A2aTaskState::Failed),
        TaskState::Cancelled => (McpTaskStatus::Cancelled, A2aTaskState::Canceled),
    };
    Projection {
        mcp_tasks,
        a2a_task,
        status_message: state,
        caller_answer_accepted: match state {
            TaskState::WaitingUser => Some(false),
            _ => None,
        },
    }
}

/// A submission refused before any task exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefusedSubmission {
    /// MCP has no task status: the submitting request gets a JSON-RPC error and no task is created.
    pub mcp_tasks: Option<McpTaskStatus>,
    /// A2A answers rejected.
    pub a2a_task: A2aTaskState,
}

/// The projection of a refused submission.
#[must_use]
pub const fn refused_submission() -> RefusedSubmission {
    RefusedSubmission {
        mcp_tasks: None,
        a2a_task: A2aTaskState::Rejected,
    }
}
