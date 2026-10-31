//! The task state machine as a pure fold over the event history; the state is never stored (CP-3, CP-11, CP-42, CP-44, INV-30, INV-32).

use alloc::vec::Vec;
use core::num::NonZeroU64;

use super::common::wire_enum;
use super::event::{EventBody, EventKind, TaskEvent, WaitKind, WaitReason};
use super::record::StepId;
use crate::id::TaskId;
use crate::ontology::WaitpointRef;

wire_enum!(
    /// The eight task states.
    TaskState {
        /// Planned; the first step has not started.
        Pending = "pending",
        /// A step is executing.
        Running = "running",
        /// Waiting for the user at a Relay waitpoint.
        WaitingUser = "waiting_user",
        /// Waiting for an external event.
        WaitingExternal = "waiting_external",
        /// Stopped; the Executor confirmed the pause.
        Paused = "paused",
        /// The completion criterion was verified.
        Completed = "completed",
        /// The completion criterion could not be reached.
        Failed = "failed",
        /// The user gave up or the authority was removed.
        Cancelled = "cancelled",
    }
);

impl TaskState {
    /// Whether no further state change can happen.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Completed | Self::Failed | Self::Cancelled)
    }
}

wire_enum!(
    /// A transition guard of `state-machine.toml`.
    Guard {
        /// The event is the first of the history and carries seq 1.
        FirstEvent = "first_event",
        /// No earlier `step_started` carries the same step.
        StepNotStarted = "step_not_started",
        /// The step started and has not finished.
        StepRunning = "step_running",
        /// Every started step has finished.
        NoStepRunning = "no_step_running",
        /// The step started at some point.
        StepStartedBefore = "step_started_before",
        /// No waitpoint is open.
        NoOpenWait = "no_open_wait",
        /// The waitpoint is the one that entered the current waiting state.
        WaitpointIsOpenWait = "waitpoint_is_open_wait",
        /// A pause was requested since the task last entered running.
        PauseRequestOpen = "pause_request_open",
    }
);

wire_enum!(
    /// Why a history is rejected.
    RejectCode {
        /// The history does not start with `task_created`.
        FirstEventNotCreated = "first_event_not_created",
        /// `task_created` after the first event.
        DuplicateCreated = "duplicate_created",
        /// `seq` is not the previous plus one.
        SeqNotContiguous = "seq_not_contiguous",
        /// Another task's event.
        TaskIdMismatch = "task_id_mismatch",
        /// The event does not validate against the event schema.
        SchemaInvalid = "schema_invalid",
        /// No row admits the event in the current state.
        IllegalTransition = "illegal_transition",
        /// An event other than a late report after a terminal state.
        EventAfterTerminal = "event_after_terminal",
        /// A row admits the event but its guard does not hold.
        GuardFailed = "guard_failed",
    }
);

/// A row that moves the task to another state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Transition {
    /// The event.
    pub event: EventKind,
    /// The wait kind the event must carry, for `wait_opened`.
    pub when: Option<WaitKind>,
    /// The states it leaves; empty for the initial event.
    pub from: &'static [TaskState],
    /// The state it enters.
    pub to: TaskState,
    /// The guard.
    pub guard: Option<Guard>,
}

/// A row that keeps the state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stay {
    /// The event.
    pub event: EventKind,
    /// The states it is admitted in.
    pub within: &'static [TaskState],
    /// The guard.
    pub guard: Option<Guard>,
}

use TaskState::{
    Cancelled, Completed, Failed, Paused, Pending, Running, WaitingExternal, WaitingUser,
};

const LIVE: &[TaskState] = &[Pending, Running, WaitingUser, WaitingExternal, Paused];
const WAITING: &[TaskState] = &[WaitingUser, WaitingExternal];

/// The transition rows of `state-machine.toml`, in table order.
pub const TRANSITIONS: &[Transition] = &[
    Transition {
        event: EventKind::TaskCreated,
        when: None,
        from: &[],
        to: Pending,
        guard: Some(Guard::FirstEvent),
    },
    Transition {
        event: EventKind::StepStarted,
        when: None,
        from: &[Pending, Running],
        to: Running,
        guard: Some(Guard::StepNotStarted),
    },
    Transition {
        event: EventKind::WaitOpened,
        when: Some(WaitKind::User),
        from: &[Running],
        to: WaitingUser,
        guard: Some(Guard::NoOpenWait),
    },
    Transition {
        event: EventKind::WaitOpened,
        when: Some(WaitKind::External),
        from: &[Running],
        to: WaitingExternal,
        guard: Some(Guard::NoOpenWait),
    },
    Transition {
        event: EventKind::WaitResolved,
        when: None,
        from: WAITING,
        to: Running,
        guard: Some(Guard::WaitpointIsOpenWait),
    },
    Transition {
        event: EventKind::WaitExpired,
        when: None,
        from: WAITING,
        to: Failed,
        guard: Some(Guard::WaitpointIsOpenWait),
    },
    Transition {
        event: EventKind::PauseConfirmed,
        when: None,
        from: &[Running],
        to: Paused,
        guard: Some(Guard::PauseRequestOpen),
    },
    Transition {
        event: EventKind::Resumed,
        when: None,
        from: &[Paused],
        to: Running,
        guard: None,
    },
    Transition {
        event: EventKind::CompletionVerified,
        when: None,
        from: &[Running],
        to: Completed,
        guard: Some(Guard::NoStepRunning),
    },
    Transition {
        event: EventKind::TaskFailed,
        when: None,
        from: &[Running],
        to: Failed,
        guard: None,
    },
    Transition {
        event: EventKind::TaskCancelled,
        when: None,
        from: LIVE,
        to: Cancelled,
        guard: None,
    },
];

/// The stay rows of `state-machine.toml`, in table order.
pub const STAYS: &[Stay] = &[
    Stay {
        event: EventKind::StepFinished,
        within: &[Running],
        guard: Some(Guard::StepRunning),
    },
    Stay {
        event: EventKind::PauseRequested,
        within: &[Running],
        guard: None,
    },
    Stay {
        event: EventKind::CheckpointRecorded,
        within: &[Running, WaitingUser, WaitingExternal, Paused],
        guard: None,
    },
    Stay {
        event: EventKind::StepOutcomeReported,
        within: &[
            Pending,
            Running,
            WaitingUser,
            WaitingExternal,
            Paused,
            Completed,
            Failed,
            Cancelled,
        ],
        guard: Some(Guard::StepStartedBefore),
    },
];

/// A rejected history: the code, the seq of the offending event and the guard that failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rejection {
    /// The code.
    pub code: RejectCode,
    /// The offending event's seq; `None` for an empty history or an event without one.
    pub seq: Option<u64>,
    /// The failed guard, for `guard_failed`.
    pub guard: Option<Guard>,
}

/// One history entry as read: a valid event or one that failed the event schema.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HistoryEntry {
    /// A valid event.
    Valid(TaskEvent),
    /// An event that does not validate; its seq when it carries a readable one.
    SchemaInvalid {
        /// The seq.
        seq: Option<u64>,
    },
}

/// What the history derives: the state and what the projections need.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Derived {
    /// The state.
    pub state: TaskState,
    /// Why the task waits, in a waiting state.
    pub wait_reason: Option<WaitReason>,
    /// A pause is requested and not yet confirmed: shown as stopping.
    pub stopping: bool,
}

#[derive(Debug, Clone)]
struct Fold {
    task_id: TaskId,
    last_seq: NonZeroU64,
    state: TaskState,
    started: Vec<(StepId, bool)>,
    open_wait: Option<(WaitpointRef, WaitReason)>,
    pause_requested: bool,
}

fn reject(code: RejectCode, seq: Option<u64>) -> Rejection {
    Rejection {
        code,
        seq,
        guard: None,
    }
}

fn row_for(state: TaskState, body: &EventBody) -> Option<(TaskState, Option<Guard>)> {
    let kind = body.kind();
    let wait = match body {
        EventBody::WaitOpened { reason, .. } => Some(reason.kind()),
        _ => None,
    };
    TRANSITIONS
        .iter()
        .find(|t| {
            t.event == kind && t.from.contains(&state) && (t.when.is_none() || t.when == wait)
        })
        .map(|t| (t.to, t.guard))
        .or_else(|| {
            STAYS
                .iter()
                .find(|s| s.event == kind && s.within.contains(&state))
                .map(|s| (state, s.guard))
        })
}

impl Fold {
    fn started(&self, step: &StepId) -> Option<bool> {
        self.started
            .iter()
            .find(|(s, _)| s == step)
            .map(|(_, finished)| *finished)
    }

    fn guard_holds(&self, guard: Guard, body: &EventBody) -> bool {
        match (guard, body) {
            (Guard::StepNotStarted, EventBody::StepStarted { step_id, .. }) => {
                self.started(step_id).is_none()
            }
            (Guard::StepRunning, EventBody::StepFinished { step_id, .. }) => {
                self.started(step_id) == Some(false)
            }
            (Guard::StepStartedBefore, EventBody::StepOutcomeReported { step_id, .. }) => {
                self.started(step_id).is_some()
            }
            (Guard::NoStepRunning, _) => self.started.iter().all(|(_, finished)| *finished),
            (Guard::NoOpenWait, _) => self.open_wait.is_none(),
            (
                Guard::WaitpointIsOpenWait,
                EventBody::WaitResolved { waitpoint_ref, .. }
                | EventBody::WaitExpired { waitpoint_ref },
            ) => self
                .open_wait
                .as_ref()
                .is_some_and(|(open, _)| open == waitpoint_ref),
            (Guard::PauseRequestOpen, _) => self.pause_requested,
            _ => false,
        }
    }

    fn apply(&mut self, event: &TaskEvent) -> Result<(), Rejection> {
        let seq = Some(event.seq.get());
        let body = &event.body;
        if body.kind() == EventKind::TaskCreated {
            return Err(reject(RejectCode::DuplicateCreated, seq));
        }
        if self.last_seq.checked_add(1) != Some(event.seq) {
            return Err(reject(RejectCode::SeqNotContiguous, seq));
        }
        if event.task_id != self.task_id {
            return Err(reject(RejectCode::TaskIdMismatch, seq));
        }
        if self.state.is_terminal() && body.kind() != EventKind::StepOutcomeReported {
            return Err(reject(RejectCode::EventAfterTerminal, seq));
        }
        let (to, guard) =
            row_for(self.state, body).ok_or(reject(RejectCode::IllegalTransition, seq))?;
        if let Some(g) = guard
            && !self.guard_holds(g, body)
        {
            return Err(Rejection {
                code: RejectCode::GuardFailed,
                seq,
                guard: Some(g),
            });
        }
        match body {
            EventBody::StepStarted { step_id, .. } => self.started.push((step_id.clone(), false)),
            EventBody::StepFinished { step_id, .. } => {
                if let Some(entry) = self.started.iter_mut().find(|(s, _)| s == step_id) {
                    entry.1 = true;
                }
            }
            EventBody::WaitOpened {
                waitpoint_ref,
                reason,
            } => {
                self.open_wait = Some((waitpoint_ref.clone(), *reason));
            }
            EventBody::WaitResolved { .. } | EventBody::WaitExpired { .. } => self.open_wait = None,
            EventBody::PauseRequested { .. } => self.pause_requested = true,
            _ => {}
        }
        if to == Running && self.state != Running {
            self.pause_requested = false;
        }
        self.last_seq = event.seq;
        self.state = to;
        Ok(())
    }

    fn derived(&self) -> Derived {
        Derived {
            state: self.state,
            wait_reason: match self.state {
                WaitingUser | WaitingExternal => self.open_wait.as_ref().map(|(_, r)| *r),
                _ => None,
            },
            stopping: self.state == Running && self.pause_requested,
        }
    }
}

fn start(first: &HistoryEntry) -> Result<Fold, Rejection> {
    let event = match first {
        HistoryEntry::SchemaInvalid { seq } => return Err(reject(RejectCode::SchemaInvalid, *seq)),
        HistoryEntry::Valid(event) => event,
    };
    let seq = Some(event.seq.get());
    if event.body.kind() != EventKind::TaskCreated {
        return Err(reject(RejectCode::FirstEventNotCreated, seq));
    }
    if event.seq.get() != 1 {
        return Err(Rejection {
            code: RejectCode::GuardFailed,
            seq,
            guard: Some(Guard::FirstEvent),
        });
    }
    Ok(Fold {
        task_id: event.task_id,
        last_seq: event.seq,
        state: Pending,
        started: Vec::new(),
        open_wait: None,
        pause_requested: false,
    })
}

/// Derives the task state from its whole history.
///
/// # Errors
/// Returns the first rejection by the `state-machine.toml` rules.
pub fn derive(history: &[HistoryEntry]) -> Result<Derived, Rejection> {
    let mut entries = history.iter();
    let first = entries
        .next()
        .ok_or(reject(RejectCode::FirstEventNotCreated, None))?;
    let mut fold = start(first)?;
    for entry in entries {
        match entry {
            HistoryEntry::SchemaInvalid { seq } => {
                return Err(reject(RejectCode::SchemaInvalid, *seq));
            }
            HistoryEntry::Valid(event) => fold.apply(event)?,
        }
    }
    Ok(fold.derived())
}

/// Derives the task state from a history of valid events.
///
/// # Errors
/// Returns the first rejection by the `state-machine.toml` rules.
pub fn derive_events(history: &[TaskEvent]) -> Result<Derived, Rejection> {
    let mut events = history.iter();
    let first = events
        .next()
        .ok_or(reject(RejectCode::FirstEventNotCreated, None))?;
    let mut fold = start(&HistoryEntry::Valid(first.clone()))?;
    for event in events {
        fold.apply(event)?;
    }
    Ok(fold.derived())
}

wire_enum!(
    /// What a user's "stop" does in each state (INV-32).
    StopCommand {
        /// Running: record `pause_requested`; the task is paused only when the Executor confirms.
        RequestPause = "request_pause",
        /// Pending, waiting or paused: record `task_cancelled` with cause `user`.
        Cancel = "cancel",
        /// Terminal: nothing to stop.
        AlreadyOver = "already_over",
    }
);

/// The event a "stop" writes in `state`; "stop" is never refused (INV-32).
#[must_use]
pub const fn stop_command(state: TaskState) -> StopCommand {
    match state {
        Running => StopCommand::RequestPause,
        Pending | WaitingUser | WaitingExternal | Paused => StopCommand::Cancel,
        Completed | Failed | Cancelled => StopCommand::AlreadyOver,
    }
}
