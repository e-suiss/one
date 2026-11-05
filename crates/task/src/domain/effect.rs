//! Replaying an effectful step (CP-43, INV-31): every effect carries its step's idempotency key and its result is recorded; a step whose result is recorded is never done again; a crash between sending and recording leaves the outcome open, so One first checks it (page, confirmation email, API query) and never sends blindly; if the check shows it did not happen, it is sent again with the same key under a new Access continuation; if it cannot be checked, the step is `unknown` and the user decides.

use one_proto::TaskId;
use one_proto::task::{IdempotencyKey, StepId, StepReason};

/// What the history shows for the step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Seen {
    /// It was never sent.
    NotSent,
    /// It was sent and no result was recorded.
    SentUnrecorded,
    /// Its result is recorded.
    Recorded,
}

/// What a check of the outcome found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Check {
    /// It happened.
    Occurred,
    /// It did not happen.
    DidNotOccur,
    /// It cannot be told.
    Unverifiable,
}

/// What the replay does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Replay {
    /// Send it for the first time.
    Send,
    /// Keep the recorded result; send nothing.
    Keep,
    /// Check the outcome before anything else.
    Check,
    /// Send it again with the same key, under a new Access continuation.
    SendAgain,
    /// Report it as unknown and leave the decision to the user.
    Unknown(StepReason),
}

/// What to do with a step the history shows as `seen`.
#[must_use]
pub const fn replay(seen: Seen) -> Replay {
    match seen {
        Seen::NotSent => Replay::Send,
        Seen::Recorded => Replay::Keep,
        Seen::SentUnrecorded => Replay::Check,
    }
}

/// What to do after checking an open outcome.
#[must_use]
pub const fn after_check(check: Check) -> Replay {
    match check {
        Check::Occurred => Replay::Keep,
        Check::DidNotOccur => Replay::SendAgain,
        Check::Unverifiable => Replay::Unknown(StepReason::CrashUnverified),
    }
}

/// The key every send of the step carries, the same on every replay.
#[must_use]
pub fn key(task: TaskId, step: &StepId) -> IdempotencyKey {
    IdempotencyKey::for_step(task, step)
}
