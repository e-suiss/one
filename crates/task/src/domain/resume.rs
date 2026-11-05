//! Resuming from a checkpoint (CP-45, OP-7): the logical state and the encrypted browser snapshot are both kept, but the screen itself cannot be replayed, so on resume the page is loaded again and what the task relied on (the cart, the price) is compared with what it shows now; any change goes to the user; a snapshot never outlives its browser profile; progress is partial and visible and can be taken over at any point.

use one_proto::ontology::Instant;

/// What resuming does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resume {
    /// The page shows what the task relied on: go on.
    GoOn,
    /// It changed: ask the user before going on.
    AskUser,
    /// The snapshot is past its profile's life: start the browser part afresh.
    Fresh,
}

/// Compares what the checkpoint relied on with what the reloaded page shows, at `now`, for a snapshot whose profile ends at `profile_ends`.
#[must_use]
pub fn resume<T: PartialEq>(
    relied_on: &T,
    shown: &T,
    now: Instant,
    profile_ends: Instant,
) -> Resume {
    if now >= profile_ends {
        Resume::Fresh
    } else if relied_on == shown {
        Resume::GoOn
    } else {
        Resume::AskUser
    }
}

/// When a snapshot taken under a profile ending at `profile_ends` must be gone: never later than the profile, and no later than `kept_until`.
#[must_use]
pub fn snapshot_ends(kept_until: Instant, profile_ends: Instant) -> Instant {
    if kept_until < profile_ends {
        kept_until
    } else {
        profile_ends
    }
}
