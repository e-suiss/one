//! The Rule of Two (SEC-18, CP-22): a session or sub-task holds at most two of (A) handling untrusted input, (B) reaching private data or a sensitive system and (C) changing state or talking to the outside; a step that needs all three is split into reading, extracting and writing sub-tasks with only typed, labelled values between them, and where it cannot be split its effectful step goes to the user's approval; while the user is away, a parameter fed by untrusted input waits for the user.

/// What a sub-task touches.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[allow(clippy::struct_excessive_bools, reason = "SEC-18")]
pub struct Reach {
    /// (A) It handles untrusted input.
    pub untrusted_input: bool,
    /// (B) It reaches private data or a sensitive system.
    pub private_data: bool,
    /// (C) It changes state or talks to the outside.
    pub outside_effect: bool,
}

impl Reach {
    /// Whether it holds all three.
    #[must_use]
    pub const fn all_three(self) -> bool {
        self.untrusted_input && self.private_data && self.outside_effect
    }
}

/// The verdict for one sub-task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// At most two: it may run as one sub-task.
    Fits,
    /// All three: it runs as these parts with typed values between them.
    Split([Reach; 3]),
    /// All three and it cannot be split: its effectful step needs the user's approval.
    Approval,
}

/// The parts of a split: read the untrusted input alone, extract typed values from it with no private data and no effect, then act on private data with only those typed values.
pub const PARTS: [Reach; 3] = [
    Reach {
        untrusted_input: true,
        private_data: false,
        outside_effect: false,
    },
    Reach {
        untrusted_input: true,
        private_data: false,
        outside_effect: false,
    },
    Reach {
        untrusted_input: false,
        private_data: true,
        outside_effect: true,
    },
];

/// Checks `reach`; `splittable` is false when the user's request itself depends on the untrusted content ("do what this email says").
#[must_use]
pub const fn check(reach: Reach, splittable: bool) -> Verdict {
    if reach.all_three() {
        if splittable {
            Verdict::Split(PARTS)
        } else {
            Verdict::Approval
        }
    } else {
        Verdict::Fits
    }
}

/// Whether a parameter may be used now: with the user away, a value fed by untrusted input waits for the user (SEC-18 (3)).
#[must_use]
pub const fn may_use_now(trusted: bool, user_present: bool) -> bool {
    trusted || user_present
}
