//! One exposed to other assistants (CP-28, CP-29, MF-25, PV-36, M-35): every caller carries an Access Grant, nothing is open without one, read-only is the default and writing or acting needs its own Grant; personal context goes only to an assistant whose provider is on the verified zero-retention, no-training list, which starts empty, and no sensitive class ever goes to any; every other assistant gets only "give One a task" and a content-free "ask the status"; the user's approval cannot lift any of this.

use one_proto::capability::CapabilityName;
use one_proto::data_class::DataClass;

/// Providers verified to keep nothing and train on nothing: a written zero-retention and no-training agreement and the provider's published terms; empty until one is verified.
pub const VERIFIED_ZERO_RETENTION: &[&str] = &[];

/// The two context-free capabilities every Granted caller may use.
pub const TASK_ONLY: [&str; 2] = [
    "app.suiss.assistant.task.submit",
    "app.suiss.assistant.task.status",
];

/// What a caller holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Caller<'a> {
    /// Whether it holds an Access Grant at all.
    pub granted: bool,
    /// Whether its Grant also allows writing and acting.
    pub write_grant: bool,
    /// Its provider.
    pub provider: &'a str,
}

/// What One offers a caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Offer {
    /// Nothing: no Grant.
    Nothing,
    /// Only "give One a task" and "ask the status", without context.
    TaskOnly,
    /// Personal context, read only.
    ReadOnly,
    /// Personal context, read and write.
    ReadWrite,
}

/// What One offers `caller`, given the `verified` provider list.
#[must_use]
pub fn offer(caller: &Caller<'_>, verified: &[&str]) -> Offer {
    if !caller.granted {
        Offer::Nothing
    } else if !verified.contains(&caller.provider) {
        Offer::TaskOnly
    } else if caller.write_grant {
        Offer::ReadWrite
    } else {
        Offer::ReadOnly
    }
}

/// Whether a capability is open under `offer`.
#[must_use]
pub fn opens(offer: Offer, capability: &CapabilityName) -> bool {
    match offer {
        Offer::Nothing => false,
        Offer::TaskOnly => TASK_ONLY.contains(&capability.as_str()),
        Offer::ReadOnly | Offer::ReadWrite => true,
    }
}

/// Whether data of `class` may go to a caller under `offer`: never a sensitive class, never without personal context.
#[must_use]
pub fn shares(offer: Offer, class: &DataClass) -> bool {
    matches!(offer, Offer::ReadOnly | Offer::ReadWrite) && !class.is_sensitive()
}
