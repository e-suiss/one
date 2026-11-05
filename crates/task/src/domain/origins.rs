//! The per-task origin set (SEC-19, CP-35, Access E54 (4)): it is derived from the plan, shown to the user in plain words, and every read or write outside it is denied; reading an origin needs it in the read or the write list, writing needs it in the write list; widening the set during the task is a new Access decision, and an origin that came from external content also needs the user's approval.

use one_proto::ontology::validate::ContractViolation;
use one_proto::task::{Origin, OriginSet, Step};
use one_provenance::Label;

/// The most origins one list may hold.
pub const MAX_ORIGINS: usize = 64;

/// What the task does with an origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Use {
    /// Reads it.
    Read,
    /// Writes to it.
    Write,
}

/// What widening the set to a new origin needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Widen {
    /// A new Access decision.
    NewDecision,
    /// A new Access decision and the user's approval, since the origin came from external content.
    UserApproval,
}

fn push(list: &mut Vec<Origin>, origin: &Origin) {
    if !list.contains(origin) {
        list.push(origin.clone());
    }
}

/// The task's origin set: every step's read and write origins, in plan order and without repeats.
///
/// # Errors
/// [`ContractViolation`] when a list would hold more than [`MAX_ORIGINS`].
pub fn derive(steps: &[Step]) -> Result<OriginSet, ContractViolation> {
    let mut set = OriginSet {
        read: Vec::new(),
        write: Vec::new(),
    };
    for origins in steps.iter().filter_map(|s| s.origin_set.as_ref()) {
        for o in &origins.read {
            push(&mut set.read, o);
        }
        for o in &origins.write {
            push(&mut set.write, o);
        }
    }
    if set.read.len() > MAX_ORIGINS || set.write.len() > MAX_ORIGINS {
        return Err(ContractViolation("origin set"));
    }
    Ok(set)
}

/// Whether the set allows `how` on `origin`; everything outside it is denied.
#[must_use]
pub fn allows(set: &OriginSet, origin: &Origin, how: Use) -> bool {
    match how {
        Use::Read => set.read.contains(origin) || set.write.contains(origin),
        Use::Write => set.write.contains(origin),
    }
}

/// What it takes to use `origin` for `how` when the set does not allow it yet; `None` when it already does. `source` is the label of the value that named the origin.
#[must_use]
pub fn widen(set: &OriginSet, origin: &Origin, how: Use, source: &Label) -> Option<Widen> {
    if allows(set, origin, how) {
        None
    } else if source.is_trusted() {
        Some(Widen::NewDecision)
    } else {
        Some(Widen::UserApproval)
    }
}
