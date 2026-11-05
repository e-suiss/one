//! What the registry holds and what it may show (CP-16, CP-19, CP-20, CP-21, SEC-24 (1, 3, 6), C-17): a capability is working only when its entry keeps the registry rules, it is not an Annex III use, a curated one passed review and signature and a custom one was added past the plain warning, the user approved its pin and the tool still matches it, its last evaluation passed within [`MAX_AGE_SECS`](crate::domain::eval::MAX_AGE_SECS) and its provider is healthy; anything else is shown as "not working right now" and the planner never sees it.

use one_proto::capability::{CapabilityDefinition, EvaluationResult, check_registry_entry};
use one_proto::ontology::Instant;
use one_proto::task::common::Sha256Digest;

use crate::domain::annex::forbidden;
use crate::domain::eval::MAX_AGE_SECS;

/// Where an entry came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    /// Suiss's curated sub-registry.
    Curated {
        /// Two Suiss reviewers passed it and its package signature verified.
        admitted: bool,
    },
    /// A server the user added under "Advanced".
    Custom {
        /// The user saw the plain warning ("Suiss did not review this connection").
        warned: bool,
    },
}

/// One registry entry.
#[derive(Debug, Clone, PartialEq)]
pub struct Entry {
    /// The definition.
    pub definition: CapabilityDefinition,
    /// Where it came from.
    pub source: Source,
    /// The pin the user approved.
    pub approved: Option<Sha256Digest>,
    /// The pin of what the server says now.
    pub current: Option<Sha256Digest>,
    /// Whether its provider is healthy.
    pub healthy: bool,
}

/// Why a capability is not working right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NotWorking {
    /// The entry breaks a registry rule.
    Malformed,
    /// It names an Annex III use.
    AnnexIii,
    /// A curated entry that was not admitted.
    NotAdmitted,
    /// A custom server added without the warning.
    NotWarned,
    /// The user has not approved its pin.
    NotApproved,
    /// The tool changed since approval: "This connection changed, approve again".
    Changed,
    /// Its last evaluation failed.
    EvaluationFailed,
    /// Its last pass is too old.
    EvaluationStale,
    /// Its provider is down.
    ProviderDown,
}

/// Whether `entry` works at `now`.
///
/// # Errors
/// The first [`NotWorking`] reason, in the order above.
pub fn working(entry: &Entry, now: Instant) -> Result<(), NotWorking> {
    let d = &entry.definition;
    check_registry_entry(d).map_err(|_| NotWorking::Malformed)?;
    if forbidden(&d.name) {
        return Err(NotWorking::AnnexIii);
    }
    match entry.source {
        Source::Curated { admitted: false } => return Err(NotWorking::NotAdmitted),
        Source::Custom { warned: false } => return Err(NotWorking::NotWarned),
        Source::Curated { .. } | Source::Custom { .. } => {}
    }
    let approved = entry.approved.as_ref().ok_or(NotWorking::NotApproved)?;
    if entry.current.as_ref() != Some(approved) {
        return Err(NotWorking::Changed);
    }
    if d.test_status.last_result == EvaluationResult::Fail {
        return Err(NotWorking::EvaluationFailed);
    }
    let fresh = now
        .since(&d.test_status.last_success_at)
        .is_some_and(|age| age.secs <= MAX_AGE_SECS);
    if !fresh {
        return Err(NotWorking::EvaluationStale);
    }
    if !entry.healthy {
        return Err(NotWorking::ProviderDown);
    }
    Ok(())
}
