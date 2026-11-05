//! What the planner sees (CP-15, CP-17, CP-18, C-17, SEC-24 (6)): only capabilities that work now and fall inside the Access Grant and, when one is bound, the Mandate; retrieval scores only those, the best [`CANDIDATES`] by score (ties by name) reach the model and nothing else does; "can you do this?" is answered from the same record, never guessed; a provider is chosen by the fixed path order, then the user's preference, then its reference, and no commission or paid placement ever ranks it, Suiss products included.

use std::collections::BTreeSet;

use one_proto::capability::{CapabilityDefinition, CapabilityName, PathType, Provider};
use one_proto::ontology::{Instant, OpaqueId};

use crate::domain::registry::{Entry, NotWorking, working};

/// How many candidates reach the model.
pub const CANDIDATES: usize = 5;

/// The authority Access allows right now.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Authority {
    /// The Grant scopes.
    pub grant_scopes: BTreeSet<OpaqueId>,
    /// The capabilities of the bound Mandate, when one is bound.
    pub mandate: Option<BTreeSet<CapabilityName>>,
}

impl Authority {
    /// Whether `definition` is inside the Grant and the Mandate.
    #[must_use]
    pub fn covers(&self, definition: &CapabilityDefinition) -> bool {
        self.grant_scopes
            .contains(&definition.authority.grant_scope)
            && self
                .mandate
                .as_ref()
                .is_none_or(|m| m.contains(&definition.name))
    }
}

/// The entries the planner may know of at `now`.
#[must_use]
pub fn eligible<'a>(entries: &'a [Entry], authority: &Authority, now: Instant) -> Vec<&'a Entry> {
    entries
        .iter()
        .filter(|e| authority.covers(&e.definition) && working(e, now).is_ok())
        .collect()
}

/// The candidates among `eligible` by retrieval `scores`; a score for anything else, or a score that is not a number, is ignored.
#[must_use]
pub fn candidates<'a>(eligible: &[&'a Entry], scores: &[(CapabilityName, f64)]) -> Vec<&'a Entry> {
    let mut scored: Vec<(f64, &'a Entry)> = eligible
        .iter()
        .filter_map(|e| {
            scores
                .iter()
                .find(|(n, s)| *n == e.definition.name && !s.is_nan())
                .map(|(_, s)| (*s, *e))
        })
        .collect();
    scored.sort_by(|(a, x), (b, y)| {
        b.total_cmp(a)
            .then_with(|| x.definition.name.cmp(&y.definition.name))
    });
    scored
        .into_iter()
        .take(CANDIDATES)
        .map(|(_, e)| e)
        .collect()
}

/// The answer to "can you do this?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Can {
    /// Yes.
    Yes,
    /// No such capability is connected.
    NotConnected,
    /// It is connected but Access does not allow it now.
    NotPermitted,
    /// It is connected and allowed but not working right now.
    NotWorking(NotWorking),
}

/// Answers "can you do `name`?" from the registry at `now`.
#[must_use]
pub fn can(entries: &[Entry], authority: &Authority, name: &CapabilityName, now: Instant) -> Can {
    let mut found = entries
        .iter()
        .filter(|e| e.definition.name == *name)
        .peekable();
    if found.peek().is_none() {
        return Can::NotConnected;
    }
    let allowed: Vec<&Entry> = found.filter(|e| authority.covers(&e.definition)).collect();
    if allowed.is_empty() {
        return Can::NotPermitted;
    }
    let mut first_reason = None;
    for entry in allowed {
        match working(entry, now) {
            Ok(()) => return Can::Yes,
            Err(why) if first_reason.is_none() => first_reason = Some(why),
            Err(_) => {}
        }
    }
    first_reason.map_or(Can::NotConnected, Can::NotWorking)
}

const fn rank(path: PathType) -> u8 {
    match path {
        PathType::Api | PathType::Mcp | PathType::CommerceProtocol => 0,
        PathType::OsIntent => 1,
        PathType::Browser => 2,
    }
}

/// The provider for `definition` among those whose path is in `reachable`, by path order, then the position in `preferred`, then the provider reference.
#[must_use]
pub fn provider<'a>(
    definition: &'a CapabilityDefinition,
    reachable: &[PathType],
    preferred: &[OpaqueId],
) -> Option<&'a Provider> {
    definition
        .providers
        .iter()
        .filter(|p| reachable.contains(&p.path_type))
        .min_by(|a, b| {
            let key = |p: &Provider| {
                (
                    rank(p.path_type),
                    preferred
                        .iter()
                        .position(|r| *r == p.provider_ref)
                        .unwrap_or(usize::MAX),
                )
            };
            key(a)
                .cmp(&key(b))
                .then_with(|| a.provider_ref.cmp(&b.provider_ref))
        })
}
