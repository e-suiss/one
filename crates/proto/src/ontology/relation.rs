//! The six relations as identity-less edge records with their allowed endpoints; an edge has no authority field and creates no authority (C-23, C-21, C-2, C-15).

use serde::{Deserialize, Serialize};

use super::concept::{CanonicalNode, Concept};
use super::reference::{AnyRef, ProductRef};
use super::time::Instant;

/// A relation name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RelationKind {
    /// A record comes from its evidence.
    DerivedFrom,
    /// A memory record is about a person, object, Goal or Routine.
    About,
    /// A new version replaces an old one of the same concept.
    Supersedes,
    /// A Task or Interaction serves a Goal.
    Serves,
    /// An Interaction concerns a record or product object.
    Concerns,
    /// A record points at an object it does not own.
    References,
}

/// The target of an edge: one of One's records or a foreign reference.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelationTarget {
    /// One's record.
    Node(CanonicalNode),
    /// A foreign object.
    Ref(AnyRef),
}

/// An edge whose endpoints the relation does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelationError {
    /// The relation.
    pub relation: RelationKind,
    /// The source concept.
    pub source: Concept,
}

impl core::fmt::Display for RelationError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "{:?} does not allow this endpoint from {}",
            self.relation,
            self.source.name()
        )
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEdge {
    relation: RelationKind,
    source: CanonicalNode,
    target: RelationTarget,
    recorded_at: Instant,
}

/// A relation edge (C-23).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawEdge", into = "RawEdge")]
pub struct RelationEdge {
    relation: RelationKind,
    source: CanonicalNode,
    target: RelationTarget,
    recorded_at: Instant,
}

impl TryFrom<RawEdge> for RelationEdge {
    type Error = RelationError;

    fn try_from(raw: RawEdge) -> Result<Self, Self::Error> {
        Self::new(raw.relation, raw.source, raw.target, raw.recorded_at)
    }
}

impl From<RelationEdge> for RawEdge {
    fn from(e: RelationEdge) -> Self {
        Self {
            relation: e.relation,
            source: e.source,
            target: e.target,
            recorded_at: e.recorded_at,
        }
    }
}

const fn is_person_or_external(r: &AnyRef) -> bool {
    matches!(
        r,
        AnyRef::External(_)
            | AnyRef::ExternalPerson(_)
            | AnyRef::Product(ProductRef::Access(
                super::reference::AccessObjectRef::Party(_)
            ))
    )
}

/// Whether `relation` allows an edge from `source` to `target` (C-23).
#[must_use]
pub fn allows(relation: RelationKind, source: Concept, target: &RelationTarget) -> bool {
    use Concept as C;
    let node = match target {
        RelationTarget::Node(n) => Some(n.concept()),
        RelationTarget::Ref(_) => None,
    };
    match relation {
        RelationKind::DerivedFrom => match source {
            C::MemoryRecord => matches!(node, Some(C::Episode | C::Observation)),
            C::Routine | C::Goal => node == Some(C::MemoryRecord),
            _ => false,
        },
        RelationKind::About => {
            source == C::MemoryRecord
                && match target {
                    RelationTarget::Node(n) => matches!(n.concept(), C::Goal | C::Routine),
                    RelationTarget::Ref(r) => is_person_or_external(r),
                }
        }
        RelationKind::Supersedes => node == Some(source),
        RelationKind::Serves => matches!(source, C::Task | C::Interaction) && node == Some(C::Goal),
        RelationKind::Concerns => {
            source == C::Interaction
                && match target {
                    RelationTarget::Node(n) => {
                        matches!(
                            n.concept(),
                            C::Task | C::MemoryRecord | C::Routine | C::Goal
                        )
                    }
                    RelationTarget::Ref(r) => matches!(r, AnyRef::Product(_)),
                }
        }
        RelationKind::References => node.is_none(),
    }
}

impl RelationEdge {
    /// Builds an edge the relation allows.
    ///
    /// # Errors
    /// Rejects endpoints outside the C-23 table.
    pub fn new(
        relation: RelationKind,
        source: CanonicalNode,
        target: RelationTarget,
        recorded_at: Instant,
    ) -> Result<Self, RelationError> {
        if allows(relation, source.concept(), &target) {
            Ok(Self {
                relation,
                source,
                target,
                recorded_at,
            })
        } else {
            Err(RelationError {
                relation,
                source: source.concept(),
            })
        }
    }

    /// The relation.
    #[must_use]
    pub const fn relation(&self) -> RelationKind {
        self.relation
    }

    /// The source record.
    #[must_use]
    pub const fn source(&self) -> CanonicalNode {
        self.source
    }

    /// The target.
    #[must_use]
    pub const fn target(&self) -> &RelationTarget {
        &self.target
    }

    /// When the edge was recorded.
    #[must_use]
    pub const fn recorded_at(&self) -> Instant {
        self.recorded_at
    }
}
