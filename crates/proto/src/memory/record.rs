//! The memory record with every M-7 field, the relationship edge built on it, and the seven-field skeleton a forgotten record becomes (M-6, M-7, M-10, M-25, MD-7 (1, 2), C-12, C-19).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::fields::{
    AlternativeExplanation, ContentType, EpistemicState, Evidence, Layer, LiveStatus, Predicate,
    Season, SourceKind, TimeKind, Trust, UsageRestriction,
};
use crate::data_class::RetentionClass;
use crate::id::{EpisodeId, MemoryRecordId};
use crate::ontology::concept::Concept;
use crate::ontology::episode::SkeletonRetention;
use crate::ontology::header::{RecordHeader, Statement};
use crate::ontology::reference::{EntityRef, PartyRef};
use crate::ontology::tags::{Forgotten, MemoryRecordType};
use crate::ontology::time::Instant;
use crate::ontology::validate::{
    ContractViolation, UnknownFields, is_memory_extension_name, no_unknown, require, unique,
};

/// A live memory record (M-7).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveMemoryRecord {
    /// `MemoryRecord`.
    #[serde(rename = "type")]
    pub concept: MemoryRecordType,
    /// Identifier.
    pub id: MemoryRecordId,
    /// C-19 header.
    #[serde(flatten)]
    pub header: RecordHeader,
    /// The record this version replaces, or `null` at version 1.
    #[serde(deserialize_with = "Option::deserialize")]
    pub supersedes: Option<MemoryRecordId>,
    /// Lifecycle.
    pub status: LiveStatus,
    /// Content type.
    pub content_type: ContentType,
    /// Epistemic state.
    pub epistemic_state: EpistemicState,
    /// Layer.
    pub layer: Layer,
    /// Time kind.
    pub time_kind: TimeKind,
    /// Valid time start.
    pub valid_from: Instant,
    /// Valid time end, or `null` while open.
    pub valid_to: Option<Instant>,
    /// Expected end of a `current` record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_end: Option<Instant>,
    /// Months of a `seasonal` record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub season: Option<Season>,
    /// When an `invalidated` record was superseded; `null` otherwise.
    pub superseded_at: Option<Instant>,
    /// Source Episodes, at least one.
    pub source_episodes: Vec<EpisodeId>,
    /// Source kind.
    pub source_kind: SourceKind,
    /// Evidence.
    pub evidence: Evidence,
    /// Trust.
    pub trust: Trust,
    /// Typed alternative explanations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alternative_explanations: Option<Vec<AlternativeExplanation>>,
    /// Usage restriction, or `null`.
    pub usage_restriction: Option<UsageRestriction>,
    /// Whom or what it is about.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<Vec<EntityRef>>,
    /// The statement.
    pub statement: Statement,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
impl LiveMemoryRecord {
    /// Contradicted by at least one record (M-20).
    #[must_use]
    pub fn is_contested(&self) -> bool {
        !self.evidence.contradicting_records.is_empty()
    }

    /// The skeleton this record leaves when forgotten at `at` (M-25).
    #[must_use]
    pub fn forget(&self, at: Instant) -> MemorySkeleton {
        MemorySkeleton {
            concept: MemoryRecordType,
            id: self.id,
            owner: self.header.owner.clone(),
            version: self.header.version,
            status: Forgotten,
            recorded_at: self.header.recorded_at,
            deleted_at: at,
            retention_class: if self.header.retention_class == RetentionClass::OneSensitive {
                SkeletonRetention::OneSensitive
            } else {
                SkeletonRetention::OneMemory
            },
            unknown: UnknownFields::new(),
        }
    }
}

/// What remains of a forgotten memory record: seven fields and `type`; the identifier stays resolvable (M-25).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemorySkeleton {
    /// `MemoryRecord`.
    #[serde(rename = "type")]
    pub concept: MemoryRecordType,
    /// Identifier.
    pub id: MemoryRecordId,
    /// The owner.
    pub owner: PartyRef,
    /// Last version.
    pub version: NonZeroU32,
    /// `forgotten`.
    pub status: Forgotten,
    /// Transaction time of the last version.
    pub recorded_at: Instant,
    /// When it was forgotten.
    pub deleted_at: Instant,
    /// Retention class.
    pub retention_class: SkeletonRetention,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
impl MemorySkeleton {
    /// The skeleton's fields besides `type`, in contract order.
    pub const FIELDS: [&'static str; 7] = [
        "id",
        "owner",
        "version",
        "status",
        "recorded_at",
        "deleted_at",
        "retention_class",
    ];
}

/// A memory record: live, or the skeleton of a forgotten one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MemoryRecord {
    /// Forgotten.
    Forgotten(MemorySkeleton),
    /// Live.
    Live(Box<LiveMemoryRecord>),
}

impl MemoryRecord {
    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> MemoryRecordId {
        match self {
            Self::Forgotten(s) => s.id,
            Self::Live(l) => l.id,
        }
    }

    /// The live record, if not forgotten.
    #[must_use]
    pub const fn live(&self) -> Option<&LiveMemoryRecord> {
        match self {
            Self::Forgotten(_) => None,
            Self::Live(l) => Some(l),
        }
    }
}

/// A live relationship edge: a memory record with subject, predicate and object (M-10, M-11).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveRelationshipEdge {
    /// The record fields.
    #[serde(flatten)]
    pub record: LiveMemoryRecord,
    /// Subject.
    pub subject: EntityRef,
    /// Predicate.
    pub predicate: Predicate,
    /// Object.
    pub object: EntityRef,
}

/// A relationship edge: live, or the skeleton of a forgotten one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RelationshipEdge {
    /// Forgotten.
    Forgotten(MemorySkeleton),
    /// Live.
    Live(Box<LiveRelationshipEdge>),
}

impl RelationshipEdge {
    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> MemoryRecordId {
        match self {
            Self::Forgotten(s) => s.id,
            Self::Live(l) => l.record.id,
        }
    }
}

impl LiveMemoryRecord {
    /// Checks the conditional M-7 rules without refusing unknown fields, as the M-40 reader does.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn check_rules(&self) -> Result<(), ContractViolation> {
        use super::fields::ContentType;
        use crate::ontology::provenance::ProvenanceLabel as P;
        self.header.check(Concept::MemoryRecord)?;
        require(
            !self.source_episodes.is_empty() && unique(&self.source_episodes),
            "source_episodes",
        )?;
        require(
            (self.header.version == NonZeroU32::MIN) == self.supersedes.is_none(),
            "version_chain",
        )?;
        let state = self.epistemic_state;
        require(
            (state == EpistemicState::Invalidated) == self.superseded_at.is_some(),
            "superseded_at",
        )?;
        require(
            (self.time_kind == TimeKind::Current) == self.expected_end.is_some(),
            "expected_end",
        )?;
        require(
            (self.time_kind == TimeKind::Seasonal) == self.season.is_some(),
            "season",
        )?;
        require(
            self.time_kind != TimeKind::OneOff || self.valid_to.is_some(),
            "valid_to",
        )?;
        if let Some(season) = &self.season {
            require(
                (1..=11).contains(&season.months.len())
                    && unique(&season.months)
                    && season.months.iter().all(|m| (1..=12).contains(m)),
                "season",
            )?;
        }
        if self.layer == Layer::BehaviourRule {
            require(
                matches!(
                    self.source_kind,
                    SourceKind::UserStatement
                        | SourceKind::UserBehaviour
                        | SourceKind::ConnectedSource
                ),
                "behaviour_rule_source",
            )?;
        }
        let label = self.header.provenance;
        if matches!(
            state,
            EpistemicState::Observed | EpistemicState::Inferred | EpistemicState::Hypothesis
        ) {
            require(!label.is_trusted(), "provenance")?;
        }
        if matches!(
            self.source_kind,
            SourceKind::ExternalContent | SourceKind::Import
        ) {
            require(
                !matches!(label, P::UserDirect | P::RecordTrusted),
                "provenance",
            )?;
            if label == P::UserMemory {
                require(
                    matches!(
                        state,
                        EpistemicState::Verified | EpistemicState::Invalidated
                    ),
                    "provenance",
                )?;
            }
        }
        if let ContentType::Extension(e) = &self.content_type {
            require(
                e.version >= 1 && is_memory_extension_name(&e.name, false),
                "content_type",
            )?;
        }
        require(self.evidence.observation_count >= 1, "evidence")?;
        require((0.0..=1.0).contains(&self.trust.value), "trust")?;
        if let Some(u) = &self.usage_restriction {
            require(
                !u.areas.is_empty() || !u.projects.is_empty(),
                "usage_restriction",
            )?;
        }
        Ok(())
    }

    /// Checks a canonical record strictly: the M-7 rules and no unknown field at any level.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        no_unknown(&self.unknown)?;
        no_unknown(&self.evidence.unknown)?;
        no_unknown(&self.trust.unknown)?;
        self.check_rules()
    }
}

impl MemoryRecord {
    /// Checks a canonical record strictly; a skeleton has nothing beyond its seven fields.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Forgotten(s) => no_unknown(&s.unknown),
            Self::Live(l) => l.validate(),
        }
    }
}

fn predicate_ok(p: &Predicate) -> bool {
    match p {
        Predicate::Core(_) => true,
        Predicate::Extension(e) => e.version >= 1 && is_memory_extension_name(&e.name, true),
    }
}

impl LiveRelationshipEdge {
    /// Checks the M-7 rules and the predicate without refusing unknown fields.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn check_rules(&self) -> Result<(), ContractViolation> {
        self.record.check_rules()?;
        require(predicate_ok(&self.predicate), "predicate")
    }

    /// Checks a canonical edge strictly.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.record.validate()?;
        require(predicate_ok(&self.predicate), "predicate")
    }
}

impl RelationshipEdge {
    /// Checks a canonical edge strictly.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::Forgotten(s) => no_unknown(&s.unknown),
            Self::Live(l) => l.validate(),
        }
    }
}
