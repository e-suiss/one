//! The M-7 memory record fields: content type, epistemic state, layer, time kind, source kind, lifecycle, season, evidence, trust, alternative explanations, usage restriction and relationship predicates (M-7, M-8, M-9, M-10, M-13, M-22, M-24, M-30).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::data_class::LifeArea;
use crate::id::{MemoryRecordId, ProjectId};
use crate::ontology::reference::EntityRef;
use crate::ontology::time::Instant;
use crate::ontology::validate::UnknownFields;

/// A core memory content type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreContentType {
    /// Preference.
    Preference,
    /// Routine.
    Routine,
    /// Goal.
    Goal,
    /// Constraint.
    Constraint,
    /// Relationship.
    Relationship,
    /// Personal fact.
    PersonalFact,
    /// Opinion.
    Opinion,
    /// Event.
    Event,
}

impl CoreContentType {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Preference => "preference",
            Self::Routine => "routine",
            Self::Goal => "goal",
            Self::Constraint => "constraint",
            Self::Relationship => "relationship",
            Self::PersonalFact => "personal_fact",
            Self::Opinion => "opinion",
            Self::Event => "event",
        }
    }
}

/// An extension of a core vocabulary, mapped to a core value (C-7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct VocabularyExtension<T> {
    /// `app.suiss.memory.…`.
    pub name: String,
    /// Version, from 1.
    pub version: u32,
    /// The core value it maps to.
    pub maps_to: T,
}

/// A memory content type: core or extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContentType {
    /// A core type.
    Core(CoreContentType),
    /// An extension mapped to a core type.
    Extension(VocabularyExtension<CoreContentType>),
}

impl ContentType {
    /// The core type it renders as.
    #[must_use]
    pub const fn core(&self) -> CoreContentType {
        match self {
            Self::Core(c) => *c,
            Self::Extension(e) => e.maps_to,
        }
    }
}

/// How the record is known (M-8).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpistemicState {
    /// The user said it.
    Stated,
    /// Observed from behaviour or a source.
    Observed,
    /// Inferred by One.
    Inferred,
    /// A hypothesis.
    Hypothesis,
    /// Confirmed by the user or a second evidence.
    Verified,
    /// No longer holds.
    Invalidated,
}

impl EpistemicState {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Stated => "stated",
            Self::Observed => "observed",
            Self::Inferred => "inferred",
            Self::Hypothesis => "hypothesis",
            Self::Verified => "verified",
            Self::Invalidated => "invalidated",
        }
    }
}

/// The memory layer (M-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Layer {
    /// One event.
    Event,
    /// A consolidated fact.
    ConsolidatedFact,
    /// A behaviour rule.
    BehaviourRule,
}

/// How long the record holds (M-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeKind {
    /// Permanent.
    Permanent,
    /// Current, with an expected end.
    Current,
    /// Seasonal, with months.
    Seasonal,
    /// One time.
    OneOff,
    /// In the past.
    Past,
}

/// Where the evidence came from (M-13).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// The user's statement.
    UserStatement,
    /// The user's behaviour.
    UserBehaviour,
    /// A connected source.
    ConnectedSource,
    /// External content.
    ExternalContent,
    /// An import.
    Import,
}

/// The lifecycle of a record (M-24, M-25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleState {
    /// Waiting for confirmation.
    Candidate,
    /// In use.
    Active,
    /// Not used.
    Suppressed,
    /// Permanently forgotten.
    Forgotten,
}

/// The lifecycle of a live record: anything but forgotten.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveStatus {
    /// Waiting for confirmation.
    Candidate,
    /// In use.
    Active,
    /// Not used.
    Suppressed,
}

impl From<LiveStatus> for LifecycleState {
    fn from(s: LiveStatus) -> Self {
        match s {
            LiveStatus::Candidate => Self::Candidate,
            LiveStatus::Active => Self::Active,
            LiveStatus::Suppressed => Self::Suppressed,
        }
    }
}

/// The months a seasonal record holds, 1 to 11 distinct months.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Season {
    /// Months, 1..=12.
    pub months: Vec<u8>,
}

/// The evidence behind a record (M-13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    /// Observations, at least 1.
    pub observation_count: u32,
    /// Supporting observations, at most `observation_count`.
    pub supporting_count: u32,
    /// First observation.
    pub first_observed_at: Instant,
    /// Last observation.
    pub last_observed_at: Instant,
    /// Records that contradict this one.
    pub contradicting_records: Vec<MemoryRecordId>,
    /// When the user confirmed it, or `null`.
    pub user_confirmed_at: Option<Instant>,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
crate::const_tag!(
    /// The trust formula version `trust/v1`.
    TrustFormula,
    "trust/v1"
);

/// A computed trust value (M-13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Trust {
    /// 0..=1, six decimals.
    pub value: f64,
    /// The formula.
    pub formula: TrustFormula,
    /// When it was computed.
    pub computed_at: Instant,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
/// The kind of an alternative explanation (M-22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AlternativeKind {
    /// About someone else.
    DifferentSubject,
    /// For another purpose.
    DifferentPurpose,
    /// A one-off context.
    OneOffContext,
    /// An external cause.
    ExternalCause,
}

/// A typed alternative explanation of the evidence (M-22).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AlternativeExplanation {
    /// The kind.
    pub kind: AlternativeKind,
    /// Whom or what it is about instead.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub about: Option<EntityRef>,
    /// The record that explains it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record: Option<MemoryRecordId>,
}

/// Where a record may be used; at least one area or project (M-30).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct UsageRestriction {
    /// Allowed life areas.
    pub areas: Vec<LifeArea>,
    /// Allowed projects.
    pub projects: Vec<ProjectId>,
}

/// A core relationship predicate (M-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorePredicate {
    /// Has manager.
    HasManager,
    /// Has report.
    HasReport,
    /// Has colleague.
    HasColleague,
    /// Has partner.
    HasPartner,
    /// Has parent.
    HasParent,
    /// Has child.
    HasChild,
    /// Has sibling.
    HasSibling,
    /// Has friend.
    HasFriend,
    /// Knows.
    Knows,
    /// Works at.
    WorksAt,
    /// Studies at.
    StudiesAt,
    /// Lives in.
    LivesIn,
    /// Member of.
    MemberOf,
}

/// A relationship predicate: core or extension.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Predicate {
    /// A core predicate.
    Core(CorePredicate),
    /// An extension mapped to a core predicate.
    Extension(VocabularyExtension<CorePredicate>),
}

impl Predicate {
    /// The core predicate it maps to.
    #[must_use]
    pub const fn core(&self) -> CorePredicate {
        match self {
            Self::Core(c) => *c,
            Self::Extension(e) => e.maps_to,
        }
    }
}
