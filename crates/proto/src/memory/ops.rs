//! Record operations as pure decisions: writes need existing source episodes, nothing is deleted or edited in place, corrections and edge changes add versions, bitemporal queries, filtered hybrid retrieval, embedding version separation, consolidation placement and the change, exception, contradiction and consistent effects (M-6, M-10, M-11, M-12, M-17, M-20, C-20, C-22, PV-65).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::fields::{EpistemicState, Layer, LiveStatus, Predicate, TimeKind};
use crate::data_class::DataClass;
use crate::id::{EpisodeId, MemoryRecordId};
use crate::ontology::time::Instant;

/// Why a memory operation was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MemoryError {
    /// A record without a source episode.
    EmptySourceEpisodes,
    /// A source episode that does not exist.
    UnknownSourceEpisode,
    /// Records are never physically deleted.
    NoPhysicalDelete,
    /// Records change only by new versions.
    RecordsAreVersioned,
    /// The text view is generated, never edited.
    ViewIsDerived,
    /// Dense-only retrieval.
    HybridRequired,
    /// Vectors of two embedding models would mix.
    ReindexIncomplete,
}

/// Checks the sources of a record before it is written (M-6).
///
/// # Errors
/// [`MemoryError::EmptySourceEpisodes`] or [`MemoryError::UnknownSourceEpisode`].
pub fn check_write(
    source_episodes: &[EpisodeId],
    existing: Option<&[EpisodeId]>,
) -> Result<(), MemoryError> {
    if source_episodes.is_empty() {
        return Err(MemoryError::EmptySourceEpisodes);
    }
    if existing.is_some_and(|existing| source_episodes.iter().any(|e| !existing.contains(e))) {
        return Err(MemoryError::UnknownSourceEpisode);
    }
    Ok(())
}

/// A physical delete; always refused (C-20).
///
/// # Errors
/// Always [`MemoryError::NoPhysicalDelete`].
pub const fn physical_delete(_record: MemoryRecordId) -> Result<(), MemoryError> {
    Err(MemoryError::NoPhysicalDelete)
}

/// An in-place update; always refused (M-6).
///
/// # Errors
/// Always [`MemoryError::RecordsAreVersioned`].
pub const fn update_in_place(_record: MemoryRecordId) -> Result<(), MemoryError> {
    Err(MemoryError::RecordsAreVersioned)
}

/// An edit of the text view; always refused (M-6).
///
/// # Errors
/// Always [`MemoryError::ViewIsDerived`].
pub const fn edit_text_view(_record: MemoryRecordId) -> Result<(), MemoryError> {
    Err(MemoryError::ViewIsDerived)
}

crate::const_tag!(
    /// The identifier slot of a record not yet minted: `"new"`.
    NewRecord,
    "new"
);

/// The identifier of a version: an existing record or a new one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecordSlot {
    /// An existing record.
    Existing(MemoryRecordId),
    /// A record to be minted.
    New(NewRecord),
}

/// The state a version ends up in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionState {
    /// The record.
    pub id: RecordSlot,
    /// Its version.
    pub version: NonZeroU32,
    /// What it supersedes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<MemoryRecordId>,
    /// Epistemic state.
    pub epistemic_state: EpistemicState,
    /// Superseded time.
    pub superseded_at: Option<Instant>,
    /// Lifecycle.
    pub status: LiveStatus,
}

/// A correction: the old version becomes `invalidated`, a new record supersedes it and both remain (C-20, M-6).
#[must_use]
pub fn correction(record: MemoryRecordId, version: NonZeroU32, at: Instant) -> [VersionState; 2] {
    [
        VersionState {
            id: RecordSlot::Existing(record),
            version,
            supersedes: None,
            epistemic_state: EpistemicState::Invalidated,
            superseded_at: Some(at),
            status: LiveStatus::Active,
        },
        VersionState {
            id: RecordSlot::New(NewRecord),
            version: version.saturating_add(1),
            supersedes: Some(record),
            epistemic_state: EpistemicState::Stated,
            superseded_at: None,
            status: LiveStatus::Active,
        },
    ]
}

/// A version of a relationship edge after a change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeVersionState {
    /// The edge.
    pub id: RecordSlot,
    /// Its version.
    pub version: NonZeroU32,
    /// What it supersedes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<MemoryRecordId>,
    /// Valid time start of a new edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<Instant>,
    /// Valid time end.
    pub valid_to: Option<Instant>,
    /// Time kind of a closed edge.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_kind: Option<TimeKind>,
    /// Transaction time.
    pub recorded_at: Instant,
}

/// A superseded version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupersededVersion {
    /// The record.
    pub id: MemoryRecordId,
    /// Its version.
    pub version: NonZeroU32,
    /// `invalidated`.
    pub epistemic_state: EpistemicState,
    /// When it was superseded.
    pub superseded_at: Instant,
}

/// A relationship change: the old edge gets a closing version in the past, a new edge opens, the previous version is invalidated; all stay queryable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeChange {
    /// The closing version, then the new edge.
    pub edges: [EdgeVersionState; 2],
    /// The version the closing one supersedes.
    pub superseded: [SupersededVersion; 1],
}

/// Closes `edge` at `changed_at` and opens a new one, both learned at `learned_at` (M-10).
#[must_use]
pub fn change_edge(
    edge: MemoryRecordId,
    version: NonZeroU32,
    changed_at: Instant,
    learned_at: Instant,
) -> EdgeChange {
    EdgeChange {
        edges: [
            EdgeVersionState {
                id: RecordSlot::Existing(edge),
                version: version.saturating_add(1),
                supersedes: Some(edge),
                valid_from: None,
                valid_to: Some(changed_at),
                time_kind: Some(TimeKind::Past),
                recorded_at: learned_at,
            },
            EdgeVersionState {
                id: RecordSlot::New(NewRecord),
                version: NonZeroU32::MIN,
                supersedes: None,
                valid_from: Some(changed_at),
                valid_to: None,
                time_kind: None,
                recorded_at: learned_at,
            },
        ],
        superseded: [SupersededVersion {
            id: edge,
            version,
            epistemic_state: EpistemicState::Invalidated,
            superseded_at: learned_at,
        }],
    }
}

/// Whether a cached view was reused or rebuilt.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewOutcome {
    /// Every record is at the cached version.
    Cached,
    /// Rebuilt from the records.
    Rebuilt,
}

/// A view build and the record versions it came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ViewBuild {
    /// Outcome.
    pub outcome: ViewOutcome,
    /// Record versions the view reflects.
    pub view_source_versions: BTreeMap<MemoryRecordId, u32>,
}

/// Rebuilds a view whose records moved past the cached version (C-22).
#[must_use]
pub fn build_view(
    cached_view_version: u32,
    record_versions: &BTreeMap<MemoryRecordId, u32>,
) -> ViewBuild {
    let stale = record_versions.values().any(|v| *v > cached_view_version);
    ViewBuild {
        outcome: if stale {
            ViewOutcome::Rebuilt
        } else {
            ViewOutcome::Cached
        },
        view_source_versions: record_versions.clone(),
    }
}

/// One stored version of a bitemporal relationship edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeVersion<E> {
    /// The edge.
    pub id: MemoryRecordId,
    /// Its version.
    pub version: NonZeroU32,
    /// Subject.
    pub subject: E,
    /// Predicate.
    pub predicate: Predicate,
    /// Object.
    pub object: E,
    /// Valid time start.
    pub valid_from: Instant,
    /// Valid time end.
    pub valid_to: Option<Instant>,
    /// Transaction time start.
    pub recorded_at: Instant,
    /// Transaction time end.
    pub superseded_at: Option<Instant>,
}

/// A query over valid time and transaction time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeQuery<E> {
    /// Subject.
    pub subject: E,
    /// Predicate.
    pub predicate: Predicate,
    /// Holds in the world at.
    pub valid_at: Instant,
    /// As One knew it at.
    pub known_at: Instant,
}

/// Answers a bitemporal query: versions known at `known_at` whose validity covers `valid_at` (M-10, M-11).
#[must_use]
pub fn query_edges<'a, E: PartialEq>(
    edges: &'a [EdgeVersion<E>],
    query: &EdgeQuery<E>,
) -> Vec<&'a EdgeVersion<E>> {
    edges
        .iter()
        .filter(|e| {
            e.subject == query.subject
                && e.predicate.core() == query.predicate.core()
                && e.recorded_at <= query.known_at
                && e.superseded_at.is_none_or(|s| s > query.known_at)
                && e.valid_from <= query.valid_at
                && e.valid_to.is_none_or(|t| query.valid_at < t)
        })
        .collect()
}

/// A retrieval mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    /// Dense, lexical and relation search together.
    Hybrid,
    /// Dense vectors only.
    DenseOnly,
}

/// A retrieval candidate before filtering.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Candidate {
    /// The record.
    pub id: MemoryRecordId,
    /// Lifecycle.
    pub status: LiveStatus,
    /// Epistemic state.
    pub epistemic_state: EpistemicState,
    /// Dense similarity.
    pub similarity: f64,
    /// Lexical score.
    pub lexical: f64,
}

/// Why a candidate was excluded before search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Exclusion {
    /// Invalidated.
    Invalidated,
    /// Suppressed.
    Suppressed,
    /// A candidate.
    Candidate,
}

/// Candidates split by the status and validity filters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Filtered {
    /// Eligible records in input order.
    pub eligible: Vec<MemoryRecordId>,
    /// Excluded records with the reason.
    pub excluded: BTreeMap<MemoryRecordId, Exclusion>,
}

/// Runs the status and validity filters before any similarity ranking (M-11).
///
/// # Errors
/// [`MemoryError::HybridRequired`] for dense-only retrieval.
pub fn filter_candidates(
    candidates: &[Candidate],
    mode: SearchMode,
) -> Result<Filtered, MemoryError> {
    if mode != SearchMode::Hybrid {
        return Err(MemoryError::HybridRequired);
    }
    let mut out = Filtered {
        eligible: Vec::new(),
        excluded: BTreeMap::new(),
    };
    for c in candidates {
        let reason = match (c.status, c.epistemic_state) {
            (LiveStatus::Suppressed, _) => Some(Exclusion::Suppressed),
            (LiveStatus::Candidate, _) => Some(Exclusion::Candidate),
            (LiveStatus::Active, EpistemicState::Invalidated) => Some(Exclusion::Invalidated),
            (LiveStatus::Active, _) => None,
        };
        match reason {
            Some(r) => {
                out.excluded.insert(c.id, r);
            }
            None => out.eligible.push(c.id),
        }
    }
    Ok(out)
}

/// An embedding model version, such as `embedding@2`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct EmbeddingVersion(pub String);

/// One indexed vector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IndexedVector {
    /// The record.
    pub id: MemoryRecordId,
    /// The embedding model version.
    pub model: EmbeddingVersion,
}

/// The vectors a query may search: only the query model's, and only after reindexing finished (M-12).
///
/// # Errors
/// [`MemoryError::ReindexIncomplete`] while reindexing.
pub fn searchable(
    query_model: &EmbeddingVersion,
    index: &[IndexedVector],
    reindex_complete: bool,
) -> Result<Vec<MemoryRecordId>, MemoryError> {
    if !reindex_complete {
        return Err(MemoryError::ReindexIncomplete);
    }
    Ok(index
        .iter()
        .filter(|v| &v.model == query_model)
        .map(|v| v.id)
        .collect())
}

/// A consolidation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConsolidationStep {
    /// Candidate detection, on the phone, without a language model.
    CandidateDetection,
    /// Structuring.
    Structuring,
    /// Merge.
    Merge,
    /// Contradiction detection.
    ContradictionDetection,
}

/// The state of the PV-65 key permit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KeyPermit {
    /// None.
    None,
    /// Valid.
    Valid,
    /// Expired.
    Expired,
}

/// Inputs to placement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlacementInput {
    /// The step.
    pub step: ConsolidationStep,
    /// The data class.
    pub data_class: DataClass,
    /// The data is in a device-only sensitive class.
    pub device_only: bool,
    /// The user is present.
    pub user_present: bool,
    /// The PV-65 permit.
    pub key_permit: KeyPermit,
    /// The cloud TEE is attested.
    pub tee_attested: bool,
}

/// Where a step runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// On the device.
    Device,
    /// In the attested cloud TEE, in the user's encrypted space.
    CloudTee,
    /// Nowhere.
    None,
}

/// Whether a step runs now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StepOutcome {
    /// Runs.
    Run,
    /// Waits for the user or a permit.
    Wait,
    /// Never runs for this data.
    NotRun,
    /// Refused: no attestation.
    Refused,
}

/// The placement of a consolidation step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Placement {
    /// Where.
    pub location: Location,
    /// Whether a language model is used.
    pub uses_language_model: bool,
    /// Whether it runs.
    pub outcome: StepOutcome,
}

/// Places a consolidation step (M-17, M-37, PV-65).
#[must_use]
pub const fn place(input: &PlacementInput) -> Placement {
    if matches!(input.step, ConsolidationStep::CandidateDetection) {
        return Placement {
            location: Location::Device,
            uses_language_model: false,
            outcome: StepOutcome::Run,
        };
    }
    if input.device_only {
        return Placement {
            location: Location::None,
            uses_language_model: false,
            outcome: StepOutcome::NotRun,
        };
    }
    if !input.tee_attested {
        return Placement {
            location: Location::None,
            uses_language_model: false,
            outcome: StepOutcome::Refused,
        };
    }
    let permitted = input.user_present || matches!(input.key_permit, KeyPermit::Valid);
    Placement {
        location: Location::CloudTee,
        uses_language_model: true,
        outcome: if permitted {
            StepOutcome::Run
        } else {
            StepOutcome::Wait
        },
    }
}

/// How a new statement relates to an existing record; the classifier's output (M-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ChangeClass {
    /// The fact changed.
    Change,
    /// A one-time exception.
    Exception,
    /// Two sources disagree.
    Contradiction,
    /// A reaffirmation.
    Consistent,
}

crate::const_tag!(
    /// `"existing"`: the record the new one relates to.
    ExistingRecord,
    "existing"
);
crate::const_tag!(
    /// `"set"`: a time is recorded.
    Set,
    "set"
);
crate::const_tag!(
    /// `"unchanged"`.
    Unchanged,
    "unchanged"
);
crate::const_tag!(
    /// `"new_episode_added"`.
    NewEpisodeAdded,
    "new_episode_added"
);
crate::const_tag!(
    /// `"both_marked"`: retrieval returns both records marked contested.
    BothMarked,
    "both_marked"
);

/// The new record a statement creates.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NewRecordEffect {
    /// Lifecycle.
    pub status: LiveStatus,
    /// Epistemic state of a change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub epistemic_state: Option<EpistemicState>,
    /// A change supersedes the existing record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supersedes: Option<Option<ExistingRecord>>,
    /// Time kind of an exception.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_kind: Option<TimeKind>,
    /// Layer of an exception.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layer: Option<Layer>,
    /// Marked contested.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contested: Option<bool>,
}

/// What happens to the existing record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ExistingEffect {
    /// Nothing.
    Unchanged(Unchanged),
    /// Invalidated with a superseded time.
    Invalidated {
        /// `invalidated`.
        epistemic_state: EpistemicState,
        /// `set`.
        superseded_at: Set,
    },
    /// Marked contested; its epistemic state stays.
    Contested {
        /// `true`.
        contested: bool,
        /// `unchanged`.
        epistemic_state: Unchanged,
    },
    /// Gains the new episode as evidence.
    Reaffirmed {
        /// `new_episode_added`.
        evidence: NewEpisodeAdded,
    },
}

/// The effect of a classified statement; nothing is ever deleted (M-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeEffect {
    /// The new record, if any.
    pub new_record: Option<NewRecordEffect>,
    /// The existing record.
    pub existing_record: ExistingEffect,
    /// Always `false`.
    pub deleted: bool,
    /// Retrieval marking of a contradiction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retrieval: Option<BothMarked>,
}

const NEW_ACTIVE: NewRecordEffect = NewRecordEffect {
    status: LiveStatus::Active,
    epistemic_state: None,
    supersedes: None,
    time_kind: None,
    layer: None,
    contested: None,
};

/// The effect of each class (M-20).
#[must_use]
pub const fn change_effect(class: ChangeClass) -> ChangeEffect {
    match class {
        ChangeClass::Change => ChangeEffect {
            new_record: Some(NewRecordEffect {
                epistemic_state: Some(EpistemicState::Stated),
                supersedes: Some(Some(ExistingRecord)),
                ..NEW_ACTIVE
            }),
            existing_record: ExistingEffect::Invalidated {
                epistemic_state: EpistemicState::Invalidated,
                superseded_at: Set,
            },
            deleted: false,
            retrieval: None,
        },
        ChangeClass::Exception => ChangeEffect {
            new_record: Some(NewRecordEffect {
                supersedes: Some(None),
                time_kind: Some(TimeKind::OneOff),
                layer: Some(Layer::Event),
                ..NEW_ACTIVE
            }),
            existing_record: ExistingEffect::Unchanged(Unchanged),
            deleted: false,
            retrieval: None,
        },
        ChangeClass::Contradiction => ChangeEffect {
            new_record: Some(NewRecordEffect {
                contested: Some(true),
                ..NEW_ACTIVE
            }),
            existing_record: ExistingEffect::Contested {
                contested: true,
                epistemic_state: Unchanged,
            },
            deleted: false,
            retrieval: Some(BothMarked),
        },
        ChangeClass::Consistent => ChangeEffect {
            new_record: None,
            existing_record: ExistingEffect::Reaffirmed {
                evidence: NewEpisodeAdded,
            },
            deleted: false,
            retrieval: None,
        },
    }
}
