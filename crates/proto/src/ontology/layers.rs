//! Layer separation: observation, inference, memory and interaction convert only through the six named conversions of `layers.toml`; nothing converts into authority, which only a user act in Access creates (C-8, M-1, C-14, C-20, F-7 (1)).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::concept::{CanonicalId, CanonicalNode, Concept};
use super::observation::{Observation, ObservationSource};
use super::provenance::ProvenanceLabel;
use super::relation::{RelationEdge, RelationError, RelationKind, RelationTarget};
use super::time::Instant;
use crate::id::InteractionId;
use crate::memory::fields::{EpistemicState, LiveStatus, SourceKind};
use crate::memory::record::LiveMemoryRecord;

/// An ontology layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OntologyLayer {
    /// Observations.
    Observation,
    /// Inferred and hypothesis records.
    Inference,
    /// Stated, observed, verified and invalidated records, Goals and Routines.
    Memory,
    /// Interactions.
    Interaction,
    /// Access Grants and Mandates; One never creates one.
    Authority,
}

/// A permitted conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conversion {
    /// Explicit remember: an utterance becomes a stated record.
    RememberExplicit,
    /// Background inference.
    Infer,
    /// An observed record.
    RecordObserved,
    /// Confirmation lifts an inference into memory.
    Confirm,
    /// A correction supersedes.
    Correct,
    /// A suggestion Interaction.
    Suggest,
}

impl Conversion {
    /// The six conversions, in contract order.
    pub const ALL: [Self; 6] = [
        Self::RememberExplicit,
        Self::Infer,
        Self::RecordObserved,
        Self::Confirm,
        Self::Correct,
        Self::Suggest,
    ];

    /// The source layer.
    #[must_use]
    pub const fn from_layer(self) -> OntologyLayer {
        match self {
            Self::RememberExplicit | Self::Infer | Self::RecordObserved => {
                OntologyLayer::Observation
            }
            Self::Confirm => OntologyLayer::Inference,
            Self::Correct | Self::Suggest => OntologyLayer::Memory,
        }
    }

    /// The target layer; never [`OntologyLayer::Authority`].
    #[must_use]
    pub const fn to_layer(self) -> OntologyLayer {
        match self {
            Self::RememberExplicit | Self::RecordObserved | Self::Confirm | Self::Correct => {
                OntologyLayer::Memory
            }
            Self::Infer => OntologyLayer::Inference,
            Self::Suggest => OntologyLayer::Interaction,
        }
    }
}

/// The conversions from one layer to another, in contract order; empty means rejected.
#[must_use]
pub fn conversions(from: OntologyLayer, to: OntologyLayer) -> Vec<Conversion> {
    Conversion::ALL
        .into_iter()
        .filter(|c| c.from_layer() == from && c.to_layer() == to)
        .collect()
}

/// The layer a memory record sits in.
#[must_use]
pub const fn layer_of(record: &LiveMemoryRecord) -> OntologyLayer {
    match record.epistemic_state {
        EpistemicState::Inferred | EpistemicState::Hypothesis => OntologyLayer::Inference,
        EpistemicState::Stated
        | EpistemicState::Observed
        | EpistemicState::Verified
        | EpistemicState::Invalidated => OntologyLayer::Memory,
    }
}

/// A conversion its input does not allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LayerError {
    /// The Observation is not the user's utterance.
    NotAnUtterance,
    /// The record does not name the Observation's Episode as a source.
    SourceMissing,
    /// The record is not in the inference layer.
    NotAnInference,
    /// The record is not in the memory layer.
    NotInMemory,
    /// A trusted label on an observed record.
    TrustedLabel,
    /// Only a Goal, Routine or memory record can be suggested.
    NotSuggestible,
}

/// Explicit remember: the user's utterance becomes a `stated`, `active` record labelled `user.memory` (M-15).
///
/// # Errors
/// [`LayerError::NotAnUtterance`] or [`LayerError::SourceMissing`].
pub fn remember_explicit(
    observation: &Observation,
    mut record: LiveMemoryRecord,
) -> Result<LiveMemoryRecord, LayerError> {
    if observation.source_kind != ObservationSource::UserUtterance {
        return Err(LayerError::NotAnUtterance);
    }
    if !record.source_episodes.contains(&observation.episode) {
        return Err(LayerError::SourceMissing);
    }
    record.epistemic_state = EpistemicState::Stated;
    record.status = LiveStatus::Active;
    record.source_kind = SourceKind::UserStatement;
    record.header.provenance = ProvenanceLabel::UserMemory;
    record.superseded_at = None;
    Ok(record)
}

/// Background inference: an `inferred` record is `active`, a `hypothesis` is a `candidate`; both are labelled `one.inferred` unless external (M-15).
#[must_use]
pub fn infer(mut record: LiveMemoryRecord, hypothesis: bool) -> LiveMemoryRecord {
    if hypothesis {
        record.epistemic_state = EpistemicState::Hypothesis;
        record.status = LiveStatus::Candidate;
    } else {
        record.epistemic_state = EpistemicState::Inferred;
        record.status = LiveStatus::Active;
    }
    if !record.header.provenance.is_external() {
        record.header.provenance = ProvenanceLabel::OneInferred;
    }
    record.superseded_at = None;
    record
}

/// An observed record from an Observation, `active` or `candidate` (M-15).
///
/// # Errors
/// [`LayerError::SourceMissing`] or [`LayerError::TrustedLabel`].
pub fn record_observed(
    observation: &Observation,
    mut record: LiveMemoryRecord,
    candidate: bool,
) -> Result<LiveMemoryRecord, LayerError> {
    if !record.source_episodes.contains(&observation.episode) {
        return Err(LayerError::SourceMissing);
    }
    if record.header.provenance.is_trusted() {
        return Err(LayerError::TrustedLabel);
    }
    record.epistemic_state = EpistemicState::Observed;
    record.status = if candidate {
        LiveStatus::Candidate
    } else {
        LiveStatus::Active
    };
    record.superseded_at = None;
    Ok(record)
}

/// What lifts an inference into memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfirmationEvidence {
    /// The user confirmed the value shown on a trusted surface at this time; the label becomes `user.memory`.
    User(Instant),
    /// An independent second evidence; lifts `external.*` only to `one.inferred`.
    SecondEvidence,
}

/// Confirmation: an inference becomes `verified` and `active` (M-18).
///
/// # Errors
/// [`LayerError::NotAnInference`].
pub fn confirm(
    mut record: LiveMemoryRecord,
    evidence: ConfirmationEvidence,
) -> Result<LiveMemoryRecord, LayerError> {
    if layer_of(&record) != OntologyLayer::Inference {
        return Err(LayerError::NotAnInference);
    }
    record.epistemic_state = EpistemicState::Verified;
    record.status = LiveStatus::Active;
    match evidence {
        ConfirmationEvidence::User(at) => {
            record.evidence.user_confirmed_at = Some(at);
            record.header.provenance = ProvenanceLabel::UserMemory;
        }
        ConfirmationEvidence::SecondEvidence => {
            if record.header.provenance.is_external() {
                record.header.provenance = ProvenanceLabel::OneInferred;
            }
        }
    }
    Ok(record)
}

/// Correction: `next` supersedes `previous` at the next version and `previous` becomes `invalidated` at `at`; both remain (C-20).
///
/// # Errors
/// [`LayerError::NotInMemory`] when `previous` is not in the memory layer.
pub fn correct(
    mut previous: LiveMemoryRecord,
    mut next: LiveMemoryRecord,
    at: Instant,
) -> Result<(LiveMemoryRecord, LiveMemoryRecord), LayerError> {
    if layer_of(&previous) != OntologyLayer::Memory {
        return Err(LayerError::NotInMemory);
    }
    next.supersedes = Some(previous.id);
    next.header.version = previous.header.version.saturating_add(1);
    next.superseded_at = None;
    previous.epistemic_state = EpistemicState::Invalidated;
    previous.superseded_at = Some(at);
    Ok((previous, next))
}

crate::const_tag!(
    /// `interaction_kind: "approval"`.
    Approval,
    "approval"
);

/// A suggestion: an approval Interaction that concerns a record; the Interaction is not authority, Access decides.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suggestion {
    /// `approval`.
    pub interaction_kind: Approval,
    /// The `concerns` edge.
    pub concerns: RelationEdge,
}

/// Suggest: a Routine, Goal or memory record reaches action only through an approval Interaction (C-14).
///
/// # Errors
/// [`LayerError::NotSuggestible`] for any other target.
pub fn suggest(
    interaction: InteractionId,
    target: CanonicalNode,
    at: Instant,
) -> Result<Suggestion, LayerError> {
    if !matches!(
        target.concept(),
        Concept::Routine | Concept::Goal | Concept::MemoryRecord
    ) {
        return Err(LayerError::NotSuggestible);
    }
    let concerns = RelationEdge::new(
        RelationKind::Concerns,
        CanonicalNode(CanonicalId::Interaction(interaction)),
        RelationTarget::Node(target),
        at,
    )
    .map_err(|_: RelationError| LayerError::NotSuggestible)?;
    Ok(Suggestion {
        interaction_kind: Approval,
        concerns,
    })
}
