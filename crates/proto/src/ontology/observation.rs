//! Observation: one thing One saw or heard, always data, with its source and read time instead of a copy of the source object (C-10, C-8).

use alloc::string::String;

use serde::{Deserialize, Serialize};

use super::concept::Concept;
use super::extension::Extensions;
use super::header::{LocalText, RecordHeader};
use super::reference::AnyRef;
use super::tags::{Active, DataRole, ObservationType};
use super::time::Instant;
use super::validate::{ContractViolation, UnknownFields, no_unknown, require};
use crate::data_class::RetentionClass;
use crate::id::{EpisodeId, ObservationId};

/// Where an observation came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationSource {
    /// Something the user said.
    UserUtterance,
    /// A device signal.
    DeviceSignal,
    /// An item read from a connected account.
    ConnectedAccountItem,
    /// External content.
    ExternalContent,
    /// A message from another agent.
    AgentMessage,
    /// A capability's output.
    CapabilityOutput,
}

impl ObservationSource {
    /// A foreign source: carries `source` and `summary`, never `content`.
    #[must_use]
    pub const fn is_foreign(self) -> bool {
        matches!(
            self,
            Self::ConnectedAccountItem
                | Self::ExternalContent
                | Self::AgentMessage
                | Self::CapabilityOutput
        )
    }
}

/// A pointer to the source object and when it was read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SourceRead<R> {
    /// The source object.
    #[serde(rename = "ref")]
    pub reference: R,
    /// When One read it.
    pub read_at: Instant,
}

/// The capture modality of a raw observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Voice.
    Voice,
    /// Screen.
    Screen,
    /// Camera.
    Camera,
    /// Location.
    Location,
}

/// A raw capture; stored only on request, then in `one_observation`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RawCapture {
    /// The modality.
    pub modality: Modality,
    /// Whether the raw capture is stored.
    pub store: bool,
    /// The blob key of a stored capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_key: Option<String>,
}

/// An Observation record (C-10).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Observation {
    /// `Observation`.
    #[serde(rename = "type")]
    pub concept: ObservationType,
    /// Identifier.
    pub id: ObservationId,
    /// C-19 header.
    #[serde(flatten)]
    pub header: RecordHeader,
    /// The version this one replaces, or `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub supersedes: Option<ObservationId>,
    /// `active`.
    pub status: Active,
    /// The Episode it belongs to.
    pub episode: EpisodeId,
    /// Where it came from.
    pub source_kind: ObservationSource,
    /// `data`.
    pub content_role: DataRole,
    /// When it was observed.
    pub observed_at: Instant,
    /// The foreign source object.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SourceRead<AnyRef>>,
    /// A minimal summary of a foreign source.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<LocalText>,
    /// The user's own content.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<LocalText>,
    /// A raw capture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<RawCapture>,
    /// Extension values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
impl Observation {
    /// Checks a canonical Observation strictly: a foreign source carries its reference and summary but no content, raw captures are stored only in `one_observation` with a blob, and no unknown field (C-10).
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        no_unknown(&self.unknown)?;
        self.header.check(Concept::Observation)?;
        if self.source_kind.is_foreign() {
            require(
                self.source.is_some() && self.summary.is_some() && self.content.is_none(),
                "foreign_source",
            )?;
        } else {
            require(self.source.is_none(), "source")?;
        }
        let stored = self.raw.as_ref().is_some_and(|r| r.store);
        let blob = self.raw.as_ref().is_some_and(|r| r.blob_key.is_some());
        let in_observation = self.header.retention_class == RetentionClass::OneObservation;
        require(stored == blob && stored == in_observation, "raw_capture")
    }
}
