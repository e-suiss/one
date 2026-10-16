//! Episode: the source of memory, a conversation, task run, meeting, observation window, source event or import with its ordered entries; a forgotten Episode is a skeleton (C-5, C-11, MD-6 (2), M-6).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::concept::Concept;
use super::extension::Extensions;
use super::header::{LocalText, RecordHeader};
use super::observation::SourceRead;
use super::provenance::ProvenanceLabel;
use super::reference::{ExternalRef, PartyRef};
use super::tags::{Active, EpisodeType, Forgotten};
use super::time::Instant;
use super::validate::{ContractViolation, UnknownFields, no_unknown, require, unique};
use crate::id::{DeviceId, EpisodeId, InteractionId, ObservationId, TaskId};
use crate::memory::fields::SourceKind;

/// The interaction mode of an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Text.
    Text,
    /// Voice.
    Voice,
    /// Card.
    Card,
    /// Workspace.
    Workspace,
}

/// Who an entry is from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryActor {
    /// The user.
    User,
    /// One.
    One,
    /// A sub-agent.
    Subagent,
    /// Another party.
    OtherParty,
}

/// What kind of Episode it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeKind {
    /// A conversation.
    Conversation,
    /// A task run; names its Task.
    TaskRun,
    /// A meeting transcript.
    MeetingTranscript,
    /// An observation window.
    ObservationWindow,
    /// A connected-source event.
    ConnectedSourceEvent,
    /// An import.
    Import,
}

/// Where imported content came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImportSource {
    /// A One export package.
    OneExport,
    /// Another assistant's dump.
    AssistantDump,
    /// A transfer protocol.
    TransferProtocol,
}

/// The kind-specific body of an entry.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EntryBody {
    /// A turn; a user turn carries `user_statement` and `user.direct`.
    ConversationTurn {
        /// The text.
        content: LocalText,
        /// `user_statement` for a user turn.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        source_kind: Option<SourceKind>,
        /// `user.direct` for a user turn.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provenance: Option<ProvenanceLabel>,
    },
    /// The user asked One to remember.
    ExplicitRemember {
        /// The text.
        content: LocalText,
        /// `user_statement`.
        source_kind: SourceKind,
        /// `user.direct`.
        provenance: ProvenanceLabel,
    },
    /// A pointer to a source event, never its content.
    SourceEventRef {
        /// The source object.
        source: SourceRead<ExternalRef>,
        /// `connected_source` or `external_content`.
        source_kind: SourceKind,
        /// An `external.*` label.
        provenance: ProvenanceLabel,
    },
    /// An imported item.
    ImportedItem {
        /// Where it came from.
        import_source: ImportSource,
        /// The text.
        content: LocalText,
        /// `import`.
        source_kind: SourceKind,
        /// `external.import`.
        provenance: ProvenanceLabel,
    },
    /// An Observation.
    Observation {
        /// The Observation.
        observation: ObservationId,
    },
    /// An Interaction.
    Interaction {
        /// The Interaction.
        interaction: InteractionId,
    },
}

/// One entry of an Episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpisodeEntry {
    /// Order within the Episode, from 0.
    pub seq: u64,
    /// When it happened.
    pub at: Instant,
    /// Who it is from.
    pub actor: EntryActor,
    /// The mode.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<Mode>,
    /// The kind and its fields.
    #[serde(flatten)]
    pub body: EntryBody,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
/// A live Episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LiveEpisode {
    /// `Episode`.
    #[serde(rename = "type")]
    pub concept: EpisodeType,
    /// Identifier.
    pub id: EpisodeId,
    /// C-19 header.
    #[serde(flatten)]
    pub header: RecordHeader,
    /// The version this one replaces, or `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub supersedes: Option<EpisodeId>,
    /// `active`.
    pub status: Active,
    /// What kind it is.
    pub kind: EpisodeKind,
    /// Modes used, without repeats.
    pub modes: Vec<Mode>,
    /// Start.
    pub started_at: Instant,
    /// End.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<Instant>,
    /// The Task of a task run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskId>,
    /// Entries in order.
    pub entries: Vec<EpisodeEntry>,
    /// The device that queued it offline.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queued_on_device: Option<DeviceId>,
    /// Extension values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
/// The retention class a skeleton keeps.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkeletonRetention {
    /// `one_memory`.
    OneMemory,
    /// `one_sensitive`.
    OneSensitive,
}

/// What remains of a forgotten Episode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EpisodeSkeleton {
    /// `Episode`.
    #[serde(rename = "type")]
    pub concept: EpisodeType,
    /// Identifier, still resolvable.
    pub id: EpisodeId,
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
/// An Episode: live, or the skeleton of a forgotten one.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Episode {
    /// Forgotten.
    Forgotten(EpisodeSkeleton),
    /// Live.
    Live(Box<LiveEpisode>),
}

impl Episode {
    /// The identifier.
    #[must_use]
    pub const fn id(&self) -> EpisodeId {
        match self {
            Self::Forgotten(s) => s.id,
            Self::Live(l) => l.id,
        }
    }
}

impl EntryBody {
    /// The wire fields of this kind, `kind` included.
    #[must_use]
    pub const fn fields(&self) -> &'static [&'static str] {
        match self {
            Self::ConversationTurn { .. } | Self::ExplicitRemember { .. } => {
                &["kind", "content", "source_kind", "provenance"]
            }
            Self::SourceEventRef { .. } => &["kind", "source", "source_kind", "provenance"],
            Self::ImportedItem { .. } => &[
                "kind",
                "import_source",
                "content",
                "source_kind",
                "provenance",
            ],
            Self::Observation { .. } => &["kind", "observation"],
            Self::Interaction { .. } => &["kind", "interaction"],
        }
    }
}

impl EpisodeEntry {
    /// Fields outside the entry's kind.
    pub fn unknown_fields(&self) -> impl Iterator<Item = &str> {
        let known = self.body.fields();
        self.unknown
            .keys()
            .map(alloc::string::String::as_str)
            .filter(move |k| !known.contains(k))
    }

    /// Checks the kind-specific source kind and label rules.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn check_rules(&self) -> Result<(), ContractViolation> {
        match &self.body {
            EntryBody::ConversationTurn {
                source_kind,
                provenance,
                ..
            } => {
                if self.actor == EntryActor::User {
                    require(
                        *source_kind == Some(SourceKind::UserStatement)
                            && *provenance == Some(ProvenanceLabel::UserDirect),
                        "user_turn_label",
                    )
                } else {
                    require(source_kind.is_none(), "turn_source_kind")
                }
            }
            EntryBody::ExplicitRemember {
                source_kind,
                provenance,
                ..
            } => require(
                self.actor == EntryActor::User
                    && *source_kind == SourceKind::UserStatement
                    && *provenance == ProvenanceLabel::UserDirect,
                "explicit_remember",
            ),
            EntryBody::SourceEventRef {
                source_kind,
                provenance,
                ..
            } => require(
                matches!(
                    source_kind,
                    SourceKind::ConnectedSource | SourceKind::ExternalContent
                ) && provenance.is_external(),
                "source_event_label",
            ),
            EntryBody::ImportedItem {
                source_kind,
                provenance,
                ..
            } => require(
                *source_kind == SourceKind::Import
                    && *provenance == ProvenanceLabel::ExternalImport,
                "import_label",
            ),
            EntryBody::Observation { .. } | EntryBody::Interaction { .. } => Ok(()),
        }
    }
}

impl LiveEpisode {
    /// Checks the C-11 rules without refusing unknown fields.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn check_rules(&self) -> Result<(), ContractViolation> {
        self.header.check(Concept::Episode)?;
        require(
            (self.kind == EpisodeKind::TaskRun) == self.task.is_some(),
            "task",
        )?;
        require(unique(&self.modes), "modes")?;
        for e in &self.entries {
            e.check_rules()?;
        }
        Ok(())
    }

    /// Checks a canonical Episode strictly.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        no_unknown(&self.unknown)?;
        for e in &self.entries {
            require(e.unknown_fields().next().is_none(), "unknown_field")?;
        }
        self.check_rules()
    }
}

impl Episode {
    /// Checks a canonical Episode strictly.
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
