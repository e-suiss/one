//! The A2A Task projection of an offer chain with its negotiation phases and commitment artifact, and the Agent Card declaration of the extension (OO-1, OO-4, OO-20).

use alloc::boxed::Box;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::message::{ApplicationJson, Message};
use super::wire::{A2aId, Digest, ExtensionUri, Extensions, Kind, Refusal, SchemaVersion, Uuid7};
use crate::capability::CapabilityVersion;
use crate::capability::Declaration;
use crate::ontology::Instant;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

/// An A2A task state (`ProtoJSON` enum names).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TaskState {
    /// Received, not yet evaluated.
    #[serde(rename = "TASK_STATE_SUBMITTED")]
    Submitted,
    /// Being evaluated.
    #[serde(rename = "TASK_STATE_WORKING")]
    Working,
    /// Waiting for the counterparty's typed reply.
    #[serde(rename = "TASK_STATE_INPUT_REQUIRED")]
    InputRequired,
    /// Waiting for the recipient person's own decision.
    #[serde(rename = "TASK_STATE_AUTH_REQUIRED")]
    AuthRequired,
    /// A Work commitment was created.
    #[serde(rename = "TASK_STATE_COMPLETED")]
    Completed,
    /// Declined with a reason code.
    #[serde(rename = "TASK_STATE_REJECTED")]
    Rejected,
    /// Expired without a reply.
    #[serde(rename = "TASK_STATE_CANCELED")]
    Canceled,
    /// Refused at protocol level.
    #[serde(rename = "TASK_STATE_FAILED")]
    Failed,
}

/// The negotiation phase of a chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Phase {
    /// Evaluating.
    Evaluating,
    /// Waiting for the counterparty.
    AwaitingCounterparty,
    /// Waiting for the principal; the reason is never shared.
    AwaitingPrincipal,
    /// Committed.
    Committed,
    /// Declined.
    Declined,
    /// Expired.
    Expired,
    /// Refused.
    Refused,
}

impl TaskState {
    /// The phase the state projects.
    #[must_use]
    pub const fn phase(self) -> Phase {
        match self {
            Self::Submitted | Self::Working => Phase::Evaluating,
            Self::InputRequired => Phase::AwaitingCounterparty,
            Self::AuthRequired => Phase::AwaitingPrincipal,
            Self::Completed => Phase::Committed,
            Self::Rejected => Phase::Declined,
            Self::Canceled => Phase::Expired,
            Self::Failed => Phase::Refused,
        }
    }
}

/// The task status.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskStatus {
    /// The state.
    pub state: TaskState,
    /// When it was entered.
    pub timestamp: Instant,
    /// The message that led to it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<Box<Message>>,
}

/// The extension object of a task.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct TaskExtension {
    /// The schema version.
    pub schema_version: SchemaVersion,
    /// The phase.
    pub phase: Phase,
    /// The chain's offer version.
    pub offer_version: u32,
    /// The open message's expiry.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Instant>,
    /// The refusal of a failed task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refusal: Option<Refusal>,
}

/// `Task.metadata`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskMetadata {
    /// The extension object.
    #[serde(rename = "https://suiss.app/a2a/one-federation/v1")]
    pub extension: TaskExtension,
}

/// The Work operation that created a commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CommitOperation {
    /// Promise of a request.
    Promise,
    /// Acceptance of a counter.
    AcceptCounter,
}

checked_string!(
    /// A resolvable Work commitment reference.
    CommitmentUri,
    "commitmentRef",
    |s| !s.is_empty() && s.len() <= 1024 && s.contains(':')
);

/// The commitment reference data.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommitmentData {
    /// The chain.
    pub correlation_id: Uuid7,
    /// The Work operation.
    pub work_operation: CommitOperation,
    /// The accepted version.
    pub accepted_offer_version: u32,
    /// The accepted message's digest.
    pub accepted_digest: Digest,
    /// The Work commitment.
    pub commitment_ref: CommitmentUri,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum CommitmentMarker {
    #[serde(rename = "commitment")]
    Commitment,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitmentExtension {
    part: CommitmentMarker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct CommitmentMetadata {
    #[serde(rename = "https://suiss.app/a2a/one-federation/v1")]
    extension: CommitmentExtension,
}

/// The commitment `DataPart`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommitmentPart {
    /// The data.
    pub data: CommitmentData,
    media_type: ApplicationJson,
    metadata: CommitmentMetadata,
}

impl CommitmentPart {
    /// Wraps commitment data.
    #[must_use]
    pub const fn new(data: CommitmentData) -> Self {
        Self {
            data,
            media_type: ApplicationJson::ApplicationJson,
            metadata: CommitmentMetadata {
                extension: CommitmentExtension {
                    part: CommitmentMarker::Commitment,
                },
            },
        }
    }
}

/// The artifact of a completed chain: a reference to the Work commitment, not acceptance of its result (OO-1).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct CommitmentArtifact {
    /// The artifact identifier.
    pub artifact_id: A2aId,
    /// The single part.
    pub parts: [CommitmentPart; 1],
    /// The extension list.
    pub extensions: Extensions,
}

/// The A2A Task projecting one offer chain (OO-1).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Task {
    /// The task identifier.
    pub id: A2aId,
    /// The chain's correlation identifier.
    pub context_id: Uuid7,
    /// The status.
    pub status: TaskStatus,
    /// The commitment artifact, completed chains only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifacts: Option<Vec<CommitmentArtifact>>,
    /// The message history.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub history: Option<Vec<Message>>,
    /// The extension object.
    pub metadata: TaskMetadata,
}

impl Task {
    /// Checks the state, phase, artifact and refusal rules.
    ///
    /// # Errors
    /// Rejects a task that breaks a rule of `task.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let extension = &self.metadata.extension;
        let state = self.status.state;
        require(extension.phase == state.phase(), "phase follows the state")?;
        let artifacts = self.artifacts.as_ref().map_or(0, Vec::len);
        require(artifacts <= 1, "at most one artifact")?;
        require(
            (state == TaskState::Completed) == (artifacts == 1)
                && (state == TaskState::Completed || self.artifacts.is_none()),
            "commitment artifact exactly on completion",
        )?;
        if let Some(artifacts) = &self.artifacts {
            require(
                artifacts
                    .iter()
                    .all(|a| a.parts.iter().all(|p| p.data.accepted_offer_version >= 1)),
                "accepted version at least 1",
            )?;
        }
        require(
            state != TaskState::Failed || extension.refusal.is_some(),
            "a failed task names its refusal",
        )?;
        if let Some(message) = &self.status.message {
            message.validate()?;
        }
        self.history
            .iter()
            .flatten()
            .try_for_each(Message::validate)
    }
}

/// `true` as a wire constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "bool", into = "bool")]
pub struct Required;

impl TryFrom<bool> for Required {
    type Error = ContractViolation;

    fn try_from(value: bool) -> Result<Self, Self::Error> {
        if value {
            Ok(Self)
        } else {
            Err(ContractViolation("extension is required"))
        }
    }
}

impl From<Required> for bool {
    fn from(_: Required) -> Self {
        true
    }
}

/// The declaration parameters.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct AgentExtensionParams {
    /// The schema versions accepted.
    pub schema_versions: Vec<SchemaVersion>,
    /// The kinds accepted.
    pub kinds: Vec<Kind>,
    /// The capabilities usable as typed bodies.
    pub capabilities: Vec<Declaration>,
}

checked_string!(
    /// A declaration description of at most 500 characters.
    Description,
    "description",
    |s| s.chars().count() <= 500
);

/// The Agent Card `AgentExtension` entry of the extension (OO-4).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentExtension {
    /// The extension URI.
    pub uri: ExtensionUri,
    /// The description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<Description>,
    /// Always required.
    pub required: Required,
    /// The parameters.
    pub params: AgentExtensionParams,
}

impl AgentExtension {
    /// Checks the declaration lists.
    ///
    /// # Errors
    /// Rejects empty or repeated lists or too many capabilities; each [`Declaration`] checks its own versions and `extends`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let p = &self.params;
        require(
            !p.schema_versions.is_empty() && unique(&p.schema_versions),
            "schemaVersions",
        )?;
        require(!p.kinds.is_empty() && unique(&p.kinds), "kinds")?;
        require(p.capabilities.len() <= 256, "capabilities")
    }
}

/// The highest version both sides offer for a capability.
#[must_use]
pub fn negotiate_capability<'a>(
    ours: &'a Declaration,
    theirs: &Declaration,
) -> Option<&'a CapabilityVersion> {
    if ours.name != theirs.name {
        return None;
    }
    ours.versions
        .iter()
        .filter(|v| theirs.versions.contains(v))
        .max_by(|a, b| a.as_str().cmp(b.as_str()))
}
