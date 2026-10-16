//! The provider-independent model request: capabilities, context, tools, response schema, latency budget and data class; it has no model, provider or credential member (MF-6, MF-20, MF-26).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::common::{is_snake_word, validate_content_classes};
use crate::capability::CapabilityName;
use crate::capability::CapabilityVersion;
use crate::data_class::DataClass;
use crate::data_class::RetentionClass;
use crate::id::{MemoryRecordId, ModelRequestId, TaskId};
use crate::ontology::JsonObject;
use crate::ontology::ProvenanceLabel;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

/// A capability a request needs from the serving model.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredCapability {
    /// Text generation.
    TextGeneration,
    /// Tool calling.
    ToolCalling,
    /// Structured output.
    StructuredOutput,
    /// Long context.
    LongContext,
    /// Multi-step planning.
    MultiStepPlanning,
    /// Image input.
    ImageInput,
    /// Audio input.
    AudioInput,
    /// Embedding.
    Embedding,
    /// Speech recognition.
    SpeechRecognition,
    /// Speech synthesis.
    SpeechSynthesis,
}

/// A context language (MF-50).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Language {
    /// Turkish.
    Tr,
    /// English.
    En,
}

/// A message role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageRole {
    /// System.
    System,
    /// User.
    User,
    /// Assistant.
    Assistant,
    /// Tool.
    Tool,
}

checked_string!(
    /// A blob reference.
    BlobRef,
    "blob_ref",
    |s| !s.is_empty()
);

checked_string!(
    /// An `image/*` or `audio/*` media type.
    MediaType,
    "media_type",
    |s| {
        let Some((top, sub)) = s.split_once('/') else {
            return false;
        };
        matches!(top, "image" | "audio")
            && !sub.is_empty()
            && sub.chars().all(|c| {
                c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '+' | '-')
            })
    }
);

/// A content part.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Part {
    /// Text.
    Text {
        /// The text.
        text: String,
    },
    /// An image by reference.
    Image {
        /// The blob reference.
        blob_ref: BlobRef,
        /// The media type.
        media_type: MediaType,
    },
    /// Audio by reference.
    Audio {
        /// The blob reference.
        blob_ref: BlobRef,
        /// The media type.
        media_type: MediaType,
    },
}

/// A context message with its provenance label.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextMessage {
    /// The role.
    pub role: MessageRole,
    /// Where the content comes from.
    pub provenance: ProvenanceLabel,
    /// The content parts.
    pub content: Vec<Part>,
}

/// The request context.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Context {
    /// The language.
    pub language: Language,
    /// The messages.
    pub messages: Vec<ContextMessage>,
    /// Referenced memory records.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present"
    )]
    pub memory_refs: Option<Vec<MemoryRecordId>>,
}

fn present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<MemoryRecordId>>, D::Error> {
    Vec::deserialize(d).map(Some)
}

/// A tool: a One capability with its input schema.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tool {
    /// The capability name.
    pub name: CapabilityName,
    /// The capability version.
    pub version: CapabilityVersion,
    /// The input JSON Schema.
    pub input_schema: JsonObject,
}

/// The request mode (MF-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Mode {
    /// Nothing is kept.
    pub ephemeral: bool,
    /// The personal adapter may be used.
    pub personalise: bool,
}

checked_string!(
    /// A task kind hint.
    TaskKind,
    "task_kind",
    is_snake_word
);

/// Difficulty heuristics for the second routing stage.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hints {
    /// The task kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_kind: Option<TaskKind>,
    /// Expected output tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_output_tokens: Option<u64>,
    /// Tool count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_count: Option<u64>,
    /// Plan depth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan_depth: Option<u64>,
}

/// A provider-independent model request (MF-6).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRequest {
    /// The request identifier.
    pub request_id: ModelRequestId,
    /// The task the request serves.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    /// Needed capabilities.
    pub capabilities: Vec<RequiredCapability>,
    /// The context.
    pub context: Context,
    /// Offered tools.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    /// The JSON Schema structured output must satisfy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<JsonObject>,
    /// The latency budget in milliseconds.
    pub latency_budget_ms: u64,
    /// The output token cap.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u64>,
    /// The mode.
    pub mode: Mode,
    /// Routing hints.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hints: Option<Hints>,
    /// The content data class.
    pub data_class: DataClass,
    /// The content retention classes.
    pub retention_classes: Vec<RetentionClass>,
    /// The content must stay on the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_only: Option<bool>,
}

impl ModelRequest {
    /// True when the content must stay on the device.
    #[must_use]
    pub fn is_device_only(&self) -> bool {
        self.device_only.unwrap_or(false)
    }

    /// Checks the cross-member rules of the request contract.
    ///
    /// # Errors
    /// Rejects a request that breaks a rule of `request.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        validate_content_classes(&self.data_class, &self.retention_classes)?;
        require(!self.capabilities.is_empty(), "capabilities empty")?;
        require(unique(&self.capabilities), "capabilities repeated")?;
        require(!self.context.messages.is_empty(), "messages empty")?;
        require(
            self.context.messages.iter().all(|m| !m.content.is_empty()),
            "message content empty",
        )?;
        if let Some(refs) = &self.context.memory_refs {
            require(unique(refs), "memory_refs repeated")?;
        }
        require(self.latency_budget_ms >= 1, "latency_budget_ms")?;
        require(self.max_output_tokens != Some(0), "max_output_tokens")?;
        require(
            !self
                .capabilities
                .contains(&RequiredCapability::StructuredOutput)
                || self.response_schema.is_some(),
            "structured_output needs response_schema",
        )?;
        let tool_calling = self.capabilities.contains(&RequiredCapability::ToolCalling);
        match &self.tools {
            Some(tools) => {
                require(tool_calling, "tools need tool_calling")?;
                require(!tools.is_empty(), "tool_calling needs a tool")?;
                require(unique(tools), "tools repeated")?;
            }
            None => require(!tool_calling, "tool_calling needs a tool")?,
        }
        if self.mode.ephemeral {
            require(!self.mode.personalise, "ephemeral cannot personalise")?;
            require(
                self.context.memory_refs.is_none(),
                "ephemeral carries no memory_refs",
            )?;
        }
        Ok(())
    }
}
