//! A2A v1.0 messages and tasks: from another agent they are labelled `external.agent`, from another One `external.one`; the One↔One profile reuses the `one-proto` federation types and their rules (SEC-14, OO-4, OO-17).

use alloc::string::String;
use alloc::vec::Vec;

use one_proto::federation::message::Role;
use one_proto::federation::task::TaskState;
use one_proto::federation::wire::A2aId;
use one_proto::federation::{Message, Task};
use one_proto::ontology::JsonValue;
use one_provenance::{ExternalSource, Untrusted};
use serde::Deserialize;

use crate::json::decode;
use crate::jsonrpc::Response;
use crate::limits::{Limits, ParseError};

/// One part of an A2A message or artifact.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(try_from = "RawPart")]
pub enum Part {
    /// Text.
    Text {
        /// The text.
        text: String,
        /// The media type.
        media_type: Option<String>,
    },
    /// Structured data.
    Data {
        /// The data.
        data: JsonValue,
        /// The media type.
        media_type: Option<String>,
    },
    /// A file by URL; never fetched here.
    Url {
        /// The URL.
        url: String,
        /// The file name.
        filename: Option<String>,
        /// The media type.
        media_type: Option<String>,
    },
    /// Inline base64 file content; never decoded here.
    Raw {
        /// The base64 content.
        raw: String,
        /// The file name.
        filename: Option<String>,
        /// The media type.
        media_type: Option<String>,
    },
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawPart {
    #[serde(default)]
    text: Option<String>,
    #[serde(default)]
    data: Option<JsonValue>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    raw: Option<String>,
    #[serde(default)]
    filename: Option<String>,
    #[serde(default)]
    media_type: Option<String>,
}

impl TryFrom<RawPart> for Part {
    type Error = &'static str;

    fn try_from(p: RawPart) -> Result<Self, Self::Error> {
        let RawPart {
            text,
            data,
            url,
            raw,
            filename,
            media_type,
        } = p;
        match (text, data, url, raw) {
            (Some(text), None, None, None) => Ok(Self::Text { text, media_type }),
            (None, Some(data), None, None) => Ok(Self::Data { data, media_type }),
            (None, None, Some(url), None) => Ok(Self::Url {
                url,
                filename,
                media_type,
            }),
            (None, None, None, Some(raw)) => Ok(Self::Raw {
                raw,
                filename,
                media_type,
            }),
            _ => Err("exactly one of text, data, url and raw"),
        }
    }
}

/// An A2A message from another agent.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentMessage {
    /// The message identifier.
    pub message_id: A2aId,
    /// The conversation context.
    #[serde(default)]
    pub context_id: Option<A2aId>,
    /// The task it belongs to.
    #[serde(default)]
    pub task_id: Option<A2aId>,
    /// The sender role.
    pub role: Role,
    /// The parts.
    pub parts: Vec<Part>,
}

/// The status of an A2A task.
#[derive(Debug, Clone, PartialEq, Deserialize)]
pub struct AgentTaskStatus {
    /// The state.
    pub state: TaskState,
    /// The message that accompanies it.
    #[serde(default)]
    pub message: Option<AgentMessage>,
}

/// An artifact of an A2A task.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentArtifact {
    /// The artifact identifier.
    pub artifact_id: A2aId,
    /// The name.
    #[serde(default)]
    pub name: Option<String>,
    /// The description.
    #[serde(default)]
    pub description: Option<String>,
    /// The parts.
    pub parts: Vec<Part>,
}

/// An A2A task from another agent.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentTask {
    /// The task identifier.
    pub id: A2aId,
    /// The conversation context.
    #[serde(default)]
    pub context_id: Option<A2aId>,
    /// The status.
    pub status: AgentTaskStatus,
    /// The artifacts.
    #[serde(default)]
    pub artifacts: Vec<AgentArtifact>,
    /// The message history.
    #[serde(default)]
    pub history: Vec<AgentMessage>,
}

/// The result of `SendMessage`: a task or a direct message.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SendResult {
    /// A task.
    Task(AgentTask),
    /// A direct message.
    Message(AgentMessage),
}

/// Parses an A2A message from another agent.
///
/// # Errors
/// A broken limit or a message that does not fit the A2A schema.
pub fn parse_agent_message(
    bytes: &[u8],
    limits: &Limits,
) -> Result<Untrusted<AgentMessage>, ParseError> {
    decode(bytes, limits).map(|m| Untrusted::external(m, ExternalSource::Agent))
}

/// Parses an A2A task from another agent.
///
/// # Errors
/// A broken limit or a task that does not fit the A2A schema.
pub fn parse_agent_task(bytes: &[u8], limits: &Limits) -> Result<Untrusted<AgentTask>, ParseError> {
    decode(bytes, limits).map(|t| Untrusted::external(t, ExternalSource::Agent))
}

/// Parses a JSON-RPC `SendMessage` response from another agent.
///
/// # Errors
/// A broken limit or malformed JSON-RPC.
pub fn parse_agent_response(
    bytes: &[u8],
    limits: &Limits,
) -> Result<Untrusted<Response<SendResult>>, ParseError> {
    decode(bytes, limits).map(|r| Untrusted::external(r, ExternalSource::Agent))
}

/// Parses a One↔One message and checks its envelope rules.
///
/// # Errors
/// A broken limit, a message outside the One Federation profile or a broken envelope rule.
pub fn parse_one_message(bytes: &[u8], limits: &Limits) -> Result<Untrusted<Message>, ParseError> {
    let message: Message = decode(bytes, limits)?;
    message.validate()?;
    Ok(Untrusted::external(message, ExternalSource::One))
}

/// Parses a One↔One task and checks its state, artifact and message rules.
///
/// # Errors
/// A broken limit, a task outside the One Federation profile or a broken task rule.
pub fn parse_one_task(bytes: &[u8], limits: &Limits) -> Result<Untrusted<Task>, ParseError> {
    let task: Task = decode(bytes, limits)?;
    task.validate()?;
    Ok(Untrusted::external(task, ExternalSource::One))
}
