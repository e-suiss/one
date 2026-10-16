//! MCP responses One reads: the `tools/list` result, labelled `external.tool_description`, and the `tools/call` result, labelled `external.tool_output`; unknown fields are ignored (SEC-14, §12).

use alloc::string::String;
use alloc::vec::Vec;

use one_proto::ontology::JsonValue;
use one_provenance::{ExternalSource, Untrusted};
use serde::Deserialize;

use crate::json::decode;
use crate::jsonrpc::{Outcome, Response};
use crate::limits::{Limits, ParseError};

/// Behaviour hints a server declares for a tool; never trusted.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolAnnotations {
    /// A display title.
    #[serde(default)]
    pub title: Option<String>,
    /// The tool claims not to change its environment.
    #[serde(default)]
    pub read_only_hint: Option<bool>,
    /// The tool claims it may destroy data.
    #[serde(default)]
    pub destructive_hint: Option<bool>,
    /// The tool claims repeated calls have no further effect.
    #[serde(default)]
    pub idempotent_hint: Option<bool>,
    /// The tool claims to reach an open world.
    #[serde(default)]
    pub open_world_hint: Option<bool>,
}

/// One tool definition.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Tool {
    /// The tool name.
    pub name: String,
    /// A display title.
    #[serde(default)]
    pub title: Option<String>,
    /// The description.
    #[serde(default)]
    pub description: Option<String>,
    /// The JSON Schema of the arguments; always an object.
    pub input_schema: JsonValue,
    /// The JSON Schema of the structured result.
    #[serde(default)]
    pub output_schema: Option<JsonValue>,
    /// The behaviour hints.
    #[serde(default)]
    pub annotations: Option<ToolAnnotations>,
}

/// The `tools/list` result.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolList {
    /// The tools.
    pub tools: Vec<Tool>,
    /// The cursor of the next page.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// A resource embedded in a tool result.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EmbeddedResource {
    /// The resource URI.
    pub uri: String,
    /// The media type.
    #[serde(default)]
    pub mime_type: Option<String>,
    /// The text content.
    #[serde(default)]
    pub text: Option<String>,
    /// The base64 binary content.
    #[serde(default)]
    pub blob: Option<String>,
}

/// One content block of a tool result.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ContentBlock {
    /// Text.
    Text {
        /// The text.
        text: String,
    },
    /// A base64 image.
    #[serde(rename_all = "camelCase")]
    Image {
        /// The base64 data.
        data: String,
        /// The media type.
        mime_type: String,
    },
    /// Base64 audio.
    #[serde(rename_all = "camelCase")]
    Audio {
        /// The base64 data.
        data: String,
        /// The media type.
        mime_type: String,
    },
    /// A link to a resource.
    #[serde(rename_all = "camelCase")]
    ResourceLink {
        /// The resource URI.
        uri: String,
        /// The resource name.
        name: String,
        /// A display title.
        #[serde(default)]
        title: Option<String>,
        /// The description.
        #[serde(default)]
        description: Option<String>,
        /// The media type.
        #[serde(default)]
        mime_type: Option<String>,
    },
    /// An embedded resource.
    Resource {
        /// The resource.
        resource: EmbeddedResource,
    },
    /// A block type this parser does not read.
    #[serde(other)]
    Unsupported,
}

/// The `tools/call` result.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolResult {
    /// The content blocks.
    #[serde(default)]
    pub content: Vec<ContentBlock>,
    /// The structured result.
    #[serde(default)]
    pub structured_content: Option<JsonValue>,
    /// The tool reported an error.
    #[serde(default)]
    pub is_error: bool,
}

/// Parses a `tools/list` response; every tool must have a name and an object input schema.
///
/// # Errors
/// A broken limit, malformed JSON-RPC or a tool that breaks the MCP schema.
pub fn parse_tool_list(
    bytes: &[u8],
    limits: &Limits,
) -> Result<Untrusted<Response<ToolList>>, ParseError> {
    let response: Response<ToolList> = decode(bytes, limits)?;
    if let Outcome::Result(list) = &response.outcome {
        for tool in &list.tools {
            if tool.name.is_empty() {
                return Err(ParseError::Contract("tool name"));
            }
            if tool.input_schema.as_object().is_none() {
                return Err(ParseError::Contract("inputSchema is an object"));
            }
        }
    }
    Ok(Untrusted::external(
        response,
        ExternalSource::ToolDescription,
    ))
}

/// Parses a `tools/call` response.
///
/// # Errors
/// A broken limit or malformed JSON-RPC.
pub fn parse_tool_result(
    bytes: &[u8],
    limits: &Limits,
) -> Result<Untrusted<Response<ToolResult>>, ParseError> {
    decode(bytes, limits).map(|r| Untrusted::external(r, ExternalSource::ToolOutput))
}
