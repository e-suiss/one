//! The two isolated model calls of T-9 and MF-11: the quarantine call reads one piece of external content and returns only structured fields, still labelled external; the auditor call sees only the metadata of a proposed action and returns a fixed verdict; neither call carries tools, memory, the personal adapter, the planner's context or the other call's output, and every answer is checked before it is used.

pub mod auditor;
pub mod quarantine;

pub use auditor::{AUDITOR_INSTRUCTION, AuditVerdict, AuditorCall, Consistency, verdict_schema};
pub use quarantine::{ExternalOutput, QUARANTINE_INSTRUCTION, QuarantineCall};

use one_proto::ModelRequestId;
use one_proto::data_class::{DataClass, RetentionClass};
use one_proto::model::request::{
    Context, ContextMessage, Language, MessageRole, Mode, Part, RequiredCapability,
};
use one_proto::model::roles::ErrorCode;
use one_proto::model::{ModelRequest, ModelResponse, ModelRole};
use one_proto::ontology::validate::ContractViolation;
use one_proto::ontology::{JsonObject, JsonValue, ProvenanceLabel};

/// What the caller sets for an isolated call: the content classes, the latency budget and the context language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSettings {
    /// The content data class.
    pub data_class: DataClass,
    /// The content retention classes.
    pub retention_classes: Vec<RetentionClass>,
    /// The latency budget in milliseconds.
    pub latency_budget_ms: u64,
    /// The context language.
    pub language: Language,
}

/// Why an isolated request could not be built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BuildError {
    /// The quarantine reads only content with an `external.*` label.
    #[error("label {0} is not external")]
    NotExternal(ProvenanceLabel),
    /// The content to read is empty.
    #[error("content empty")]
    EmptyContent,
    /// The action metadata could not be written as JSON text.
    #[error("action metadata not serializable")]
    Metadata,
    /// The built request breaks the request contract.
    #[error("request contract: {0}")]
    Contract(ContractViolation),
}

/// Why the answer to an isolated call is not used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ResponseError {
    /// The response answers another request.
    #[error("response answers another request")]
    RequestMismatch,
    /// The response breaks the response contract.
    #[error("response contract: {0}")]
    Contract(ContractViolation),
    /// The model ended in a common error.
    #[error("model error {0:?}")]
    Failed(ErrorCode),
    /// The response carries a tool call.
    #[error("tool call in an isolated call")]
    ToolCall,
    /// The response was served by another role.
    #[error("served by {0:?}")]
    WrongRole(ModelRole),
    /// The response was served with a personal adapter.
    #[error("served with an adapter")]
    Adapter,
    /// The response has no structured output.
    #[error("no structured output")]
    NoStructuredOutput,
    /// The structured output is not a verdict.
    #[error("structured output is not a verdict")]
    Verdict,
}

/// Builds an ephemeral, unpersonalised request with no tools and no memory: one fixed system instruction and one user message with `provenance`.
fn isolated(
    request_id: ModelRequestId,
    settings: CallSettings,
    instruction: &str,
    provenance: ProvenanceLabel,
    content: String,
    schema: JsonObject,
) -> Result<ModelRequest, BuildError> {
    let request = ModelRequest {
        request_id,
        task_id: None,
        capabilities: vec![
            RequiredCapability::TextGeneration,
            RequiredCapability::StructuredOutput,
        ],
        context: Context {
            language: settings.language,
            messages: vec![
                ContextMessage {
                    role: MessageRole::System,
                    provenance: ProvenanceLabel::RecordTrusted,
                    content: vec![Part::Text {
                        text: instruction.to_owned(),
                    }],
                },
                ContextMessage {
                    role: MessageRole::User,
                    provenance,
                    content: vec![Part::Text { text: content }],
                },
            ],
            memory_refs: None,
        },
        tools: None,
        response_schema: Some(schema),
        latency_budget_ms: settings.latency_budget_ms,
        max_output_tokens: None,
        mode: Mode {
            ephemeral: true,
            personalise: false,
        },
        hints: None,
        data_class: settings.data_class,
        retention_classes: settings.retention_classes,
        device_only: None,
    };
    request.validate().map_err(BuildError::Contract)?;
    Ok(request)
}

/// The structured output of a served answer to `expected`, when `role` served it without an adapter and without tool calls.
fn served(
    expected: ModelRequestId,
    response: &ModelResponse,
    role: ModelRole,
) -> Result<&JsonValue, ResponseError> {
    if response.request_id != expected {
        return Err(ResponseError::RequestMismatch);
    }
    let (model, output) = response
        .result()
        .map_err(ResponseError::Contract)?
        .map_err(|e| ResponseError::Failed(e.code))?;
    if output.tool_calls.is_some() {
        return Err(ResponseError::ToolCall);
    }
    if model.model_role != role {
        return Err(ResponseError::WrongRole(model.model_role));
    }
    if model.adapter_id.is_some() {
        return Err(ResponseError::Adapter);
    }
    output
        .structured
        .as_ref()
        .ok_or(ResponseError::NoStructuredOutput)
}
