//! The mapping between the `one.serving.v1` wire messages and the canonical model types; a value the wire cannot carry is rejected, never dropped silently (T-31, T-8, MF-6, MF-55).

use one_proto::capability::CapabilityName;
use one_proto::data_class::DataClass;
use one_proto::id::{AdapterId, ModelRequestId, ModelVersionId, TaskId};
use one_proto::model::request::{
    ContextMessage, Language, MessageRole, ModelRequest, Part, RequiredCapability, Tool,
};
use one_proto::model::response::{ModelError, Outcome, Output, ToolCall};
use one_proto::model::{ErrorCode, ModelRef, ModelResponse, ModelRole, Usage};
use one_proto::ontology::validate::ContractViolation;
use one_proto::ontology::{JsonObject, JsonValue};

use crate::serving_v1 as wire;
use crate::serving_v1::__buffa::oneof::generate_response::Result as WireResult;
use crate::serving_v1::__buffa::oneof::generate_stream_response::Event as WireEvent;

/// Why a value could not cross between the wire and the canonical types.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConvertError {
    /// The canonical value breaks its own contract.
    #[error("canonical contract: {0}")]
    Contract(ContractViolation),
    /// The canonical value has a member the wire contract cannot carry.
    #[error("not representable on the wire: {0}")]
    Unrepresentable(&'static str),
    /// The request must stay on the device and never reaches cloud serving.
    #[error("device-only request")]
    DeviceOnly,
    /// A number does not fit the wire or canonical width.
    #[error("out of range: {0}")]
    OutOfRange(&'static str),
    /// A wire value breaks the contract.
    #[error("invalid wire value: {0}")]
    Invalid(&'static str),
    /// The response names another model version than the one asked for (MF-55).
    #[error("model version differs from the request")]
    VersionMismatch,
}

impl From<ContractViolation> for ConvertError {
    fn from(v: ContractViolation) -> Self {
        Self::Contract(v)
    }
}

fn narrow(value: u64, what: &'static str) -> Result<u32, ConvertError> {
    u32::try_from(value).map_err(|_| ConvertError::OutOfRange(what))
}

fn optional(text: &str) -> Option<&str> {
    (!text.is_empty()).then_some(text)
}

fn json_text(value: &impl serde::Serialize, what: &'static str) -> Result<String, ConvertError> {
    serde_json::to_string(value).map_err(|_| ConvertError::Unrepresentable(what))
}

fn parse_json<T: serde::de::DeserializeOwned>(
    text: &str,
    what: &'static str,
) -> Result<T, ConvertError> {
    serde_json::from_str(text).map_err(|_| ConvertError::Invalid(what))
}

fn code(value: &impl serde::Serialize, what: &'static str) -> Result<String, ConvertError> {
    match serde_json::to_value(value) {
        Ok(serde_json::Value::String(s)) => Ok(s),
        _ => Err(ConvertError::Unrepresentable(what)),
    }
}

fn capability(c: RequiredCapability) -> Result<wire::Capability, ConvertError> {
    Ok(match c {
        RequiredCapability::TextGeneration => wire::Capability::CAPABILITY_TEXT_GENERATION,
        RequiredCapability::ToolCalling => wire::Capability::CAPABILITY_TOOL_CALLING,
        RequiredCapability::StructuredOutput => wire::Capability::CAPABILITY_STRUCTURED_OUTPUT,
        RequiredCapability::LongContext => wire::Capability::CAPABILITY_LONG_CONTEXT,
        RequiredCapability::MultiStepPlanning => wire::Capability::CAPABILITY_MULTI_STEP_PLANNING,
        RequiredCapability::ImageInput
        | RequiredCapability::AudioInput
        | RequiredCapability::Embedding
        | RequiredCapability::SpeechRecognition
        | RequiredCapability::SpeechSynthesis => {
            return Err(ConvertError::Unrepresentable("capability"));
        }
    })
}

fn model_role(r: ModelRole) -> Result<wire::ModelRole, ConvertError> {
    Ok(match r {
        ModelRole::SmallLm => wire::ModelRole::MODEL_ROLE_SMALL_LM,
        ModelRole::LargeLm => wire::ModelRole::MODEL_ROLE_LARGE_LM,
        ModelRole::Quarantine => wire::ModelRole::MODEL_ROLE_QUARANTINE,
        _ => return Err(ConvertError::Unrepresentable("model_role")),
    })
}

const fn language(l: Language) -> wire::Language {
    match l {
        Language::Tr => wire::Language::LANGUAGE_TR,
        Language::En => wire::Language::LANGUAGE_EN,
    }
}

const fn message_role(r: MessageRole) -> wire::MessageRole {
    match r {
        MessageRole::System => wire::MessageRole::MESSAGE_ROLE_SYSTEM,
        MessageRole::User => wire::MessageRole::MESSAGE_ROLE_USER,
        MessageRole::Assistant => wire::MessageRole::MESSAGE_ROLE_ASSISTANT,
        MessageRole::Tool => wire::MessageRole::MESSAGE_ROLE_TOOL,
    }
}

const fn error_code(c: ErrorCode) -> wire::ErrorCode {
    match c {
        ErrorCode::RateLimited => wire::ErrorCode::ERROR_CODE_RATE_LIMITED,
        ErrorCode::Refusal => wire::ErrorCode::ERROR_CODE_REFUSAL,
        ErrorCode::ContextSizeExceeded => wire::ErrorCode::ERROR_CODE_CONTEXT_SIZE_EXCEEDED,
        ErrorCode::Unavailable => wire::ErrorCode::ERROR_CODE_UNAVAILABLE,
    }
}

fn canonical_error_code(c: buffa::EnumValue<wire::ErrorCode>) -> Result<ErrorCode, ConvertError> {
    match c.as_known() {
        Some(wire::ErrorCode::ERROR_CODE_RATE_LIMITED) => Ok(ErrorCode::RateLimited),
        Some(wire::ErrorCode::ERROR_CODE_REFUSAL) => Ok(ErrorCode::Refusal),
        Some(wire::ErrorCode::ERROR_CODE_CONTEXT_SIZE_EXCEEDED) => {
            Ok(ErrorCode::ContextSizeExceeded)
        }
        Some(wire::ErrorCode::ERROR_CODE_UNAVAILABLE) => Ok(ErrorCode::Unavailable),
        Some(wire::ErrorCode::ERROR_CODE_UNSPECIFIED) | None => Err(ConvertError::Invalid("error")),
    }
}

fn message(m: &ContextMessage) -> Result<wire::Message, ConvertError> {
    let [Part::Text { text }] = m.content.as_slice() else {
        return Err(ConvertError::Unrepresentable("message content"));
    };
    Ok(wire::Message {
        role: message_role(m.role).into(),
        provenance_label: m.provenance.as_str().to_owned(),
        content: text.clone(),
        ..Default::default()
    })
}

fn tool(t: &Tool) -> Result<wire::Tool, ConvertError> {
    Ok(wire::Tool {
        name: t.name.as_str().to_owned(),
        input_schema_json: json_text(&t.input_schema, "input_schema")?,
        ..Default::default()
    })
}

fn data_classes(class: &DataClass) -> Result<Vec<String>, ConvertError> {
    let kinds = class.kinds().iter().map(|k| code(k, "data_class"));
    let sensitive = class.sensitive().iter().map(|s| code(s, "data_class"));
    kinds.chain(sensitive).collect()
}

fn wire_usage(u: &Usage) -> Result<wire::Usage, ConvertError> {
    Ok(wire::Usage {
        input_tokens: narrow(u.input_tokens, "input_tokens")?,
        output_tokens: narrow(u.output_tokens, "output_tokens")?,
        cached_tokens: narrow(u.cached_input_tokens, "cached_input_tokens")?,
        reasoning_tokens: narrow(u.reasoning_tokens, "reasoning_tokens")?,
        latency_ms: narrow(u.latency_ms, "latency_ms")?,
        ..Default::default()
    })
}

fn canonical_usage(u: Option<&wire::Usage>) -> Result<Usage, ConvertError> {
    let u = u.ok_or(ConvertError::Invalid("usage"))?;
    Ok(Usage {
        input_tokens: u.input_tokens.into(),
        output_tokens: u.output_tokens.into(),
        cached_input_tokens: u.cached_tokens.into(),
        reasoning_tokens: u.reasoning_tokens.into(),
        latency_ms: u.latency_ms.into(),
    })
}

/// The wire request for `request` served by `target`; One-side members (memory references, hints, retention classes, tool versions) stay with One.
///
/// # Errors
/// Rejects an invalid or device-only request and any member the wire cannot carry.
pub fn generate_request(
    request: &ModelRequest,
    target: &ModelRef,
) -> Result<wire::GenerateRequest, ConvertError> {
    request.validate()?;
    target.validate()?;
    if request.is_device_only() {
        return Err(ConvertError::DeviceOnly);
    }
    Ok(wire::GenerateRequest {
        request_id: request.request_id.to_string(),
        task_id: request.task_id.map(|t| t.to_string()).unwrap_or_default(),
        capabilities: request
            .capabilities
            .iter()
            .map(|c| capability(*c).map(Into::into))
            .collect::<Result<_, _>>()?,
        role: model_role(target.model_role)?.into(),
        model_version_id: target.model_version_id.to_string(),
        adapter_id: target.adapter_id.map(|a| a.to_string()).unwrap_or_default(),
        language: language(request.context.language).into(),
        messages: request
            .context
            .messages
            .iter()
            .map(message)
            .collect::<Result<_, _>>()?,
        tools: request
            .tools
            .iter()
            .flatten()
            .map(tool)
            .collect::<Result<_, _>>()?,
        response_schema_json: request
            .response_schema
            .as_ref()
            .map(|s| json_text(s, "response_schema"))
            .transpose()?
            .unwrap_or_default(),
        latency_budget_ms: narrow(request.latency_budget_ms, "latency_budget_ms")?,
        max_output_tokens: request
            .max_output_tokens
            .map(|m| narrow(m, "max_output_tokens"))
            .transpose()?
            .unwrap_or(0),
        data_classes: data_classes(&request.data_class)?,
        mode: wire::Mode {
            ephemeral: request.mode.ephemeral,
            personalise: request.mode.personalise,
            ..Default::default()
        }
        .into(),
        ..Default::default()
    })
}

fn wire_output(o: &Output) -> Result<wire::Output, ConvertError> {
    if o.embedding.is_some() {
        return Err(ConvertError::Unrepresentable("embedding"));
    }
    if o.text.as_deref() == Some("") {
        return Err(ConvertError::Unrepresentable("empty text"));
    }
    Ok(wire::Output {
        text: o.text.clone().unwrap_or_default(),
        structured_json: o
            .structured
            .as_ref()
            .map(|s| json_text(s, "structured"))
            .transpose()?
            .unwrap_or_default(),
        tool_calls: o
            .tool_calls
            .iter()
            .flatten()
            .map(|c| {
                Ok(wire::ToolCall {
                    name: c.name.as_str().to_owned(),
                    input_json: json_text(&c.arguments, "arguments")?,
                    ..Default::default()
                })
            })
            .collect::<Result<_, ConvertError>>()?,
        ..Default::default()
    })
}

fn canonical_output(o: &wire::Output) -> Result<Output, ConvertError> {
    let tool_calls = o
        .tool_calls
        .iter()
        .map(|c| {
            Ok(ToolCall {
                name: CapabilityName::parse(&c.name).map_err(|_| ConvertError::Invalid("name"))?,
                arguments: parse_json::<JsonObject>(&c.input_json, "input_json")?,
            })
        })
        .collect::<Result<Vec<_>, ConvertError>>()?;
    let output = Output {
        text: optional(&o.text).map(str::to_owned),
        structured: optional(&o.structured_json)
            .map(|s| parse_json::<JsonValue>(s, "structured_json"))
            .transpose()?,
        tool_calls: (!tool_calls.is_empty()).then_some(tool_calls),
        embedding: None,
    };
    output.validate()?;
    Ok(output)
}

/// The wire response for `response`.
///
/// # Errors
/// Rejects an invalid response and any member the wire cannot carry (error hints, the short-answer mark, embeddings).
pub fn generate_response(response: &ModelResponse) -> Result<wire::GenerateResponse, ConvertError> {
    response.validate()?;
    if response.short_answer.is_some() {
        return Err(ConvertError::Unrepresentable("short_answer"));
    }
    let result = match (&response.output, &response.error) {
        (Some(output), None) => WireResult::from(wire_output(output)?),
        (None, Some(error)) => {
            if error.retry_after_ms.is_some() || error.context_limit_tokens.is_some() {
                return Err(ConvertError::Unrepresentable("error hint"));
            }
            WireResult::Error(error_code(error.code).into())
        }
        _ => return Err(ConvertError::Contract(ContractViolation("outcome members"))),
    };
    Ok(wire::GenerateResponse {
        request_id: response.request_id.to_string(),
        model_version_id: response
            .model
            .as_ref()
            .map(|m| m.model_version_id.to_string())
            .unwrap_or_default(),
        result: Some(result),
        usage: wire_usage(&response.usage)?.into(),
        ..Default::default()
    })
}

/// The canonical response for a wire response to a request served by `target`.
///
/// # Errors
/// Rejects a wire response that breaks the contract or names another model version.
pub fn model_response(
    response: &wire::GenerateResponse,
    target: &ModelRef,
) -> Result<ModelResponse, ConvertError> {
    let request_id = ModelRequestId::parse(&response.request_id)
        .map_err(|_| ConvertError::Invalid("request_id"))?;
    let model = optional(&response.model_version_id)
        .map(|v| {
            let version =
                ModelVersionId::parse(v).map_err(|_| ConvertError::Invalid("model_version_id"))?;
            if version != target.model_version_id {
                return Err(ConvertError::VersionMismatch);
            }
            Ok(target.clone())
        })
        .transpose()?;
    let (outcome, output, error) = match &response.result {
        Some(WireResult::Output(o)) => (Outcome::Ok, Some(canonical_output(o)?), None),
        Some(WireResult::Error(c)) => (
            Outcome::Error,
            None,
            Some(ModelError {
                code: canonical_error_code(*c)?,
                retry_after_ms: None,
                context_limit_tokens: None,
            }),
        ),
        None => return Err(ConvertError::Invalid("result")),
    };
    let canonical = ModelResponse {
        request_id,
        outcome,
        model,
        short_answer: None,
        output,
        error,
        usage: canonical_usage(response.usage.as_option())?,
    };
    canonical.validate()?;
    Ok(canonical)
}

/// One event of a streamed generation.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEvent {
    /// Text produced so far; never a usable output on its own.
    TextDelta(String),
    /// The complete response.
    Final(Box<ModelResponse>),
}

/// The canonical event for a wire stream event.
///
/// # Errors
/// Rejects an empty event and an invalid final response.
pub fn stream_event(
    event: &wire::GenerateStreamResponse,
    target: &ModelRef,
) -> Result<StreamEvent, ConvertError> {
    match &event.event {
        Some(WireEvent::TextDelta(t)) => Ok(StreamEvent::TextDelta(t.clone())),
        Some(WireEvent::Final(r)) => {
            model_response(r, target).map(|r| StreamEvent::Final(Box::new(r)))
        }
        None => Err(ConvertError::Invalid("event")),
    }
}

/// Reads a generation stream; only the final event yields the response, so a stream cut short yields nothing usable.
#[derive(Debug, Clone)]
pub struct StreamReader {
    target: ModelRef,
    done: Option<ModelResponse>,
}

impl StreamReader {
    /// A reader for a request served by `target`.
    #[must_use]
    pub const fn new(target: ModelRef) -> Self {
        Self { target, done: None }
    }

    /// Takes the next event and returns its text delta, if any.
    ///
    /// # Errors
    /// Rejects an invalid event and any event after the final one.
    pub fn push(
        &mut self,
        event: &wire::GenerateStreamResponse,
    ) -> Result<Option<String>, ConvertError> {
        if self.done.is_some() {
            return Err(ConvertError::Invalid("event after final"));
        }
        match stream_event(event, &self.target)? {
            StreamEvent::TextDelta(t) => Ok(Some(t)),
            StreamEvent::Final(r) => {
                self.done = Some(*r);
                Ok(None)
            }
        }
    }

    /// The final response once the stream has ended.
    ///
    /// # Errors
    /// Rejects a stream that ended before its final event.
    pub fn finish(self) -> Result<ModelResponse, ConvertError> {
        self.done.ok_or(ConvertError::Invalid("stream cut short"))
    }
}

/// Embeddings tagged with the model version that produced them (MF-55).
#[derive(Debug, Clone, PartialEq)]
pub struct Embeddings {
    /// The request this answers.
    pub request_id: ModelRequestId,
    /// The embedding model version.
    pub model_version_id: ModelVersionId,
    /// One vector per text, in request order, all of one dimension.
    pub vectors: Vec<Vec<f32>>,
    /// Usage.
    pub usage: Usage,
}

/// The wire request embedding `texts` with `model_version_id`.
#[must_use]
pub fn embed_request(
    request_id: ModelRequestId,
    model_version_id: ModelVersionId,
    texts: &[String],
) -> wire::EmbedRequest {
    wire::EmbedRequest {
        request_id: request_id.to_string(),
        model_version_id: model_version_id.to_string(),
        texts: texts.to_vec(),
        ..Default::default()
    }
}

fn check_vectors(vectors: &[Vec<f32>], expected: usize) -> Result<(), ConvertError> {
    let dimension = vectors.first().map_or(0, Vec::len);
    if vectors.len() != expected {
        return Err(ConvertError::Invalid("embedding count"));
    }
    if vectors.iter().any(|v| v.is_empty() || v.len() != dimension) {
        return Err(ConvertError::Invalid("embedding dimension"));
    }
    if vectors.iter().flatten().any(|x| !x.is_finite()) {
        return Err(ConvertError::Invalid("embedding values"));
    }
    Ok(())
}

/// The wire response for `embeddings`.
///
/// # Errors
/// Rejects vectors of mixed or empty dimension, non-finite values and usage that does not fit the wire.
pub fn embed_response(embeddings: &Embeddings) -> Result<wire::EmbedResponse, ConvertError> {
    check_vectors(&embeddings.vectors, embeddings.vectors.len())?;
    Ok(wire::EmbedResponse {
        request_id: embeddings.request_id.to_string(),
        model_version_id: embeddings.model_version_id.to_string(),
        embeddings: embeddings
            .vectors
            .iter()
            .map(|v| wire::Embedding {
                values: v.clone(),
                ..Default::default()
            })
            .collect(),
        usage: wire_usage(&embeddings.usage)?.into(),
        ..Default::default()
    })
}

/// The embeddings in a wire response to `request`.
///
/// # Errors
/// Rejects a response for another request or model version, a count other than the request's text count, mixed dimensions and non-finite values.
pub fn embeddings(
    response: &wire::EmbedResponse,
    request: &wire::EmbedRequest,
) -> Result<Embeddings, ConvertError> {
    if response.request_id != request.request_id {
        return Err(ConvertError::Invalid("request_id"));
    }
    if response.model_version_id != request.model_version_id {
        return Err(ConvertError::VersionMismatch);
    }
    let vectors: Vec<Vec<f32>> = response
        .embeddings
        .iter()
        .map(|e| e.values.clone())
        .collect();
    check_vectors(&vectors, request.texts.len())?;
    Ok(Embeddings {
        request_id: ModelRequestId::parse(&response.request_id)
            .map_err(|_| ConvertError::Invalid("request_id"))?,
        model_version_id: ModelVersionId::parse(&response.model_version_id)
            .map_err(|_| ConvertError::Invalid("model_version_id"))?,
        vectors,
        usage: canonical_usage(response.usage.as_option())?,
    })
}

/// The typed identifiers of a wire generation request.
///
/// # Errors
/// Rejects an identifier that is not a typed ID of its kind.
pub fn request_ids(
    request: &wire::GenerateRequest,
) -> Result<
    (
        ModelRequestId,
        Option<TaskId>,
        ModelVersionId,
        Option<AdapterId>,
    ),
    ConvertError,
> {
    Ok((
        ModelRequestId::parse(&request.request_id)
            .map_err(|_| ConvertError::Invalid("request_id"))?,
        optional(&request.task_id)
            .map(TaskId::parse)
            .transpose()
            .map_err(|_| ConvertError::Invalid("task_id"))?,
        ModelVersionId::parse(&request.model_version_id)
            .map_err(|_| ConvertError::Invalid("model_version_id"))?,
        optional(&request.adapter_id)
            .map(AdapterId::parse)
            .transpose()
            .map_err(|_| ConvertError::Invalid("adapter_id"))?,
    ))
}
