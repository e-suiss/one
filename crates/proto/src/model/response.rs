//! The provider-independent model response: the serving role and version, output or one of the four common errors, and usage (MF-2, MF-6, MF-23).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::roles::{ErrorCode, ModelRef, ModelRole, Usage};
use crate::capability::CapabilityName;
use crate::id::ModelRequestId;
use crate::ontology::JsonObject;
use crate::ontology::JsonValue;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;

/// Whether the request was served.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Served.
    Ok,
    /// Ended in a common error.
    Error,
}

/// A tool call naming a One capability.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolCall {
    /// The capability.
    pub name: CapabilityName,
    /// The arguments.
    pub arguments: JsonObject,
}

/// The model output.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Output {
    /// Text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    /// Structured output.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<JsonValue>,
    /// Tool calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    /// An embedding.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
}

impl Output {
    /// Checks the output has a member and no empty list.
    ///
    /// # Errors
    /// Rejects an empty output or an empty list.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require(
            self.text.is_some()
                || self.structured.is_some()
                || self.tool_calls.is_some()
                || self.embedding.is_some(),
            "output empty",
        )?;
        require(
            self.tool_calls.as_ref().is_none_or(|c| !c.is_empty()),
            "tool_calls empty",
        )?;
        require(
            self.embedding.as_ref().is_none_or(|e| !e.is_empty()),
            "embedding empty",
        )
    }
}

/// One of the four common errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelError {
    /// The code.
    pub code: ErrorCode,
    /// The retry hint, `rate_limited` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_ms: Option<u64>,
    /// The context limit, `context_size_exceeded` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context_limit_tokens: Option<u64>,
}

impl ModelError {
    /// Checks that each hint appears only with its code.
    ///
    /// # Errors
    /// Rejects a hint on another code.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require(
            self.retry_after_ms.is_none() || self.code == ErrorCode::RateLimited,
            "retry_after_ms only on rate_limited",
        )?;
        require(
            self.context_limit_tokens
                .is_none_or(|limit| self.code == ErrorCode::ContextSizeExceeded && limit >= 1),
            "context_limit_tokens only on context_size_exceeded",
        )
    }
}

/// A provider-independent model response (MF-6).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelResponse {
    /// The request this answers.
    pub request_id: ModelRequestId,
    /// Served or error.
    pub outcome: Outcome,
    /// The serving role and version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelRef>,
    /// A small model answered work routed for a large one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub short_answer: Option<bool>,
    /// The output when served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Output>,
    /// The error when not served.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<ModelError>,
    /// Usage, also on errors.
    pub usage: Usage,
}

impl ModelResponse {
    /// The served model and output, or the error.
    ///
    /// # Errors
    /// Returns the common error when the request was not served, or a contract error for an inconsistent response.
    pub fn result(&self) -> Result<Result<(&ModelRef, &Output), &ModelError>, ContractViolation> {
        self.validate()?;
        match (self.outcome, &self.model, &self.output, &self.error) {
            (Outcome::Ok, Some(model), Some(output), None) => Ok(Ok((model, output))),
            (Outcome::Error, _, None, Some(error)) => Ok(Err(error)),
            _ => Err(ContractViolation("outcome members")),
        }
    }

    /// Checks the cross-member rules of the response contract.
    ///
    /// # Errors
    /// Rejects a response that breaks a rule of `response.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(model) = &self.model {
            model.validate()?;
        }
        if let Some(output) = &self.output {
            output.validate()?;
        }
        if let Some(error) = &self.error {
            error.validate()?;
        }
        match self.outcome {
            Outcome::Ok => require(
                self.model.is_some() && self.output.is_some() && self.error.is_none(),
                "ok needs model and output and no error",
            )?,
            Outcome::Error => require(
                self.error.is_some() && self.output.is_none(),
                "error needs error and no output",
            )?,
        }
        if self.short_answer == Some(true) {
            require(
                self.model
                    .as_ref()
                    .is_some_and(|m| m.model_role == ModelRole::SmallLm),
                "short answer comes from small_lm",
            )?;
        }
        Ok(())
    }
}
