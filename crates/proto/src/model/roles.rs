//! Model roles, placement, the served-model reference, the closed error set and usage measures (MF-2, MF-6, MF-32).

use serde::{Deserialize, Serialize};

use crate::id::{AdapterId, ModelVersionId};
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;

/// A model role of One.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelRole {
    /// The small language model.
    SmallLm,
    /// The large language model.
    LargeLm,
    /// The quarantine model.
    Quarantine,
    /// The embedding model.
    Embedding,
    /// Speech recognition.
    SpeechRecognition,
    /// Speech synthesis.
    SpeechSynthesis,
    /// The short-command classifier.
    ShortCommandClassifier,
    /// The attention decision head.
    Attention,
    /// The risk model.
    Risk,
    /// Voice activity detection.
    VoiceActivity,
    /// Wake-word detection.
    WakeWord,
}

impl ModelRole {
    /// True for the language model roles.
    #[must_use]
    pub const fn is_language_model(self) -> bool {
        matches!(self, Self::SmallLm | Self::LargeLm | Self::Quarantine)
    }

    /// True for roles that only run on the device and never reach a processor.
    #[must_use]
    pub const fn is_device_only(self) -> bool {
        matches!(
            self,
            Self::ShortCommandClassifier
                | Self::Attention
                | Self::Risk
                | Self::VoiceActivity
                | Self::WakeWord
        )
    }
}

/// Where a model runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Placement {
    /// Suiss-operated cloud serving.
    Cloud,
    /// The user's device.
    Device,
}

/// The model role and exact version that served a request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelRef {
    /// The role.
    pub model_role: ModelRole,
    /// The exact version.
    pub model_version_id: ModelVersionId,
    /// The personal adapter, small model only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter_id: Option<AdapterId>,
}

impl ModelRef {
    /// Checks that an adapter is attached only to the small model (MF-32).
    ///
    /// # Errors
    /// Rejects an adapter on any other role.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require(
            self.adapter_id.is_none() || self.model_role == ModelRole::SmallLm,
            "adapter only on small_lm",
        )
    }
}

/// The closed common error set (MF-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    /// Rate limited; may carry a retry hint.
    RateLimited,
    /// The model refused.
    Refusal,
    /// The context does not fit; may carry the limit.
    ContextSizeExceeded,
    /// No model is available.
    Unavailable,
}

/// Usage measures every response reports (MF-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    /// Input tokens.
    pub input_tokens: u64,
    /// Output tokens.
    pub output_tokens: u64,
    /// Cached input tokens.
    pub cached_input_tokens: u64,
    /// Reasoning tokens.
    pub reasoning_tokens: u64,
    /// Latency in milliseconds.
    pub latency_ms: u64,
}
