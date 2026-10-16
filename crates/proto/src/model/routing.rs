//! The routing record, split into a `one_memory` part (gate, eliminated options, chosen role and version, estimate, outcome) and a `one_provider_trace` part (processor hops); it carries no content (MF-3, MF-20, MF-22, MF-24).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::common::{is_artifact_name, validate_content_classes};
use super::roles::{ModelRef, ModelRole};
use crate::data_class::DataClass;
use crate::data_class::RetentionClass;
use crate::id::{ModelRequestId, ModelVersionId};
use crate::ontology::Instant;
use crate::ontology::tags::{OneMemoryClass, OneProviderTraceClass};
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;
use crate::ontology::validate::require;

/// The first-stage gate result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateResult {
    /// A model was chosen.
    Passed,
    /// Refused.
    Refused,
    /// Queued until online.
    QueuedOffline,
    /// No suitable model; the request waits.
    WaitingNoModel,
}

/// A routing option the gate considered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingOption {
    /// The role.
    pub model_role: ModelRole,
    /// The version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version_id: Option<ModelVersionId>,
    /// With the personal adapter.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub with_adapter: Option<bool>,
}

/// Why the gate eliminated an option.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EliminationRule {
    /// The data class.
    DataClass,
    /// Consent.
    Consent,
    /// Grant budget.
    GrantBudget,
    /// Connectivity.
    Connectivity,
    /// Region.
    Region,
    /// Request mode.
    Mode,
    /// Unavailable.
    Unavailable,
    /// Not released.
    NotReleased,
}

/// An eliminated option and the rule that eliminated it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Elimination {
    /// The option.
    pub option: RoutingOption,
    /// The rule.
    pub rule: EliminationRule,
}

/// The gate outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Gate {
    /// The result.
    pub result: GateResult,
    /// The eliminated options.
    pub eliminated: Vec<Elimination>,
}

/// The second-stage estimate that the small model suffices.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Estimate {
    /// The probability the small model suffices.
    pub small_sufficient: f64,
    /// The estimator version.
    pub estimator_version: EstimatorVersion,
}

checked_string!(
    /// An estimator version.
    EstimatorVersion,
    "estimator_version",
    |s| !s.is_empty()
);

/// The fallback taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Fallback {
    /// None.
    None,
    /// Another instance.
    OtherInstance,
    /// The backup family.
    BackupFamily,
    /// A short answer from the small model.
    SmallShortAnswer,
    /// Wait.
    Wait,
}

/// A learned outcome signal (MF-21).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeSignal {
    /// Not yet known.
    Pending,
    /// Accepted.
    Accepted,
    /// Corrected.
    Corrected,
    /// Asked again.
    ReAsked,
    /// Undone.
    Undone,
    /// The task succeeded.
    TaskSucceeded,
    /// The task failed.
    TaskFailed,
}

/// The outcome of a routed request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingOutcome {
    /// The signal.
    pub signal: OutcomeSignal,
    /// When it was observed; absent while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Instant>,
}

/// The `one_memory` part of a routing record.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryPart {
    /// Always `one_memory`.
    pub retention_class: OneMemoryClass,
    /// The content data class.
    pub data_class: DataClass,
    /// The content retention classes.
    pub retention_classes: Vec<RetentionClass>,
    /// The content stayed on the device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_only: Option<bool>,
    /// The gate outcome.
    pub gate: Gate,
    /// The chosen role and version when the gate passed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chosen: Option<ModelRef>,
    /// The estimate; `null` when the gate left at most one role.
    #[serde(deserialize_with = "Option::deserialize")]
    pub estimate: Option<Estimate>,
    /// The fallback taken.
    pub fallback: Fallback,
    /// The outcome.
    pub outcome: RoutingOutcome,
}

checked_string!(
    /// A Suiss serving region code.
    Region,
    "region",
    |s| {
        let mut parts = s.split('-');
        parts
            .next()
            .is_some_and(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_lowercase()))
            && parts.all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()))
    }
);

checked_string!(
    /// A sub-processor name.
    SubProcessor,
    "sub_processor",
    is_artifact_name
);

/// A processor; only Suiss model serving exists (MF-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Processor {
    /// Suiss model serving.
    SuissModelServing,
}

/// A processor hop and the data class it received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Hop {
    /// The processor.
    pub processor: Processor,
    /// The region.
    pub region: Region,
    /// The sub-processor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sub_processor: Option<SubProcessor>,
    /// Served inside an attested TEE.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attested_tee: Option<bool>,
    /// The data class received.
    pub data_class: DataClass,
}

/// The `one_provider_trace` part of a routing record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderTracePart {
    /// Always `one_provider_trace`.
    pub retention_class: OneProviderTraceClass,
    /// The hops.
    pub hops: Vec<Hop>,
}

/// A routing record (MF-22).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingRecord {
    /// The request.
    pub request_id: ModelRequestId,
    /// When it was recorded.
    pub recorded_at: Instant,
    /// The `one_memory` part.
    pub memory_part: MemoryPart,
    /// The `one_provider_trace` part.
    pub provider_trace_part: ProviderTracePart,
}

impl RoutingRecord {
    /// Splits the record into its `one_memory` and `one_provider_trace` parts.
    #[must_use]
    pub fn split(self) -> (MemoryPart, ProviderTracePart) {
        (self.memory_part, self.provider_trace_part)
    }

    /// Checks the cross-member rules of the routing record contract.
    ///
    /// # Errors
    /// Rejects a record that breaks a rule of `routing-record.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let m = &self.memory_part;
        validate_content_classes(&m.data_class, &m.retention_classes)?;
        if let Some(chosen) = &m.chosen {
            chosen.validate()?;
        }
        if let Some(estimate) = &m.estimate {
            require(
                (0.0..=1.0).contains(&estimate.small_sufficient),
                "small_sufficient",
            )?;
        }
        let passed = m.gate.result == GateResult::Passed;
        require(
            passed == m.chosen.is_some(),
            "chosen exactly when the gate passed",
        )?;
        if !passed {
            require(
                matches!(m.fallback, Fallback::None | Fallback::Wait),
                "no serving fallback without a passed gate",
            )?;
        }
        if m.fallback == Fallback::SmallShortAnswer {
            require(
                m.chosen
                    .as_ref()
                    .is_some_and(|c| c.model_role == ModelRole::SmallLm),
                "short answer served by small_lm",
            )?;
        }
        require(
            (m.fallback == Fallback::Wait) == (m.gate.result == GateResult::WaitingNoModel),
            "wait exactly when no model",
        )?;
        require(
            (m.outcome.signal == OutcomeSignal::Pending) != m.outcome.at.is_some(),
            "outcome at exactly when not pending",
        )?;
        let hops = &self.provider_trace_part.hops;
        let local = !passed
            || m.chosen
                .as_ref()
                .is_some_and(|c| c.model_role.is_device_only())
            || m.device_only == Some(true);
        require(!local || hops.is_empty(), "no processor hop")?;
        hops.iter().try_for_each(|hop| {
            require(
                !hop.data_class.is_sensitive() || hop.attested_tee == Some(true),
                "PV-20 data only to an attested TEE",
            )
        })
    }
}
