//! Model registry entries: one row per artifact with role, base model, version, format, licence, evaluation and lineage; a released entry is signed and passed its gate (MF-16, MF-55, T-39 (5), SEC-26).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::common::is_artifact_name;
use super::roles::{ModelRole, Placement};
use crate::id::ModelVersionId;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

checked_string!(
    /// An artifact name `[a-z0-9][a-z0-9._-]*`.
    ArtifactName,
    "name",
    is_artifact_name
);

checked_string!(
    /// An artifact version `[0-9A-Za-z.+_-]+`.
    ArtifactVersion,
    "version",
    |s| !s.is_empty()
        && s
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '_' | '-'))
);

checked_string!(
    /// A lower-case hex SHA-256.
    Sha256Hex,
    "sha256",
    |s| s.len() == 64 && s.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
);

checked_string!(
    /// A non-blank text.
    NonBlank,
    "non-blank text",
    |s| s.chars().any(|c| !c.is_whitespace())
);

checked_string!(
    /// A non-empty text.
    NonEmpty,
    "non-empty text",
    |s| !s.is_empty()
);

checked_string!(
    /// A quantisation code.
    Quantisation,
    "quantisation",
    |s| {
        if matches!(s, "fp32" | "fp16" | "bf16" | "fp8" | "int8" | "int4") {
            return true;
        }
        let mut chars = s.chars();
        chars.next() == Some('q')
            && chars.next().is_some_and(|c| ('2'..='8').contains(&c))
            && chars.as_str().split('_').skip(1).all(|seg| {
                !seg.is_empty() && seg.chars().all(|c| c.is_ascii_digit() || c.is_ascii_lowercase())
            })
            && (chars.as_str().is_empty() || chars.as_str().starts_with('_'))
    }
);

checked_string!(
    /// An SPDX licence identifier or `LicenseRef-…`.
    Spdx,
    "spdx",
    |s| match s.strip_prefix("LicenseRef-") {
        Some(rest) => {
            !rest.is_empty() && rest.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        }
        None => {
            !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '-'))
        }
    }
);

checked_string!(
    /// An evaluation set name `[a-z0-9_]+`.
    EvaluationSet,
    "evaluation.set",
    |s| !s.is_empty() && s.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
);

checked_string!(
    /// A dataset manifest path `ml/datasets/manifests/….toml`.
    ManifestPath,
    "manifest",
    |s| s
        .strip_prefix("ml/datasets/manifests/")
        .and_then(|rest| rest.strip_suffix(".toml"))
        .is_some_and(|stem| {
            !stem.is_empty()
                && stem
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-'))
        })
);

/// An artifact format; code-executing formats are absent (SEC-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    /// `safetensors`.
    Safetensors,
    /// `gguf`.
    Gguf,
    /// `onnx`.
    Onnx,
    /// `tflite`.
    Tflite,
    /// `litertlm`.
    Litertlm,
    /// `mlpackage`.
    Mlpackage,
    /// `pte`.
    Pte,
}

/// The release status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Not yet released.
    Candidate,
    /// Released.
    Released,
    /// Retired.
    Retired,
}

/// The model kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelKind {
    /// An upstream base model.
    Base,
    /// A One behaviour-trained model.
    OneBehaviour,
    /// A personal adapter.
    PersonalAdapter,
    /// A device model.
    Device,
    /// An embedding model.
    Embedding,
    /// A voice model.
    Voice,
}

/// The platform an artifact is built for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Platform {
    /// Cloud serving.
    Cloud,
    /// iOS.
    Ios,
    /// Android.
    Android,
    /// macOS.
    Macos,
    /// Windows.
    Windows,
    /// Linux.
    Linux,
}

/// The base model an artifact derives from.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BaseModel {
    /// The base name.
    pub name: ArtifactName,
    /// The base version.
    pub version: NonEmpty,
    /// The base version identifier.
    pub model_version_id: ModelVersionId,
}

/// The licence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Licence {
    /// The SPDX identifier.
    pub spdx: Spdx,
}

/// The evaluation gate result.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    /// Not yet evaluated.
    Pending,
    /// Passed.
    Passed,
    /// Failed.
    Failed,
}

/// The evaluation result.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    /// The gate.
    pub gate: Gate,
    /// The evaluation set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set: Option<EvaluationSet>,
    /// The set version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub set_version: Option<NonEmpty>,
    /// The result reference.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_ref: Option<NonEmpty>,
}

/// The training data lineage kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LineageKind {
    /// Upstream.
    Upstream,
    /// Open and synthetic data.
    OpenAndSynthetic,
    /// The user's own data.
    Personal,
    /// Shared data under differential privacy.
    SharedDp,
}

/// The training data lineage.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lineage {
    /// The kind.
    pub kind: LineageKind,
    /// The dataset manifests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub manifests: Option<Vec<ManifestPath>>,
    /// The `one_training_lineage` record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub training_lineage_ref: Option<NonEmpty>,
    /// Training compute in FLOP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub training_compute_flop: Option<f64>,
}

impl Lineage {
    fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(manifests) = &self.manifests {
            require(unique(manifests), "manifests repeated")?;
        }
        require(
            self.training_compute_flop
                .is_none_or(|f| f > 0.0 && f.is_finite()),
            "training_compute_flop",
        )?;
        match self.kind {
            LineageKind::OpenAndSynthetic => require(
                self.manifests.as_ref().is_some_and(|m| !m.is_empty()),
                "open_and_synthetic lists manifests",
            ),
            LineageKind::SharedDp => require(
                self.manifests.is_some() && self.training_lineage_ref.is_some(),
                "shared_dp names manifests and training lineage",
            ),
            LineageKind::Upstream | LineageKind::Personal => require(
                self.training_lineage_ref.is_none(),
                "no training lineage record",
            ),
        }
    }
}

/// A model registry entry (MF-55).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    /// The artifact name.
    pub name: ArtifactName,
    /// The artifact version.
    pub version: ArtifactVersion,
    /// Cloud or device.
    pub role: Placement,
    /// The component.
    pub component: NonEmpty,
    /// The format.
    pub format: Format,
    /// The artifact digest.
    pub sha256: Sha256Hex,
    /// Where it comes from.
    pub source: NonBlank,
    /// The release status.
    pub status: Status,
    /// The signature; required and non-blank once released.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<String>,
    /// The version identifier.
    pub model_version_id: ModelVersionId,
    /// The model kind.
    pub kind: ModelKind,
    /// The model role.
    pub model_role: ModelRole,
    /// The base model.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_model: Option<BaseModel>,
    /// The platform.
    pub platform: Platform,
    /// The quantisation.
    pub quantisation: Quantisation,
    /// The size in bytes.
    pub size_bytes: u64,
    /// The embedding dimension, embedding models only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding_dimension: Option<u64>,
    /// The licence.
    pub licence: Licence,
    /// The evaluation result.
    pub evaluation: Evaluation,
    /// The training data lineage.
    pub lineage: Lineage,
}

impl RegistryEntry {
    /// True when the entry may be served: released, signed and passed (MF-52, SEC-26).
    #[must_use]
    pub fn is_releasable(&self) -> bool {
        self.signature
            .as_deref()
            .is_some_and(|s| s.chars().any(|c| !c.is_whitespace()))
            && self.evaluation.gate == Gate::Passed
    }

    /// Checks the cross-member rules of the registry entry contract.
    ///
    /// # Errors
    /// Rejects an entry that breaks a rule of `registry-entry.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.lineage.validate()?;
        require(self.size_bytes >= 1, "size_bytes")?;
        require(self.embedding_dimension != Some(0), "embedding_dimension")?;
        if self.evaluation.gate != Gate::Pending {
            require(
                self.evaluation.set.is_some()
                    && self.evaluation.set_version.is_some()
                    && self.evaluation.result_ref.is_some(),
                "evaluated gate names set, version and result",
            )?;
        }
        if self.status == Status::Released {
            require(
                self.is_releasable(),
                "released needs signature and passed gate",
            )?;
        }
        match self.role {
            Placement::Cloud => require(self.platform == Platform::Cloud, "cloud entry on cloud")?,
            Placement::Device => {
                require(self.platform != Platform::Cloud, "device entry on a device")?;
                require(
                    !self.model_role.is_language_model(),
                    "no language model on a device",
                )?;
            }
        }
        self.validate_kind()?;
        let role = self.model_role;
        require(
            (role == ModelRole::Embedding) == self.embedding_dimension.is_some(),
            "embedding_dimension exactly for embedding",
        )?;
        require(
            self.lineage.kind != LineageKind::Personal
                || matches!(self.kind, ModelKind::PersonalAdapter | ModelKind::Device),
            "personal lineage only for adapters and device models",
        )
    }

    fn validate_kind(&self) -> Result<(), ContractViolation> {
        let role = self.model_role;
        match self.kind {
            ModelKind::Base => {
                require(self.base_model.is_none(), "base has no base_model")?;
                require(
                    self.lineage.kind == LineageKind::Upstream,
                    "base lineage upstream",
                )?;
                require(
                    matches!(
                        role,
                        ModelRole::SmallLm
                            | ModelRole::LargeLm
                            | ModelRole::Embedding
                            | ModelRole::SpeechRecognition
                            | ModelRole::SpeechSynthesis
                    ),
                    "base role",
                )?;
            }
            ModelKind::OneBehaviour => {
                require(self.base_model.is_some(), "one_behaviour needs base_model")?;
                require(self.role == Placement::Cloud, "one_behaviour in the cloud")?;
                require(role.is_language_model(), "one_behaviour role")?;
                require(
                    self.lineage.training_compute_flop.is_some(),
                    "one_behaviour records training compute",
                )?;
                require(
                    matches!(
                        self.lineage.kind,
                        LineageKind::OpenAndSynthetic | LineageKind::SharedDp
                    ),
                    "one_behaviour lineage",
                )?;
            }
            ModelKind::PersonalAdapter => {
                require(
                    self.base_model.is_some(),
                    "personal_adapter needs base_model",
                )?;
                require(
                    self.role == Placement::Cloud,
                    "personal_adapter in the cloud",
                )?;
                require(role == ModelRole::SmallLm, "personal_adapter for small_lm")?;
                require(
                    self.source.as_str() == "user_space",
                    "personal_adapter in user_space",
                )?;
                require(
                    self.format == Format::Safetensors,
                    "personal_adapter safetensors",
                )?;
                require(
                    self.lineage.kind == LineageKind::Personal,
                    "personal_adapter lineage",
                )?;
            }
            ModelKind::Device => {
                require(self.role == Placement::Device, "device model on the device")?;
                require(
                    matches!(
                        role,
                        ModelRole::ShortCommandClassifier | ModelRole::Attention | ModelRole::Risk
                    ),
                    "device role",
                )?;
            }
            ModelKind::Embedding => {
                require(role == ModelRole::Embedding, "embedding role")?;
            }
            ModelKind::Voice => require(
                matches!(
                    role,
                    ModelRole::SpeechRecognition
                        | ModelRole::SpeechSynthesis
                        | ModelRole::VoiceActivity
                        | ModelRole::WakeWord
                ),
                "voice role",
            )?,
        }
        Ok(())
    }
}

/// The model registry document.
#[derive(Clone, Debug, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    /// The entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<Vec<RegistryEntry>>,
}

impl Registry {
    /// Checks every entry.
    ///
    /// # Errors
    /// Returns the first entry's contract error.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.model
            .iter()
            .flatten()
            .try_for_each(RegistryEntry::validate)
    }

    /// The released, servable entries.
    pub fn releasable(&self) -> impl Iterator<Item = &RegistryEntry> {
        self.model
            .iter()
            .flatten()
            .filter(|e| e.status == Status::Released && e.is_releasable())
    }
}
