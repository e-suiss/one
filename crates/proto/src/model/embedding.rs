//! A stored embedding vector carries the embedding model version that produced it; vectors of different models are never compared (MF-55).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::registry::{ArtifactName, NonEmpty};
use crate::id::ModelVersionId;
use crate::ontology::AnyId;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;

/// The embedded modality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Text.
    Text,
    /// Image.
    Image,
    /// Audio.
    Audio,
}

/// The embedding model that produced a vector.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingModel {
    /// The version identifier.
    pub model_version_id: ModelVersionId,
    /// The model name.
    pub name: ArtifactName,
    /// The model version.
    pub version: NonEmpty,
    /// The dimension.
    pub dimension: u64,
}

/// A stored embedding vector (MF-55).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddingVector {
    /// The embedded record.
    pub record_id: AnyId,
    /// The modality.
    pub modality: Modality,
    /// The producing model.
    pub embedding_model: EmbeddingModel,
    /// The values.
    pub values: Vec<f32>,
}

impl EmbeddingVector {
    /// Checks the dimension and values.
    ///
    /// # Errors
    /// Rejects a zero dimension, an empty vector, a length that differs from the dimension or a non-finite value.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require(self.embedding_model.dimension >= 1, "dimension")?;
        require(!self.values.is_empty(), "values empty")?;
        require(
            u64::try_from(self.values.len()).is_ok_and(|n| n == self.embedding_model.dimension),
            "values length equals dimension",
        )?;
        require(self.values.iter().all(|v| v.is_finite()), "values finite")
    }

    /// True when both vectors come from the same embedding space and can be compared.
    #[must_use]
    pub fn same_space(&self, other: &Self) -> bool {
        self.modality == other.modality
            && self.embedding_model.model_version_id == other.embedding_model.model_version_id
            && self.embedding_model.dimension == other.embedding_model.dimension
    }
}
