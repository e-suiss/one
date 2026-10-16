//! Capability references in intents: the proposed name and dated version, the same bound to the input schema `$id` and its JCS SHA-256 digest, the registry of pinned input schemas and the caller's input validator (CP-5, CP-15, CP-16).

use alloc::collections::BTreeMap;
use core::fmt;

use one_proto::capability::{CapabilityName, CapabilityRef, CapabilityVersion};
use one_proto::ontology::JsonValue;
use one_proto::task::common::Sha256Digest;
use serde::{Deserialize, Serialize};

use super::jcs::sha256_digest;
use super::text::{checked_text, is_https_uri};

checked_text!(
    /// A JSON Schema `$id`: an `https` URI of at most 2048 characters.
    plain SchemaId,
    "https schema id",
    is_https_uri
);

/// The input schema an intent is bound to: its `$id` and the `sha256:` digest of its JCS form (`capability-ref/v1#/$defs/input_schema`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InputSchemaRef {
    /// The schema `$id`.
    pub id: SchemaId,
    /// The digest of the canonical schema.
    pub digest: Sha256Digest,
}

/// A capability bound to the input schema the registry gives for its name and version (`capability-ref/v1#/$defs/bound`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundCapability {
    /// The capability name.
    pub name: CapabilityName,
    /// The dated version.
    pub version: CapabilityVersion,
    /// The pinned input schema.
    pub input_schema: InputSchemaRef,
}

impl BoundCapability {
    /// Binds a proposed capability to a pinned input schema.
    #[must_use]
    pub fn bind(capability: CapabilityRef, schema: &PinnedSchema) -> Self {
        Self {
            name: capability.name,
            version: capability.version,
            input_schema: schema.reference(),
        }
    }

    /// The name and version alone, as the summary and the planner write them.
    #[must_use]
    pub fn proposed(&self) -> CapabilityRef {
        CapabilityRef {
            name: self.name.clone(),
            version: self.version.clone(),
        }
    }
}

/// A capability input schema document with its `$id` and the digest computed from its JCS form.
#[derive(Clone, PartialEq)]
pub struct PinnedSchema {
    id: SchemaId,
    digest: Sha256Digest,
    document: JsonValue,
}

impl PinnedSchema {
    /// Pins a schema document; `None` without an `https` `$id` or with a number JSON cannot carry.
    #[must_use]
    pub fn new(document: JsonValue) -> Option<Self> {
        let id = SchemaId::new(document.as_object()?.get("$id")?.as_str()?)?;
        let digest = sha256_digest(&document)?;
        Some(Self {
            id,
            digest,
            document,
        })
    }

    /// The schema `$id`.
    #[must_use]
    pub const fn id(&self) -> &SchemaId {
        &self.id
    }

    /// The digest of the canonical schema.
    #[must_use]
    pub const fn digest(&self) -> &Sha256Digest {
        &self.digest
    }

    /// The schema document.
    #[must_use]
    pub const fn document(&self) -> &JsonValue {
        &self.document
    }

    /// The reference an intent carries for this schema.
    #[must_use]
    pub fn reference(&self) -> InputSchemaRef {
        InputSchemaRef {
            id: self.id.clone(),
            digest: self.digest.clone(),
        }
    }
}

impl fmt::Debug for PinnedSchema {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PinnedSchema")
            .field("id", &self.id)
            .field("digest", &self.digest)
            .finish_non_exhaustive()
    }
}

/// The capability registry's pinned input schema for each name and version.
pub trait InputSchemaRegistry {
    /// The pinned input schema of a capability; `None` when the registry has none.
    fn input_schema(&self, capability: &CapabilityRef) -> Option<&PinnedSchema>;
}

impl InputSchemaRegistry for BTreeMap<CapabilityRef, PinnedSchema> {
    fn input_schema(&self, capability: &CapabilityRef) -> Option<&PinnedSchema> {
        self.get(capability)
    }
}

/// Validates a capability input object against its pinned JSON Schema; supplied by the caller, since no schema engine runs in this crate.
pub trait InputSchemaValidator {
    /// Whether the input object, labels removed, conforms to the schema.
    fn conforms(&self, schema: &PinnedSchema, input: &JsonValue) -> bool;
}
