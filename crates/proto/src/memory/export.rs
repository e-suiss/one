//! The export package `app.suiss.one.export` of `export.cddl`, JSON encoded: versions only add fields, a reader skips fields it does not know, and an import keeps each original record while it arrives as an unverified `candidate` labelled `external.import` (M-39, M-40, M-41, M-42, M-43, MD-8 (2), INV-27, E-36).

use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::fields::{LiveStatus, SourceKind};
use super::record::{LiveMemoryRecord, LiveRelationshipEdge, MemoryRecord, RelationshipEdge};
use super::text_view::TrustClass;
use crate::id::{AdapterId, MemoryRecordId, TaskId};
use crate::ontology::episode::{Episode, SkeletonRetention};
use crate::ontology::header::Statement;
use crate::ontology::json::JsonValue;
use crate::ontology::provenance::ProvenanceLabel;
use crate::ontology::reference::PartyRef;
use crate::ontology::time::Instant;
use crate::ontology::validate::ContractViolation;

crate::const_tag!(
    /// `format: "app.suiss.one.export"`.
    ExportFormat,
    "app.suiss.one.export"
);
crate::const_tag!(
    /// `source: "access-e65"`: grants and connections come only from the Access E65 read API.
    AccessE65,
    "access-e65"
);
crate::const_tag!(
    /// `format: "safetensors"`.
    Safetensors,
    "safetensors"
);

/// The schema version this reader writes.
pub const SCHEMA_VERSION: NonZeroU32 = NonZeroU32::MIN;

/// The program that wrote the package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Generator {
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
}

/// Records, relationship edges and episodes of one section.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemorySection {
    /// Memory records, forgotten ones as skeletons.
    pub records: Vec<MemoryRecord>,
    /// Relationship edges.
    pub relationship_edges: Vec<RelationshipEdge>,
    /// Episodes.
    pub episodes: Vec<Episode>,
}

/// A section left out of the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExcludedSection {
    /// The sensitive section.
    Sensitive,
}

/// The exported profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProfileExport {
    /// Assistant name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Form of address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub form_of_address: Option<String>,
    /// Style.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub style: Option<String>,
    /// Values.
    pub values: Vec<String>,
}

/// The exported personality.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersonalityExport {
    /// Profile.
    pub profile: ProfileExport,
    /// Rule records.
    pub rules: Vec<MemoryRecordId>,
}

/// A projection read from the Access E65 API, never a partial package.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessProjection {
    /// `access-e65`.
    pub source: AccessE65,
    /// When it was read.
    pub read_at: Instant,
    /// The Access schema of the items.
    pub schema: String,
    /// Items as Access returned them.
    pub items: Vec<BTreeMap<String, JsonValue>>,
}

/// A task step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportTaskStep {
    /// Capability name.
    pub capability: String,
    /// State.
    pub state: String,
    /// Result.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<Statement>,
}

/// An exported task.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExportTask {
    /// The task.
    pub id: TaskId,
    /// Creation time.
    pub created_at: Instant,
    /// State.
    pub state: String,
    /// Goal.
    pub goal: Statement,
    /// Steps.
    pub steps: Vec<ExportTaskStep>,
    /// Outcome.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Statement>,
}

/// The base model an adapter needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BaseModel {
    /// Name.
    pub name: String,
    /// Version.
    pub version: String,
}

/// The exported personal adapter.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterExport {
    /// The adapter.
    pub id: AdapterId,
    /// Its base model.
    pub base_model: BaseModel,
    /// Training time.
    pub trained_at: Instant,
    /// `safetensors`.
    pub format: Safetensors,
    /// SHA-256 of the weights, 64 hex digits.
    pub sha256: String,
    /// Weights, base64url without padding.
    pub weights_b64: String,
    /// The note that the weights need the base model.
    pub note: Statement,
}

/// An export package (M-39, M-40).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportDocument {
    /// `app.suiss.one.export`.
    pub format: ExportFormat,
    /// Schema version, from 1.
    pub schema_version: NonZeroU32,
    /// Export time.
    pub exported_at: Instant,
    /// Owner.
    pub owner: PartyRef,
    /// Generator.
    pub generator: Generator,
    /// Retention class of the package.
    pub retention_class: SkeletonRetention,
    /// Memory.
    pub memory: MemorySection,
    /// The sensitive section, unless excluded.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sensitive: Option<MemorySection>,
    /// Sections left out.
    pub excluded_sections: Vec<ExcludedSection>,
    /// Personality.
    pub personality: PersonalityExport,
    /// Grants.
    pub grants: AccessProjection,
    /// Connections.
    pub connections: AccessProjection,
    /// Tasks.
    pub tasks: Vec<ExportTask>,
    /// Personal adapter, or `null`.
    pub adapter: Option<AdapterExport>,
    /// Human-readable view.
    pub text_view: String,
}

impl MemorySection {
    fn check_rules(&self) -> Result<(), ContractViolation> {
        for r in self.records.iter().filter_map(MemoryRecord::live) {
            r.check_rules()?;
        }
        for e in &self.relationship_edges {
            if let RelationshipEdge::Live(l) = e {
                l.check_rules()?;
            }
        }
        for e in &self.episodes {
            if let Episode::Live(l) = e {
                l.check_rules()?;
            }
        }
        Ok(())
    }
}

impl ExportDocument {
    /// Checks the record rules the types alone do not express; unknown fields stay allowed (M-40).
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        for section in core::iter::once(&self.memory).chain(self.sensitive.iter()) {
            section.check_rules()?;
        }
        Ok(())
    }
}

/// The original of an imported record, kept field for field.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ImportedOriginal {
    /// A relationship edge.
    Edge(Box<LiveRelationshipEdge>),
    /// A memory record.
    Record(Box<LiveMemoryRecord>),
}

/// An imported record: data, never instruction or behaviour rule, until the user confirms it (M-43).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportedRecord {
    /// `candidate`.
    pub status: LiveStatus,
    /// `import`.
    pub source_kind: SourceKind,
    /// `external.import`.
    pub provenance: ProvenanceLabel,
    /// `imported_unverified`.
    pub trust_class: TrustClass,
    /// The exported record unchanged.
    pub original: ImportedOriginal,
}

/// The result of an import.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportResult {
    /// Imported records.
    pub imported: Vec<ImportedRecord>,
    /// Imported records never train the personal adapter before confirmation.
    pub training_eligible: bool,
}

fn imported(original: ImportedOriginal) -> ImportedRecord {
    ImportedRecord {
        status: LiveStatus::Candidate,
        source_kind: SourceKind::Import,
        provenance: ProvenanceLabel::ExternalImport,
        trust_class: TrustClass::ImportedUnverified,
        original,
    }
}

/// Imports the live records and edges of a package; skeletons stay behind (M-43).
#[must_use]
pub fn import(document: &ExportDocument) -> ImportResult {
    let mut out = Vec::new();
    for section in core::iter::once(&document.memory).chain(document.sensitive.iter()) {
        for r in section.records.iter().filter_map(MemoryRecord::live) {
            out.push(imported(ImportedOriginal::Record(Box::new(r.clone()))));
        }
        for e in &section.relationship_edges {
            if let RelationshipEdge::Live(l) = e {
                out.push(imported(ImportedOriginal::Edge(l.clone())));
            }
        }
    }
    ImportResult {
        imported: out,
        training_eligible: false,
    }
}
