//! The capability registry entry: one primary action, undo for reversible, compensate for compensable, no undeclared reversibility, safe schemas, a strong approval ceiling for irreversible or high-tier actions, and projections named after the capability with UCP only for commerce (CP-16, CP-19, CP-23, A-24, A-26, A-28, C-27).

use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::name::{CapabilityName, CapabilityVersion, Extends, NameKind, ThirdPartyName};
use super::schema::TypedSchema;
use crate::data_class::DataClass;
use crate::data_class::Domain;
use crate::data_class::RetentionClass;
use crate::id::CapabilityId;
use crate::interaction_types::Authentication;
use crate::interaction_types::ConsequenceTier;
use crate::interaction_types::Modality;
use crate::interaction_types::SurfaceClass;
use crate::ontology::ActionRef;
use crate::ontology::Instant;
use crate::ontology::JsonObject;
use crate::ontology::OpaqueId;
use crate::ontology::PartyRef;
use crate::ontology::ProducedBy;
use crate::ontology::ProvenanceLabel;
use crate::ontology::RecordStatus;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;
use crate::task::common::{
    AutonomyBehaviour, LocalizedText, check_header, checked_record, wire_enum,
};

wire_enum!(
    /// The role of an action in a registry entry.
    ActionRole {
        /// The capability's own action.
        Primary = "primary",
        /// Undoes the primary action.
        Undo = "undo",
        /// Compensates the primary action.
        Compensate = "compensate",
    }
);

/// One action of a registry entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RegistryAction {
    /// The role.
    pub role: ActionRole,
    /// The Access action.
    pub action_ref: ActionRef,
}

wire_enum!(
    /// An example language.
    ExampleLang {
        /// Turkish.
        Tr = "tr",
        /// English.
        En = "en",
    }
);

fn is_utterance(text: &str) -> bool {
    (1..=512).contains(&text.chars().count())
}

crate::ontology::validate::checked_string!(
    /// An example utterance.
    Utterance,
    "utterance",
    is_utterance
);

/// One example request with its typed input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Example {
    /// The language.
    pub lang: ExampleLang,
    /// What the user says.
    pub utterance: Utterance,
    /// The typed input it maps to.
    pub input: JsonObject,
}

/// The authority a capability needs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRequirement {
    /// The Grant scope.
    pub grant_scope: OpaqueId,
    /// The consequence tier.
    pub consequence_tier: ConsequenceTier,
}

/// The data a capability reads and writes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DataAccess {
    /// Read data class, or none.
    #[serde(deserialize_with = "Option::deserialize")]
    pub reads: Option<DataClass>,
    /// Written data class, or none.
    #[serde(deserialize_with = "Option::deserialize")]
    pub writes: Option<DataClass>,
}

fn check_ceiling(value: &ApprovalCeiling) -> Result<(), ContractViolation> {
    require(
        !value.surface_classes.is_empty() && unique(&value.surface_classes),
        "approval surface classes",
    )
}

checked_record!(
    /// Where and how strongly an approval must happen.
    #[derive(Eq)]
    pub struct ApprovalCeiling via ApprovalCeilingWire = "ApprovalCeilingWire", check check_ceiling {
        /// Surfaces that may approve.
        pub surface_classes: Vec<SurfaceClass>,
        /// The weakest accepted authentication.
        pub min_assurance: Authentication,
    }
);

fn check_surface(value: &SurfaceRequirement) -> Result<(), ContractViolation> {
    require(unique(&value.modalities), "modalities are unique")
}

checked_record!(
    /// The surface a capability needs.
    #[derive(Eq)]
    pub struct SurfaceRequirement via SurfaceRequirementWire = "SurfaceRequirementWire", check check_surface {
        /// Modalities it can be presented in.
        pub modalities: Vec<Modality>,
        /// The approval ceiling.
        pub approval_ceiling: ApprovalCeiling,
    }
);

wire_enum!(
    /// How a provider is reached.
    PathType {
        /// A provider API.
        Api = "api",
        /// An MCP server.
        Mcp = "mcp",
        /// A commerce protocol.
        CommerceProtocol = "commerce_protocol",
        /// An OS intent.
        OsIntent = "os_intent",
        /// The browser.
        Browser = "browser",
    }
);

/// A provider and its path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    /// The provider.
    pub provider_ref: OpaqueId,
    /// The path.
    pub path_type: PathType,
}

wire_enum!(
    /// The last evaluation result.
    EvaluationResult {
        /// Passed.
        Pass = "pass",
        /// Failed; the planner hides the capability.
        Fail = "fail",
    }
);

/// Which declarations the evaluation gate verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, reason = "CP-19")]
pub struct Verified {
    /// Reversibility.
    pub reversibility: bool,
    /// Data access.
    pub data_access: bool,
    /// Surface.
    pub surface: bool,
}

/// The evaluation status (CP-19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TestStatus {
    /// The last success.
    pub last_success_at: Instant,
    /// The last result.
    pub last_result: EvaluationResult,
    /// The evaluation record.
    pub evaluation_ref: OpaqueId,
    /// What the gate verified.
    pub verified: Verified,
}

fn is_apple_schema(text: &str) -> bool {
    let Some(rest) = text.strip_prefix('.') else {
        return false;
    };
    let Some((domain, action)) = rest.split_once('.') else {
        return false;
    };
    !domain.is_empty()
        && domain.bytes().all(|b| b.is_ascii_lowercase())
        && !action.is_empty()
        && action.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_app_function(text: &str) -> bool {
    (1..=256).contains(&text.chars().count())
}

crate::ontology::validate::checked_string!(
    /// An Apple App Intents app schema identifier such as `.mail.createDraft`.
    AppleAppSchema,
    "Apple app schema",
    is_apple_schema
);
crate::ontology::validate::checked_string!(
    /// An Android `AppFunction` identifier.
    AndroidAppFunction,
    "Android AppFunction",
    is_app_function
);

/// The outbound protocol projections of a capability (C-27).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Projections {
    /// The MCP tool name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_tool: Option<CapabilityName>,
    /// The A2A skill id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_skill: Option<CapabilityName>,
    /// The Apple app schema.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub apple_app_schema: Option<AppleAppSchema>,
    /// The Android `AppFunction`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub android_app_function: Option<AndroidAppFunction>,
    /// The UCP capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ucp: Option<ThirdPartyName>,
}

wire_enum!(
    /// The record type discriminator of a registry entry.
    CapabilityDefinitionType {
        /// A capability definition.
        CapabilityDefinition = "CapabilityDefinition",
    }
);

/// Why a registry entry is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RegistryRejection {
    /// Not exactly one primary action.
    PrimaryActionCount,
    /// Reversible without an undo action.
    ReversibleWithoutUndo,
    /// Compensable without a compensate action.
    CompensableWithoutCompensate,
    /// Irreversible but offering undo or compensation.
    IrreversibleWithUndo,
    /// Irreversible or CT2/CT3 but approvable outside phone and desktop or without a passkey.
    WeakApprovalCeiling,
    /// A third-party name without `extends`.
    ThirdPartyWithoutExtends,
    /// Examples missing Turkish or English, or fewer than two.
    ExamplesIncomplete,
    /// No provider.
    NoProvider,
    /// An MCP tool name or A2A skill id other than the capability name.
    ProjectionNameMismatch,
    /// A UCP projection on a capability outside the commerce category.
    UcpOutsideCommerce,
}

impl RegistryRejection {
    const fn what(self) -> &'static str {
        match self {
            Self::PrimaryActionCount => "exactly one primary action",
            Self::ReversibleWithoutUndo => "reversible needs an undo action",
            Self::CompensableWithoutCompensate => "compensable needs a compensate action",
            Self::IrreversibleWithUndo => "irreversible offers no undo or compensation",
            Self::WeakApprovalCeiling => {
                "irreversible or CT2/CT3 approval only on phone or desktop with a passkey"
            }
            Self::ThirdPartyWithoutExtends => "a third-party name extends a parent",
            Self::ExamplesIncomplete => "examples in Turkish and English",
            Self::NoProvider => "at least one provider",
            Self::ProjectionNameMismatch => "an MCP tool or A2A skill is the capability name",
            Self::UcpOutsideCommerce => "a UCP projection only on a commerce capability",
        }
    }
}

/// Checks the registry rules over a definition's parts.
///
/// # Errors
/// Returns the first rule the entry breaks.
pub fn check_registry_entry(definition: &CapabilityDefinition) -> Result<(), RegistryRejection> {
    let roles = |role: ActionRole| definition.actions.iter().filter(|a| a.role == role).count();
    if roles(ActionRole::Primary) != 1 {
        return Err(RegistryRejection::PrimaryActionCount);
    }
    let undo = roles(ActionRole::Undo);
    let compensate = roles(ActionRole::Compensate);
    match definition.reversibility {
        crate::interaction_types::Reversibility::Reversible if undo == 0 => {
            return Err(RegistryRejection::ReversibleWithoutUndo);
        }
        crate::interaction_types::Reversibility::Compensable if compensate == 0 => {
            return Err(RegistryRejection::CompensableWithoutCompensate);
        }
        crate::interaction_types::Reversibility::Irreversible if undo != 0 || compensate != 0 => {
            return Err(RegistryRejection::IrreversibleWithUndo);
        }
        _ => {}
    }
    let strong = definition.reversibility == crate::interaction_types::Reversibility::Irreversible
        || matches!(
            definition.authority.consequence_tier,
            ConsequenceTier::Ct2 | ConsequenceTier::Ct3
        );
    let ceiling = &definition.surface.approval_ceiling;
    if strong
        && (ceiling.min_assurance != Authentication::Passkey
            || !ceiling
                .surface_classes
                .iter()
                .all(|c| matches!(c, SurfaceClass::Phone | SurfaceClass::Desktop)))
    {
        return Err(RegistryRejection::WeakApprovalCeiling);
    }
    if definition.name.kind() == NameKind::ThirdParty && definition.extends.is_none() {
        return Err(RegistryRejection::ThirdPartyWithoutExtends);
    }
    let has = |lang: ExampleLang| definition.examples.iter().any(|e| e.lang == lang);
    if definition.examples.len() < 2 || !has(ExampleLang::Tr) || !has(ExampleLang::En) {
        return Err(RegistryRejection::ExamplesIncomplete);
    }
    if definition.providers.is_empty() {
        return Err(RegistryRejection::NoProvider);
    }
    let projections = &definition.projections;
    if [&projections.mcp_tool, &projections.a2a_skill]
        .into_iter()
        .flatten()
        .any(|n| *n != definition.name)
    {
        return Err(RegistryRejection::ProjectionNameMismatch);
    }
    if projections.ucp.is_some() && definition.name.category() != Some("commerce") {
        return Err(RegistryRejection::UcpOutsideCommerce);
    }
    Ok(())
}

fn check_definition(definition: &CapabilityDefinition) -> Result<(), ContractViolation> {
    check_header(
        definition.version,
        definition.supersedes.is_some(),
        definition.status,
        definition.deleted_at.as_ref(),
        &definition.data_class,
        definition.retention_class,
    )?;
    definition.domain.check()?;
    definition.produced_by.check()?;
    require(!definition.actions.is_empty(), "at least one action")?;
    check_registry_entry(definition).map_err(|r| ContractViolation(r.what()))
}

checked_record!(
    /// A capability registry entry; a definition is not authority (CP-16).
    pub struct CapabilityDefinition via CapabilityDefinitionWire = "CapabilityDefinitionWire", check check_definition {
        /// The record type.
        #[serde(rename = "type")]
        pub record_type: CapabilityDefinitionType,
        /// The record identifier.
        pub id: CapabilityId,
        /// The owner.
        pub owner: PartyRef,
        /// Life areas and project.
        pub domain: Domain,
        /// The data class.
        pub data_class: DataClass,
        /// The retention class.
        pub retention_class: RetentionClass,
        /// The record's provenance.
        pub provenance: ProvenanceLabel,
        /// When the record was written.
        pub recorded_at: Instant,
        /// The record version.
        pub version: NonZeroU32,
        /// The version this one supersedes.
        #[serde(deserialize_with = "Option::deserialize")]
        pub supersedes: Option<CapabilityId>,
        /// Record lifecycle.
        pub status: RecordStatus,
        /// When the record was deleted.
        #[serde(deserialize_with = "Option::deserialize")]
        pub deleted_at: Option<Instant>,
        /// Who produced the record.
        pub produced_by: ProducedBy,
        /// The capability name.
        pub name: CapabilityName,
        /// The dated capability version.
        pub capability_version: CapabilityVersion,
        /// The parents.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub extends: Option<Extends>,
        /// The publisher.
        pub publisher: PartyRef,
        /// The meaning in Turkish and English.
        pub meaning: LocalizedText,
        /// The actions: exactly one primary.
        pub actions: Vec<RegistryAction>,
        /// The input schema.
        pub input_schema: TypedSchema,
        /// The output schema.
        pub output_schema: TypedSchema,
        /// Examples in Turkish and English.
        pub examples: Vec<Example>,
        /// The authority it needs.
        pub authority: AuthorityRequirement,
        /// The autonomy ceiling.
        pub autonomy_ceiling: AutonomyBehaviour,
        /// The declared reversibility.
        pub reversibility: crate::interaction_types::Reversibility,
        /// The data it reads and writes.
        pub data_access: DataAccess,
        /// The surface it needs.
        pub surface: SurfaceRequirement,
        /// Providers and their paths.
        pub providers: Vec<Provider>,
        /// The evaluation status.
        pub test_status: TestStatus,
        /// Outbound projections.
        pub projections: Projections,
    }
);

/// The reversibility the gate records: a declaration counts only when verified; undeclared or unverified is irreversible (A-24).
#[must_use]
pub const fn effective_reversibility(
    declared: Option<crate::interaction_types::Reversibility>,
    verified: bool,
) -> crate::interaction_types::Reversibility {
    match declared {
        Some(r) if verified => r,
        _ => crate::interaction_types::Reversibility::Irreversible,
    }
}

/// MCP tool annotations of a capability (C-27).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "C-27")]
pub struct McpToolHints {
    /// CT0 and writes nothing.
    pub read_only: bool,
    /// Irreversible.
    pub destructive: bool,
    /// Always false.
    pub idempotent: bool,
    /// Some provider runs in a browser.
    pub open_world: bool,
}

impl CapabilityDefinition {
    /// The MCP tool annotations by `projections.toml`.
    #[must_use]
    pub fn mcp_tool_hints(&self) -> McpToolHints {
        McpToolHints {
            read_only: self.authority.consequence_tier == ConsequenceTier::Ct0
                && self.data_access.writes.is_none(),
            destructive: self.reversibility
                == crate::interaction_types::Reversibility::Irreversible,
            idempotent: false,
            open_world: self
                .providers
                .iter()
                .any(|p| p.path_type == PathType::Browser),
        }
    }
}
