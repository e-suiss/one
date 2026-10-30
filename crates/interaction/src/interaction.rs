//! The canonical semantic `Interaction` record with the C-19 header; every surface output is a projection of it (X-12, X-7, X-14, X-16, X-19, X-20, X-21, X-28, C-16, C-25, AT-5, AT-6, AT-12, AT-13).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use one_proto::data_class::{DataClass, Domain, RetentionClass};
use one_proto::ontology::{
    GrantRef, Instant, OpaqueId, PartyRef, ProducedBy, ProvenanceLabel, RecordStatus, Target,
};
use one_proto::{DeviceId, InteractionId};
use serde::{Deserialize, Serialize};

use crate::catalog::{Bind, Component};
use crate::common::{ActionId, DeepLink, Duration, Localized, MandateFit, Nonce, Timestamp};
use crate::kind::{Effect, Kind};
use one_proto::interaction_types::Authentication;
use one_proto::interaction_types::ConsequenceTier;
use one_proto::interaction_types::Interruption;
use one_proto::interaction_types::Reversibility;
use one_proto::interaction_types::SurfaceClass;
use one_proto::money::Money;

/// The concept name of the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InteractionType {
    /// `Interaction`.
    Interaction,
}

/// What the Interaction is about.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    /// Title, at most 60 code points per locale.
    pub title: Localized,
    /// The subject record or object.
    #[serde(rename = "ref")]
    pub reference: Target,
    /// Further records it concerns.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub concerns: Option<Vec<Target>>,
}

/// The other party, as displayed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counterparty {
    /// Display text.
    pub display: String,
    /// Reference.
    #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
    pub reference: Option<Target>,
}

/// A time range.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TimeRange {
    /// Start.
    pub start: Timestamp,
    /// End.
    pub end: Timestamp,
}

/// A coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Geo {
    /// Latitude.
    pub lat: f64,
    /// Longitude.
    pub lon: f64,
}

/// A place.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Place {
    /// Name.
    pub name: String,
    /// Address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    /// Coordinate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geo: Option<Geo>,
}

/// Remote content loads only after the user opens it (X-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Load {
    /// On user open.
    OnUserOpen,
}

/// An image asset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Asset {
    /// Key in One's encrypted blob store.
    pub asset_id: OpaqueId,
    /// Alternative text.
    pub alt: Localized,
    /// Load rule.
    pub load: Load,
}

/// An option attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribute {
    /// Label.
    pub label: String,
    /// Value.
    pub value: String,
}

/// A typed option.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OptionItem {
    /// Option identifier.
    pub id: ActionId,
    /// Title.
    pub title: String,
    /// Summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    /// Amount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<Money>,
    /// Time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<Timestamp>,
    /// Place.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<Place>,
    /// Attributes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attributes: Option<Vec<Attribute>>,
    /// Image.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Asset>,
    /// Recommended by One.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recommended: Option<bool>,
}

/// Form field types; never a secret (X-18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum FieldType {
    Text,
    Number,
    Date,
    Time,
    DateTime,
    Choice,
    Boolean,
    Amount,
    Place,
}

/// A choice of a form field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FieldOption {
    /// Identifier.
    pub id: ActionId,
    /// Label.
    pub label: Localized,
}

/// A form field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Field {
    /// Identifier.
    pub id: ActionId,
    /// Label.
    pub label: Localized,
    /// Type.
    #[serde(rename = "type")]
    pub field_type: FieldType,
    /// Required.
    pub required: bool,
    /// Longest text.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<u32>,
    /// Choices.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<FieldOption>>,
}

/// Progress phase.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Phase {
    Starting,
    InProgress,
    Waiting,
    Stopping,
    Finished,
    Unknown,
}

/// Live state of one task.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Progress {
    /// Phase.
    pub phase: Phase,
    /// Fraction done, 0 to 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fraction: Option<f64>,
    /// Current step label.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub step_label: Option<String>,
}

/// Step status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum StepStatus {
    Pending,
    Active,
    Done,
    Skipped,
    Failed,
    Unknown,
}

impl StepStatus {
    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Done => "done",
            Self::Skipped => "skipped",
            Self::Failed => "failed",
            Self::Unknown => "unknown",
        }
    }
}

/// A task step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Step {
    /// Label.
    pub label: String,
    /// Status.
    pub status: StepStatus,
    /// Time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Timestamp>,
}

/// Outcome status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum OutcomeStatus {
    Done,
    Partial,
    Failed,
    Unknown,
    Stopping,
    Stopped,
}

/// Outcome of finished work.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Outcome {
    /// Status.
    pub status: OutcomeStatus,
    /// Executor confirmed it.
    pub executor_confirmed: bool,
    /// Cost.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cost: Option<Money>,
    /// Related references.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refs: Option<Vec<Target>>,
}

/// Untrusted display note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Note {
    /// Text.
    pub text: String,
    /// Always true.
    pub untrusted: bool,
}

/// Typed details.
#[derive(Debug, Clone, PartialEq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Details {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<Money>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub counterparty: Option<Counterparty>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time: Option<Timestamp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_range: Option<TimeRange>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<Place>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<OptionItem>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<Field>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub progress: Option<Progress>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub steps: Option<Vec<Step>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<Note>,
}

/// A component in the presentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ComponentUse {
    /// Component.
    pub component: Component,
    /// Component version.
    pub version: u32,
    /// Bound detail fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binds: Option<Vec<Bind>>,
}

/// Composition from the catalog (X-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Presentation {
    /// Catalog version.
    pub catalog_version: u32,
    /// Components.
    pub components: Vec<ComponentUse>,
}

/// Why now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WhyNow {
    /// Reason.
    pub reason: Localized,
    /// Evidence.
    pub evidence: Vec<Target>,
}

/// Delivery timing (AT-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Delivery {
    /// Now.
    Immediate,
    /// At the next break, within `max_defer`.
    NextBreak,
}

/// A fallback channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Channel {
    Push,
    Email,
    Sms,
    Inbox,
}

/// A device or channel in a schedule step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicySurface {
    /// A device.
    Device(DeviceSurface),
    /// A channel.
    Channel(ChannelSurface),
}

/// A device surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceSurface {
    /// Device.
    pub device_id: DeviceId,
}

/// A channel surface.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChannelSurface {
    /// Channel.
    pub channel: Channel,
}

/// One escalation step (X-21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyStep {
    /// Surfaces.
    pub surfaces: Vec<PolicySurface>,
    /// Escalation delay.
    pub escalate_after: Duration,
}

/// Approval invitation schedule (X-21).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfacePolicy {
    /// Steps.
    pub steps: Vec<PolicyStep>,
}

/// Timing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Timing {
    /// Delivery.
    pub delivery: Delivery,
    /// Longest deferral.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_defer: Option<Duration>,
    /// Approval schedule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub surface_policy: Option<SurfacePolicy>,
}

/// A binary answer of the minimal projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalAnswer {
    /// Action it triggers.
    pub action: ActionId,
    /// Label, at most 12 code points.
    pub label: Localized,
}

/// The minimal projection: one sentence and a binary answer (X-13).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinimalProjection {
    /// Sentence, at most 120 code points.
    pub sentence: Localized,
    /// Yes.
    pub yes: MinimalAnswer,
    /// No.
    pub no: MinimalAnswer,
}

/// The budget table this record follows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BudgetTable {
    /// `surface-budgets/v1`.
    #[serde(rename = "https://suiss.app/schemas/one/interaction/surface-budgets/v1.json")]
    V1,
}

/// Visual density.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Visuals {
    Normal,
    Reduced,
    TextOnly,
}

/// A per-class tightening; it only lowers the table (X-19, X-61).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct ClassTighten {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub visuals: Option<Visuals>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_title_chars: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_body_chars: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_approval: Option<bool>,
}

/// Per-class tightenings.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(missing_docs)]
pub struct Tighten {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phone: Option<ClassTighten>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub desktop: Option<ClassTighten>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub watch: Option<ClassTighten>,
    #[serde(rename = "voice:car", default, skip_serializing_if = "Option::is_none")]
    pub voice_car: Option<ClassTighten>,
    #[serde(
        rename = "voice:glasses",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub voice_glasses: Option<ClassTighten>,
}

impl Tighten {
    /// The tightening of one class.
    #[must_use]
    pub const fn get(&self, class: SurfaceClass) -> Option<&ClassTighten> {
        match class {
            SurfaceClass::Phone => self.phone.as_ref(),
            SurfaceClass::Desktop => self.desktop.as_ref(),
            SurfaceClass::Watch => self.watch.as_ref(),
            SurfaceClass::VoiceCar => self.voice_car.as_ref(),
            SurfaceClass::VoiceGlasses => self.voice_glasses.as_ref(),
        }
    }
}

/// `surface_budgets`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceBudgets {
    /// Table.
    pub table: BudgetTable,
    /// Tightenings.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tighten: Option<Tighten>,
}

/// An action the user can take (X-16: buttons come only from here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    /// Identifier.
    pub id: ActionId,
    /// Effect.
    pub effect: Effect,
    /// Label, at most 24 code points.
    pub label: Localized,
    /// Option for `choose`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub option_id: Option<ActionId>,
    /// Value for `answer`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<bool>,
}

/// Minimum assurance for an answer (X-19).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MinAssurance {
    /// Classes that may answer.
    pub surface_classes: Vec<SurfaceClass>,
    /// Weakest authentication.
    pub authentication: Authentication,
    /// Only the user's own direct act (Access E45).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub direct_act_only: Option<bool>,
}

/// The `Interaction` record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interaction {
    /// Concept.
    #[serde(rename = "type")]
    pub record_type: InteractionType,
    /// Identifier.
    pub id: InteractionId,
    /// Lifecycle.
    pub status: RecordStatus,
    /// Previous version, null at version 1.
    #[serde(deserialize_with = "Option::deserialize")]
    pub supersedes: Option<InteractionId>,
    /// Owner.
    pub owner: PartyRef,
    /// Domain.
    pub domain: Domain,
    /// Data class.
    pub data_class: DataClass,
    /// Retention class.
    pub retention_class: RetentionClass,
    /// Joined provenance label.
    pub provenance: ProvenanceLabel,
    /// Recorded at.
    pub recorded_at: Instant,
    /// Version.
    pub version: u32,
    /// Privacy promise version the record was collected under (PV-19).
    pub promise_version: NonZeroU32,
    /// Deleted at, null unless deleted.
    pub deleted_at: Option<Instant>,
    /// Producer.
    pub produced_by: ProducedBy,
    /// Kind.
    pub kind: Kind,
    /// Subject.
    pub subject: Subject,
    /// Details.
    pub details: Details,
    /// Presentation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub presentation: Option<Presentation>,
    /// Risk.
    pub risk: ConsequenceTier,
    /// Reversibility.
    pub reversibility: Reversibility,
    /// Mandate fit, approvals only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mandate_fit: Option<MandateFit>,
    /// Sensitive (X-20).
    pub sensitive: bool,
    /// Per-field provenance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub field_provenance: Option<BTreeMap<Bind, ProvenanceLabel>>,
    /// Why now.
    pub why_now: WhyNow,
    /// Interruption.
    pub interruption: Interruption,
    /// Critical Grant, only at `critical`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub critical_grant: Option<GrantRef>,
    /// Timing.
    pub timing: Timing,
    /// Minimal projection.
    pub minimal_projection: MinimalProjection,
    /// Budgets.
    pub surface_budgets: SurfaceBudgets,
    /// Actions.
    pub actions: Vec<Action>,
    /// Answer nonce.
    pub answer_nonce: Nonce,
    /// Minimum assurance.
    pub min_assurance: MinAssurance,
    /// Deep link.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deep_link: Option<DeepLink>,
    /// Expiry.
    pub expires_at: Timestamp,
}

impl Interaction {
    /// The action with this identifier.
    #[must_use]
    pub fn action(&self, id: &ActionId) -> Option<&Action> {
        self.actions.iter().find(|a| &a.id == id)
    }

    /// True if an action has this effect.
    #[must_use]
    pub fn has_effect(&self, effect: Effect) -> bool {
        self.actions.iter().any(|a| a.effect == effect)
    }

    /// The tightening for a class.
    #[must_use]
    pub fn tighten(&self, class: SurfaceClass) -> Option<&ClassTighten> {
        self.surface_budgets
            .tighten
            .as_ref()
            .and_then(|t| t.get(class))
    }
}
