//! Canonical concept records, references, the C-19 header, the six relations and the layer conversions; memory types never convert into authority, and the only authority One sees is an opaque Access `GrantRef` or `MandateRef` (C-1, C-8, C-19, C-23, M-1).

pub mod concept;
pub mod episode;
pub mod extension;
pub mod goal;
pub mod header;
pub mod json;
pub mod layers;
pub mod observation;
pub mod personality;
pub mod provenance;
pub mod reference;
pub mod relation;
pub mod routine;
pub mod tag;
pub mod tags;
pub mod time;
pub mod validate;

pub use concept::{AnyId, CanonicalId, CanonicalNode, Concept, EntityRecordId};
pub use episode::{EntryBody, Episode, EpisodeEntry, EpisodeSkeleton, LiveEpisode};
pub use goal::Goal;
pub use header::{
    Actor, Lang, LocalText, ProducedBy, RecordHeader, RecordStatus, Statement, UiLang,
};
pub use json::{JsonObject, JsonValue};
pub use observation::Observation;
pub use provenance::ProvenanceLabel;
pub use reference::{
    AcceptanceRef, AccessObjectRef, ActionRef, AgeBandRef, AgentTokenRef, AnyRef, CheckpointRef,
    ClaimRef, CommitmentRef, ConnectedAccountRef, DecisionRecordRef, EntityRecordRef, EntityRef,
    ExecutionReportRef, ExecutorObjectRef, ExecutorRef, ExerciseRef, ExternalPersonRef,
    ExternalRef, ExternalSystem, GrantRef, GuardianshipRef, HouseholdRef, InstanceRef,
    KeyBindingRef, Locator, MailboxMessageRef, MandateRef, NeedsAttentionRef, NotificationRef,
    OfferChainRef, OpaqueId, OrderRef, OwnerId, PartyRef, PayObjectRef, PaymentRef, PersonRef,
    PersonSystem, ProductRef, RecordRef, RelayObjectRef, Target, TenantRef, TriggerRef,
    WaitpointRef, WorkObjectRef,
};
pub use relation::{RelationEdge, RelationKind, RelationTarget};
pub use routine::Routine;
pub use time::Instant;
