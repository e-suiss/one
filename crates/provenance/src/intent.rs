//! Typed intent, planner and quarantine model outputs and model contexts: the planner proposes a capability with literal or referenced inputs, code labels them and builds the typed intent bound to a pinned input schema, the quarantine model returns only typed fields that code labels `external.*`, and every context keeps typed control apart from marked data (SEC-4, SEC-12, SEC-13, SEC-14, SEC-19, T-9, T-31, T-36 (2, 6)).

mod capability;
mod context;
pub mod jcs;
mod model_output;
mod origin;
mod quarantine;
mod text;
mod typed;

pub use capability::{
    BoundCapability, InputSchemaRef, InputSchemaRegistry, InputSchemaValidator, PinnedSchema,
    SchemaId,
};
pub use context::{
    Constraint, Control, Extraction, MemoryData, MemoryText, ModelContext, PlannerControl,
    PlannerData, PlannerModelContext, QuarantineControl, QuarantineModelContext, RecordSource,
    RecordTrustedMark, Request, RequestText, Scalar, Scope, StepLimit, SummaryLang, TaskControl,
    TextPlain, TrustedRecord, UntrustedData, UntrustedDataMarking, UntrustedText, UserDirectMark,
    UserEpistemicState, UserMemoryMark, VariableData, VariableKind,
};
pub use model_output::{BindError, InputLabels, IntentModelOutput, Literal, ProposedInputs};
pub use origin::{MAX_ORIGINS, Origin, OriginSet, Origins};
pub use quarantine::{
    Address, CountryCode, Date, DisplayOnly, DisplaySummary, Email, ExternalLabel, FieldKind,
    LabelledField, Line, MAX_FIELDS, MAX_SAFE_INTEGER, ModelSummary, OptionCode, Phone, PostalCode,
    QuarantineModelOutput, QuarantineOutput, SafeInteger, SummaryText, TypedField, Url,
};
pub use text::FieldName;
pub use typed::{IntentInputs, IntentSummary, MAX_INPUTS, Rejection, TypedIntent, accept_intent};
