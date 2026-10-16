//! The named facade operations and their JSON input and output shapes (T-29 (1)).

mod attention;
mod capability;
mod interaction;
mod memory;
mod provenance;
mod task;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::CoreError;

/// One facade operation; its name is the stable wire name every binding passes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum Operation {
    /// `provenance.join`: `{"inputs": [label]}` → the joined label (SEC-14 (1)).
    ProvenanceJoin,
    /// `provenance.transform`: `{"transform", "inputs"}` → the derived label (SEC-14 (1), T-36 (3)).
    ProvenanceTransform,
    /// `provenance.open`: `{"encoded"}` → the opened label, Access provenance, conformance and value (T-36 (4)).
    ProvenanceOpen,
    /// `provenance.access_mapping`: `{"label"}` → `{"provenance"}` (T-36 (5)).
    ProvenanceAccessMapping,
    /// `task.derive`: the event history → state, stop command and stopping, or the rejection (CP-3, INV-30).
    TaskDerive,
    /// `task.project`: `{"state", "wait_reason"}` → the MCP and A2A projection (CP-3, C-27).
    TaskProject,
    /// `interaction.resolve_kind`: `{"registry", "kind"}` → the core kind or the error (X-12, C-7).
    InteractionResolveKind,
    /// `interaction.project`: one Interaction on one surface target → the projection decision (X-13).
    InteractionProject,
    /// `interaction.process_responses`: responses to one Interaction in order → their outcomes (X-22, C-26).
    InteractionProcessResponses,
    /// `capability.parse_name`: a capability name → its kind, segments and category, or the error (CP-15).
    CapabilityParseName,
    /// `capability.parse_version`: a capability version → valid or not (CP-15).
    CapabilityParseVersion,
    /// `capability.negotiate`: `{"local", "remote"}` declarations → the kept capability versions (CP-15).
    CapabilityNegotiate,
    /// `memory.trust_v1`: one trust input → `{"trust"}` or `{"error"}` (M-13).
    MemoryTrustV1,
    /// `memory.text_view`: `{"entries"}` → the memory text view or its error (M-6, INV-14).
    MemoryTextView,
    /// `attention.decide`: the decision head inputs → route, arm and level (AT-1).
    AttentionDecide,
    /// `attention.relay_mapping`: an output on its way to Relay → what is sent (AT-42).
    AttentionRelayMapping,
}

impl Operation {
    /// Every operation, in a stable order.
    pub const ALL: [Self; 16] = [
        Self::ProvenanceJoin,
        Self::ProvenanceTransform,
        Self::ProvenanceOpen,
        Self::ProvenanceAccessMapping,
        Self::TaskDerive,
        Self::TaskProject,
        Self::InteractionResolveKind,
        Self::InteractionProject,
        Self::InteractionProcessResponses,
        Self::CapabilityParseName,
        Self::CapabilityParseVersion,
        Self::CapabilityNegotiate,
        Self::MemoryTrustV1,
        Self::MemoryTextView,
        Self::AttentionDecide,
        Self::AttentionRelayMapping,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ProvenanceJoin => "provenance.join",
            Self::ProvenanceTransform => "provenance.transform",
            Self::ProvenanceOpen => "provenance.open",
            Self::ProvenanceAccessMapping => "provenance.access_mapping",
            Self::TaskDerive => "task.derive",
            Self::TaskProject => "task.project",
            Self::InteractionResolveKind => "interaction.resolve_kind",
            Self::InteractionProject => "interaction.project",
            Self::InteractionProcessResponses => "interaction.process_responses",
            Self::CapabilityParseName => "capability.parse_name",
            Self::CapabilityParseVersion => "capability.parse_version",
            Self::CapabilityNegotiate => "capability.negotiate",
            Self::MemoryTrustV1 => "memory.trust_v1",
            Self::MemoryTextView => "memory.text_view",
            Self::AttentionDecide => "attention.decide",
            Self::AttentionRelayMapping => "attention.relay_mapping",
        }
    }

    /// The operation with wire name `name`.
    #[must_use]
    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|op| op.as_str() == name)
    }

    pub(crate) fn run(self, input: Value) -> Result<Value, CoreError> {
        match self {
            Self::ProvenanceJoin => provenance::join(input),
            Self::ProvenanceTransform => provenance::transform(input),
            Self::ProvenanceOpen => provenance::open(input),
            Self::ProvenanceAccessMapping => provenance::access_mapping(input),
            Self::TaskDerive => task::derive(input),
            Self::TaskProject => task::project(input),
            Self::InteractionResolveKind => interaction::resolve_kind(input),
            Self::InteractionProject => interaction::project(input),
            Self::InteractionProcessResponses => interaction::process_responses(input),
            Self::CapabilityParseName => capability::parse_name(input),
            Self::CapabilityParseVersion => capability::parse_version(input),
            Self::CapabilityNegotiate => capability::negotiate(input),
            Self::MemoryTrustV1 => memory::trust_v1(input),
            Self::MemoryTextView => memory::text_view(input),
            Self::AttentionDecide => attention::decide(input),
            Self::AttentionRelayMapping => attention::relay_mapping(input),
        }
    }
}

fn parse<T: DeserializeOwned>(value: Value, part: &'static str) -> Result<T, CoreError> {
    serde_json::from_value(value).map_err(|_| CoreError::InvalidInput(part))
}

fn wire<T: Serialize>(value: &T) -> Result<Value, CoreError> {
    serde_json::to_value(value).map_err(|_| CoreError::InvalidInput("output"))
}

fn object(members: impl IntoIterator<Item = (&'static str, Value)>) -> Value {
    Value::Object(
        members
            .into_iter()
            .map(|(k, v)| (k.to_owned(), v))
            .collect::<Map<String, Value>>(),
    )
}
