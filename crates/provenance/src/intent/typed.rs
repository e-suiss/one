//! The typed intent: task, bound capability, labelled inputs, origin set and the structured summary Access reads, and its acceptance in contract order: envelope, input schema `$id`, digest, input schema, then the summary against the inputs (SEC-4, SEC-14 (1, 2, 4), SEC-19, CP-5).

use alloc::collections::BTreeMap;
use core::fmt;

use one_proto::TaskId;
use one_proto::capability::CapabilityRef;
use one_proto::ontology::{JsonObject, JsonValue};
use serde::de::Error as _;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::capability::{BoundCapability, InputSchemaRegistry, InputSchemaValidator};
use super::origin::OriginSet;
use super::text::{decode, map_at_most};
use crate::access::{AccessMapping, ParameterName, ParameterProvenance};
use crate::label::Label;
use crate::value::{Labelled, Opened};

/// The most inputs one intent carries.
pub const MAX_INPUTS: usize = 128;

/// The labelled inputs of an intent; every input carries a well-formed label, and an unlabelled one fails the envelope (SEC-14 (2)).
#[derive(Clone, Default, PartialEq)]
pub struct IntentInputs(BTreeMap<ParameterName, Labelled<JsonValue>>);

impl IntentInputs {
    /// An empty set.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub(crate) const fn from_map(map: BTreeMap<ParameterName, Labelled<JsonValue>>) -> Self {
        Self(map)
    }

    /// Adds an input, returning the one it replaces; `Err` gives the input back when the set is full.
    ///
    /// # Errors
    /// Refuses a new name past [`MAX_INPUTS`].
    pub fn insert(
        &mut self,
        name: ParameterName,
        value: Labelled<JsonValue>,
    ) -> Result<Option<Labelled<JsonValue>>, Labelled<JsonValue>> {
        if self.0.len() >= MAX_INPUTS && !self.0.contains_key(&name) {
            return Err(value);
        }
        Ok(self.0.insert(name, value))
    }

    /// The input of a name.
    #[must_use]
    pub fn get(&self, name: &ParameterName) -> Option<&Labelled<JsonValue>> {
        self.0.get(name)
    }

    /// The inputs by name.
    pub fn iter(&self) -> impl Iterator<Item = (&ParameterName, &Labelled<JsonValue>)> {
        self.0.iter()
    }

    /// The number of inputs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Whether there are none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// The join of every input label; `None` without inputs (SEC-14 (1)).
    #[must_use]
    pub fn worst(&self) -> Option<Label> {
        self.0.values().fold(None, |acc, value| {
            let label = value.label();
            Some(match acc {
                None => label,
                Some(acc) => Label::join(&acc, &label),
            })
        })
    }

    /// The Access provenance of every input (SEC-14 table).
    #[must_use]
    pub fn provenance(&self) -> ParameterProvenance {
        let mut out = ParameterProvenance::new();
        for (name, value) in &self.0 {
            out.insert(name.clone(), &value.label());
        }
        out
    }

    /// The capability input object: every value with its label removed, for the input schema check.
    #[must_use]
    pub fn values(&self) -> JsonValue {
        let object: JsonObject = self
            .0
            .iter()
            .map(|(name, value)| {
                (
                    alloc::string::String::from(name.as_str()),
                    value.expose().clone(),
                )
            })
            .collect();
        JsonValue::Object(object)
    }
}

impl fmt::Debug for IntentInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.0.iter()).finish()
    }
}

impl Serialize for IntentInputs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, value) in &self.0 {
            map.serialize_entry(name, value)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for IntentInputs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw: BTreeMap<ParameterName, Opened<JsonValue>> =
            map_at_most::<D, ParameterName, Opened<JsonValue>, MAX_INPUTS>(deserializer)?;
        let mut out = BTreeMap::new();
        for (name, opened) in raw {
            if !opened.conforms() {
                return Err(D::Error::custom(
                    "input is not a labelled value (SEC-14 (2))",
                ));
            }
            out.insert(name, opened.into_labelled());
        }
        Ok(Self(out))
    }
}

/// The structured summary of an intent: capability, each input's label and Access provenance, the worst label and the origin set (`typed-intent/v1#/$defs/summary`, SEC-14 (4)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentSummary {
    /// The capability by name and version.
    pub capability: CapabilityRef,
    /// The label of each input.
    #[serde(deserialize_with = "map_at_most::<_, _, _, MAX_INPUTS>")]
    pub inputs: BTreeMap<ParameterName, AccessMapping>,
    /// The join of the input labels; absent exactly when there are no inputs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worst: Option<AccessMapping>,
    /// The origin set.
    pub origin_set: OriginSet,
}

impl IntentSummary {
    /// The summary the inputs and origin set imply.
    #[must_use]
    pub fn of(capability: &BoundCapability, inputs: &IntentInputs, origin_set: &OriginSet) -> Self {
        Self {
            capability: capability.proposed(),
            inputs: inputs
                .iter()
                .map(|(name, value)| (name.clone(), AccessMapping::from(&value.label())))
                .collect(),
            worst: inputs.worst().as_ref().map(AccessMapping::from),
            origin_set: origin_set.clone(),
        }
    }
}

/// A typed intent (`typed-intent/v1`); built by [`TypedIntent::new`] or read from the wire, where the summary must carry `worst` exactly when there are inputs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "WireIntent")]
pub struct TypedIntent {
    task_id: TaskId,
    capability: BoundCapability,
    inputs: IntentInputs,
    origin_set: OriginSet,
    summary: IntentSummary,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireIntent {
    task_id: TaskId,
    capability: BoundCapability,
    inputs: IntentInputs,
    origin_set: OriginSet,
    summary: IntentSummary,
}

impl TryFrom<WireIntent> for TypedIntent {
    type Error = one_proto::ontology::validate::ContractViolation;

    fn try_from(wire: WireIntent) -> Result<Self, Self::Error> {
        if wire.inputs.is_empty() == wire.summary.worst.is_some() {
            return Err(one_proto::ontology::validate::ContractViolation(
                "summary worst present exactly when there are inputs",
            ));
        }
        Ok(Self {
            task_id: wire.task_id,
            capability: wire.capability,
            inputs: wire.inputs,
            origin_set: wire.origin_set,
            summary: wire.summary,
        })
    }
}

impl TypedIntent {
    /// An intent whose summary is computed from its inputs and origin set.
    #[must_use]
    pub fn new(
        task_id: TaskId,
        capability: BoundCapability,
        inputs: IntentInputs,
        origin_set: OriginSet,
    ) -> Self {
        let summary = IntentSummary::of(&capability, &inputs, &origin_set);
        Self {
            task_id,
            capability,
            inputs,
            origin_set,
            summary,
        }
    }

    /// The task.
    #[must_use]
    pub const fn task_id(&self) -> TaskId {
        self.task_id
    }

    /// The bound capability.
    #[must_use]
    pub const fn capability(&self) -> &BoundCapability {
        &self.capability
    }

    /// The labelled inputs.
    #[must_use]
    pub const fn inputs(&self) -> &IntentInputs {
        &self.inputs
    }

    /// The origin set.
    #[must_use]
    pub const fn origin_set(&self) -> &OriginSet {
        &self.origin_set
    }

    /// The summary as written.
    #[must_use]
    pub const fn summary(&self) -> &IntentSummary {
        &self.summary
    }

    /// Accepts the intent: its input schema must be the registry's for the capability, by `$id` and digest, its inputs must conform to it, and its summary must be the one its inputs imply.
    ///
    /// # Errors
    /// The first failed check, in contract order.
    pub fn accept(
        &self,
        registry: &impl InputSchemaRegistry,
        validator: &impl InputSchemaValidator,
    ) -> Result<(), Rejection> {
        let bound = &self.capability.input_schema;
        let pinned = registry
            .input_schema(&self.capability.proposed())
            .filter(|p| *p.id() == bound.id)
            .ok_or(Rejection::UnknownInputSchema)?;
        if *pinned.digest() != bound.digest {
            return Err(Rejection::InputSchemaDigest);
        }
        if !validator.conforms(pinned, &self.inputs.values()) {
            return Err(Rejection::InputSchema);
        }
        if self.summary != IntentSummary::of(&self.capability, &self.inputs, &self.origin_set) {
            return Err(Rejection::SummaryMismatch);
        }
        Ok(())
    }
}

/// Why an intent is not accepted (`intent-acceptance` `reason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rejection {
    /// The intent does not conform to `typed-intent/v1`.
    EnvelopeSchema,
    /// The registry has no input schema with this `$id` for the capability.
    UnknownInputSchema,
    /// The digest is not the pinned schema's.
    InputSchemaDigest,
    /// The inputs do not conform to the capability input schema; the user is asked, the model is not retried.
    InputSchema,
    /// The summary does not match the inputs or the origin set.
    SummaryMismatch,
}

impl Rejection {
    /// The wire code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::EnvelopeSchema => "envelope_schema",
            Self::UnknownInputSchema => "unknown_input_schema",
            Self::InputSchemaDigest => "input_schema_digest",
            Self::InputSchema => "input_schema",
            Self::SummaryMismatch => "summary_mismatch",
        }
    }
}

impl fmt::Display for Rejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Reads a wire intent and accepts it (SEC-4, CP-5).
///
/// # Errors
/// [`Rejection::EnvelopeSchema`] when the value is not a typed intent, otherwise the first failed check of [`TypedIntent::accept`].
pub fn accept_intent(
    wire: JsonValue,
    registry: &impl InputSchemaRegistry,
    validator: &impl InputSchemaValidator,
) -> Result<TypedIntent, Rejection> {
    let intent: TypedIntent = decode(wire).map_err(|_| Rejection::EnvelopeSchema)?;
    intent.accept(registry, validator)?;
    Ok(intent)
}
