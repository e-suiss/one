//! The planner model's output: one proposed capability and, per input, a literal or an opaque variable reference and nothing else; labels are attached by code, a reference takes its variable's label and a literal the join of the planner context (SEC-4, SEC-12, T-36 (2)).

use alloc::collections::BTreeMap;
use core::fmt;

use one_proto::TaskId;
use one_proto::capability::CapabilityRef;
use one_proto::ontology::JsonValue;
use serde::de::Error as _;
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::capability::BoundCapability;
use super::origin::OriginSet;
use super::text::map_at_most;
use super::typed::{IntentInputs, MAX_INPUTS, TypedIntent};
use crate::access::ParameterName;
use crate::label::{Label, TrustedLabel};
use crate::planner::{ProposedInput, VarRef, VariableTable};
use crate::value::Labelled;

/// A literal the planner wrote: any JSON value but `null`; never shown in `Debug`.
#[derive(Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Literal(JsonValue);

impl Literal {
    /// Wraps a value; `None` for `null`.
    #[must_use]
    pub fn new(value: JsonValue) -> Option<Self> {
        (value != JsonValue::Null).then_some(Self(value))
    }

    /// Borrows the value.
    #[must_use]
    pub const fn expose(&self) -> &JsonValue {
        &self.0
    }

    /// Unwraps the value.
    #[must_use]
    pub fn into_value(self) -> JsonValue {
        self.0
    }
}

impl fmt::Debug for Literal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Literal([masked])")
    }
}

impl<'de> Deserialize<'de> for Literal {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(JsonValue::deserialize(deserializer)?)
            .ok_or_else(|| D::Error::custom("null literal"))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireInput {
    literal: Option<Literal>,
    #[serde(rename = "ref")]
    reference: Option<VarRef>,
}

/// The proposed inputs by name, each exactly one of `literal` and `ref`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ProposedInputs(BTreeMap<ParameterName, ProposedInput<Literal>>);

impl ProposedInputs {
    /// The inputs by name.
    pub fn iter(&self) -> impl Iterator<Item = (&ParameterName, &ProposedInput<Literal>)> {
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
}

impl Serialize for ProposedInputs {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for (name, input) in &self.0 {
            map.serialize_entry(name, input)?;
        }
        map.end()
    }
}

impl<'de> Deserialize<'de> for ProposedInputs {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = map_at_most::<D, ParameterName, WireInput, MAX_INPUTS>(deserializer)?;
        let mut out = BTreeMap::new();
        for (name, wire) in raw {
            let input = match (wire.literal, wire.reference) {
                (Some(literal), None) => ProposedInput::Literal(literal),
                (None, Some(var)) => ProposedInput::Ref(var),
                _ => return Err(D::Error::custom("exactly one of literal and ref")),
            };
            out.insert(name, input);
        }
        Ok(Self(out))
    }
}

/// The planner's proposal of one typed intent (`intent-model-output/v1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntentModelOutput {
    /// The proposed capability.
    pub capability: CapabilityRef,
    /// The proposed inputs.
    pub inputs: ProposedInputs,
}

/// The label of each proposed input and their join.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputLabels {
    /// The label of each input.
    pub inputs: BTreeMap<ParameterName, Label>,
    /// The join of every input label; `None` without inputs.
    pub worst: Option<Label>,
}

/// Why a proposal does not become an intent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BindError {
    /// The bound capability is not the proposed one.
    CapabilityMismatch,
    /// A reference names no bound value.
    UnknownVariable(VarRef),
}

impl IntentModelOutput {
    /// The label of each input: the variable's label for a reference, `external.unknown` for an unbound one, and the planner context join for a literal (T-36 (2), SEC-12).
    #[must_use]
    pub fn input_labels<V>(
        &self,
        variables: &VariableTable<V>,
        context: TrustedLabel,
    ) -> InputLabels {
        let inputs: BTreeMap<ParameterName, Label> = self
            .inputs
            .iter()
            .map(|(name, input)| (name.clone(), input.label(variables, context)))
            .collect();
        let worst = Label::join_all(inputs.values());
        InputLabels { inputs, worst }
    }

    /// The typed intent this proposal makes: references are filled from the bound values with their labels and literals take the planner context join.
    ///
    /// # Errors
    /// [`BindError::CapabilityMismatch`] when `capability` is not the proposed one, [`BindError::UnknownVariable`] for a reference without a bound value.
    pub fn bind(
        self,
        task_id: TaskId,
        capability: BoundCapability,
        variables: &VariableTable<JsonValue>,
        context: TrustedLabel,
        origin_set: OriginSet,
    ) -> Result<TypedIntent, BindError> {
        if capability.proposed() != self.capability {
            return Err(BindError::CapabilityMismatch);
        }
        let mut inputs = BTreeMap::new();
        for (name, input) in self.inputs.0 {
            let value = match input {
                ProposedInput::Literal(literal) => {
                    Labelled::from_label(literal.into_value(), Label::Trusted(context))
                }
                ProposedInput::Ref(var) => variables
                    .get(var)
                    .cloned()
                    .ok_or(BindError::UnknownVariable(var))?,
            };
            inputs.insert(name, value);
        }
        Ok(TypedIntent::new(
            task_id,
            capability,
            IntentInputs::from_map(inputs),
            origin_set,
        ))
    }
}
