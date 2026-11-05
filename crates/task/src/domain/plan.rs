//! What the planner may build a plan from (SEC-12, SEC-31 (6), M-2, INV-14): only the user's request, One's records and Access or Work records reach it as content; external content reaches it only as typed, labelled variables from the quarantine model, and only in a value position: the control fields of a step (its capability, action, recipient and whether it runs) take a literal, never a variable; an action parameter that came from memory carries its record's provenance label, and a parameter built from several sources falls to the worst of their labels.

use one_proto::ontology::ProvenanceLabel;
use one_provenance::label::LabelKind;
use one_provenance::{Label, ProposedInput};

/// A step's control field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControlField {
    /// The capability.
    Capability,
    /// The action.
    Action,
    /// The recipient.
    Recipient,
    /// Whether the step runs or is skipped.
    Runs,
}

/// A control field the planner bound to a variable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BoundToVariable(pub ControlField);

/// The literal value of control field `field`.
///
/// # Errors
/// [`BoundToVariable`] when the planner put a variable there.
pub fn control<T>(field: ControlField, input: &ProposedInput<T>) -> Result<&T, BoundToVariable> {
    match input {
        ProposedInput::Literal(value) => Ok(value),
        ProposedInput::Ref(_) => Err(BoundToVariable(field)),
    }
}

/// The label of an action parameter read from a memory record with provenance `record`: the record's own label, `external.unknown` when it is not a single label.
#[must_use]
pub fn from_memory(record: ProvenanceLabel) -> Label {
    LabelKind::from_proto(record)
        .single()
        .unwrap_or(Label::UNKNOWN)
}

/// The label of a parameter built from `parts`: the worst of them, `external.unknown` for none.
#[must_use]
pub fn joined<'a>(parts: impl IntoIterator<Item = &'a Label>) -> Label {
    Label::join_all(parts).unwrap_or(Label::UNKNOWN)
}
