//! Model contexts with typed control fields kept apart from marked, labelled data parts: the planner reads the user's request, user memory blocks, trusted Access or Work records and opaque variable references; the quarantine model reads one untrusted content part and the extraction schema, nothing else (SEC-2, SEC-3, SEC-12, SEC-13 (1, 2), SEC-21 (1), T-36 (2)).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use one_proto::capability::CapabilityRef;
use one_proto::memory::fields::{ContentType, EpistemicState};
use one_proto::money::Money;
use one_proto::ontology::validate::ContractViolation;
use one_proto::ontology::{AccessObjectRef, Instant, JsonValue, UiLang, WorkObjectRef};
use one_proto::{MemoryRecordId, TaskId};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::capability::SchemaId;
use super::origin::OriginSet;
use super::quarantine::{
    ExternalLabel, QuarantineModelOutput, QuarantineOutput, WireSources, external_from_wire,
    present_sources, untrusted_from_wire, untrusted_to_wire,
};
use super::text::{
    FieldName, at_most, chars_within, checked_text, map_at_most, unique_at_most, wire_const,
};
use crate::label::{LabelKind, TrustedLabel, UntrustedLabel};

fn is_request_text(text: &str) -> bool {
    chars_within(text, 1, 8000)
}

fn is_memory_text(text: &str) -> bool {
    chars_within(text, 1, 2000)
}

fn is_untrusted_text(text: &str) -> bool {
    chars_within(text, 0, 200_000)
}

checked_text!(
    /// The user's request text, 1–8000 characters.
    masked RequestText,
    "request text",
    is_request_text
);
checked_text!(
    /// The text of a memory block, 1–2000 characters.
    masked MemoryText,
    "memory text",
    is_memory_text
);
checked_text!(
    /// Read external content, at most 200000 characters; data, never instructions.
    masked UntrustedText,
    "untrusted text",
    is_untrusted_text
);

wire_const!(
    /// The constant `user.direct` of the request label.
    UserDirectMark = "user.direct"
);
wire_const!(
    /// The constant `user.memory` of a memory block label.
    UserMemoryMark = "user.memory"
);
wire_const!(
    /// The constant `record.trusted` of a record block label.
    RecordTrustedMark = "record.trusted"
);
wire_const!(
    /// The constant media type `text/plain` of untrusted content.
    TextPlain = "text/plain"
);
wire_const!(
    /// The marking of untrusted content.
    UntrustedDataMarking = "untrusted_data"
);

/// The task a context belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskControl {
    /// The task.
    pub task_id: TaskId,
}

/// The user's request: the only source of instructions (SEC-3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// The text.
    pub text: RequestText,
    /// Its language.
    pub lang: UiLang,
    /// Always `user.direct`.
    pub label: UserDirectMark,
}

/// The capabilities and origins the task may use.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scope {
    /// Up to 32 distinct capabilities.
    #[serde(deserialize_with = "unique_at_most::<_, _, 32>")]
    pub capabilities: Vec<CapabilityRef>,
    /// The origin set.
    pub origin_set: OriginSet,
}

/// A step limit from 1 to 100.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StepLimit(u8);

impl StepLimit {
    /// Checks and wraps a limit.
    #[must_use]
    pub const fn new(steps: u8) -> Option<Self> {
        if 1 <= steps && steps <= 100 {
            Some(Self(steps))
        } else {
            None
        }
    }

    /// The limit.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl<'de> Deserialize<'de> for StepLimit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(u8::deserialize(deserializer)?).ok_or_else(|| D::Error::custom("1 to 100 steps"))
    }
}

/// A typed task constraint; there is no free-text constraint (SEC-2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "value",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Constraint {
    /// Finish before this UTC instant.
    Deadline(Instant),
    /// Spend at most this amount.
    Budget(Money),
    /// Read only, or not.
    ReadOnly(bool),
    /// Reply in this language.
    ReplyLanguage(UiLang),
    /// Take at most this many steps.
    MaxSteps(StepLimit),
}

/// The planner's control part: task, request, scope and constraints, all typed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerControl {
    /// The task.
    pub task: TaskControl,
    /// The user's request.
    pub request: Request,
    /// The scope.
    pub scope: Scope,
    /// Up to 32 constraints.
    #[serde(deserialize_with = "at_most::<_, _, 32>")]
    pub constraints: Vec<Constraint>,
}

/// How a memory block is known: only what the user stated or verified enters the planner (SEC-14 table).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserEpistemicState {
    /// The user said it.
    Stated,
    /// Confirmed by the user or second evidence.
    Verified,
}

impl From<UserEpistemicState> for EpistemicState {
    fn from(state: UserEpistemicState) -> Self {
        match state {
            UserEpistemicState::Stated => Self::Stated,
            UserEpistemicState::Verified => Self::Verified,
        }
    }
}

/// A user memory record given to the planner as a marked data block; it carries no control field (SEC-21 (1)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryData {
    /// The record.
    pub record_id: MemoryRecordId,
    /// Always `user.memory`.
    pub label: UserMemoryMark,
    /// The content type.
    pub content_type: ContentType,
    /// Stated or verified.
    pub epistemic_state: UserEpistemicState,
    /// Whether the record is in conflict with another.
    pub conflicted: bool,
    /// The text.
    pub text: MemoryText,
}

/// The Access or Work record a trusted block comes from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecordSource {
    /// An Access object.
    Access(AccessObjectRef),
    /// A Work object.
    Work(WorkObjectRef),
}

/// A scalar field value of a trusted record: a string, number or boolean.
#[derive(Clone, PartialEq, Serialize)]
#[serde(transparent)]
pub struct Scalar(JsonValue);

impl Scalar {
    /// Wraps a scalar; `None` for `null`, an array or an object.
    #[must_use]
    pub fn new(value: JsonValue) -> Option<Self> {
        match value {
            JsonValue::Null | JsonValue::Array(_) | JsonValue::Object(_) => None,
            scalar => Some(Self(scalar)),
        }
    }

    /// Borrows the value.
    #[must_use]
    pub const fn expose(&self) -> &JsonValue {
        &self.0
    }
}

impl fmt::Debug for Scalar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Scalar([masked])")
    }
}

impl<'de> Deserialize<'de> for Scalar {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(JsonValue::deserialize(deserializer)?)
            .ok_or_else(|| D::Error::custom("string, number or boolean"))
    }
}

/// Fields read from an Access or Work record (`record.trusted`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedRecord {
    /// The record.
    pub record: RecordSource,
    /// Always `record.trusted`.
    pub label: RecordTrustedMark,
    /// Up to 64 scalar fields.
    #[serde(deserialize_with = "map_at_most::<_, _, _, 64>")]
    pub fields: BTreeMap<FieldName, Scalar>,
}

/// The value kind of a variable the planner sees only by reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VariableKind {
    /// A date.
    Date,
    /// A date-time.
    DateTime,
    /// An amount.
    Amount,
    /// An integer.
    Integer,
    /// A boolean.
    Boolean,
    /// A name.
    Name,
    /// An email address.
    Email,
    /// A phone number.
    Phone,
    /// A URL.
    Url,
    /// An address.
    Address,
    /// One option.
    Choice,
    /// A set of options.
    ChoiceList,
}

/// An opaque variable reference with its kind and untrusted label; never its value, and a trusted value never travels by reference (T-36 (2)).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "WireVariable", into = "WireVariable")]
pub struct VariableData {
    /// The reference.
    pub var: crate::planner::VarRef,
    /// The value kind.
    pub kind: VariableKind,
    /// The value's label: `one.inferred` or `external.*`, `external.mixed` with its sources.
    pub label: UntrustedLabel,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireVariable {
    #[serde(rename = "ref")]
    var: crate::planner::VarRef,
    kind: VariableKind,
    label: LabelKind,
    #[serde(
        default,
        deserialize_with = "present_sources",
        skip_serializing_if = "Option::is_none"
    )]
    sources: WireSources,
}

impl TryFrom<WireVariable> for VariableData {
    type Error = ContractViolation;

    fn try_from(wire: WireVariable) -> Result<Self, Self::Error> {
        Ok(Self {
            var: wire.var,
            kind: wire.kind,
            label: untrusted_from_wire(wire.label, wire.sources.as_deref())
                .ok_or(ContractViolation("untrusted label with its sources"))?,
        })
    }
}

impl From<VariableData> for WireVariable {
    fn from(data: VariableData) -> Self {
        let (label, sources) = untrusted_to_wire(&data.label);
        Self {
            var: data.var,
            kind: data.kind,
            label,
            sources,
        }
    }
}

/// One data part of a planner context; read external content has no variant here (SEC-12).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "marking", rename_all = "snake_case")]
pub enum PlannerData {
    /// A user memory block.
    MemoryData(MemoryData),
    /// A trusted record block.
    TrustedRecord(TrustedRecord),
    /// A variable reference.
    VariableRef(VariableData),
}

/// What the planner reads.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannerModelContext {
    /// The control part.
    pub control: PlannerControl,
    /// Up to 256 data parts.
    #[serde(deserialize_with = "at_most::<_, _, 256>")]
    pub data: Vec<PlannerData>,
}

impl PlannerModelContext {
    /// The join of the request and every memory and record block: the label of each literal the planner writes (T-36 (2)).
    #[must_use]
    pub fn literal_label(&self) -> TrustedLabel {
        self.data
            .iter()
            .filter_map(|part| match part {
                PlannerData::MemoryData(_) => Some(TrustedLabel::UserMemory),
                PlannerData::TrustedRecord(_) => Some(TrustedLabel::RecordTrusted),
                PlannerData::VariableRef(_) => None,
            })
            .fold(TrustedLabel::UserDirect, TrustedLabel::join)
    }
}

/// The summary language the extraction asks for, or none.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SummaryLang {
    /// Turkish.
    Tr,
    /// English.
    En,
    /// No summary.
    None,
}

/// The quarantine output has a display summary although `summary_lang` is `none`, or none although it names a language.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SummaryLangMismatch;

impl fmt::Display for SummaryLangMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("display summary present exactly when summary_lang is not none")
    }
}

/// The extraction the quarantine model performs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Extraction {
    /// The `$id` of the extraction schema.
    pub schema_id: SchemaId,
    /// The summary language; `none` exactly when the output carries no display summary.
    pub summary_lang: SummaryLang,
}

/// The quarantine model's control part: the extraction alone; no task, request, capability or memory (SEC-13 (2)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineControl {
    /// The extraction.
    pub extraction: Extraction,
}

/// One piece of read external content, marked as data and labelled `external.*`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireUntrustedData", into = "WireUntrustedData")]
pub struct UntrustedData {
    /// Always `untrusted_data`.
    pub marking: UntrustedDataMarking,
    /// The content's label.
    pub label: ExternalLabel,
    /// Always `text/plain`.
    pub media_type: TextPlain,
    /// The content.
    pub text: UntrustedText,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireUntrustedData {
    marking: UntrustedDataMarking,
    label: LabelKind,
    #[serde(
        default,
        deserialize_with = "present_sources",
        skip_serializing_if = "Option::is_none"
    )]
    sources: WireSources,
    media_type: TextPlain,
    text: UntrustedText,
}

impl TryFrom<WireUntrustedData> for UntrustedData {
    type Error = ContractViolation;

    fn try_from(wire: WireUntrustedData) -> Result<Self, Self::Error> {
        Ok(Self {
            marking: wire.marking,
            label: external_from_wire(wire.label, wire.sources.as_deref())?,
            media_type: wire.media_type,
            text: wire.text,
        })
    }
}

impl From<UntrustedData> for WireUntrustedData {
    fn from(data: UntrustedData) -> Self {
        let (label, sources) = untrusted_to_wire(data.label.untrusted());
        Self {
            marking: data.marking,
            label,
            sources,
            media_type: data.media_type,
            text: data.text,
        }
    }
}

/// What the quarantine model reads: the extraction and exactly one untrusted content part (SEC-13 (1)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineModelContext {
    /// The control part.
    pub control: QuarantineControl,
    /// The single content part.
    pub data: [UntrustedData; 1],
}

impl QuarantineModelContext {
    /// The context for one content part.
    #[must_use]
    pub const fn new(extraction: Extraction, data: UntrustedData) -> Self {
        Self {
            control: QuarantineControl { extraction },
            data: [data],
        }
    }

    /// The content part.
    #[must_use]
    pub const fn content(&self) -> &UntrustedData {
        let [data] = &self.data;
        data
    }

    /// Labels the model's output with the content's label (SEC-13 (3)).
    ///
    /// # Errors
    /// [`SummaryLangMismatch`] when the output carries a display summary and `summary_lang` is `none`, or carries none and `summary_lang` names a language.
    pub fn label_output(
        &self,
        output: QuarantineModelOutput,
    ) -> Result<QuarantineOutput, SummaryLangMismatch> {
        let asked = self.control.extraction.summary_lang != SummaryLang::None;
        if asked != output.display_summary.is_some() {
            return Err(SummaryLangMismatch);
        }
        Ok(output.label(self.content().label.clone()))
    }
}

/// A model context (`model-context/v1`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum ModelContext {
    /// The planner's context.
    Planner(PlannerModelContext),
    /// The quarantine model's context.
    Quarantine(QuarantineModelContext),
}

/// The control part of a context, apart from its data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Control<'a> {
    /// The planner's control part.
    Planner(&'a PlannerControl),
    /// The quarantine model's control part.
    Quarantine(&'a QuarantineControl),
}

impl ModelContext {
    /// The control part; it depends only on the typed control fields, never on the data parts (SEC-2, SEC-21 (1)).
    #[must_use]
    pub const fn control(&self) -> Control<'_> {
        match self {
            Self::Planner(context) => Control::Planner(&context.control),
            Self::Quarantine(context) => Control::Quarantine(&context.control),
        }
    }
}
