//! Routine: a learned or stated pattern with trigger, behaviour, evidence and exceptions; it suggests through an Interaction and never carries authority, because its `authority` field has the single value `NONE` (C-14, C-21, AT-27, AT-29, AT-31).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::concept::Concept;
use super::extension::Extensions;
use super::header::{LocalText, RecordHeader};
use super::reference::ExternalRef;
use super::tags::{Active, NoAuthority, RoutineType};
use super::time::Instant;
use super::validate::{
    ContractViolation, UnknownFields, is_capability_name, no_unknown, require, unique,
};
use crate::id::{MemoryRecordId, RoutineId};

/// A day of the week.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Weekday {
    /// Monday.
    Mon,
    /// Tuesday.
    Tue,
    /// Wednesday.
    Wed,
    /// Thursday.
    Thu,
    /// Friday.
    Fri,
    /// Saturday.
    Sat,
    /// Sunday.
    Sun,
}

/// A local time window, `HH:MM` to `HH:MM`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TimeWindow {
    /// Start.
    pub start: String,
    /// End.
    pub end: String,
}

/// When a routine applies; at least one part is set.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoutineTrigger {
    /// Days of the week.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub days: Option<Vec<Weekday>>,
    /// Time window.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub time_window: Option<TimeWindow>,
    /// Place; a place routine is always sensitive.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<ExternalRef>,
    /// Free context.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<LocalText>,
}

/// What the routine does when it applies.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoutineBehaviour {
    /// The capability it would suggest.
    pub capability: String,
    /// The preference record it uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preference: Option<MemoryRecordId>,
    /// A short summary.
    pub summary: LocalText,
}

/// How often the user did it unprompted and after a suggestion (AT-29).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RoutineEvidence {
    /// Unprompted repetitions.
    pub spontaneous: u32,
    /// Repetitions after a suggestion.
    pub after_suggestion: u32,
}

/// How a routine came to be.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutineSource {
    /// Learned from behaviour.
    Learned,
    /// Stated by the user.
    Stated,
    /// Confirmed by the user.
    Confirmed,
}

/// Whether a routine is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutineState {
    /// In use.
    Active,
    /// Suspended.
    Suspended,
    /// No longer valid.
    Invalid,
}

/// A Routine record (C-14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Routine {
    /// `Routine`.
    #[serde(rename = "type")]
    pub concept: RoutineType,
    /// Identifier.
    pub id: RoutineId,
    /// C-19 header.
    #[serde(flatten)]
    pub header: RecordHeader,
    /// The version this one replaces, or `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub supersedes: Option<RoutineId>,
    /// `active`.
    pub status: Active,
    /// When it applies.
    pub trigger: RoutineTrigger,
    /// What it does.
    pub behaviour: RoutineBehaviour,
    /// Repetition evidence.
    pub evidence: RoutineEvidence,
    /// Known exceptions, at most 32.
    pub exceptions: Vec<LocalText>,
    /// First seen.
    pub first_seen: Instant,
    /// Last seen.
    pub last_seen: Instant,
    /// ISO 8601 period.
    pub period: String,
    /// How it came to be.
    pub source: RoutineSource,
    /// Whether it is in use.
    pub state: RoutineState,
    /// Always `NONE`.
    pub authority: NoAuthority,
    /// Sensitive; on by default and always on for a place routine.
    #[serde(default = "default_sensitive")]
    pub sensitive: bool,
    /// The evidence records, at least one.
    pub derived_from: Vec<MemoryRecordId>,
    /// Extension values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
const fn default_sensitive() -> bool {
    true
}

impl RoutineTrigger {
    /// At least one part is set.
    #[must_use]
    pub const fn is_readable(&self) -> bool {
        self.days.is_some()
            || self.time_window.is_some()
            || self.place.is_some()
            || self.context.is_some()
    }
}

impl Routine {
    /// A routine with a place trigger must be sensitive (C-14).
    #[must_use]
    pub const fn sensitivity_holds(&self) -> bool {
        self.trigger.place.is_none() || self.sensitive
    }

    /// Checks a canonical Routine strictly (C-14).
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        no_unknown(&self.unknown)?;
        self.header.check(Concept::Routine)?;
        require(self.trigger.is_readable(), "trigger")?;
        require(self.sensitivity_holds(), "sensitive")?;
        require(
            !self.derived_from.is_empty() && unique(&self.derived_from),
            "derived_from",
        )?;
        require(self.exceptions.len() <= 32, "exceptions")?;
        require(is_capability_name(&self.behaviour.capability), "capability")
    }
}
