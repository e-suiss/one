//! Goal: a stable identity bound to the memory records that state it, so tasks and interactions can serve it (C-13, C-21).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::concept::Concept;
use super::extension::Extensions;
use super::header::RecordHeader;
use super::tags::{Active, GoalType};
use super::validate::{ContractViolation, UnknownFields, no_unknown, require, unique};
use crate::id::{GoalId, MemoryRecordId};

/// A Goal record (C-13).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Goal {
    /// `Goal`.
    #[serde(rename = "type")]
    pub concept: GoalType,
    /// Identifier.
    pub id: GoalId,
    /// C-19 header.
    #[serde(flatten)]
    pub header: RecordHeader,
    /// The version this one replaces, or `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub supersedes: Option<GoalId>,
    /// `active`.
    pub status: Active,
    /// The goal records, at least one.
    pub derived_from: Vec<MemoryRecordId>,
    /// Extension values.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<Extensions>,
    /// Fields this reader does not know; never re-encoded (M-40).
    #[serde(flatten, skip_serializing)]
    pub unknown: UnknownFields,
}
impl Goal {
    /// Checks a canonical Goal strictly: bound to at least one goal record, no unknown field (C-13).
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        no_unknown(&self.unknown)?;
        self.header.check(Concept::Goal)?;
        require(
            !self.derived_from.is_empty() && unique(&self.derived_from),
            "derived_from",
        )
    }
}
