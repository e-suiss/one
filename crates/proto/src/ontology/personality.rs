//! The personality profile: a derived, versioned view over memory records with structured address, style, values and rules; not a canonical concept (MF-47, MF-49, C-12, C-28).

use alloc::string::String;
use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::header::LocalText;
use super::reference::PartyRef;
use super::tags::OneMemoryClass;
use super::time::Instant;
use crate::id::MemoryRecordId;

crate::const_tag!(
    /// `view: "personality_profile"`.
    PersonalityView,
    "personality_profile"
);

/// Formal or informal address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressForm {
    /// Informal.
    Informal,
    /// Formal.
    Formal,
}

/// How One addresses the user.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    /// The form.
    pub form: AddressForm,
    /// Whether One uses the user's name.
    pub use_user_name: bool,
}

/// Reply length.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ReplyLength {
    /// Short.
    Short,
    /// Medium.
    #[default]
    Medium,
    /// Detailed.
    Detailed,
}

/// Formality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Formality {
    /// Formal.
    Formal,
    /// Neutral.
    Neutral,
    /// Casual.
    Casual,
}

/// Reply style.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Style {
    /// Length.
    pub length: ReplyLength,
    /// Formality.
    pub formality: Formality,
    /// Humour.
    pub humour: bool,
}

/// A value or rule with the record it comes from.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProfileItem {
    /// The statement, at most 280 characters.
    pub statement: LocalText,
    /// The source record.
    pub record: MemoryRecordId,
}

/// The personality profile view.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersonalityProfile {
    /// `personality_profile`.
    pub view: PersonalityView,
    /// The owner.
    pub owner: PartyRef,
    /// Version, from 1.
    pub version: NonZeroU32,
    /// `one_memory`.
    pub retention_class: OneMemoryClass,
    /// When it was built.
    pub recorded_at: Instant,
    /// The assistant's name, `One` by default.
    pub assistant_name: String,
    /// Address.
    pub address: Address,
    /// Style.
    pub style: Style,
    /// Values.
    pub values: Vec<ProfileItem>,
    /// Rules.
    pub rules: Vec<ProfileItem>,
    /// Every source record.
    pub source_records: Vec<MemoryRecordId>,
}
