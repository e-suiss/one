//! Extension points: declarations for new memory content types, interaction kinds, capability names and typed fields, and the versioned values records carry under `extensions` (C-3, C-7, CP-15, OO-9).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::concept::Concept;
use super::json::JsonValue;
use super::validate::{
    ContractViolation, is_capability_name, is_interaction_extension_name, is_memory_extension_name,
    is_suiss_extension_name, require,
};
use crate::memory::fields::CoreContentType;

/// A typed extension value on a canonical record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExtensionValue {
    /// The extension version, from 1.
    pub version: u32,
    /// The value, shaped by the declared value schema.
    pub value: JsonValue,
}

/// Extension values keyed by `app.suiss.…` name.
pub type Extensions = BTreeMap<String, ExtensionValue>;

/// One or more capability names a capability extends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Extends {
    /// One parent.
    One(String),
    /// Two or more parents.
    Many(Vec<String>),
}

/// An extension declaration at one of the four extension points.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "point", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionDeclaration {
    /// A memory content type mapped to a core type.
    MemoryContentType {
        /// `app.suiss.memory.…`.
        name: String,
        /// Version, from 1.
        version: u32,
        /// The core type it renders as.
        maps_to: CoreContentType,
    },
    /// An interaction kind mapped to a core kind.
    InteractionKind {
        /// `app.suiss.interaction.…`.
        name: String,
        /// Version, from 1.
        version: u32,
        /// The core interaction kind.
        maps_to: String,
    },
    /// A capability name that extends a parent.
    CapabilityName {
        /// The capability name.
        name: String,
        /// Dated version, `YYYY-MM-DD`.
        version: String,
        /// The parent capability or capabilities.
        extends: Extends,
    },
    /// A typed field on a canonical concept.
    TypedField {
        /// `app.suiss.…`, outside the reserved product roots.
        name: String,
        /// Version, from 1.
        version: u32,
        /// The concept carrying the field.
        maps_to: Concept,
        /// The `https://` schema of the value.
        value_schema: String,
    },
}

/// The core interaction kinds an interaction kind extension maps to.
pub const INTERACTION_CORE_KINDS: [&str; 9] = [
    "approval",
    "choice",
    "question",
    "info",
    "progress",
    "receipt",
    "comparison",
    "form",
    "digest_item",
];

impl ExtensionDeclaration {
    /// Checks names, versions and mappings of each extension point (C-7).
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn validate(&self) -> Result<(), ContractViolation> {
        match self {
            Self::MemoryContentType { name, version, .. } => require(
                *version >= 1 && is_memory_extension_name(name, false),
                "name",
            ),
            Self::InteractionKind {
                name,
                version,
                maps_to,
            } => {
                require(*version >= 1 && is_interaction_extension_name(name), "name")?;
                require(
                    INTERACTION_CORE_KINDS.contains(&maps_to.as_str()),
                    "maps_to",
                )
            }
            Self::CapabilityName {
                name,
                version,
                extends,
            } => {
                require(is_capability_name(name), "name")?;
                require(super::validate::is_dated_version(version), "version")?;
                let parents_ok = match extends {
                    Extends::One(p) => is_capability_name(p),
                    Extends::Many(ps) => {
                        ps.len() >= 2
                            && super::validate::unique(ps)
                            && ps.iter().all(|p| is_capability_name(p))
                    }
                };
                require(parents_ok, "extends")
            }
            Self::TypedField {
                name,
                version,
                value_schema,
                ..
            } => {
                require(*version >= 1 && is_suiss_extension_name(name), "name")?;
                require(value_schema.starts_with("https://"), "value_schema")
            }
        }
    }
}
