//! Task and capability shared definitions: the checked-record and wire-enum macros, snake names, digests, single lines, Executor evidence, the autonomy behaviour, TR and EN text and the C-19 header rules (C-19, A-1, X-52).

use serde::{Deserialize, Serialize};

use crate::data_class::{DataClass, RetentionClass};
use crate::ontology::validate::{ContractViolation, require};
use crate::ontology::{ClaimRef, ExecutionReportRef, RecordStatus};

macro_rules! checked_record {
    (
        $(#[$meta:meta])*
        pub struct $name:ident via $wire:ident = $wire_lit:literal, check $check:path {
            $( $(#[$fmeta:meta])* pub $field:ident : $ty:ty, )*
        }
    ) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = $wire_lit)]
        pub struct $name {
            $( $(#[$fmeta])* pub $field: $ty, )*
        }

        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct $wire {
            $( $(#[$fmeta])* $field: $ty, )*
        }

        impl TryFrom<$wire> for $name {
            type Error = $crate::ontology::validate::ContractViolation;

            fn try_from(wire: $wire) -> Result<Self, Self::Error> {
                let record = Self { $( $field: wire.$field, )* };
                $check(&record)?;
                Ok(record)
            }
        }
    };
}
pub(crate) use checked_record;

pub(crate) fn is_snake_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && text.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_sha256_digest(text: &str) -> bool {
    text.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_line(text: &str) -> bool {
    !text.is_empty() && !text.contains(['\r', '\n', '\t'])
}

crate::ontology::validate::checked_string!(
    /// A snake-case name of at most 64 characters.
    SnakeName,
    "snake-case name",
    is_snake_name
);
crate::ontology::validate::checked_string!(
    /// A `sha256:` digest in lower-case hex.
    Sha256Digest,
    "sha256 digest",
    is_sha256_digest
);
crate::ontology::validate::checked_string!(
    /// One line of user-facing text: no carriage return, line feed or tab.
    Line,
    "single line",
    is_line
);

crate::ontology::reference::ref_union!(
    /// Evidence the Executor produced: a claim or an execution report.
    ExecutorEvidence {
        /// An Executor Claim.
        Claim(ClaimRef),
        /// An Executor report.
        ExecutionReport(ExecutionReportRef),
    }
);

/// Defines a closed string enum with its exact wire strings.
macro_rules! wire_enum {
    ($(#[$meta:meta])* $name:ident { $( $(#[$vmeta:meta])* $variant:ident = $wire:literal ),+ $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        pub enum $name {
            $( $(#[$vmeta])* #[serde(rename = $wire)] $variant, )+
        }

        impl $name {
            /// Every value in contract order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire string.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self {
                    $( Self::$variant => $wire, )+
                }
            }

            /// Parses the wire string.
            #[must_use]
            pub fn from_wire(text: &str) -> Option<Self> {
                match text {
                    $( $wire => Some(Self::$variant), )+
                    _ => None,
                }
            }
        }
    };
}
pub(crate) use wire_enum;

wire_enum!(
    /// A Mandate behaviour for one action (A-1).
    AutonomyBehaviour {
        /// Act.
        Act = "act",
        /// Act when the pre-approval origin is recorded.
        ActIfPreapproved = "act-if-preapproved",
        /// Ask first.
        Ask = "ask",
        /// Hand the work to the user.
        Handoff = "handoff",
    }
);

/// TR and EN text, both required (X-52).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalizedText {
    /// Turkish.
    pub tr: Line,
    /// English.
    pub en: Line,
}

/// The C-19 header rules shared by every canonical record that is not an observation.
pub(crate) fn check_header(
    version: core::num::NonZeroU32,
    has_supersedes: bool,
    status: RecordStatus,
    deleted_at: Option<&crate::ontology::Instant>,
    data_class: &DataClass,
    retention: RetentionClass,
) -> Result<(), ContractViolation> {
    require(
        (version.get() == 1) != has_supersedes,
        "supersedes matches version",
    )?;
    require(
        (status == RecordStatus::Deleted) == deleted_at.is_some(),
        "deleted_at matches status",
    )?;
    let wanted = if data_class.is_sensitive() {
        RetentionClass::OneSensitive
    } else {
        RetentionClass::OneMemory
    };
    require(
        retention == wanted,
        "retention class follows the data class",
    )
}
