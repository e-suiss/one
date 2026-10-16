//! The `<memory-data version="1">` text view: a data block generated from canonical records, one escaped line per active, non-invalidated record, so record text can never close the block or become instruction (M-6, M-2, M-14, M-30, INV-14, MD-7 (2), C-22).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::fields::{EpistemicState, LiveStatus};
use super::record::MemoryRecord;
use crate::id::MemoryRecordId;

/// The opening line.
pub const OPEN: &str = "<memory-data version=\"1\">";
/// The closing line.
pub const CLOSE: &str = "</memory-data>";

crate::const_tag!(
    /// `format: "memory-data/v1"`.
    MemoryDataFormat,
    "memory-data/v1"
);

/// The trust class shown instead of a number (M-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustClass {
    /// The user said it.
    YouSaid,
    /// One thinks so.
    IThink,
    /// One is not sure.
    NotSure,
    /// Seen in a source, not verified.
    SeenUnverified,
    /// Imported, not verified.
    ImportedUnverified,
}

impl TrustClass {
    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::YouSaid => "you_said",
            Self::IThink => "i_think",
            Self::NotSure => "not_sure",
            Self::SeenUnverified => "seen_unverified",
            Self::ImportedUnverified => "imported_unverified",
        }
    }
}

/// One record selected for the view.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextViewEntry {
    /// The record.
    pub record: MemoryRecord,
    /// Its trust class.
    pub trust_class: TrustClass,
    /// Whether it holds now (season, validity window).
    pub currently_valid: bool,
}

/// The records to render.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TextViewRequest {
    /// Entries in order.
    pub entries: Vec<TextViewEntry>,
}

/// The rendered view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TextView {
    /// `memory-data/v1`.
    pub format: MemoryDataFormat,
    /// The data block.
    pub text: String,
    /// The rendered records in order.
    pub records: Vec<MemoryRecordId>,
}

/// A record that must never reach the view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum TextViewError {
    /// A candidate, suppressed, forgotten or invalidated record.
    NotRenderable {
        /// The record.
        record: MemoryRecordId,
    },
}

/// Escapes record text: `&`, `<`, `>` become entities and each line break becomes one space.
#[must_use]
pub fn escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '\r' => {
                if chars.peek() == Some(&'\n') {
                    chars.next();
                }
                out.push(' ');
            }
            '\n' => out.push(' '),
            other => out.push(other),
        }
    }
    out
}

/// Renders the view from canonical records.
///
/// # Errors
/// [`TextViewError::NotRenderable`] for the first record that is not active or is invalidated.
pub fn render(entries: &[TextViewEntry]) -> Result<TextView, TextViewError> {
    let mut text = String::from(OPEN);
    text.push('\n');
    let mut records = Vec::with_capacity(entries.len());
    for entry in entries {
        let record = match &entry.record {
            MemoryRecord::Live(r)
                if r.status == LiveStatus::Active
                    && r.epistemic_state != EpistemicState::Invalidated =>
            {
                r
            }
            other => return Err(TextViewError::NotRenderable { record: other.id() }),
        };
        text.push('[');
        text.push_str(record.content_type.core().name());
        text.push('|');
        text.push_str(record.epistemic_state.name());
        text.push('|');
        text.push_str(entry.trust_class.name());
        if record.is_contested() {
            text.push_str("|contested");
        }
        if !entry.currently_valid {
            text.push_str("|not_current");
        }
        text.push_str("] ");
        text.push_str(&escape(&record.statement.text));
        text.push('\n');
        records.push(record.id);
    }
    text.push_str(CLOSE);
    Ok(TextView {
        format: MemoryDataFormat,
        text,
        records,
    })
}
