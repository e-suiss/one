//! The Claude Code and Codex bridge (CP-37 to CP-41, MF-27, PV-39, SEC-22 (4)): the official `claude` and `codex` programs run on the user's own computer in the local executor under the user's own account; their login stays in the tool's own store and no type here can hold it; One sends them only what the user typed for them, never its memory, preferences or other tasks; what they produce is `external.tool_output` data, never an instruction; they are never router candidates and One never uses them for its own work; each tool has a terms switch, and a closed tool's bridge does not start.

use one_proto::ontology::ProvenanceLabel;
use one_provenance::{ExternalSource, Label, LabelKind, Trusted, UntrustedLabel};

/// A coding tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    /// The official `claude` program.
    ClaudeCode,
    /// The official `codex` program.
    Codex,
}

/// The terms switch of a tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Terms {
    /// The provider's terms allow the bridge.
    Open,
    /// They do not, or changed: the bridge is closed.
    Closed,
}

/// The switches at release, checked again at every release.
pub const SWITCHES: [(Tool, Terms); 2] =
    [(Tool::ClaudeCode, Terms::Open), (Tool::Codex, Terms::Open)];

/// Whether the bridge for `tool` may start under `switches`.
#[must_use]
pub fn may_start(tool: Tool, switches: &[(Tool, Terms)]) -> bool {
    switches
        .iter()
        .any(|(t, s)| *t == tool && *s == Terms::Open)
}

/// What goes to the tool: only the user's own words for it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input(String);

impl Input {
    /// The input from text the user typed in this task; anything else, memory included, is refused.
    #[must_use]
    pub fn from_user(text: Trusted<String>) -> Option<Self> {
        (LabelKind::Trusted(text.label()).to_proto() == ProvenanceLabel::UserDirect)
            .then(|| Self(text.into_value()))
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The label of everything the tool produces.
pub const OUTPUT: Label = Label::Untrusted(UntrustedLabel::External(ExternalSource::ToolOutput));
