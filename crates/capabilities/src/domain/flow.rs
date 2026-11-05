//! Flows between servers and the custom-server sandbox (CP-20, CP-22, CP-23, SEC-24 (4, 5, 7), E-35): a server's output reaches another server only as a typed field with its provenance label, never as free text; no server sees another's tool definitions; private data, untrusted content and outside communication in one step need the user's approval; no secret ever reaches a capability; a custom server reaches only the origins it declared, its output is always `external.tool_output`, nothing flows from it to another server, and it never receives memory or a sensitive class, only the values the user saw for that call.

use one_proto::task::Origin;
use one_provenance::{ExternalSource, Label, UntrustedLabel};

/// The label every server's output carries.
pub const OUTPUT: Label = Label::Untrusted(UntrustedLabel::External(ExternalSource::ToolOutput));

/// A value handed from one server to another, or from One to a server.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "CP-22")]
pub struct Transfer {
    /// It is a typed field, not free text.
    pub typed: bool,
    /// It comes from a custom server.
    pub from_custom: bool,
    /// It goes to a custom server.
    pub to_custom: bool,
    /// It carries memory.
    pub memory: bool,
    /// It carries a sensitive class.
    pub sensitive: bool,
    /// It carries a password, token, cookie or card.
    pub secret: bool,
    /// The user saw it for this call.
    pub shown_to_user: bool,
}

/// Why a transfer is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A secret never reaches a capability.
    Secret,
    /// Free text never crosses servers.
    Untyped,
    /// Nothing flows from a custom server to another.
    FromCustom,
    /// A custom server gets no memory and no sensitive class.
    PersonalToCustom,
    /// A custom server gets only values the user saw for the call.
    NotShown,
}

/// Checks `transfer`.
///
/// # Errors
/// The first [`Refused`] reason, in the order above.
pub const fn check(transfer: &Transfer) -> Result<(), Refused> {
    if transfer.secret {
        Err(Refused::Secret)
    } else if !transfer.typed {
        Err(Refused::Untyped)
    } else if transfer.from_custom {
        Err(Refused::FromCustom)
    } else if transfer.to_custom && (transfer.memory || transfer.sensitive) {
        Err(Refused::PersonalToCustom)
    } else if transfer.to_custom && !transfer.shown_to_user {
        Err(Refused::NotShown)
    } else {
        Ok(())
    }
}

/// Whether one step joins private data, untrusted content and outside communication and so needs the user's approval.
#[must_use]
pub const fn needs_approval(private: bool, untrusted: bool, outside: bool) -> bool {
    private && untrusted && outside
}

/// Whether a custom server may reach `origin`: only one it declared.
#[must_use]
pub fn egress(declared: &[Origin], origin: &Origin) -> bool {
    declared.contains(origin)
}

/// The tool names a server is told about: only its own.
#[must_use]
pub fn visible_to<'a, T: PartialEq>(server: &T, tools: &'a [(T, String)]) -> Vec<&'a str> {
    tools
        .iter()
        .filter(|(s, _)| s == server)
        .map(|(_, name)| name.as_str())
        .collect()
}
