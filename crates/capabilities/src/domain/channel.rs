//! Inbound channels (CP-26, CP-27, INV-13, Relay AG-26, Relay AG-32): messaging and email are a way in whose content is never trusted; every message is `external.message` (or `external.email`) and goes to the quarantine model, not the planner; a command is taken only from a channel account bound in Access to the user, anyone else's message is data; a channel reply is evidence at `channel_claim` and never an approval, which goes to the Access trusted surface by deep link; One has no agent address of its own besides its One↔One address.

use one_provenance::{ExternalSource, Label, UntrustedLabel};

/// The kind of channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    /// A messaging app.
    Messaging,
    /// Email.
    Email,
}

/// What an inbound message is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Inbound {
    /// A command from the user; its content still goes through quarantine.
    Command,
    /// Data from someone else.
    Data,
}

/// The evidence level of a channel reply.
pub const REPLY_EVIDENCE: &str = "channel_claim";

/// Classifies a message whose sender is bound in Access to the user when `bound_to_owner`.
#[must_use]
pub const fn classify(bound_to_owner: bool) -> Inbound {
    if bound_to_owner {
        Inbound::Command
    } else {
        Inbound::Data
    }
}

/// The label of a message from `channel`.
#[must_use]
pub const fn label(channel: Channel) -> Label {
    Label::Untrusted(UntrustedLabel::External(match channel {
        Channel::Messaging => ExternalSource::Message,
        Channel::Email => ExternalSource::Email,
    }))
}

/// Whether a channel reply or button approves anything: never.
#[must_use]
pub const fn approves() -> bool {
    false
}
