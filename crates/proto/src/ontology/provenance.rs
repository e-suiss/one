//! The provenance label every record header carries, in the order external < `one.inferred` < `record.trusted` < `user.memory` < `user.direct` (SEC-14, T-36).

use core::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Where a value came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProvenanceLabel {
    /// Said by the user in this turn.
    UserDirect,
    /// The user's own memory.
    UserMemory,
    /// A trusted record.
    RecordTrusted,
    /// Inferred by One.
    OneInferred,
    /// A web page.
    ExternalWeb,
    /// An e-mail.
    ExternalEmail,
    /// A calendar entry.
    ExternalCalendar,
    /// A document.
    ExternalDocument,
    /// Screen content.
    ExternalScreen,
    /// Media.
    ExternalMedia,
    /// A message.
    ExternalMessage,
    /// Another One.
    ExternalOne,
    /// Another agent.
    ExternalAgent,
    /// A tool description.
    ExternalToolDescription,
    /// A tool output.
    ExternalToolOutput,
    /// An import.
    ExternalImport,
    /// An application.
    ExternalApp,
    /// Unknown origin.
    ExternalUnknown,
    /// A join of several external sources.
    ExternalMixed,
}

impl ProvenanceLabel {
    /// Every label, most trusted first.
    pub const ALL: [Self; 19] = [
        Self::UserDirect,
        Self::UserMemory,
        Self::RecordTrusted,
        Self::OneInferred,
        Self::ExternalWeb,
        Self::ExternalEmail,
        Self::ExternalCalendar,
        Self::ExternalDocument,
        Self::ExternalScreen,
        Self::ExternalMedia,
        Self::ExternalMessage,
        Self::ExternalOne,
        Self::ExternalAgent,
        Self::ExternalToolDescription,
        Self::ExternalToolOutput,
        Self::ExternalImport,
        Self::ExternalApp,
        Self::ExternalUnknown,
        Self::ExternalMixed,
    ];

    /// The wire form, such as `external.email`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::UserDirect => "user.direct",
            Self::UserMemory => "user.memory",
            Self::RecordTrusted => "record.trusted",
            Self::OneInferred => "one.inferred",
            Self::ExternalWeb => "external.web",
            Self::ExternalEmail => "external.email",
            Self::ExternalCalendar => "external.calendar",
            Self::ExternalDocument => "external.document",
            Self::ExternalScreen => "external.screen",
            Self::ExternalMedia => "external.media",
            Self::ExternalMessage => "external.message",
            Self::ExternalOne => "external.one",
            Self::ExternalAgent => "external.agent",
            Self::ExternalToolDescription => "external.tool_description",
            Self::ExternalToolOutput => "external.tool_output",
            Self::ExternalImport => "external.import",
            Self::ExternalApp => "external.app",
            Self::ExternalUnknown => "external.unknown",
            Self::ExternalMixed => "external.mixed",
        }
    }

    /// Parses the exact, case-sensitive wire form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|l| l.as_str() == text)
    }

    /// `user.direct`, `user.memory` or `record.trusted`.
    #[must_use]
    pub const fn is_trusted(self) -> bool {
        matches!(
            self,
            Self::UserDirect | Self::UserMemory | Self::RecordTrusted
        )
    }

    /// Any `external.*` label.
    #[must_use]
    pub const fn is_external(self) -> bool {
        !self.is_trusted() && !matches!(self, Self::OneInferred)
    }

    /// The position in the trust order; higher is more trusted.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::UserDirect => 4,
            Self::UserMemory => 3,
            Self::RecordTrusted => 2,
            Self::OneInferred => 1,
            _ => 0,
        }
    }
}

impl fmt::Display for ProvenanceLabel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl Serialize for ProvenanceLabel {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

struct LabelVisitor;

impl Visitor<'_> for LabelVisitor {
    type Value = ProvenanceLabel;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a provenance label")
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<ProvenanceLabel, E> {
        ProvenanceLabel::parse(v).ok_or_else(|| E::unknown_variant(v, &["a provenance label"]))
    }
}

impl<'de> Deserialize<'de> for ProvenanceLabel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(LabelVisitor)
    }
}
