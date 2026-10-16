//! The internal label set of SEC-14, its trust order and the join that falls to the worst label; trusted and untrusted labels are different types (T-36 (1, 3)).

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;

use one_proto::ontology::ProvenanceLabel;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// The origin of external content: one `external.*` sub-label other than `external.mixed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExternalSource {
    /// `external.agent`: a message from another agent that is not a One.
    Agent,
    /// `external.app`: content handed over by another app.
    App,
    /// `external.calendar`: calendar invitation content.
    Calendar,
    /// `external.document`: document or PDF content.
    Document,
    /// `external.email`: email headers, body and attachment metadata.
    Email,
    /// `external.import`: an imported record.
    Import,
    /// `external.media`: photo, audio or video content the user did not dictate.
    Media,
    /// `external.message`: a message from another person or an unverified channel sender.
    Message,
    /// `external.one`: a field received from another One.
    One,
    /// `external.screen`: screen capture or screenshot text.
    Screen,
    /// `external.tool_description`: a tool name, description, schema or annotation.
    ToolDescription,
    /// `external.tool_output`: tool, MCP or API call output.
    ToolOutput,
    /// `external.unknown`: an unlabelled, malformed or unrecognised label.
    Unknown,
    /// `external.web`: web page content, including hidden text, URL query and fragment.
    Web,
}

impl ExternalSource {
    /// Every external source.
    pub const ALL: [Self; 14] = [
        Self::Agent,
        Self::App,
        Self::Calendar,
        Self::Document,
        Self::Email,
        Self::Import,
        Self::Media,
        Self::Message,
        Self::One,
        Self::Screen,
        Self::ToolDescription,
        Self::ToolOutput,
        Self::Unknown,
        Self::Web,
    ];

    /// The wire form, such as `external.email`.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        LabelKind::External(self).as_str()
    }
}

impl PartialOrd for ExternalSource {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for ExternalSource {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}

/// A trusted label: `user.direct`, `user.memory` or `record.trusted` (T-36 (1)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustedLabel {
    /// `user.direct`: the user's direct input in this task.
    UserDirect,
    /// `user.memory`: a memory record whose whole origin is the user's own statement or explicit confirmation.
    UserMemory,
    /// `record.trusted`: a value read from an Access or Work record.
    RecordTrusted,
}

impl TrustedLabel {
    /// Every trusted label, most trusted first.
    pub const ALL: [Self; 3] = [Self::UserDirect, Self::UserMemory, Self::RecordTrusted];

    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        LabelKind::Trusted(self).as_str()
    }

    /// The trust rank: 4 for `user.direct`, 3 for `user.memory`, 2 for `record.trusted`.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::UserDirect => 4,
            Self::UserMemory => 3,
            Self::RecordTrusted => 2,
        }
    }

    /// The worse of two trusted labels; joining trusted labels never leaves the trusted type (SEC-14 (1)).
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if other.rank() < self.rank() {
            other
        } else {
            self
        }
    }
}

/// Two or more different external sources joined into `external.mixed`, kept sorted and unique.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct MixedSources(Vec<ExternalSource>);

impl MixedSources {
    /// Builds the set from any sources; `None` unless at least two differ.
    #[must_use]
    pub fn new(sources: impl IntoIterator<Item = ExternalSource>) -> Option<Self> {
        let mut all: Vec<ExternalSource> = sources.into_iter().collect();
        all.sort_unstable();
        all.dedup();
        (all.len() >= 2).then_some(Self(all))
    }

    /// The sources in wire order.
    #[must_use]
    pub fn as_slice(&self) -> &[ExternalSource] {
        &self.0
    }
}

/// An untrusted label: `one.inferred` or `external.*` (T-36 (1)).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum UntrustedLabel {
    /// `one.inferred`: a value One observed or inferred.
    OneInferred,
    /// One `external.*` source.
    External(ExternalSource),
    /// `external.mixed` with its flattened sources.
    Mixed(MixedSources),
}

impl UntrustedLabel {
    /// The trust rank: 1 for `one.inferred`, 0 for every external label.
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::OneInferred => 1,
            Self::External(_) | Self::Mixed(_) => 0,
        }
    }

    /// The bare label string.
    #[must_use]
    pub const fn kind(&self) -> LabelKind {
        match self {
            Self::OneInferred => LabelKind::OneInferred,
            Self::External(source) => LabelKind::External(*source),
            Self::Mixed(_) => LabelKind::Mixed,
        }
    }

    /// The external sources this label names; empty for `one.inferred`.
    #[must_use]
    pub fn external_sources(&self) -> &[ExternalSource] {
        match self {
            Self::OneInferred => &[],
            Self::External(source) => core::slice::from_ref(source),
            Self::Mixed(mixed) => mixed.as_slice(),
        }
    }

    /// The worse of this label and any other; the result stays untrusted (SEC-14 (1), T-36 (3)).
    #[must_use]
    pub fn join(&self, other: &Label) -> Self {
        let Label::Untrusted(other) = other else {
            return self.clone();
        };
        let sources = self
            .external_sources()
            .iter()
            .chain(other.external_sources())
            .copied();
        let mut all: Vec<ExternalSource> = sources.collect();
        all.sort_unstable();
        all.dedup();
        match all.as_slice() {
            [] => Self::OneInferred,
            [one] => Self::External(*one),
            _ => Self::Mixed(MixedSources(all)),
        }
    }
}

/// Any internal label.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Label {
    /// A trusted label.
    Trusted(TrustedLabel),
    /// An untrusted label.
    Untrusted(UntrustedLabel),
}

impl Label {
    /// `external.unknown`, the label of every unlabelled or malformed value (SEC-14 (2)).
    pub const UNKNOWN: Self = Self::Untrusted(UntrustedLabel::External(ExternalSource::Unknown));

    /// The trust rank from 4 (`user.direct`) down to 0 (`external.*`).
    #[must_use]
    pub const fn rank(&self) -> u8 {
        match self {
            Self::Trusted(label) => label.rank(),
            Self::Untrusted(label) => label.rank(),
        }
    }

    /// Compares trust: `Less` means `self` is less trusted than `other`.
    #[must_use]
    pub fn cmp_trust(&self, other: &Self) -> Ordering {
        self.rank().cmp(&other.rank())
    }

    /// True for `user.*` and `record.trusted`.
    #[must_use]
    pub const fn is_trusted(&self) -> bool {
        matches!(self, Self::Trusted(_))
    }

    /// The bare label string.
    #[must_use]
    pub const fn kind(&self) -> LabelKind {
        match self {
            Self::Trusted(label) => LabelKind::Trusted(*label),
            Self::Untrusted(label) => label.kind(),
        }
    }

    /// The worse of two labels; two different external labels meet in `external.mixed` (SEC-14 (1), SEC-31 (5)).
    #[must_use]
    pub fn join(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::Trusted(a), Self::Trusted(b)) => Self::Trusted(a.join(*b)),
            (Self::Untrusted(a), b) => Self::Untrusted(a.join(b)),
            (a, Self::Untrusted(b)) => Self::Untrusted(b.join(a)),
        }
    }

    /// The join of every label; `None` when there is none.
    #[must_use]
    pub fn join_all<'a>(labels: impl IntoIterator<Item = &'a Self>) -> Option<Self> {
        labels.into_iter().fold(None, |acc, next| {
            Some(match acc {
                None => next.clone(),
                Some(acc) => acc.join(next),
            })
        })
    }

    /// Builds a label from its wire string and optional `sources`; `None` for a malformed pair (labelled-value/v1).
    #[must_use]
    pub fn from_wire(kind: LabelKind, sources: Option<&[Source]>) -> Option<Self> {
        if let Some(list) = sources
            && (list.is_empty() || !unique(list))
        {
            return None;
        }
        let trail = sources.unwrap_or(&[]).iter().map(|s| s.label());
        match kind {
            LabelKind::Mixed => {
                let externals = sources
                    .unwrap_or(&[])
                    .iter()
                    .filter(|s| matches!(s, Source::External(_)))
                    .count();
                if externals < 2 {
                    return None;
                }
                Self::join_all(trail.collect::<Vec<_>>().iter())
            }
            other => {
                let declared = other.single()?;
                Some(trail.fold(declared, |acc, next| acc.join(&next)))
            }
        }
    }
}

fn unique(list: &[Source]) -> bool {
    list.iter()
        .enumerate()
        .all(|(i, s)| !list.iter().skip(i.saturating_add(1)).any(|t| t == s))
}

/// The label string of `label/v1`: every internal label, with `external.mixed` carried without its sources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LabelKind {
    /// `user.direct`, `user.memory` or `record.trusted`.
    Trusted(TrustedLabel),
    /// `one.inferred`.
    OneInferred,
    /// One `external.*` source.
    External(ExternalSource),
    /// `external.mixed`.
    Mixed,
}

impl LabelKind {
    /// Every label string, most trusted first.
    pub const ALL: [Self; 19] = [
        Self::Trusted(TrustedLabel::UserDirect),
        Self::Trusted(TrustedLabel::UserMemory),
        Self::Trusted(TrustedLabel::RecordTrusted),
        Self::OneInferred,
        Self::External(ExternalSource::Agent),
        Self::External(ExternalSource::App),
        Self::External(ExternalSource::Calendar),
        Self::External(ExternalSource::Document),
        Self::External(ExternalSource::Email),
        Self::External(ExternalSource::Import),
        Self::External(ExternalSource::Media),
        Self::External(ExternalSource::Message),
        Self::External(ExternalSource::One),
        Self::External(ExternalSource::Screen),
        Self::External(ExternalSource::ToolDescription),
        Self::External(ExternalSource::ToolOutput),
        Self::External(ExternalSource::Unknown),
        Self::External(ExternalSource::Web),
        Self::Mixed,
    ];

    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.to_proto().as_str()
    }

    /// Parses the exact, case-sensitive wire form.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        ProvenanceLabel::parse(text).map(Self::from_proto)
    }

    /// The `one-proto` wire label.
    #[must_use]
    pub const fn to_proto(self) -> ProvenanceLabel {
        match self {
            Self::Trusted(TrustedLabel::UserDirect) => ProvenanceLabel::UserDirect,
            Self::Trusted(TrustedLabel::UserMemory) => ProvenanceLabel::UserMemory,
            Self::Trusted(TrustedLabel::RecordTrusted) => ProvenanceLabel::RecordTrusted,
            Self::OneInferred => ProvenanceLabel::OneInferred,
            Self::External(ExternalSource::Agent) => ProvenanceLabel::ExternalAgent,
            Self::External(ExternalSource::App) => ProvenanceLabel::ExternalApp,
            Self::External(ExternalSource::Calendar) => ProvenanceLabel::ExternalCalendar,
            Self::External(ExternalSource::Document) => ProvenanceLabel::ExternalDocument,
            Self::External(ExternalSource::Email) => ProvenanceLabel::ExternalEmail,
            Self::External(ExternalSource::Import) => ProvenanceLabel::ExternalImport,
            Self::External(ExternalSource::Media) => ProvenanceLabel::ExternalMedia,
            Self::External(ExternalSource::Message) => ProvenanceLabel::ExternalMessage,
            Self::External(ExternalSource::One) => ProvenanceLabel::ExternalOne,
            Self::External(ExternalSource::Screen) => ProvenanceLabel::ExternalScreen,
            Self::External(ExternalSource::ToolDescription) => {
                ProvenanceLabel::ExternalToolDescription
            }
            Self::External(ExternalSource::ToolOutput) => ProvenanceLabel::ExternalToolOutput,
            Self::External(ExternalSource::Unknown) => ProvenanceLabel::ExternalUnknown,
            Self::External(ExternalSource::Web) => ProvenanceLabel::ExternalWeb,
            Self::Mixed => ProvenanceLabel::ExternalMixed,
        }
    }

    /// The label string of a `one-proto` wire label.
    #[must_use]
    pub const fn from_proto(label: ProvenanceLabel) -> Self {
        match label {
            ProvenanceLabel::UserDirect => Self::Trusted(TrustedLabel::UserDirect),
            ProvenanceLabel::UserMemory => Self::Trusted(TrustedLabel::UserMemory),
            ProvenanceLabel::RecordTrusted => Self::Trusted(TrustedLabel::RecordTrusted),
            ProvenanceLabel::OneInferred => Self::OneInferred,
            ProvenanceLabel::ExternalAgent => Self::External(ExternalSource::Agent),
            ProvenanceLabel::ExternalApp => Self::External(ExternalSource::App),
            ProvenanceLabel::ExternalCalendar => Self::External(ExternalSource::Calendar),
            ProvenanceLabel::ExternalDocument => Self::External(ExternalSource::Document),
            ProvenanceLabel::ExternalEmail => Self::External(ExternalSource::Email),
            ProvenanceLabel::ExternalImport => Self::External(ExternalSource::Import),
            ProvenanceLabel::ExternalMedia => Self::External(ExternalSource::Media),
            ProvenanceLabel::ExternalMessage => Self::External(ExternalSource::Message),
            ProvenanceLabel::ExternalOne => Self::External(ExternalSource::One),
            ProvenanceLabel::ExternalScreen => Self::External(ExternalSource::Screen),
            ProvenanceLabel::ExternalToolDescription => {
                Self::External(ExternalSource::ToolDescription)
            }
            ProvenanceLabel::ExternalToolOutput => Self::External(ExternalSource::ToolOutput),
            ProvenanceLabel::ExternalUnknown => Self::External(ExternalSource::Unknown),
            ProvenanceLabel::ExternalWeb => Self::External(ExternalSource::Web),
            ProvenanceLabel::ExternalMixed => Self::Mixed,
        }
    }

    /// The trust rank; `external.mixed` ranks 0 like every external label.
    #[must_use]
    pub const fn rank(self) -> u8 {
        match self {
            Self::Trusted(label) => label.rank(),
            Self::OneInferred => 1,
            Self::External(_) | Self::Mixed => 0,
        }
    }

    /// The trusted label, if this is one.
    #[must_use]
    pub const fn trusted(self) -> Option<TrustedLabel> {
        match self {
            Self::Trusted(label) => Some(label),
            _ => None,
        }
    }

    /// The full label of every kind except `external.mixed`, which needs its sources.
    #[must_use]
    pub const fn single(self) -> Option<Label> {
        match self {
            Self::Trusted(label) => Some(Label::Trusted(label)),
            Self::OneInferred => Some(Label::Untrusted(UntrustedLabel::OneInferred)),
            Self::External(source) => Some(Label::Untrusted(UntrustedLabel::External(source))),
            Self::Mixed => None,
        }
    }
}

impl fmt::Display for LabelKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<LabelKind> for ProvenanceLabel {
    fn from(kind: LabelKind) -> Self {
        kind.to_proto()
    }
}

impl From<ProvenanceLabel> for LabelKind {
    fn from(label: ProvenanceLabel) -> Self {
        Self::from_proto(label)
    }
}

impl Serialize for LabelKind {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.to_proto().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for LabelKind {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        ProvenanceLabel::deserialize(deserializer).map(Self::from_proto)
    }
}

/// One entry of `sources`: any label except `external.mixed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Source {
    /// A trusted source.
    Trusted(TrustedLabel),
    /// `one.inferred`.
    OneInferred,
    /// One external source.
    External(ExternalSource),
}

impl Source {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.kind().as_str()
    }

    /// The label string of this source.
    #[must_use]
    pub const fn kind(self) -> LabelKind {
        match self {
            Self::Trusted(label) => LabelKind::Trusted(label),
            Self::OneInferred => LabelKind::OneInferred,
            Self::External(source) => LabelKind::External(source),
        }
    }

    /// The label of a value from this one source.
    #[must_use]
    pub const fn label(self) -> Label {
        match self {
            Self::Trusted(label) => Label::Trusted(label),
            Self::OneInferred => Label::Untrusted(UntrustedLabel::OneInferred),
            Self::External(source) => Label::Untrusted(UntrustedLabel::External(source)),
        }
    }

    /// Parses the exact wire form; `external.mixed` is never a source.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match LabelKind::parse(text)? {
            LabelKind::Trusted(label) => Some(Self::Trusted(label)),
            LabelKind::OneInferred => Some(Self::OneInferred),
            LabelKind::External(source) => Some(Self::External(source)),
            LabelKind::Mixed => None,
        }
    }
}

impl Serialize for Source {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Source {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        Self::parse(&text)
            .ok_or_else(|| serde::de::Error::unknown_variant(&text, &["a source label"]))
    }
}
