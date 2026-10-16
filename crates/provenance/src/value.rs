//! Labelled values: trusted and untrusted values are different types, the value never shows in `Debug`, and opening a value never yields a better label than its wire form proves (SEC-14 (2), T-28 (7), T-36 (1, 4)).

use alloc::vec::Vec;
use core::fmt;

use serde::de::DeserializeOwned;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::access::AccessProvenance;
use crate::content::{Content, ContentDeserializer};
use crate::label::{ExternalSource, Label, LabelKind, Source, TrustedLabel, UntrustedLabel};
use crate::transform::Transform;

/// The `sources` list of a labelled value: non-empty, unique, in wire order.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Sources(Vec<Source>);

impl Sources {
    /// Checks and wraps a list; `None` if it is empty or repeats an entry.
    #[must_use]
    pub fn new(list: Vec<Source>) -> Option<Self> {
        let unique = list
            .iter()
            .enumerate()
            .all(|(i, s)| !list.iter().skip(i.saturating_add(1)).any(|t| t == s));
        (!list.is_empty() && unique).then_some(Self(list))
    }

    /// The entries.
    #[must_use]
    pub fn as_slice(&self) -> &[Source] {
        &self.0
    }
}

/// A value with a trusted label (`user.direct`, `user.memory`, `record.trusted`); the only kind the planner reads as content (T-36 (1, 2)).
#[derive(Clone, PartialEq, Eq)]
pub struct Trusted<T> {
    value: T,
    label: TrustedLabel,
    sources: Option<Sources>,
}

impl<T> Trusted<T> {
    /// The user's direct input in this task, taken from a trusted surface.
    pub const fn user_direct(value: T) -> Self {
        Self::with_label(value, TrustedLabel::UserDirect)
    }

    /// A value read from an Access or Work record.
    pub const fn record(value: T) -> Self {
        Self::with_label(value, TrustedLabel::RecordTrusted)
    }

    pub(crate) const fn with_label(value: T, label: TrustedLabel) -> Self {
        Self {
            value,
            label,
            sources: None,
        }
    }

    /// The label.
    pub const fn label(&self) -> TrustedLabel {
        self.label
    }

    /// The `sources` carried from the wire, if any.
    pub const fn sources(&self) -> Option<&Sources> {
        self.sources.as_ref()
    }

    /// Borrows the value.
    pub const fn expose(&self) -> &T {
        &self.value
    }

    /// Unwraps the value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Applies a label-preserving transform such as translation or normalisation (SEC-14 (1)).
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Trusted<U> {
        Trusted {
            value: f(self.value),
            label: self.label,
            sources: self.sources,
        }
    }

    /// Writes the value to memory: `user.direct` becomes `user.memory`, other labels stay (SEC-14 (1)).
    #[must_use]
    pub fn into_memory(self) -> Self {
        let label = match self.label {
            TrustedLabel::UserDirect => TrustedLabel::UserMemory,
            other => other,
        };
        Self {
            value: self.value,
            label,
            sources: self.sources,
        }
    }
}

impl<T> fmt::Debug for Trusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Trusted")
            .field("label", &self.label.as_str())
            .field("value", &"[masked]")
            .finish_non_exhaustive()
    }
}

/// A value with an untrusted label (`one.inferred`, `external.*`); it reaches the planner only as a [`crate::planner::VarRef`] (T-36 (1, 2)).
#[derive(Clone, PartialEq, Eq)]
pub struct Untrusted<T> {
    value: T,
    label: UntrustedLabel,
    sources: Option<Sources>,
}

impl<T> Untrusted<T> {
    /// Parser output from one external source (T-36 (4)).
    pub const fn external(value: T, source: ExternalSource) -> Self {
        Self::with_label(value, UntrustedLabel::External(source))
    }

    /// A value One observed or inferred.
    pub const fn inferred(value: T) -> Self {
        Self::with_label(value, UntrustedLabel::OneInferred)
    }

    /// A value whose origin is not known: `external.unknown` (SEC-14 (2)).
    pub const fn unknown(value: T) -> Self {
        Self::external(value, ExternalSource::Unknown)
    }

    pub(crate) const fn with_label(value: T, label: UntrustedLabel) -> Self {
        Self {
            value,
            label,
            sources: None,
        }
    }

    /// The label.
    pub const fn label(&self) -> &UntrustedLabel {
        &self.label
    }

    /// The `sources` carried from the wire, if any.
    pub const fn sources(&self) -> Option<&Sources> {
        self.sources.as_ref()
    }

    /// Borrows the value.
    pub const fn expose(&self) -> &T {
        &self.value
    }

    /// Unwraps the value.
    pub fn into_value(self) -> T {
        self.value
    }

    /// Applies a transform; summarising, translating, extracting or normalising never clears the label (SEC-14 (1)).
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Untrusted<U> {
        Untrusted {
            value: f(self.value),
            label: self.label,
            sources: self.sources,
        }
    }

    /// Writes the value to memory; the label stays (SEC-21 (2)).
    #[must_use]
    pub fn into_memory(self) -> Self {
        self
    }
}

impl<T> fmt::Debug for Untrusted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Untrusted")
            .field("label", &self.label.kind().as_str())
            .field("value", &"[masked]")
            .finish_non_exhaustive()
    }
}

/// A value with any label, as it travels on the wire (`labelled-value/v1`).
#[derive(Clone, PartialEq, Eq)]
pub enum Labelled<T> {
    /// A trusted value.
    Trusted(Trusted<T>),
    /// An untrusted value.
    Untrusted(Untrusted<T>),
}

impl<T> Labelled<T> {
    /// The label.
    pub fn label(&self) -> Label {
        match self {
            Self::Trusted(v) => Label::Trusted(v.label),
            Self::Untrusted(v) => Label::Untrusted(v.label.clone()),
        }
    }

    /// The Access provenance of the label (SEC-14 table).
    pub fn access_provenance(&self) -> AccessProvenance {
        match self {
            Self::Trusted(v) => v.label.access_provenance(),
            Self::Untrusted(_) => AccessProvenance::UntrustedExternal,
        }
    }

    /// Borrows the value.
    pub const fn expose(&self) -> &T {
        match self {
            Self::Trusted(v) => &v.value,
            Self::Untrusted(v) => &v.value,
        }
    }

    /// Unwraps the value.
    pub fn into_value(self) -> T {
        match self {
            Self::Trusted(v) => v.value,
            Self::Untrusted(v) => v.value,
        }
    }

    /// Applies a label-preserving transform.
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> Labelled<U> {
        match self {
            Self::Trusted(v) => Labelled::Trusted(v.map(f)),
            Self::Untrusted(v) => Labelled::Untrusted(v.map(f)),
        }
    }

    /// A value derived from inputs with these labels; `None` without inputs (SEC-14 (1), T-36 (3)).
    pub fn derive<'a>(
        transform: Transform,
        inputs: impl IntoIterator<Item = &'a Label>,
        value: T,
    ) -> Option<Self> {
        Some(Self::from_label(value, transform.label(inputs)?))
    }

    pub(crate) fn from_label(value: T, label: Label) -> Self {
        match label {
            Label::Trusted(label) => Self::Trusted(Trusted::with_label(value, label)),
            Label::Untrusted(label) => Self::Untrusted(Untrusted::with_label(value, label)),
        }
    }

    fn with_sources(self, sources: Option<Sources>) -> Self {
        match self {
            Self::Trusted(v) => Self::Trusted(Trusted { sources, ..v }),
            Self::Untrusted(v) => Self::Untrusted(Untrusted { sources, ..v }),
        }
    }

    const fn wire_sources(&self) -> Option<&Sources> {
        match self {
            Self::Trusted(v) => v.sources.as_ref(),
            Self::Untrusted(v) => v.sources.as_ref(),
        }
    }
}

impl<T> From<Trusted<T>> for Labelled<T> {
    fn from(value: Trusted<T>) -> Self {
        Self::Trusted(value)
    }
}

impl<T> From<Untrusted<T>> for Labelled<T> {
    fn from(value: Untrusted<T>) -> Self {
        Self::Untrusted(value)
    }
}

impl<T> fmt::Debug for Labelled<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Trusted(v) => v.fmt(f),
            Self::Untrusted(v) => v.fmt(f),
        }
    }
}

impl<T: Serialize> Serialize for Labelled<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let label = self.label();
        let mixed: Option<Vec<Source>> = match (&label, self.wire_sources()) {
            (Label::Untrusted(UntrustedLabel::Mixed(m)), None) => {
                Some(m.as_slice().iter().copied().map(Source::External).collect())
            }
            _ => None,
        };
        let sources: Option<&[Source]> = self
            .wire_sources()
            .map(Sources::as_slice)
            .or(mixed.as_deref());
        let len = if sources.is_some() { 3 } else { 2 };
        let mut s = serializer.serialize_struct("Labelled", len)?;
        s.serialize_field("value", self.expose())?;
        s.serialize_field("label", &label.kind())?;
        if let Some(sources) = sources {
            s.serialize_field("sources", sources)?;
        }
        s.end()
    }
}

impl<T: Serialize> Serialize for Trusted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Labelled::Trusted(Trusted {
            value: &self.value,
            label: self.label,
            sources: self.sources.clone(),
        })
        .serialize(serializer)
    }
}

impl<T: Serialize> Serialize for Untrusted<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        Labelled::Untrusted(Untrusted {
            value: &self.value,
            label: self.label.clone(),
            sources: self.sources.clone(),
        })
        .serialize(serializer)
    }
}

/// The result of opening a wire value: the labelled value and whether the input conformed to `labelled-value/v1`; a non-conforming input is always `external.unknown` (SEC-14 (2), T-36 (4)).
#[derive(Clone, PartialEq, Eq)]
pub struct Opened<T> {
    labelled: Labelled<T>,
    conforms: bool,
}

impl<T> Opened<T> {
    /// The labelled value.
    pub const fn labelled(&self) -> &Labelled<T> {
        &self.labelled
    }

    /// Unwraps the labelled value.
    pub fn into_labelled(self) -> Labelled<T> {
        self.labelled
    }

    /// True when the input was a well-formed labelled value.
    pub const fn conforms(&self) -> bool {
        self.conforms
    }
}

impl<T> fmt::Debug for Opened<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Opened")
            .field("labelled", &self.labelled)
            .field("conforms", &self.conforms)
            .finish()
    }
}

struct Wrapper {
    value: Option<Content>,
    label: Option<Content>,
    sources: Option<Content>,
    extra: bool,
}

fn split(entries: Vec<(Content, Content)>) -> Wrapper {
    let mut w = Wrapper {
        value: None,
        label: None,
        sources: None,
        extra: false,
    };
    for (key, value) in entries {
        let slot = match key.as_str() {
            Some("value") => &mut w.value,
            Some("label") => &mut w.label,
            Some("sources") => &mut w.sources,
            _ => {
                w.extra = true;
                continue;
            }
        };
        if slot.replace(value).is_some() {
            w.extra = true;
        }
    }
    w
}

fn wire_label(
    label: Option<&Content>,
    sources: Option<&Content>,
) -> Option<(Label, Option<Sources>)> {
    let kind = LabelKind::parse(label?.as_str()?)?;
    let sources = match sources {
        None => None,
        Some(Content::Seq(items)) => {
            let parsed = items
                .iter()
                .map(|item| item.as_str().and_then(Source::parse))
                .collect::<Option<Vec<Source>>>()?;
            Some(Sources::new(parsed)?)
        }
        Some(_) => return None,
    };
    let label = Label::from_wire(kind, sources.as_ref().map(Sources::as_slice))?;
    Some((label, sources))
}

fn open_content<T: DeserializeOwned, E: serde::de::Error>(
    content: Content,
) -> Result<Opened<T>, E> {
    let entries = match content {
        Content::Map(entries) if entries.iter().any(|(k, _)| k.as_str() == Some("value")) => {
            entries
        }
        bare => {
            let value = T::deserialize(ContentDeserializer::<E>::new(bare))?;
            return Ok(Opened {
                labelled: Labelled::Untrusted(Untrusted::unknown(value)),
                conforms: false,
            });
        }
    };
    let w = split(entries);
    let Some(raw) = w.value else {
        return Err(E::custom("labelled value without a value"));
    };
    let null = matches!(raw, Content::Null);
    let value = T::deserialize(ContentDeserializer::<E>::new(raw))?;
    let parsed = if w.extra || null {
        None
    } else {
        wire_label(w.label.as_ref(), w.sources.as_ref())
    };
    Ok(match parsed {
        Some((label, sources)) => Opened {
            labelled: Labelled::from_label(value, label).with_sources(sources),
            conforms: true,
        },
        None => Opened {
            labelled: Labelled::Untrusted(Untrusted::unknown(value)),
            conforms: false,
        },
    })
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Opened<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let content = Content::deserialize(deserializer)?;
        open_content::<T, D::Error>(content)
    }
}

impl<'de, T: DeserializeOwned> Deserialize<'de> for Labelled<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Opened::<T>::deserialize(deserializer).map(Opened::into_labelled)
    }
}
