//! The mapping from the internal labels to the three-valued Access `provenance` and the per-parameter map sent with an intent (SEC-14, T-36 (5), Access E54 (1)).

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::label::{Label, LabelKind, TrustedLabel};

/// The Access `IntentEnvelope` provenance value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AccessProvenance {
    /// `user`.
    #[serde(rename = "user")]
    User,
    /// `trusted`.
    #[serde(rename = "trusted")]
    Trusted,
    /// `untrusted-external`.
    #[serde(rename = "untrusted-external")]
    UntrustedExternal,
}

impl AccessProvenance {
    /// The wire form.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Trusted => "trusted",
            Self::UntrustedExternal => "untrusted-external",
        }
    }
}

impl TrustedLabel {
    /// The Access provenance of this label (SEC-14 table).
    #[must_use]
    pub const fn access_provenance(self) -> AccessProvenance {
        match self {
            Self::UserDirect | Self::UserMemory => AccessProvenance::User,
            Self::RecordTrusted => AccessProvenance::Trusted,
        }
    }
}

impl LabelKind {
    /// The Access provenance of this label (SEC-14 table); every untrusted label is `untrusted-external`.
    #[must_use]
    pub const fn access_provenance(self) -> AccessProvenance {
        match self {
            Self::Trusted(label) => label.access_provenance(),
            Self::OneInferred | Self::External(_) | Self::Mixed => {
                AccessProvenance::UntrustedExternal
            }
        }
    }
}

impl Label {
    /// The Access provenance of this label (SEC-14 table).
    #[must_use]
    pub const fn access_provenance(&self) -> AccessProvenance {
        self.kind().access_provenance()
    }
}

/// A label paired with its Access provenance; deserialising rejects a pair the table does not allow (`access-mapping/v1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub struct AccessMapping {
    label: LabelKind,
    provenance: AccessProvenance,
}

impl AccessMapping {
    /// The pair for a label string.
    #[must_use]
    pub const fn of(label: LabelKind) -> Self {
        Self {
            label,
            provenance: label.access_provenance(),
        }
    }

    /// The label.
    #[must_use]
    pub const fn label(self) -> LabelKind {
        self.label
    }

    /// The Access provenance.
    #[must_use]
    pub const fn provenance(self) -> AccessProvenance {
        self.provenance
    }
}

impl From<&Label> for AccessMapping {
    fn from(label: &Label) -> Self {
        Self::of(label.kind())
    }
}

impl<'de> Deserialize<'de> for AccessMapping {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            label: LabelKind,
            provenance: AccessProvenance,
        }
        let wire = Wire::deserialize(deserializer)?;
        if wire.label.access_provenance() == wire.provenance {
            Ok(Self::of(wire.label))
        } else {
            Err(D::Error::custom(
                "provenance does not match the label (T-36 (5))",
            ))
        }
    }
}

/// A parameter name of an intent: `^[a-z][a-z0-9_]{0,63}$`.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ParameterName(String);

impl ParameterName {
    /// Checks and wraps a name; `None` if it is not snake case of at most 64 characters.
    #[must_use]
    pub fn new(name: &str) -> Option<Self> {
        let mut bytes = name.bytes();
        let first_ok = bytes.next().is_some_and(|b| b.is_ascii_lowercase());
        let rest_ok = bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
        (first_ok && rest_ok && name.len() <= 64).then(|| Self(String::from(name)))
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for ParameterName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for ParameterName {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ParameterName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(&text).ok_or_else(|| D::Error::custom("parameter names are snake case"))
    }
}

/// The per-parameter Access provenance of one intent (`access-parameter-provenance/v1`, SEC-14 (4)).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ParameterProvenance(BTreeMap<ParameterName, AccessProvenance>);

impl ParameterProvenance {
    /// An empty map.
    #[must_use]
    pub const fn new() -> Self {
        Self(BTreeMap::new())
    }

    /// Maps each parameter's label to its Access provenance.
    #[must_use]
    pub fn from_labels<'a>(params: impl IntoIterator<Item = (ParameterName, &'a Label)>) -> Self {
        Self(
            params
                .into_iter()
                .map(|(name, label)| (name, label.access_provenance()))
                .collect(),
        )
    }

    /// Records one parameter's label.
    pub fn insert(&mut self, name: ParameterName, label: &Label) {
        self.0.insert(name, label.access_provenance());
    }

    /// The Access provenance of a parameter.
    #[must_use]
    pub fn get(&self, name: &ParameterName) -> Option<AccessProvenance> {
        self.0.get(name).copied()
    }

    /// The number of parameters.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// True when the intent has no parameters.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
