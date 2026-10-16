//! Capability names under the reverse-DNS root `app.suiss`, third-party names under their publisher's reverse DNS, dated versions and `extends` (CP-15, OO-9).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::is_dated_version;
use crate::ontology::validate::unique;

/// The Suiss reverse-DNS root.
pub const ROOT: &str = "app.suiss";

/// The longest capability name.
pub const MAX_NAME_LENGTH: usize = 128;

/// First segments that never follow `app.suiss`; `one` is the reverse form of the handle subdomain.
pub const RESERVED_SEGMENTS: &[&str] = &[
    "one", "access", "relay", "work", "pay", "suiss", "www", "api",
];

/// Why a name does not parse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameError {
    /// An upper-case letter appears.
    NotLowercase,
    /// Longer than [`MAX_NAME_LENGTH`].
    TooLong,
    /// A third-party name without a valid top-level label or without two labels below it.
    BadRoot,
    /// A segment breaks the segment grammar.
    BadSegment,
    /// Fewer than two semantic segments under `app.suiss`.
    TooFewSegments,
    /// More than five semantic segments under `app.suiss`, or more than nine labels below a third-party top level.
    TooManySegments,
    /// A product or host label as the first segment.
    ReservedSegment,
    /// `app.suiss.one.*`, the reverse form of a handle.
    HandleNamespace,
}

impl NameError {
    /// Every error in `naming.toml` order.
    pub const ALL: [Self; 8] = [
        Self::NotLowercase,
        Self::TooLong,
        Self::BadRoot,
        Self::BadSegment,
        Self::TooFewSegments,
        Self::TooManySegments,
        Self::ReservedSegment,
        Self::HandleNamespace,
    ];

    /// The contract code.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::NotLowercase => "not_lowercase",
            Self::TooLong => "too_long",
            Self::BadRoot => "bad_root",
            Self::BadSegment => "bad_segment",
            Self::TooFewSegments => "too_few_segments",
            Self::TooManySegments => "too_many_segments",
            Self::ReservedSegment => "reserved_segment",
            Self::HandleNamespace => "handle_namespace",
        }
    }
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}

/// Which namespace a name lives in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum NameKind {
    /// Under `app.suiss`.
    Suiss,
    /// Under a third party's reverse DNS.
    ThirdParty,
}

/// A parsed capability name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CapabilityName(String);

fn is_suiss_segment(segment: &str) -> bool {
    let mut bytes = segment.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && segment.len() <= 32
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (1..=63).contains(&bytes.len())
        && edge(bytes.first())
        && edge(bytes.last())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn is_tld(label: &str) -> bool {
    (2..=63).contains(&label.len()) && label.bytes().all(|b| b.is_ascii_lowercase())
}

impl CapabilityName {
    /// Parses a name by the `naming.toml` grammar.
    ///
    /// # Errors
    /// Returns the first rule the name breaks.
    pub fn parse(text: &str) -> Result<Self, NameError> {
        if text.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(NameError::NotLowercase);
        }
        if text.len() > MAX_NAME_LENGTH {
            return Err(NameError::TooLong);
        }
        if text == ROOT {
            return Err(NameError::TooFewSegments);
        }
        if let Some(rest) = text.strip_prefix("app.suiss.") {
            let segments: Vec<&str> = rest.split('.').collect();
            if !segments.iter().all(|s| is_suiss_segment(s)) {
                return Err(NameError::BadSegment);
            }
            match segments.first().copied() {
                Some("one") => return Err(NameError::HandleNamespace),
                Some(first) if RESERVED_SEGMENTS.contains(&first) => {
                    return Err(NameError::ReservedSegment);
                }
                _ => {}
            }
            return match segments.len() {
                0 | 1 => Err(NameError::TooFewSegments),
                2..=5 => Ok(Self(String::from(text))),
                _ => Err(NameError::TooManySegments),
            };
        }
        let mut labels = text.split('.');
        if !labels.next().is_some_and(is_tld) {
            return Err(NameError::BadRoot);
        }
        let rest: Vec<&str> = labels.collect();
        if !rest.iter().all(|l| is_label(l)) {
            return Err(NameError::BadSegment);
        }
        match rest.len() {
            0 | 1 => Err(NameError::BadRoot),
            2..=9 => Ok(Self(String::from(text))),
            _ => Err(NameError::TooManySegments),
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The namespace.
    #[must_use]
    pub fn kind(&self) -> NameKind {
        if self.0.starts_with("app.suiss.") {
            NameKind::Suiss
        } else {
            NameKind::ThirdParty
        }
    }

    /// The semantic segments: below `app.suiss` for a Suiss name, every label for a third-party name.
    pub fn segments(&self) -> impl Iterator<Item = &str> {
        self.0
            .strip_prefix("app.suiss.")
            .unwrap_or(&self.0)
            .split('.')
    }

    /// The category segment of a Suiss name.
    #[must_use]
    pub fn category(&self) -> Option<&str> {
        match self.kind() {
            NameKind::Suiss => self.segments().next(),
            NameKind::ThirdParty => None,
        }
    }
}

impl fmt::Display for CapabilityName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for CapabilityName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for CapabilityName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let text = String::deserialize(d)?;
        Self::parse(&text).map_err(de::Error::custom)
    }
}

/// A capability name that must be a third-party name.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "CapabilityName", into = "CapabilityName")]
pub struct ThirdPartyName(CapabilityName);

impl ThirdPartyName {
    /// The name.
    #[must_use]
    pub const fn name(&self) -> &CapabilityName {
        &self.0
    }
}

impl TryFrom<CapabilityName> for ThirdPartyName {
    type Error = ContractViolation;

    fn try_from(name: CapabilityName) -> Result<Self, ContractViolation> {
        if name.kind() == NameKind::ThirdParty {
            Ok(Self(name))
        } else {
            Err(ContractViolation("third-party name"))
        }
    }
}

impl From<ThirdPartyName> for CapabilityName {
    fn from(value: ThirdPartyName) -> Self {
        value.0
    }
}

/// A dated capability version `YYYY-MM-DD`; lexicographic order is chronological order.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CapabilityVersion(String);

impl CapabilityVersion {
    /// Parses a dated version.
    ///
    /// # Errors
    /// Rejects any other form, an unpadded field, a month outside 01–12 or a day outside 01–31.
    pub fn parse(text: &str) -> Result<Self, ContractViolation> {
        is_dated_version(text)
            .then(|| Self(String::from(text)))
            .ok_or(ContractViolation("dated version"))
    }

    /// The version.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CapabilityVersion {
    type Error = ContractViolation;

    fn try_from(text: String) -> Result<Self, ContractViolation> {
        Self::parse(&text)
    }
}

impl From<CapabilityVersion> for String {
    fn from(value: CapabilityVersion) -> Self {
        value.0
    }
}

/// The parents a name extends: one name, or two or more distinct names.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Extends(Vec<CapabilityName>);

impl Extends {
    /// One parent.
    #[must_use]
    pub fn one(parent: CapabilityName) -> Self {
        Self(alloc::vec![parent])
    }

    /// Several distinct parents.
    ///
    /// # Errors
    /// Rejects fewer than two or repeated parents.
    pub fn many(parents: Vec<CapabilityName>) -> Result<Self, ContractViolation> {
        if parents.len() >= 2 && unique(&parents) {
            Ok(Self(parents))
        } else {
            Err(ContractViolation(
                "extends needs two or more distinct names",
            ))
        }
    }

    /// The parents in declaration order.
    #[must_use]
    pub fn parents(&self) -> &[CapabilityName] {
        &self.0
    }

    /// Whether both declare the same set of parents.
    #[must_use]
    pub fn same_set(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.0.iter().all(|p| other.0.contains(p))
    }
}

impl Serialize for Extends {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self.0.as_slice() {
            [single] => single.serialize(s),
            many => many.serialize(s),
        }
    }
}

impl<'de> Deserialize<'de> for Extends {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ExtendsVisitor;

        impl<'de> de::Visitor<'de> for ExtendsVisitor {
            type Value = Extends;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a capability name or an array of two or more")
            }

            fn visit_str<E: de::Error>(self, v: &str) -> Result<Extends, E> {
                CapabilityName::parse(v)
                    .map(Extends::one)
                    .map_err(E::custom)
            }

            fn visit_seq<A: de::SeqAccess<'de>>(self, mut seq: A) -> Result<Extends, A::Error> {
                let mut parents = Vec::new();
                while let Some(p) = seq.next_element::<CapabilityName>()? {
                    parents.push(p);
                }
                Extends::many(parents).map_err(de::Error::custom)
            }
        }

        d.deserialize_any(ExtendsVisitor)
    }
}

/// A capability by name and dated version.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapabilityRef {
    /// The name.
    pub name: CapabilityName,
    /// The dated version.
    pub version: CapabilityVersion,
}
