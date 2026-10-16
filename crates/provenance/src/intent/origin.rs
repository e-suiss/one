//! The per-task read and write origin set: `https` origins only, lower-case host, no path or query, at most 64 per list, compared as sets (SEC-19, Access E54 (4)).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use super::text::{checked_text, has_unique};

/// The most origins one list holds.
pub const MAX_ORIGINS: usize = 64;

fn is_label(label: &str) -> bool {
    let bytes = label.as_bytes();
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    (1..=63).contains(&bytes.len())
        && edge(bytes.first())
        && edge(bytes.last())
        && bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn is_port(port: &str) -> bool {
    (1..=5).contains(&port.len())
        && !port.starts_with('0')
        && port.bytes().all(|b| b.is_ascii_digit())
}

fn is_origin(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("https://") else {
        return false;
    };
    let host = match rest.split_once(':') {
        Some((host, port)) if is_port(port) => host,
        Some(_) => return false,
        None => rest,
    };
    text.len() <= 262 && host.split('.').count() >= 2 && host.split('.').all(is_label)
}

checked_text!(
    /// An `https` origin: scheme, lower-case host of two or more labels and an optional port, nothing else.
    plain Origin,
    "https origin",
    is_origin
);

impl Origin {
    /// The canonical origin of a written one: scheme and host lower-cased, a trailing `/` and the default port `:443` dropped; `None` for any other scheme, a path, a query, a fragment or user information.
    #[must_use]
    pub fn normalise(text: &str) -> Option<Self> {
        if !text.is_ascii() {
            return None;
        }
        let lower = text.to_ascii_lowercase();
        let rest = lower.strip_prefix("https://")?;
        let rest = rest.strip_suffix('/').unwrap_or(rest);
        let rest = rest.strip_suffix(":443").unwrap_or(rest);
        let mut canonical = String::from("https://");
        canonical.push_str(rest);
        Self::new(&canonical)
    }
}

/// One list of origins: unique, at most [`MAX_ORIGINS`], equal to another list with the same members in any order.
#[derive(Clone, Default, Serialize)]
#[serde(transparent)]
pub struct Origins(Vec<Origin>);

impl Origins {
    /// Checks and wraps a list; `None` when it repeats an origin or holds more than [`MAX_ORIGINS`].
    #[must_use]
    pub fn new(origins: Vec<Origin>) -> Option<Self> {
        (origins.len() <= MAX_ORIGINS && has_unique(&origins)).then_some(Self(origins))
    }

    /// The origins in wire order.
    #[must_use]
    pub fn as_slice(&self) -> &[Origin] {
        &self.0
    }

    /// Whether the list holds the origin.
    #[must_use]
    pub fn contains(&self, origin: &Origin) -> bool {
        self.0.contains(origin)
    }
}

impl PartialEq for Origins {
    fn eq(&self, other: &Self) -> bool {
        self.0.len() == other.0.len() && self.0.iter().all(|o| other.0.contains(o))
    }
}

impl Eq for Origins {}

impl fmt::Debug for Origins {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.0.iter()).finish()
    }
}

impl<'de> Deserialize<'de> for Origins {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let list = Vec::<Origin>::deserialize(deserializer)?;
        Self::new(list).ok_or_else(|| D::Error::custom("repeated origin or more than 64"))
    }
}

/// The origins a task may read from and write to (`origin-set/v1`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OriginSet {
    /// Origins the task may read.
    pub read: Origins,
    /// Origins the task may write to.
    pub write: Origins,
}
