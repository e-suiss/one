//! Contract checks the serde shape alone cannot express: conditional fields, name grammars and fields a strict canonical reader refuses, while the lenient M-40 reader keeps decoding them (C-7, C-19, M-6, M-40).

use alloc::collections::BTreeMap;
use alloc::string::String;
use core::fmt;

use super::json::JsonValue;

/// A broken contract rule, named by the field or condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ContractViolation(pub &'static str);

impl fmt::Display for ContractViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// Fields a reader did not know; never re-encoded.
pub type UnknownFields = BTreeMap<String, JsonValue>;

/// Declares a string newtype checked by `$check` on the way in.
macro_rules! checked_string {
    ($(#[$meta:meta])* $name:ident, $what:literal, $check:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "alloc::string::String", into = "alloc::string::String")]
        pub struct $name(alloc::string::String);

        impl $name {
            /// Checks and wraps the text.
            ///
            /// # Errors
            /// Rejects text outside the contract's pattern.
            pub fn parse(text: &str) -> Result<Self, $crate::ontology::validate::ContractViolation> {
                Self::try_from(alloc::string::String::from(text))
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<alloc::string::String> for $name {
            type Error = $crate::ontology::validate::ContractViolation;

            fn try_from(text: alloc::string::String) -> Result<Self, Self::Error> {
                let check: fn(&str) -> bool = $check;
                if check(&text) {
                    Ok(Self(text))
                } else {
                    Err($crate::ontology::validate::ContractViolation($what))
                }
            }
        }

        impl From<$name> for alloc::string::String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

pub(crate) use checked_string;

/// Fails with `code` unless `ok`.
///
/// # Errors
/// [`ContractViolation`] with `code`.
pub const fn require(ok: bool, code: &'static str) -> Result<(), ContractViolation> {
    if ok {
        Ok(())
    } else {
        Err(ContractViolation(code))
    }
}

/// A canonical record has no field outside its schema.
///
/// # Errors
/// [`ContractViolation`] `unknown_field`.
pub fn no_unknown(unknown: &UnknownFields) -> Result<(), ContractViolation> {
    require(unknown.is_empty(), "unknown_field")
}

/// Distinct items.
#[must_use]
pub fn unique<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .all(|(i, a)| items.iter().skip(i.saturating_add(1)).all(|b| a != b))
}

fn segment_ok(seg: &str, extra: impl Fn(u8) -> bool) -> bool {
    let mut bytes = seg.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || extra(b))
}

fn under<'a>(name: &'a str, root: &str) -> Option<core::str::Split<'a, char>> {
    let rest = name.strip_prefix(root)?.strip_prefix('.')?;
    Some(rest.split('.'))
}

/// `app.suiss(.[a-z][a-z0-9]*(_[a-z0-9]+)*)+`, at most 128 characters, outside the `one`, `access`, `relay`, `work` and `pay` roots (C-7).
#[must_use]
pub fn is_suiss_extension_name(name: &str) -> bool {
    let Some(mut segs) = under(name, "app.suiss") else {
        return false;
    };
    let grammar = segs.all(|s| {
        segment_ok(s, |b| b == b'_')
            && !s.contains("__")
            && !s.ends_with('_')
            && !s.split('_').skip(1).any(str::is_empty)
    });
    let first = name.split('.').nth(2).unwrap_or_default();
    name.len() <= 128 && grammar && !matches!(first, "one" | "access" | "relay" | "work" | "pay")
}

/// `app.suiss.memory(.[a-z][a-z0-9_]*)+`, or under `app.suiss.memory.predicate` for a predicate (C-7, M-10).
#[must_use]
pub fn is_memory_extension_name(name: &str, predicate: bool) -> bool {
    let root = if predicate {
        "app.suiss.memory.predicate"
    } else {
        "app.suiss.memory"
    };
    under(name, root).is_some_and(|mut segs| segs.all(|s| segment_ok(s, |b| b == b'_')))
}

/// `app.suiss.[a-z][a-z0-9]*(.[a-z][a-z0-9_]*)+`, at most 128 characters, outside `app.suiss.one` (C-7).
#[must_use]
pub fn is_interaction_extension_name(name: &str) -> bool {
    let Some(segs) = under(name, "app.suiss") else {
        return false;
    };
    let segs: alloc::vec::Vec<&str> = segs.collect();
    let head_ok = segs.first().is_some_and(|s| segment_ok(s, |_| false));
    let tail_ok = segs.len() >= 2 && segs.iter().skip(1).all(|s| segment_ok(s, |b| b == b'_'));
    name.len() <= 128 && head_ok && tail_ok && segs.first() != Some(&"one")
}

/// A capability name: `app.suiss` with 2 to 5 segments outside the reserved roots, or a third-party reverse-DNS name outside `app.suiss` (CP-15).
#[must_use]
pub fn is_capability_name(name: &str) -> bool {
    if name.len() > 128 {
        return false;
    }
    if let Some(segs) = under(name, "app.suiss") {
        let segs: alloc::vec::Vec<&str> = segs.collect();
        let reserved = matches!(
            segs.first().copied().unwrap_or_default(),
            "one" | "access" | "relay" | "work" | "pay" | "suiss" | "www" | "api"
        );
        return (2..=5).contains(&segs.len())
            && segs
                .iter()
                .all(|s| s.len() <= 32 && segment_ok(s, |_| false))
            && !reserved;
    }
    if name == "app.suiss" {
        return false;
    }
    let mut parts = name.split('.');
    let head = parts.next().unwrap_or_default();
    let rest: alloc::vec::Vec<&str> = parts.collect();
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
        (1..=63).contains(&b.len())
            && b.first().is_some_and(edge)
            && b.last().is_some_and(edge)
            && b.iter().all(|c| edge(c) || *c == b'_' || *c == b'-')
    };
    (2..=63).contains(&head.len())
        && head.bytes().all(|b| b.is_ascii_lowercase())
        && (2..=9).contains(&rest.len())
        && rest.iter().all(|l| label_ok(l))
}

/// A dated version `YYYY-MM-DD` (CP-15).
#[must_use]
pub fn is_dated_version(text: &str) -> bool {
    let b = text.as_bytes();
    let digits =
        |r: core::ops::Range<usize>| b.get(r).is_some_and(|s| s.iter().all(u8::is_ascii_digit));
    let month = text.get(5..7).unwrap_or_default();
    let day = text.get(8..10).unwrap_or_default();
    b.len() == 10
        && digits(0..4)
        && b.get(4) == Some(&b'-')
        && b.get(7) == Some(&b'-')
        && digits(5..7)
        && digits(8..10)
        && ("01"..="12").contains(&month)
        && ("01"..="31").contains(&day)
}
