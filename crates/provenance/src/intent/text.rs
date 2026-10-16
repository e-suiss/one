//! Checked text newtypes, wire constants and bounded collections shared by the intent contracts; content-bearing text never shows in `Debug` (T-28 (7), T-31).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

macro_rules! checked_text {
    (@debug masked $name:ident) => {
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(concat!(stringify!($name), "([masked])"))
            }
        }
    };
    (@debug plain $name:ident) => {
        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }
    };
    ($(#[$meta:meta])* $debug:ident $name:ident, $what:literal, $check:path) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(try_from = "alloc::string::String", into = "alloc::string::String")]
        pub struct $name(alloc::string::String);

        impl $name {
            /// Checks and wraps the text; `None` outside the contract.
            #[must_use]
            pub fn new(text: &str) -> Option<Self> {
                $check(text).then(|| Self(alloc::string::String::from(text)))
            }

            /// The text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<alloc::string::String> for $name {
            type Error = one_proto::ontology::validate::ContractViolation;

            fn try_from(text: alloc::string::String) -> Result<Self, Self::Error> {
                if $check(&text) {
                    Ok(Self(text))
                } else {
                    Err(one_proto::ontology::validate::ContractViolation($what))
                }
            }
        }

        impl From<$name> for alloc::string::String {
            fn from(value: $name) -> Self {
                value.0
            }
        }

        $crate::intent::text::checked_text!(@debug $debug $name);
    };
}

pub(crate) use checked_text;

macro_rules! wire_const {
    ($(#[$meta:meta])* $name:ident = $wire:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
        pub struct $name;

        impl $name {
            /// The wire string.
            pub const WIRE: &'static str = $wire;
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($wire)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = alloc::string::String::deserialize(deserializer)?;
                if text == $wire {
                    Ok(Self)
                } else {
                    Err(<D::Error as serde::de::Error>::custom(concat!("expected ", $wire)))
                }
            }
        }
    };
}

pub(crate) use wire_const;

pub(crate) fn chars_within(text: &str, min: usize, max: usize) -> bool {
    let count = text.chars().count();
    (min..=max).contains(&count)
}

pub(crate) fn is_snake_name(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && text.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub(crate) const fn is_ecma_space(c: char) -> bool {
    matches!(
        c,
        '\u{9}' | '\u{a}' | '\u{b}' | '\u{c}' | '\u{d}' | ' ' | '\u{a0}' | '\u{1680}' | '\u{2000}'
            ..='\u{200a}'
                | '\u{2028}'
                | '\u{2029}'
                | '\u{202f}'
                | '\u{205f}'
                | '\u{3000}'
                | '\u{feff}'
    )
}

pub(crate) fn is_uri_text(text: &str) -> bool {
    text.bytes().all(|b| {
        b.is_ascii_graphic()
            && !matches!(
                b,
                b'"' | b'<' | b'>' | b'\\' | b'^' | b'`' | b'{' | b'|' | b'}'
            )
    })
}

pub(crate) fn is_https_uri(text: &str) -> bool {
    text.len() <= 2048
        && is_uri_text(text)
        && text
            .strip_prefix("https://")
            .is_some_and(|rest| rest.bytes().next().is_some_and(|b| b != b'/'))
}

pub(crate) fn has_unique<T: PartialEq>(items: &[T]) -> bool {
    items
        .iter()
        .enumerate()
        .all(|(i, a)| !items.iter().skip(i.saturating_add(1)).any(|b| a == b))
}

pub(crate) fn at_most<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    let items = Vec::<T>::deserialize(deserializer)?;
    if items.len() <= N {
        Ok(items)
    } else {
        Err(D::Error::custom("too many items"))
    }
}

pub(crate) fn unique_at_most<'de, D, T, const N: usize>(deserializer: D) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + PartialEq,
{
    let items = at_most::<D, T, N>(deserializer)?;
    if has_unique(&items) {
        Ok(items)
    } else {
        Err(D::Error::custom("repeated item"))
    }
}

pub(crate) fn map_at_most<'de, D, K, V, const N: usize>(
    deserializer: D,
) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    let map = BTreeMap::<K, V>::deserialize(deserializer)?;
    if map.len() <= N {
        Ok(map)
    } else {
        Err(D::Error::custom("too many entries"))
    }
}

pub(crate) fn decode<T: serde::de::DeserializeOwned>(
    value: one_proto::ontology::JsonValue,
) -> Result<T, serde::de::value::Error> {
    T::deserialize(one_proto::ontology::json::JsonDeserializer::<
        serde::de::value::Error,
    >::new(value))
}

checked_text!(
    /// A snake-case field name, `^[a-z][a-z0-9_]{0,63}$`.
    plain FieldName,
    "field name",
    is_snake_name
);
