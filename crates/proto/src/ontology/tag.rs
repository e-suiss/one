//! Single-value wire tags: a field such as `type`, `ref`, `status` or `authority` that a record type always carries with one fixed value (C-19, C-14).

use core::fmt;

use serde::Deserializer;
use serde::de::Visitor;

struct Expect(&'static str);

impl Visitor<'_> for Expect {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the string {:?}", self.0)
    }

    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<(), E> {
        if v == self.0 {
            Ok(())
        } else {
            Err(E::custom(format_args!(
                "expected {:?}, found {v:?}",
                self.0
            )))
        }
    }
}

/// Reads a string and accepts only `value`.
///
/// # Errors
/// Rejects any other value.
pub fn expect<'de, D: Deserializer<'de>>(
    deserializer: D,
    value: &'static str,
) -> Result<(), D::Error> {
    deserializer.deserialize_str(Expect(value))
}

/// Declares a unit type that is written and read only as one string.
#[macro_export]
macro_rules! const_tag {
    ($(#[$meta:meta])* $name:ident, $value:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
        pub struct $name;

        impl $name {
            /// The only wire value.
            pub const VALUE: &'static str = $value;
        }

        impl serde::Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str($value)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                $crate::ontology::tag::expect(deserializer, $value).map(|()| $name)
            }
        }
    };
}
