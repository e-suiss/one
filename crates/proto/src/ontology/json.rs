//! An owned JSON value for the open parts of a contract: extension values, Access projection items and fields a reader keeps without interpreting (C-7, M-40).

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use serde::de::value::{MapAccessDeserializer, MapDeserializer, SeqDeserializer};
use serde::de::{self, IntoDeserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// A JSON object with its keys sorted.
pub type JsonObject = BTreeMap<String, JsonValue>;

/// Any JSON value; object keys are kept sorted.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    /// `null`.
    Null,
    /// `true` or `false`.
    Bool(bool),
    /// A non-negative integer.
    Unsigned(u64),
    /// A negative integer.
    Signed(i64),
    /// A number with a fraction or exponent.
    Float(f64),
    /// A string.
    String(String),
    /// An array.
    Array(Vec<JsonValue>),
    /// An object.
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    /// The string, when this is one.
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(s) => Some(s),
            _ => None,
        }
    }

    /// The object, when this is one.
    #[must_use]
    pub const fn as_object(&self) -> Option<&JsonObject> {
        match self {
            Self::Object(o) => Some(o),
            _ => None,
        }
    }
}

impl Serialize for JsonValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Null => serializer.serialize_unit(),
            Self::Bool(b) => serializer.serialize_bool(*b),
            Self::Unsigned(n) => serializer.serialize_u64(*n),
            Self::Signed(n) => serializer.serialize_i64(*n),
            Self::Float(n) => serializer.serialize_f64(*n),
            Self::String(s) => serializer.serialize_str(s),
            Self::Array(items) => serializer.collect_seq(items),
            Self::Object(map) => {
                let mut out = serializer.serialize_map(Some(map.len()))?;
                for (k, v) in map {
                    out.serialize_entry(k, v)?;
                }
                out.end()
            }
        }
    }
}

struct ValueVisitor;

impl<'de> Visitor<'de> for ValueVisitor {
    type Value = JsonValue;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_unit<E>(self) -> Result<JsonValue, E> {
        Ok(JsonValue::Null)
    }

    fn visit_none<E>(self) -> Result<JsonValue, E> {
        Ok(JsonValue::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<JsonValue, D::Error> {
        JsonValue::deserialize(d)
    }

    fn visit_bool<E>(self, v: bool) -> Result<JsonValue, E> {
        Ok(JsonValue::Bool(v))
    }

    fn visit_u64<E>(self, v: u64) -> Result<JsonValue, E> {
        Ok(JsonValue::Unsigned(v))
    }

    fn visit_i64<E>(self, v: i64) -> Result<JsonValue, E> {
        Ok(u64::try_from(v).map_or(JsonValue::Signed(v), JsonValue::Unsigned))
    }

    fn visit_f64<E>(self, v: f64) -> Result<JsonValue, E> {
        Ok(JsonValue::Float(v))
    }

    fn visit_str<E>(self, v: &str) -> Result<JsonValue, E> {
        Ok(JsonValue::String(String::from(v)))
    }

    fn visit_string<E>(self, v: String) -> Result<JsonValue, E> {
        Ok(JsonValue::String(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<JsonValue, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(JsonValue::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<JsonValue, A::Error> {
        let mut out = BTreeMap::new();
        while let Some((k, v)) = map.next_entry::<String, JsonValue>()? {
            out.insert(k, v);
        }
        Ok(JsonValue::Object(out))
    }
}

impl<'de> Deserialize<'de> for JsonValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ValueVisitor)
    }
}

/// Reads a typed value back out of a [`JsonValue`].
#[derive(Debug)]
pub struct JsonDeserializer<E> {
    value: JsonValue,
    error: PhantomData<E>,
}

impl<E> JsonDeserializer<E> {
    /// A deserializer over `value`.
    #[must_use]
    pub const fn new(value: JsonValue) -> Self {
        Self {
            value,
            error: PhantomData,
        }
    }
}

impl<E: de::Error> IntoDeserializer<'_, E> for JsonValue {
    type Deserializer = JsonDeserializer<E>;

    fn into_deserializer(self) -> JsonDeserializer<E> {
        JsonDeserializer::new(self)
    }
}

impl<'de, E: de::Error> Deserializer<'de> for JsonDeserializer<E> {
    type Error = E;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, E> {
        match self.value {
            JsonValue::Null => visitor.visit_unit(),
            JsonValue::Bool(b) => visitor.visit_bool(b),
            JsonValue::Unsigned(n) => visitor.visit_u64(n),
            JsonValue::Signed(n) => visitor.visit_i64(n),
            JsonValue::Float(n) => visitor.visit_f64(n),
            JsonValue::String(s) => visitor.visit_string(s),
            JsonValue::Array(items) => {
                let mut seq = SeqDeserializer::new(items.into_iter());
                let out = visitor.visit_seq(&mut seq)?;
                seq.end()?;
                Ok(out)
            }
            JsonValue::Object(map) => {
                let mut access = MapDeserializer::new(map.into_iter());
                let out = visitor.visit_map(&mut access)?;
                access.end()?;
                Ok(out)
            }
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, E> {
        match self.value {
            JsonValue::Null => visitor.visit_none(),
            other => visitor.visit_some(Self::new(other)),
        }
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, E> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, E> {
        match self.value {
            JsonValue::String(s) => visitor.visit_enum(s.into_deserializer()),
            JsonValue::Object(map) => visitor.visit_enum(MapAccessDeserializer::new(
                MapDeserializer::new(map.into_iter()),
            )),
            _ => Err(E::custom("expected an enum")),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}
