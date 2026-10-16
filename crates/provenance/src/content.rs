//! A buffered self-describing value, so opening can look at a wrapper's keys before the value type reads it (T-36 (4)).

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::marker::PhantomData;

use serde::de::value::{MapDeserializer, SeqDeserializer};
use serde::de::{self, Deserialize, Deserializer, IntoDeserializer, MapAccess, SeqAccess, Visitor};

pub(crate) enum Content {
    Null,
    Bool(bool),
    U64(u64),
    I64(i64),
    F64(f64),
    Str(String),
    Bytes(Vec<u8>),
    Seq(Vec<Content>),
    Map(Vec<(Content, Content)>),
    Some(Box<Content>),
}

impl Content {
    pub(crate) fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s),
            _ => None,
        }
    }
}

struct ContentVisitor;

impl<'de> Visitor<'de> for ContentVisitor {
    type Value = Content;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Content, E> {
        Ok(Content::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Content, E> {
        Ok(Content::I64(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Content, E> {
        Ok(Content::U64(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Content, E> {
        Ok(Content::F64(v))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Content, E> {
        Ok(Content::Str(String::from(v)))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Content, E> {
        Ok(Content::Str(v))
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<Content, E> {
        Ok(Content::Bytes(Vec::from(v)))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Content, E> {
        Ok(Content::Null)
    }

    fn visit_none<E: de::Error>(self) -> Result<Content, E> {
        Ok(Content::Null)
    }

    fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Content, D::Error> {
        Ok(Content::Some(Box::new(Content::deserialize(d)?)))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Content, A::Error> {
        let mut items = Vec::new();
        while let Some(item) = seq.next_element()? {
            items.push(item);
        }
        Ok(Content::Seq(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Content, A::Error> {
        let mut entries = Vec::new();
        while let Some(entry) = map.next_entry()? {
            entries.push(entry);
        }
        Ok(Content::Map(entries))
    }
}

impl<'de> Deserialize<'de> for Content {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_any(ContentVisitor)
    }
}

pub(crate) struct ContentDeserializer<E> {
    content: Content,
    error: PhantomData<E>,
}

impl<E> ContentDeserializer<E> {
    pub(crate) const fn new(content: Content) -> Self {
        Self {
            content,
            error: PhantomData,
        }
    }
}

impl<E: de::Error> IntoDeserializer<'_, E> for Content {
    type Deserializer = ContentDeserializer<E>;

    fn into_deserializer(self) -> Self::Deserializer {
        ContentDeserializer::new(self)
    }
}

impl<'de, E: de::Error> Deserializer<'de> for ContentDeserializer<E> {
    type Error = E;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, E> {
        match self.content {
            Content::Null => visitor.visit_unit(),
            Content::Bool(v) => visitor.visit_bool(v),
            Content::U64(v) => visitor.visit_u64(v),
            Content::I64(v) => visitor.visit_i64(v),
            Content::F64(v) => visitor.visit_f64(v),
            Content::Str(v) => visitor.visit_string(v),
            Content::Bytes(v) => visitor.visit_byte_buf(v),
            Content::Some(v) => visitor.visit_some(Self::new(*v)),
            Content::Seq(v) => {
                let mut seq = SeqDeserializer::new(v.into_iter());
                let value = visitor.visit_seq(&mut seq)?;
                seq.end()?;
                Ok(value)
            }
            Content::Map(v) => {
                let mut map = MapDeserializer::new(v.into_iter());
                let value = visitor.visit_map(&mut map)?;
                map.end()?;
                Ok(value)
            }
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, E> {
        match self.content {
            Content::Null => visitor.visit_none(),
            Content::Some(v) => visitor.visit_some(Self::new(*v)),
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
        match self.content {
            Content::Str(v) => visitor.visit_enum(v.into_deserializer()),
            Content::Map(mut v) if v.len() == 1 => match v.pop() {
                Some((key, value)) => visitor.visit_enum(EnumAccess {
                    key,
                    value,
                    error: PhantomData,
                }),
                None => Err(E::custom("empty enum map")),
            },
            _ => Err(E::custom("expected an enum")),
        }
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf unit unit_struct seq tuple tuple_struct map struct
        identifier ignored_any
    }
}

struct EnumAccess<E> {
    key: Content,
    value: Content,
    error: PhantomData<E>,
}

impl<'de, E: de::Error> de::EnumAccess<'de> for EnumAccess<E> {
    type Error = E;
    type Variant = VariantAccess<E>;

    fn variant_seed<S: de::DeserializeSeed<'de>>(
        self,
        seed: S,
    ) -> Result<(S::Value, Self::Variant), E> {
        let variant = seed.deserialize(ContentDeserializer::<E>::new(self.key))?;
        Ok((
            variant,
            VariantAccess {
                value: self.value,
                error: PhantomData,
            },
        ))
    }
}

struct VariantAccess<E> {
    value: Content,
    error: PhantomData<E>,
}

impl<'de, E: de::Error> de::VariantAccess<'de> for VariantAccess<E> {
    type Error = E;

    fn unit_variant(self) -> Result<(), E> {
        de::IgnoredAny::deserialize(ContentDeserializer::<E>::new(self.value)).map(|_| ())
    }

    fn newtype_variant_seed<S: de::DeserializeSeed<'de>>(self, seed: S) -> Result<S::Value, E> {
        seed.deserialize(ContentDeserializer::new(self.value))
    }

    fn tuple_variant<V: Visitor<'de>>(self, _len: usize, visitor: V) -> Result<V::Value, E> {
        ContentDeserializer::<E>::new(self.value).deserialize_any(visitor)
    }

    fn struct_variant<V: Visitor<'de>>(
        self,
        _fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, E> {
        ContentDeserializer::<E>::new(self.value).deserialize_any(visitor)
    }
}
