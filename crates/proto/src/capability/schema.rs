//! Embedded input and output schemas: closed JSON Schema 2020-12 objects without password, token, secret, cookie or card fields, or a reference to a Suiss schema (CP-5, CP-16, CP-23).

use serde::{Deserialize, Serialize};

use crate::ontology::JsonObject;
use crate::ontology::JsonValue;
use crate::ontology::validate::ContractViolation;

/// Name fragments a field name may not carry, matched between `_` boundaries.
pub const FORBIDDEN_FIELD_WORDS: &[&str] = &[
    "password",
    "passwd",
    "passcode",
    "passphrase",
    "pin",
    "otp",
    "totp",
    "token",
    "secret",
    "secrets",
    "credential",
    "credentials",
    "cookie",
    "cookies",
    "session_key",
    "api_key",
    "apikey",
    "private_key",
    "card",
    "pan",
    "cvv",
    "cvc",
    "cvv2",
];

const DRAFT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Whether a field name carries a secret-like word between `_` boundaries.
#[must_use]
pub fn is_forbidden_field_name(name: &str) -> bool {
    let tokens: alloc::vec::Vec<&str> = name.split('_').collect();
    FORBIDDEN_FIELD_WORDS.iter().any(|word| {
        let parts: alloc::vec::Vec<&str> = word.split('_').collect();
        tokens.windows(parts.len()).any(|w| w == parts.as_slice())
    })
}

fn is_property_name(name: &str) -> bool {
    crate::task::common::is_snake_name(name)
}

/// Whether a field name may appear in an embedded schema.
#[must_use]
pub fn is_safe_property_name(name: &str) -> bool {
    is_property_name(name) && !is_forbidden_field_name(name)
}

fn is_schema_path(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("https://suiss.app/schemas/one/") else {
        return false;
    };
    let parts: alloc::vec::Vec<&str> = rest.split('/').collect();
    let segment = |s: &str| {
        !s.is_empty()
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    };
    match parts.as_slice() {
        [a, b, file] => {
            segment(a)
                && segment(b)
                && file
                    .strip_prefix('v')
                    .and_then(|f| f.strip_suffix(".json"))
                    .is_some_and(|n| !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit()))
        }
        _ => false,
    }
}

fn is_local_def(text: &str) -> bool {
    text.strip_prefix("#/$defs/").is_some_and(is_property_name)
}

fn is_safe_ref(text: &str) -> bool {
    if is_local_def(text) {
        return true;
    }
    match text.split_once('#') {
        Some((path, fragment)) => {
            is_schema_path(path) && is_local_def(&alloc::format!("#{fragment}"))
        }
        None => is_schema_path(text),
    }
}

fn safe_map(
    value: &JsonValue,
    name_ok: fn(&str) -> bool,
    member_ok: fn(&JsonValue) -> bool,
) -> bool {
    value
        .as_object()
        .is_some_and(|o| o.iter().all(|(k, v)| name_ok(k) && member_ok(v)))
}

fn safe_name_list(value: &JsonValue) -> bool {
    matches!(value, JsonValue::Array(items) if items.iter().all(|i| i.as_str().is_some_and(is_safe_property_name)))
}

fn safe_schema_array(value: &JsonValue) -> bool {
    matches!(value, JsonValue::Array(items) if !items.is_empty() && items.iter().all(is_safe_schema))
}

/// Whether a schema is safe to embed: every property name is snake case and not secret-like, objects are closed, and no pattern properties, dynamic references, foreign references, password formats or write-only fields appear.
#[must_use]
pub fn is_safe_schema(value: &JsonValue) -> bool {
    let object = match value {
        JsonValue::Bool(_) => return true,
        JsonValue::Object(o) => o,
        _ => return false,
    };
    let keyword_ok = |key: &str, v: &JsonValue| -> bool {
        match key {
            "properties" | "dependentSchemas" => safe_map(v, is_safe_property_name, is_safe_schema),
            "required" => safe_name_list(v),
            "dependentRequired" => safe_map(v, is_safe_property_name, safe_name_list),
            "additionalProperties" | "writeOnly" => *v == JsonValue::Bool(false),
            "patternProperties" | "unevaluatedProperties" | "propertyNames" | "$dynamicRef" => {
                false
            }
            "items" | "contains" | "unevaluatedItems" | "not" | "if" | "then" | "else" => {
                is_safe_schema(v)
            }
            "prefixItems" | "allOf" | "anyOf" | "oneOf" => safe_schema_array(v),
            "$defs" => safe_map(v, is_property_name, is_safe_schema),
            "$ref" => v.as_str().is_some_and(is_safe_ref),
            "format" => v.as_str() != Some("password"),
            _ => true,
        }
    };
    if !object.iter().all(|(k, v)| keyword_ok(k, v)) {
        return false;
    }
    let is_object_schema = object.get("properties").is_some()
        || object.get("type").and_then(JsonValue::as_str) == Some("object");
    !is_object_schema || object.get("additionalProperties").is_some()
}

fn is_typed_schema(value: &JsonObject) -> bool {
    let reference = value.len() == 1
        && value
            .get("$ref")
            .and_then(JsonValue::as_str)
            .is_some_and(is_schema_path);
    let inline = value.get("$schema").and_then(JsonValue::as_str) == Some(DRAFT)
        && value.get("type").and_then(JsonValue::as_str) == Some("object")
        && value.get("properties").is_some()
        && value.get("additionalProperties").is_some()
        && is_safe_schema(&JsonValue::Object(value.clone()));
    reference || inline
}

/// An input or output schema of a registry entry: a safe inline 2020-12 object schema or a reference to a Suiss schema.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "JsonObject", into = "JsonObject")]
pub struct TypedSchema(JsonObject);

impl TypedSchema {
    /// Checks and wraps a schema.
    ///
    /// # Errors
    /// Rejects a schema that is open, secret-carrying, not 2020-12 or a foreign reference.
    pub fn new(schema: JsonObject) -> Result<Self, ContractViolation> {
        if is_typed_schema(&schema) {
            Ok(Self(schema))
        } else {
            Err(ContractViolation("typed schema"))
        }
    }

    /// The schema.
    #[must_use]
    pub const fn schema(&self) -> &JsonObject {
        &self.0
    }
}

impl TryFrom<JsonObject> for TypedSchema {
    type Error = ContractViolation;

    fn try_from(schema: JsonObject) -> Result<Self, ContractViolation> {
        Self::new(schema)
    }
}

impl From<TypedSchema> for JsonObject {
    fn from(value: TypedSchema) -> Self {
        value.0
    }
}
