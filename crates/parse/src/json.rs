//! Bounded JSON: a pre-scan checks size, depth, item count and string length before `serde_json` decodes a byte (T-36 (4), SEC-14).

use one_proto::ontology::JsonValue;
use one_provenance::{ExternalSource, Untrusted};
use serde::de::DeserializeOwned;

use crate::limits::{Budget, Limits, ParseError};

/// Checks `bytes` against `limits` without decoding: size, nesting depth, value and key count, string length and the allocation estimate.
///
/// # Errors
/// The first limit the input breaks.
pub fn prescan(bytes: &[u8], limits: &Limits) -> Result<(), ParseError> {
    let mut budget = Budget::new(limits, bytes.len())?;
    let mut depth: usize = 0;
    let mut in_string = false;
    let mut escape = false;
    let mut in_scalar = false;
    let mut string_len: usize = 0;
    for &c in bytes {
        if in_string {
            if escape {
                escape = false;
            } else if c == b'\\' {
                escape = true;
            } else if c == b'"' {
                in_string = false;
                budget.string(string_len)?;
                continue;
            }
            string_len = string_len.saturating_add(1);
            continue;
        }
        match c {
            b'"' => {
                in_string = true;
                in_scalar = false;
                string_len = 0;
                budget.item::<JsonValue>()?;
            }
            b'[' | b'{' => {
                in_scalar = false;
                depth = depth.saturating_add(1);
                budget.depth(depth)?;
                budget.item::<JsonValue>()?;
            }
            b']' | b'}' => {
                in_scalar = false;
                depth = depth.saturating_sub(1);
            }
            b',' | b':' | b' ' | b'\t' | b'\n' | b'\r' => in_scalar = false,
            _ => {
                if !in_scalar {
                    in_scalar = true;
                    budget.item::<JsonValue>()?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn decode<T: DeserializeOwned>(bytes: &[u8], limits: &Limits) -> Result<T, ParseError> {
    prescan(bytes, limits)?;
    serde_json::from_slice(bytes).map_err(|_| ParseError::Malformed("json"))
}

/// Parses any JSON value from `source`.
///
/// # Errors
/// A broken limit or malformed JSON.
pub fn parse(
    bytes: &[u8],
    limits: &Limits,
    source: ExternalSource,
) -> Result<Untrusted<JsonValue>, ParseError> {
    parse_as(bytes, limits, source)
}

/// Parses JSON from `source` into `T`; unknown fields follow `T`'s own serde rules.
///
/// # Errors
/// A broken limit, malformed JSON or a value that does not fit `T`.
pub fn parse_as<T: DeserializeOwned>(
    bytes: &[u8],
    limits: &Limits,
    source: ExternalSource,
) -> Result<Untrusted<T>, ParseError> {
    decode(bytes, limits).map(|v| Untrusted::external(v, source))
}
