//! The key permission body: deterministic CBOR per `conformance/keys/key-permission.cddl`, `classes` sorted and unique, decoded into [`PermissionBody`] and labelled external (PV-65, T-36 (4)).

use alloc::string::String;
use alloc::vec::Vec;

use one_proto::key_permission::{PermissionBody, PermissionId, UUID_TAG};
use one_provenance::{ExternalSource, Untrusted};

use crate::cbor::{self, CborValue};
use crate::limits::{Limits, ParseError};

const SHAPE: &str = "key permission body";

/// Parses a permission body.
///
/// # Errors
/// A broken limit or malformed CBOR, a non-deterministic encoding (including unsorted or repeated `classes`), or a body outside the CDDL.
pub fn parse(
    bytes: &[u8],
    limits: &Limits,
    source: ExternalSource,
) -> Result<Untrusted<PermissionBody>, ParseError> {
    let value = cbor::parse(bytes, limits, source)?.into_value();
    let body = body(value)?;
    Ok(Untrusted::external(body, source))
}

fn contract<T>(value: Option<T>) -> Result<T, ParseError> {
    value.ok_or(ParseError::Contract(SHAPE))
}

fn fixed<const N: usize>(value: CborValue) -> Result<[u8; N], ParseError> {
    match value {
        CborValue::Bytes(b) => contract(b.try_into().ok()),
        _ => Err(ParseError::Contract(SHAPE)),
    }
}

fn text(value: CborValue) -> Result<String, ParseError> {
    match value {
        CborValue::Text(t) => Ok(t),
        _ => Err(ParseError::Contract(SHAPE)),
    }
}

fn unsigned(value: &CborValue) -> Result<u64, ParseError> {
    match value {
        CborValue::Unsigned(n) => Ok(*n),
        _ => Err(ParseError::Contract(SHAPE)),
    }
}

#[derive(Default)]
struct Fields {
    permission_id: Option<PermissionId>,
    classes: Option<Vec<String>>,
    purpose: Option<String>,
    not_before: Option<u64>,
    expires_at: Option<u64>,
    tee_measurement: Option<[u8; 48]>,
    job_key_digest: Option<[u8; 32]>,
    mandate_ref: Option<String>,
}

fn body(value: CborValue) -> Result<PermissionBody, ParseError> {
    let CborValue::Map(entries) = value else {
        return Err(ParseError::Contract(SHAPE));
    };
    let mut f = Fields::default();
    for (key, value) in entries {
        match text(key)?.as_str() {
            "permission_id" => {
                let CborValue::Tag(UUID_TAG, inner) = value else {
                    return Err(ParseError::Contract(SHAPE));
                };
                f.permission_id = Some(contract(PermissionId::from_bytes(fixed(*inner)?))?);
            }
            "classes" => {
                let CborValue::Array(items) = value else {
                    return Err(ParseError::Contract(SHAPE));
                };
                let classes = items.into_iter().map(text).collect::<Result<Vec<_>, _>>()?;
                if classes.is_empty() {
                    return Err(ParseError::Contract(SHAPE));
                }
                if classes.windows(2).any(|w| matches!(w, [a, b] if a >= b)) {
                    return Err(ParseError::NonCanonical("classes not sorted and unique"));
                }
                f.classes = Some(classes);
            }
            "purpose" => f.purpose = Some(text(value)?),
            "not_before" => f.not_before = Some(unsigned(&value)?),
            "expires_at" => f.expires_at = Some(unsigned(&value)?),
            "tee_measurement" => f.tee_measurement = Some(fixed(value)?),
            "job_key_digest" => f.job_key_digest = Some(fixed(value)?),
            "mandate_ref" => {
                let m = text(value)?;
                if !(1..=255).contains(&m.len()) {
                    return Err(ParseError::Contract(SHAPE));
                }
                f.mandate_ref = Some(m);
            }
            _ => return Err(ParseError::Contract(SHAPE)),
        }
    }
    Ok(PermissionBody {
        permission_id: contract(f.permission_id)?,
        classes: contract(f.classes)?,
        purpose: contract(f.purpose)?,
        not_before: contract(f.not_before)?,
        expires_at: contract(f.expires_at)?,
        tee_measurement: contract(f.tee_measurement)?,
        job_key_digest: contract(f.job_key_digest)?,
        mandate_ref: f.mandate_ref,
    })
}
