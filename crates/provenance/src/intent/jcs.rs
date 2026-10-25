//! RFC 8785 JSON Canonicalization Scheme over [`JsonValue`] and the `sha256:` digest of the canonical bytes that pins a capability input schema (CP-5, CP-16).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;
use core::num::FpCategory;

use one_proto::ontology::JsonValue;
use one_proto::task::common::Sha256Digest;
use sha2::{Digest as _, Sha256};

/// The canonical JSON text of a value; `None` when it holds a NaN or an infinity, which JSON cannot carry.
#[must_use]
pub fn canonicalize(value: &JsonValue) -> Option<String> {
    let mut out = String::new();
    write_value(&mut out, value)?;
    Some(out)
}

/// The `sha256:` digest of the canonical JSON bytes; `None` when the value cannot be canonicalised.
#[must_use]
pub fn sha256_digest(value: &JsonValue) -> Option<Sha256Digest> {
    let text = canonicalize(value)?;
    let hash = Sha256::digest(text.as_bytes());
    let mut hex = String::from("sha256:");
    for byte in &hash {
        write!(hex, "{byte:02x}").ok()?;
    }
    Sha256Digest::parse(&hex).ok()
}

fn write_value(out: &mut String, value: &JsonValue) -> Option<()> {
    match value {
        JsonValue::Null => out.push_str("null"),
        JsonValue::Bool(true) => out.push_str("true"),
        JsonValue::Bool(false) => out.push_str("false"),
        JsonValue::Unsigned(n) => write_unsigned(out, *n, false)?,
        JsonValue::Signed(n) => write_unsigned(out, n.unsigned_abs(), *n < 0)?,
        JsonValue::Float(n) => write_float(out, *n)?,
        JsonValue::String(s) => write_string(out, s),
        JsonValue::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item)?;
            }
            out.push(']');
        }
        JsonValue::Object(map) => {
            let mut entries: Vec<(&String, &JsonValue)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                write_value(out, item)?;
            }
            out.push('}');
        }
    }
    Some(())
}

const EXACT_LIMIT: u64 = 1 << 53;

fn write_unsigned(out: &mut String, magnitude: u64, negative: bool) -> Option<()> {
    if magnitude <= EXACT_LIMIT {
        if negative && magnitude != 0 {
            out.push('-');
        }
        write!(out, "{magnitude}").ok()
    } else {
        let high = u32::try_from(magnitude >> 32).ok()?;
        let low = u32::try_from(magnitude & 0xffff_ffff).ok()?;
        let value = f64::from(high) * 4_294_967_296.0 + f64::from(low);
        write_float(out, if negative { -value } else { value })
    }
}

fn write_float(out: &mut String, value: f64) -> Option<()> {
    match value.classify() {
        FpCategory::Nan | FpCategory::Infinite => return None,
        FpCategory::Zero => {
            out.push('0');
            return Some(());
        }
        FpCategory::Normal | FpCategory::Subnormal => {}
    }
    let sci = alloc::format!("{:e}", value.abs());
    let (mantissa, exponent) = sci.split_once('e')?;
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let exponent: i32 = exponent.parse().ok()?;
    let k = i32::try_from(digits.len()).ok()?;
    let n = exponent.checked_add(1)?;
    if value.is_sign_negative() {
        out.push('-');
    }
    if k <= n && n <= 21 {
        out.push_str(&digits);
        for _ in 0..n.checked_sub(k)? {
            out.push('0');
        }
    } else if 0 < n && n <= 21 {
        let split = usize::try_from(n).ok()?;
        out.push_str(digits.get(..split)?);
        out.push('.');
        out.push_str(digits.get(split..)?);
    } else if -6 < n && n <= 0 {
        out.push_str("0.");
        for _ in 0..n.checked_neg()? {
            out.push('0');
        }
        out.push_str(&digits);
    } else {
        let e = n.checked_sub(1)?;
        out.push_str(digits.get(..1)?);
        if k > 1 {
            out.push('.');
            out.push_str(digits.get(1..)?);
        }
        out.push('e');
        out.push(if e.is_negative() { '-' } else { '+' });
        write!(out, "{}", e.unsigned_abs()).ok()?;
    }
    Some(())
}

fn write_string(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{9}' => out.push_str("\\t"),
            '\u{a}' => out.push_str("\\n"),
            '\u{c}' => out.push_str("\\f"),
            '\u{d}' => out.push_str("\\r"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
