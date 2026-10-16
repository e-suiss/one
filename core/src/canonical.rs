//! Canonical JSON bytes: keys sorted by UTF-16 code units, no insignificant whitespace, UTF-8 without escaping non-ASCII, ECMAScript number form (RFC 8785); the byte form the differential tests compare (T-38 (2)).

use core::fmt::Write;

use serde_json::Value;

/// The canonical bytes of `value`.
#[must_use]
pub fn to_vec(value: &Value) -> Vec<u8> {
    to_string(value).into_bytes()
}

/// The canonical text of `value`.
#[must_use]
pub fn to_string(value: &Value) -> String {
    let mut out = String::new();
    write_value(&mut out, value);
    out
}

fn write_value(out: &mut String, value: &Value) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => write_number(out, n),
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_value(out, item);
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(out, key);
                out.push(':');
                if let Some(v) = members.get(key) {
                    write_value(out, v);
                }
            }
            out.push('}');
        }
    }
}

fn write_number(out: &mut String, n: &serde_json::Number) {
    if let Some(u) = n.as_u64() {
        let _ = write!(out, "{u}");
    } else if let Some(i) = n.as_i64() {
        let _ = write!(out, "{i}");
    } else if let Some(x) = n.as_f64() {
        write_float(out, x);
    }
}

fn write_float(out: &mut String, x: f64) {
    if x == 0.0 || !x.is_finite() {
        out.push('0');
        return;
    }
    let a = x.abs();
    if (1e-6..1e21).contains(&a) {
        let _ = write!(out, "{x}");
    } else {
        let text = format!("{x:e}");
        match text.split_once('e') {
            Some((mantissa, exp)) if !exp.starts_with('-') => {
                let _ = write!(out, "{mantissa}e+{exp}");
            }
            _ => out.push_str(&text),
        }
    }
}

fn write_string(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if u32::from(c) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn t_38_canonical_form_sorts_keys_and_uses_ecmascript_numbers() {
        let value = json!({
            "b": [null, false, 42, -7],
            "a": "ş\"\n\u{1}",
            "n": [0.4, 1.0, 1e-7, 1e21, 0.954_545],
            "\u{e9}": 1,
            "z": {}
        });
        assert_eq!(
            to_string(&value),
            r#"{"a":"ş\"\n\u0001","b":[null,false,42,-7],"n":[0.4,1,1e-7,1e+21,0.954545],"z":{},"é":1}"#
        );
    }

    #[test]
    fn t_38_keys_sort_by_utf16_code_units() {
        let value = json!({"\u{1f600}": 1, "\u{ff61}": 2});
        assert_eq!(to_string(&value), "{\"\u{1f600}\":1,\"\u{ff61}\":2}");
    }
}
