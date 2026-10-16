//! Deterministic canonical JSON size: sorted keys, no insignificant whitespace, UTF-8 without escaping non-ASCII, ECMAScript number form (RFC 8785); used for the Live Activity byte budget (X-13, X-6).

use alloc::borrow::Cow;
use alloc::vec::Vec;
use core::fmt::{self, Write};

/// A JSON value borrowed from the projected record.
#[derive(Debug, Clone, PartialEq)]
pub enum Json<'a> {
    /// `null`.
    Null,
    /// A boolean.
    Bool(bool),
    /// An unsigned integer.
    UInt(u64),
    /// A finite number.
    Number(f64),
    /// A string.
    Str(Cow<'a, str>),
    /// An array.
    Array(Vec<Json<'a>>),
    /// An object with distinct keys; key order does not change the canonical length.
    Object(Vec<(&'a str, Json<'a>)>),
}

struct Counter(usize);

impl Write for Counter {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.0 = self.0.saturating_add(s.len());
        Ok(())
    }
}

fn written(args: fmt::Arguments<'_>) -> usize {
    let mut c = Counter(0);
    let _ = c.write_fmt(args);
    c.0
}

fn string_len(s: &str) -> usize {
    let escapes = s.chars().fold(0_usize, |n, c| {
        let extra = match c {
            '"' | '\\' | '\u{8}' | '\u{c}' | '\n' | '\r' | '\t' => 1,
            c if u32::from(c) < 0x20 => 5,
            _ => 0,
        };
        n.saturating_add(extra)
    });
    s.len().saturating_add(escapes).saturating_add(2)
}

fn number_len(x: f64) -> usize {
    if !x.is_finite() {
        return 4;
    }
    if x == 0.0 {
        return 1;
    }
    let a = x.abs();
    if (1e-6..1e21).contains(&a) {
        written(format_args!("{x}"))
    } else {
        let exp = written(format_args!("{x:e}"));
        let plus = usize::from(a >= 1e21);
        exp.saturating_add(plus)
    }
}

impl Json<'_> {
    /// The UTF-8 byte length of the canonical form.
    #[must_use]
    pub fn canonical_len(&self) -> usize {
        match self {
            Self::Null | Self::Bool(true) => 4,
            Self::Bool(false) => 5,
            Self::UInt(n) => written(format_args!("{n}")),
            Self::Number(x) => number_len(*x),
            Self::Str(s) => string_len(s),
            Self::Array(items) => items
                .iter()
                .fold(items.len().saturating_sub(1).saturating_add(2), |n, v| {
                    n.saturating_add(v.canonical_len())
                }),
            Self::Object(members) => {
                let commas = members.len().saturating_sub(1);
                members.iter().fold(commas.saturating_add(2), |n, (k, v)| {
                    n.saturating_add(string_len(k))
                        .saturating_add(1)
                        .saturating_add(v.canonical_len())
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use alloc::string::ToString;

    #[test]
    fn x_13_canonical_length_counts_escapes_numbers_and_utf8() {
        let value = Json::Object(alloc::vec![
            (
                "b",
                Json::Array(alloc::vec![Json::Null, Json::Bool(false), Json::UInt(42)])
            ),
            ("a", Json::Str(Cow::Borrowed("ş\"\n\u{1}"))),
            (
                "n",
                Json::Array(alloc::vec![
                    Json::Number(0.4),
                    Json::Number(1.0),
                    Json::Number(1e-7),
                    Json::Number(1e21)
                ])
            ),
        ]);
        let expected = r#"{"a":"ş\"\n\u0001","b":[null,false,42],"n":[0.4,1,1e-7,1e+21]}"#;
        assert_eq!(value.canonical_len(), expected.to_string().len());
    }
}
