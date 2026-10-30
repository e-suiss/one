//! Shared helpers for the key-layer contract tests: vector loading, hex and the CBOR diagnostic notation the vectors write bodies in.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::format_collect,
    dead_code,
    reason = "T-38"
)]

use one_parse::cbor::CborValue;
use one_proto::cbor::Writer;
use serde_json::Value;

pub(crate) fn load(path: &str) -> Vec<Value> {
    let full = format!("{}/../../conformance/{path}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&full).unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

pub(crate) fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex: {s}");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn fixed<const N: usize>(s: &str) -> [u8; N] {
    unhex(s).try_into().unwrap()
}

struct Diag<'a> {
    s: &'a [u8],
    i: usize,
}

impl Diag<'_> {
    fn ws(&mut self) {
        while self.i < self.s.len() && (self.s[self.i] as char).is_whitespace() {
            self.i += 1;
        }
    }

    fn eat(&mut self, c: u8) -> bool {
        self.ws();
        if self.s.get(self.i) == Some(&c) {
            self.i += 1;
            true
        } else {
            false
        }
    }

    fn value(&mut self) -> CborValue {
        self.ws();
        match self.s[self.i] {
            b'{' => {
                self.i += 1;
                let mut entries = Vec::new();
                while !self.eat(b'}') {
                    let k = self.value();
                    assert!(self.eat(b':'));
                    let v = self.value();
                    entries.push((k, v));
                    self.eat(b',');
                }
                CborValue::Map(entries)
            }
            b'[' => {
                self.i += 1;
                let mut items = Vec::new();
                while !self.eat(b']') {
                    items.push(self.value());
                    self.eat(b',');
                }
                CborValue::Array(items)
            }
            b'"' => {
                self.i += 1;
                let start = self.i;
                while self.s[self.i] != b'"' {
                    self.i += 1;
                }
                let text = std::str::from_utf8(&self.s[start..self.i])
                    .unwrap()
                    .to_owned();
                self.i += 1;
                CborValue::Text(text)
            }
            b'h' => {
                assert_eq!(self.s[self.i + 1], b'\'');
                self.i += 2;
                let start = self.i;
                while self.s[self.i] != b'\'' {
                    self.i += 1;
                }
                let bytes = unhex(std::str::from_utf8(&self.s[start..self.i]).unwrap());
                self.i += 1;
                CborValue::Bytes(bytes)
            }
            b'n' if self.s[self.i..].starts_with(b"null") => {
                self.i += 4;
                CborValue::Null
            }
            c if c.is_ascii_digit() => {
                let start = self.i;
                while self.i < self.s.len() && self.s[self.i].is_ascii_digit() {
                    self.i += 1;
                }
                let n: u64 = std::str::from_utf8(&self.s[start..self.i])
                    .unwrap()
                    .parse()
                    .unwrap();
                if self.eat(b'(') {
                    let inner = self.value();
                    assert!(self.eat(b')'));
                    CborValue::Tag(n, Box::new(inner))
                } else {
                    CborValue::Unsigned(n)
                }
            }
            c => panic!("diagnostic notation: unexpected {:?}", c as char),
        }
    }
}

/// Reads the diagnostic notation subset the vectors use: maps, arrays, text, unsigned integers, tags, `h'..'` and `null`.
pub(crate) fn diag(text: &str) -> CborValue {
    let mut d = Diag {
        s: text.as_bytes(),
        i: 0,
    };
    let v = d.value();
    d.ws();
    assert_eq!(d.i, text.len(), "trailing diagnostic notation");
    v
}

fn write(w: &mut Writer, v: &CborValue) {
    match v {
        CborValue::Unsigned(n) => {
            w.unsigned(*n);
        }
        CborValue::Negative(n) => {
            w.negative(*n);
        }
        CborValue::Bytes(b) => {
            w.bytes(b);
        }
        CborValue::Text(t) => {
            w.text(t);
        }
        CborValue::Array(items) => {
            w.array(items.len());
            for item in items {
                write(w, item);
            }
        }
        CborValue::Map(entries) => {
            let encoded = entries
                .iter()
                .map(|(k, v)| (encode(k), encode(v)))
                .collect();
            assert!(w.map(encoded));
        }
        CborValue::Tag(t, inner) => {
            w.tag(*t);
            write(w, inner);
        }
        other => panic!("not used by the vectors: {other:?}"),
    }
}

/// The deterministic encoding of a value: map keys sorted, array order kept as written.
pub(crate) fn encode(v: &CborValue) -> Vec<u8> {
    let mut w = Writer::new();
    write(&mut w, v);
    w.into_bytes()
}
