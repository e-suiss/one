//! A deterministic CBOR writer (RFC 8949 §4.2.1): shortest arguments, definite lengths and map entries in bytewise order of their encoded keys; decoding lives in `one-parse` (T-15, T-36 (4)).

use alloc::vec::Vec;

const UNSIGNED: u8 = 0;
const NEGATIVE: u8 = 1;
const BYTES: u8 = 2;
const TEXT: u8 = 3;
const ARRAY: u8 = 4;
const MAP: u8 = 5;
const TAG: u8 = 6;

/// Appends deterministic CBOR items to a buffer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Writer {
    out: Vec<u8>,
}

impl Writer {
    /// An empty writer.
    #[must_use]
    pub const fn new() -> Self {
        Self { out: Vec::new() }
    }

    /// The bytes written so far.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.out
    }

    fn head(&mut self, major: u8, value: u64) {
        let major = major << 5;
        if let Ok(small) = u8::try_from(value) {
            if small <= 23 {
                self.out.push(major | small);
            } else {
                self.out.push(major | 0x18);
                self.out.push(small);
            }
        } else if let Ok(v) = u16::try_from(value) {
            self.out.push(major | 0x19);
            self.out.extend_from_slice(&v.to_be_bytes());
        } else if let Ok(v) = u32::try_from(value) {
            self.out.push(major | 0x1a);
            self.out.extend_from_slice(&v.to_be_bytes());
        } else {
            self.out.push(major | 0x1b);
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn length(&mut self, major: u8, len: usize) {
        self.head(major, u64::try_from(len).unwrap_or(u64::MAX));
    }

    /// An unsigned integer.
    pub fn unsigned(&mut self, value: u64) -> &mut Self {
        self.head(UNSIGNED, value);
        self
    }

    /// The negative integer `-1 - n`.
    pub fn negative(&mut self, n: u64) -> &mut Self {
        self.head(NEGATIVE, n);
        self
    }

    /// A byte string.
    pub fn bytes(&mut self, value: &[u8]) -> &mut Self {
        self.length(BYTES, value.len());
        self.out.extend_from_slice(value);
        self
    }

    /// A text string.
    pub fn text(&mut self, value: &str) -> &mut Self {
        self.length(TEXT, value.len());
        self.out.extend_from_slice(value.as_bytes());
        self
    }

    /// The head of an array of `len` items; the items follow.
    pub fn array(&mut self, len: usize) -> &mut Self {
        self.length(ARRAY, len);
        self
    }

    /// A tag; the tagged item follows.
    pub fn tag(&mut self, tag: u64) -> &mut Self {
        self.head(TAG, tag);
        self
    }

    /// Already encoded items, appended unchanged.
    pub fn raw(&mut self, encoded: &[u8]) -> &mut Self {
        self.out.extend_from_slice(encoded);
        self
    }

    /// A map of already encoded `(key, value)` pairs, written in bytewise order of the encoded keys.
    ///
    /// Returns `false`, writing nothing, when two keys are equal: a deterministic map has no duplicates.
    pub fn map(&mut self, mut entries: Vec<(Vec<u8>, Vec<u8>)>) -> bool {
        entries.sort_by(|a, b| a.0.cmp(&b.0));
        if entries
            .windows(2)
            .any(|w| matches!(w, [a, b] if a.0 == b.0))
        {
            return false;
        }
        self.length(MAP, entries.len());
        for (key, value) in entries {
            self.out.extend_from_slice(&key);
            self.out.extend_from_slice(&value);
        }
        true
    }
}

/// One encoded item written by `f`.
#[must_use]
pub fn encode(f: impl FnOnce(&mut Writer)) -> Vec<u8> {
    let mut w = Writer::new();
    f(&mut w);
    w.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-15
    #[test]
    fn t_15_arguments_use_the_shortest_form() {
        assert_eq!(
            encode(|w| {
                w.unsigned(23);
            }),
            [0x17]
        );
        assert_eq!(
            encode(|w| {
                w.unsigned(24);
            }),
            [0x18, 0x18]
        );
        assert_eq!(
            encode(|w| {
                w.unsigned(256);
            }),
            [0x19, 0x01, 0x00]
        );
        assert_eq!(
            encode(|w| {
                w.unsigned(1_793_667_600);
            }),
            [0x1a, 0x6a, 0xe9, 0x32, 0x10]
        );
        assert_eq!(
            encode(|w| {
                w.unsigned(u64::MAX);
            }),
            [0x1b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
        );
        assert_eq!(
            encode(|w| {
                w.negative(6);
            }),
            [0x26]
        );
        assert_eq!(
            encode(|w| {
                w.tag(37);
            }),
            [0xd8, 0x25]
        );
    }

    // T-15
    #[test]
    fn t_15_map_keys_are_sorted_and_unique() {
        let a = encode(|w| {
            w.text("bb");
        });
        let b = encode(|w| {
            w.text("a");
        });
        let one = encode(|w| {
            w.unsigned(1);
        });
        let mut w = Writer::new();
        assert!(w.map(alloc::vec![
            (a.clone(), one.clone()),
            (b.clone(), one.clone())
        ]));
        assert_eq!(
            w.into_bytes(),
            [0xa2, 0x61, b'a', 0x01, 0x62, b'b', b'b', 0x01]
        );
        let mut dup = Writer::new();
        assert!(!dup.map(alloc::vec![(a.clone(), one.clone()), (a, one)]));
        assert_eq!(dup.into_bytes(), alloc::vec::Vec::<u8>::new());
    }
}
