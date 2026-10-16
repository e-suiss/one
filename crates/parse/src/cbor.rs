//! A bounded decoder for deterministic CBOR (RFC 8949 §4.2.1): shortest arguments, no indefinite lengths, shortest floats, map keys in bytewise order without duplicates; every length is checked against the limits before it is allocated.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use one_provenance::{ExternalSource, Untrusted};

use crate::limits::{Budget, Limits, ParseError};

/// A decoded CBOR data item.
#[derive(Debug, Clone, PartialEq)]
pub enum CborValue {
    /// Major type 0.
    Unsigned(u64),
    /// Major type 1: the value is `-1 - n`.
    Negative(u64),
    /// Major type 2.
    Bytes(Vec<u8>),
    /// Major type 3.
    Text(String),
    /// Major type 4.
    Array(Vec<CborValue>),
    /// Major type 5, in encoded key order.
    Map(Vec<(CborValue, CborValue)>),
    /// Major type 6.
    Tag(u64, Box<CborValue>),
    /// `false` or `true`.
    Bool(bool),
    /// `null`.
    Null,
    /// A half, single or double precision float.
    Float(f64),
}

/// Parses one deterministic CBOR data item from `source`; trailing bytes are refused.
///
/// # Errors
/// A broken limit, an indefinite length, a non-deterministic encoding or malformed CBOR.
pub fn parse(
    bytes: &[u8],
    limits: &Limits,
    source: ExternalSource,
) -> Result<Untrusted<CborValue>, ParseError> {
    let mut decoder = Decoder {
        input: bytes,
        pos: 0,
        budget: Budget::new(limits, bytes.len())?,
    };
    let value = decoder.value(0)?;
    if decoder.pos != bytes.len() {
        return Err(ParseError::Malformed("trailing bytes"));
    }
    Ok(Untrusted::external(value, source))
}

struct Decoder<'a> {
    input: &'a [u8],
    pos: usize,
    budget: Budget,
}

const TRUNCATED: ParseError = ParseError::Malformed("truncated");

impl<'a> Decoder<'a> {
    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.pos)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        let end = self.pos.checked_add(n).ok_or(TRUNCATED)?;
        let slice = self.input.get(self.pos..end).ok_or(TRUNCATED)?;
        self.pos = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, ParseError> {
        let b = *self.input.get(self.pos).ok_or(TRUNCATED)?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn uint<const N: usize>(&mut self) -> Result<u64, ParseError> {
        let mut out: u64 = 0;
        for &b in self.take(N)? {
            out = out.checked_mul(256).ok_or(TRUNCATED)? | u64::from(b);
        }
        Ok(out)
    }

    fn argument(&mut self, info: u8) -> Result<u64, ParseError> {
        let (value, floor) = match info {
            0..=23 => return Ok(u64::from(info)),
            24 => (self.uint::<1>()?, 24),
            25 => (self.uint::<2>()?, 0x100),
            26 => (self.uint::<4>()?, 0x1_0000),
            27 => (self.uint::<8>()?, 0x1_0000_0000),
            31 => return Err(ParseError::Indefinite),
            _ => return Err(ParseError::Malformed("reserved additional information")),
        };
        if value < floor {
            return Err(ParseError::NonCanonical("argument not in shortest form"));
        }
        Ok(value)
    }

    fn length(&mut self, info: u8) -> Result<usize, ParseError> {
        usize::try_from(self.argument(info)?).map_err(|_| TRUNCATED)
    }

    fn value(&mut self, depth: usize) -> Result<CborValue, ParseError> {
        self.budget.depth(depth)?;
        self.budget.item::<CborValue>()?;
        let initial = self.byte()?;
        let major = initial.checked_shr(5).unwrap_or(0);
        let info = initial & 0x1f;
        if major == 7 {
            return self.simple(info);
        }
        let next = depth.saturating_add(1);
        match major {
            0 => Ok(CborValue::Unsigned(self.argument(info)?)),
            1 => Ok(CborValue::Negative(self.argument(info)?)),
            2 => {
                let len = self.length(info)?;
                self.budget.string(len)?;
                Ok(CborValue::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(info)?;
                self.budget.string(len)?;
                let text = core::str::from_utf8(self.take(len)?)
                    .map_err(|_| ParseError::Malformed("text is not utf-8"))?;
                Ok(CborValue::Text(String::from(text)))
            }
            4 => {
                let len = self.container(info, 1)?;
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.value(next)?);
                }
                Ok(CborValue::Array(items))
            }
            5 => {
                let len = self.container(info, 2)?;
                let mut entries = Vec::with_capacity(len);
                let mut previous: Option<&'a [u8]> = None;
                for _ in 0..len {
                    let start = self.pos;
                    let key = self.value(next)?;
                    let encoded = self.input.get(start..self.pos).ok_or(TRUNCATED)?;
                    if previous.is_some_and(|p| p >= encoded) {
                        return Err(ParseError::NonCanonical("map keys out of order"));
                    }
                    previous = Some(encoded);
                    entries.push((key, self.value(next)?));
                }
                Ok(CborValue::Map(entries))
            }
            _ => {
                let tag = self.argument(info)?;
                Ok(CborValue::Tag(tag, Box::new(self.value(next)?)))
            }
        }
    }

    fn container(&mut self, info: u8, per_entry: usize) -> Result<usize, ParseError> {
        let len = self.length(info)?;
        let items = len.checked_mul(per_entry).ok_or(TRUNCATED)?;
        if items > self.remaining() {
            return Err(TRUNCATED);
        }
        if items > self.budget.items_left() {
            return Err(ParseError::TooManyItems);
        }
        self.budget.alloc_many::<CborValue>(items)?;
        Ok(len)
    }

    fn simple(&mut self, info: u8) -> Result<CborValue, ParseError> {
        match info {
            20 => Ok(CborValue::Bool(false)),
            21 => Ok(CborValue::Bool(true)),
            22 => Ok(CborValue::Null),
            23 => Err(ParseError::Malformed("undefined")),
            24 => {
                if self.byte()? < 32 {
                    Err(ParseError::Malformed("simple value in two bytes"))
                } else {
                    Err(ParseError::Malformed("unassigned simple value"))
                }
            }
            25 => {
                let half = u16::try_from(self.uint::<2>()?).map_err(|_| TRUNCATED)?;
                let bits = half_to_double_bits(half);
                if is_nan(bits) && half != 0x7e00 {
                    return Err(ParseError::NonCanonical("NaN is not 0xf97e00"));
                }
                Ok(CborValue::Float(f64::from_bits(bits)))
            }
            26 => {
                let single = u32::try_from(self.uint::<4>()?).map_err(|_| TRUNCATED)?;
                let bits = f64::from(f32::from_bits(single)).to_bits();
                if is_nan(bits) || fits(bits, HALF) {
                    return Err(ParseError::NonCanonical("float not in shortest form"));
                }
                Ok(CborValue::Float(f64::from_bits(bits)))
            }
            27 => {
                let bits = self.uint::<8>()?;
                if is_nan(bits) || fits(bits, HALF) || fits(bits, SINGLE) {
                    return Err(ParseError::NonCanonical("float not in shortest form"));
                }
                Ok(CborValue::Float(f64::from_bits(bits)))
            }
            31 => Err(ParseError::Indefinite),
            28..=30 => Err(ParseError::Malformed("reserved additional information")),
            _ => Err(ParseError::Malformed("unassigned simple value")),
        }
    }
}

const FRACTION_BITS: u32 = 52;
const FRACTION_MASK: u64 = 0x000f_ffff_ffff_ffff;
const EXPONENT_MASK: u64 = 0x7ff;
const BIAS: i64 = 1023;

#[derive(Clone, Copy)]
struct Format {
    fraction_bits: u32,
    min_exponent: i64,
    max_exponent: i64,
}

const HALF: Format = Format {
    fraction_bits: 10,
    min_exponent: -14,
    max_exponent: 15,
};

const SINGLE: Format = Format {
    fraction_bits: 23,
    min_exponent: -126,
    max_exponent: 127,
};

const fn is_nan(bits: u64) -> bool {
    (bits >> FRACTION_BITS) & EXPONENT_MASK == EXPONENT_MASK && bits & FRACTION_MASK != 0
}

fn fits(bits: u64, format: Format) -> bool {
    let exponent_field = (bits >> FRACTION_BITS) & EXPONENT_MASK;
    let fraction = bits & FRACTION_MASK;
    if exponent_field == 0 || exponent_field == EXPONENT_MASK {
        return fraction == 0;
    }
    let exponent = i64::try_from(exponent_field)
        .unwrap_or(0)
        .saturating_sub(BIAS);
    if exponent > format.max_exponent {
        return false;
    }
    let used = if exponent >= format.min_exponent {
        format.fraction_bits
    } else {
        let lowest = format
            .min_exponent
            .saturating_sub(i64::from(format.fraction_bits));
        if exponent < lowest {
            return false;
        }
        u32::try_from(exponent.saturating_sub(lowest)).unwrap_or(0)
    };
    fraction.trailing_zeros() >= FRACTION_BITS.saturating_sub(used)
}

fn half_to_double_bits(half: u16) -> u64 {
    let sign = u64::from(half >> 15) << 63;
    let exponent = u64::from((half >> 10) & 0x1f);
    let fraction = u64::from(half & 0x3ff);
    match (exponent, fraction) {
        (0, 0) => sign,
        (0, f) => {
            let top = 63_u32.saturating_sub(f.leading_zeros());
            let rest = f & !(1_u64 << top);
            let biased = u64::from(top).saturating_add(999);
            sign | (biased << FRACTION_BITS) | (rest << FRACTION_BITS.saturating_sub(top))
        }
        (0x1f, 0) => sign | (EXPONENT_MASK << FRACTION_BITS),
        (0x1f, f) => sign | (EXPONENT_MASK << FRACTION_BITS) | (f << 42),
        (e, f) => sign | (e.saturating_add(1008) << FRACTION_BITS) | (f << 42),
    }
}
