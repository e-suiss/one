//! Deterministic CBOR (RFC 8949 §4.2.1): limits before allocation, indefinite lengths and non-canonical encodings refused, output labelled (T-36 (4), SEC-14).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::format_push_string,
    clippy::format_collect,
    reason = "T-38"
)]

mod common;

use common::{assert_label, tight};
use one_parse::ParseError;
use one_parse::cbor::{self, CborValue};
use one_provenance::ExternalSource;

fn parse(bytes: &[u8]) -> Result<CborValue, ParseError> {
    cbor::parse(bytes, &tight(), ExternalSource::Unknown).map(one_provenance::Untrusted::into_value)
}

#[test]
fn t_36_cbor_output_is_labelled() {
    let v = cbor::parse(&[0xa1, 0x61, 0x61, 0x01], &tight(), ExternalSource::One).unwrap();
    assert_label(&v, "external.one");
    assert_eq!(
        v.expose(),
        &CborValue::Map(vec![(CborValue::Text("a".into()), CborValue::Unsigned(1))])
    );
    let u = cbor::parse(&[0x00], &tight(), ExternalSource::Unknown).unwrap();
    assert_label(&u, "external.unknown");
}

#[test]
fn t_36_cbor_canonical_values_decode() {
    assert_eq!(parse(&[0x17]).unwrap(), CborValue::Unsigned(23));
    assert_eq!(parse(&[0x18, 0x18]).unwrap(), CborValue::Unsigned(24));
    assert_eq!(
        parse(&[0x19, 0x01, 0x00]).unwrap(),
        CborValue::Unsigned(256)
    );
    assert_eq!(parse(&[0x20]).unwrap(), CborValue::Negative(0));
    assert_eq!(
        parse(&[0x42, 0x01, 0x02]).unwrap(),
        CborValue::Bytes(vec![1, 2])
    );
    assert_eq!(
        parse(&[0x82, 0xf5, 0xf6]).unwrap(),
        CborValue::Array(vec![CborValue::Bool(true), CborValue::Null])
    );
    assert_eq!(
        parse(&[0xc1, 0x00]).unwrap(),
        CborValue::Tag(1, Box::new(CborValue::Unsigned(0)))
    );
    assert_eq!(parse(&[0xf9, 0x3c, 0x00]).unwrap(), CborValue::Float(1.0));
    assert_eq!(
        parse(&[0xf9, 0x00, 0x01]).unwrap(),
        CborValue::Float(5.960_464_477_539_063e-8)
    );
    assert_eq!(
        parse(&[0xf9, 0x7c, 0x00]).unwrap(),
        CborValue::Float(f64::INFINITY)
    );
    assert_eq!(
        parse(&[0xfa, 0x47, 0xc3, 0x50, 0x00]).unwrap(),
        CborValue::Float(100_000.0)
    );
    assert_eq!(
        parse(&[0xfb, 0x3f, 0xf1, 0x99, 0x99, 0x99, 0x99, 0x99, 0x9a]).unwrap(),
        CborValue::Float(1.1)
    );
    assert!(matches!(parse(&[0xf9, 0x7e, 0x00]).unwrap(), CborValue::Float(f) if f.is_nan()));
}

#[test]
fn t_36_cbor_non_shortest_arguments_are_rejected() {
    for bytes in [
        &[0x18, 0x17][..],
        &[0x19, 0x00, 0xff],
        &[0x1a, 0x00, 0x00, 0xff, 0xff],
        &[0x1b, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff],
        &[0x58, 0x01, 0x00],
        &[0x98, 0x00],
    ] {
        assert!(
            matches!(parse(bytes), Err(ParseError::NonCanonical(_))),
            "{bytes:x?}"
        );
    }
}

#[test]
fn t_36_cbor_non_shortest_floats_are_rejected() {
    for bytes in [
        &[0xfa, 0x3f, 0x80, 0x00, 0x00][..],
        &[0xfb, 0x3f, 0xf0, 0, 0, 0, 0, 0, 0],
        &[0xfb, 0x40, 0xf8, 0x6a, 0, 0, 0, 0, 0],
        &[0xfa, 0x7f, 0xc0, 0x00, 0x00],
        &[0xf9, 0x7e, 0x01],
        &[0xfa, 0x00, 0x00, 0x00, 0x00],
    ] {
        assert!(
            matches!(parse(bytes), Err(ParseError::NonCanonical(_))),
            "{bytes:x?}"
        );
    }
}

#[test]
fn t_36_cbor_map_keys_out_of_order_or_duplicated_are_rejected() {
    assert!(parse(&[0xa2, 0x01, 0x00, 0x02, 0x00]).is_ok());
    assert_eq!(
        parse(&[0xa2, 0x02, 0x00, 0x01, 0x00]),
        Err(ParseError::NonCanonical("map keys out of order"))
    );
    assert_eq!(
        parse(&[0xa2, 0x01, 0x00, 0x01, 0x00]),
        Err(ParseError::NonCanonical("map keys out of order"))
    );
    assert!(parse(&[0xa2, 0x0a, 0x00, 0x18, 0x64, 0x00]).is_ok());
    assert!(parse(&[0xa2, 0x18, 0x64, 0x00, 0x20, 0x00]).is_ok());
    assert_eq!(
        parse(&[0xa2, 0x62, 0x61, 0x61, 0x00, 0x61, 0x62, 0x00]),
        Err(ParseError::NonCanonical("map keys out of order"))
    );
}

#[test]
fn t_36_cbor_indefinite_lengths_are_rejected() {
    for bytes in [
        &[0x5f, 0x41, 0x00, 0xff][..],
        &[0x7f, 0xff],
        &[0x9f, 0xff],
        &[0xbf, 0xff],
        &[0xff],
    ] {
        assert_eq!(parse(bytes), Err(ParseError::Indefinite), "{bytes:x?}");
    }
}

#[test]
fn t_36_cbor_malformed_items_are_rejected() {
    for bytes in [
        &[][..],
        &[0x1c],
        &[0x62, 0xff, 0xfe],
        &[0x82, 0x00],
        &[0x00, 0x00],
        &[0xf7],
        &[0xf8, 0x10],
        &[0xf8, 0x20],
        &[0xe0],
    ] {
        assert!(
            matches!(parse(bytes), Err(ParseError::Malformed(_))),
            "{bytes:x?}"
        );
    }
}

#[test]
fn sec_13_cbor_oversize_is_rejected() {
    let mut big = vec![0x59, 0x10, 0x00];
    big.extend(vec![0; 4096]);
    assert_eq!(parse(&big), Err(ParseError::TooLarge));
}

#[test]
fn sec_13_cbor_declared_lengths_are_checked_before_allocation() {
    assert_eq!(
        parse(&[0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]),
        Err(ParseError::StringTooLong)
    );
    assert_eq!(
        parse(&[0x9b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]),
        Err(ParseError::Malformed("truncated"))
    );
    assert_eq!(parse(&[0x59, 0x01, 0x01]), Err(ParseError::StringTooLong));
}

#[test]
fn sec_13_cbor_too_deep_is_rejected() {
    assert_eq!(
        parse(&[0x81, 0x81, 0x81, 0x81, 0x81, 0x00]),
        Err(ParseError::TooDeep)
    );
    assert!(parse(&[0x81, 0x81, 0x81, 0x81, 0x00]).is_ok());
    assert_eq!(
        parse(&[0xc1, 0xc1, 0xc1, 0xc1, 0xc1, 0x00]),
        Err(ParseError::TooDeep)
    );
}

#[test]
fn sec_13_cbor_too_many_items_is_rejected() {
    let mut many = vec![0x98, 0x41];
    many.extend(vec![0x00; 65]);
    assert_eq!(parse(&many), Err(ParseError::TooManyItems));
}
