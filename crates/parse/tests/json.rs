//! JSON: limits are checked by the pre-scan before decoding, and the output carries the caller's `external.*` label (T-36 (4), SEC-14).

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
use one_parse::{Limits, ParseError, json};
use one_proto::ontology::JsonValue;
use one_provenance::ExternalSource;

#[test]
fn t_36_json_output_is_labelled_with_its_source() {
    let v = json::parse(br#"{"a":[1,"x",null]}"#, &tight(), ExternalSource::Web).unwrap();
    assert_label(&v, "external.web");
    assert!(v.expose().as_object().is_some());
    let u = json::parse(b"1", &tight(), ExternalSource::Unknown).unwrap();
    assert_label(&u, "external.unknown");
    assert_eq!(u.expose(), &JsonValue::Unsigned(1));
}

#[test]
fn sec_13_json_oversize_is_rejected_before_decoding() {
    let big = vec![b' '; 4097];
    assert_eq!(json::prescan(&big, &tight()), Err(ParseError::TooLarge));
    assert_eq!(
        json::parse(&big, &tight(), ExternalSource::Web).unwrap_err(),
        ParseError::TooLarge
    );
}

#[test]
fn sec_13_json_too_deep_is_rejected() {
    assert_eq!(
        json::parse(b"[[[[[1]]]]]", &tight(), ExternalSource::Web).unwrap_err(),
        ParseError::TooDeep
    );
    assert!(json::parse(b"[[[[1]]]]", &tight(), ExternalSource::Web).is_ok());
    let deep = "[".repeat(100_000);
    let limits = Limits {
        max_depth: 10_000,
        ..Limits::DEFAULT
    };
    assert_eq!(
        json::prescan(deep.as_bytes(), &limits),
        Err(ParseError::TooDeep)
    );
}

#[test]
fn sec_13_json_too_many_items_is_rejected() {
    let many = format!("[{}0]", "0,".repeat(64));
    assert_eq!(
        json::parse(many.as_bytes(), &tight(), ExternalSource::Web).unwrap_err(),
        ParseError::TooManyItems
    );
}

#[test]
fn sec_13_json_long_string_is_rejected() {
    let long = format!("\"{}\"", "a".repeat(257));
    assert_eq!(
        json::parse(long.as_bytes(), &tight(), ExternalSource::Web).unwrap_err(),
        ParseError::StringTooLong
    );
}

#[test]
fn sec_13_json_brackets_inside_strings_do_not_count_as_depth() {
    let v = json::parse(br#"["[[[[[[\"]]]]"]"#, &tight(), ExternalSource::Web).unwrap();
    assert_eq!(
        v.expose(),
        &JsonValue::Array(vec![JsonValue::String("[[[[[[\"]]]]".into())])
    );
}

#[test]
fn sec_13_json_allocation_budget_is_enforced() {
    let limits = Limits {
        max_total: 64,
        ..tight()
    };
    assert_eq!(
        json::parse(b"[1,2,3,4]", &limits, ExternalSource::Web).unwrap_err(),
        ParseError::BudgetExceeded
    );
}

#[test]
fn t_36_json_malformed_is_rejected() {
    assert!(matches!(
        json::parse(b"{\"a\":", &tight(), ExternalSource::Web),
        Err(ParseError::Malformed(_))
    ));
}
