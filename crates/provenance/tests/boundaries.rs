//! Boundary cases of the checked text types, the label rules, labelled-value opening, intent inputs and canonical numbers (SEC-13, SEC-14, SEC-19, T-31, T-36).

#![allow(
    clippy::unwrap_used,
    clippy::unreachable,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use one_proto::ontology::JsonValue;
use one_provenance::confirm::{Evidence, Target, upgrade_label};
use one_provenance::intent::jcs::canonicalize;
use one_provenance::intent::{
    CountryCode, Date, Email, FieldKind, FieldName, IntentInputs, MAX_FIELDS, MAX_INPUTS,
    MemoryText, OptionCode, Origin, Origins, Phone, PostalCode, ProposedInputs, Rejection,
    RequestText, SafeInteger, SchemaId, StepLimit, SummaryLangMismatch, SummaryText, TypedField,
    UntrustedText, Url,
};
use one_provenance::{
    AccessProvenance, ExternalSource, Label, LabelKind, Labelled, Opened, ParameterName,
    ParameterProvenance, PlannerContext, Source, Trusted, TrustedLabel, UntrustedLabel,
    VariableTable,
};
use serde::Deserialize;
use serde::de::value::{Error as ValueError, I128Deserializer};
use serde_json::json;

fn repeat(c: char, n: usize) -> String {
    std::iter::repeat_n(c, n).collect()
}

fn name(text: &str) -> ParameterName {
    ParameterName::new(text).unwrap()
}

fn external(source: ExternalSource) -> Label {
    Label::Untrusted(UntrustedLabel::External(source))
}

#[test]
fn sec_13_dates_follow_the_gregorian_calendar() {
    for ok in [
        "2024-02-29",
        "2000-02-29",
        "2023-02-28",
        "1900-02-28",
        "2024-01-31",
        "2024-12-31",
        "2024-04-30",
        "0004-02-29",
    ] {
        assert!(Date::new(ok).is_some(), "{ok}");
    }
    for bad in [
        "2023-02-29",
        "1900-02-29",
        "2100-02-29",
        "2024-02-30",
        "2024-04-31",
        "2024-06-31",
        "2024-13-01",
        "2024-00-10",
        "2024-01-00",
        "2024-01-32",
        "2024x01-15",
        "2024-01x15",
        "2024-01-151",
        "2024-1-15",
        "x",
        "",
    ] {
        assert!(Date::new(bad).is_none(), "{bad}");
    }
}

#[test]
fn sec_13_emails_have_one_at_between_two_plain_parts() {
    let longest = format!("{}@b", repeat('a', 252));
    assert_eq!(longest.chars().count(), 254);
    assert!(Email::new(&longest).is_some());
    assert!(Email::new(&format!("a{longest}")).is_none());
    assert!(Email::new("a@example.com").is_some());
    for bad in [
        "",
        "abc",
        "a@",
        "@b",
        "@",
        "a@b@c",
        "a b@example.com",
        "a@exa mple.com",
        "a\u{a0}b@example.com",
        "a@b\u{3000}",
        "a\u{feff}@b",
    ] {
        assert!(Email::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn sec_13_phones_are_e164() {
    for ok in ["+1234567", "+14155552671", "+123456789012345"] {
        assert!(Phone::new(ok).is_some(), "{ok}");
    }
    for bad in [
        "14155552671",
        "+123456",
        "+1234567890123456",
        "+01234567",
        "+1234567a",
        "+",
        "",
    ] {
        assert!(Phone::new(bad).is_none(), "{bad}");
    }
}

#[test]
fn sec_13_urls_are_http_or_https_within_2048() {
    let at_max = format!("https://{}", repeat('a', 2040));
    assert_eq!(at_max.len(), 2048);
    assert!(Url::new(&at_max).is_some());
    assert!(Url::new(&format!("{at_max}a")).is_none());
    for ok in ["https://example.com", "http://example.com/a?b=c"] {
        assert!(Url::new(ok).is_some(), "{ok}");
    }
    for bad in [
        "https://",
        "http://",
        "ftp://example.com",
        "https://a b",
        "https://a\"b",
        "https://a<b",
        "https://a{b",
        "",
    ] {
        assert!(Url::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn cp_16_schema_ids_are_https_within_2048() {
    let at_max = format!("https://{}", repeat('a', 2040));
    assert!(SchemaId::new(&at_max).is_some());
    assert!(SchemaId::new(&format!("{at_max}a")).is_none());
    for bad in [
        "http://example.com/s",
        "https://a b",
        "https:///x",
        "https://",
    ] {
        assert!(SchemaId::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn sec_13_option_codes() {
    assert!(OptionCode::new(&repeat('a', 64)).is_some());
    assert!(OptionCode::new(&repeat('a', 65)).is_none());
    for ok in ["a", "1", "a_1", "a1", "9_z"] {
        assert!(OptionCode::new(ok).is_some(), "{ok}");
    }
    for bad in ["", "_a", "A", "aB", "a-b", "a b"] {
        assert!(OptionCode::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn sec_13_postal_codes() {
    assert!(PostalCode::new(&repeat('1', 16)).is_some());
    assert!(PostalCode::new(&repeat('1', 17)).is_none());
    for ok in ["SW1A 1AA", "12345", "12-34", "a"] {
        assert!(PostalCode::new(ok).is_some(), "{ok}");
    }
    for bad in ["", "-123", " 123", "12_34", "12.34"] {
        assert!(PostalCode::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn sec_13_country_codes() {
    assert!(CountryCode::new("US").is_some());
    for bad in ["us", "Us", "USA", "U", ""] {
        assert!(CountryCode::new(bad).is_none(), "{bad}");
    }
}

#[test]
fn sec_13_summary_text_is_1_to_2000_characters() {
    assert!(SummaryText::new(&repeat('ü', 2000)).is_some());
    assert!(SummaryText::new(&repeat('ü', 2001)).is_none());
    assert!(SummaryText::new("").is_none());
}

#[test]
fn sec_12_context_text_lengths() {
    assert!(RequestText::new(&repeat('ü', 8000)).is_some());
    assert!(RequestText::new(&repeat('ü', 8001)).is_none());
    assert!(RequestText::new("").is_none());
    assert!(MemoryText::new(&repeat('ü', 2000)).is_some());
    assert!(MemoryText::new(&repeat('ü', 2001)).is_none());
    assert!(MemoryText::new("").is_none());
    assert!(UntrustedText::new("").is_some());
    assert!(UntrustedText::new(&repeat('a', 200_000)).is_some());
    assert!(UntrustedText::new(&repeat('a', 200_001)).is_none());
}

#[test]
fn t_31_field_names_are_snake_case() {
    assert!(FieldName::new(&repeat('a', 64)).is_some());
    assert!(FieldName::new(&repeat('a', 65)).is_none());
    assert!(FieldName::new("a_1").is_some());
    for bad in ["", "1a", "_a", "Ab", "aB", "a-b"] {
        assert!(FieldName::new(bad).is_none(), "{bad:?}");
    }
}

#[test]
fn sec_12_step_limit_and_safe_integer_keep_their_value() {
    assert_eq!(StepLimit::new(7).unwrap().get(), 7);
    assert_eq!(SafeInteger::new(42).unwrap().get(), 42);
    assert_eq!(SafeInteger::new(-2).unwrap().get(), -2);
}

fn codes(n: usize) -> JsonValue {
    JsonValue::Array((0..n).map(|i| JsonValue::String(format!("c{i}"))).collect())
}

#[test]
fn sec_13_choice_lists_hold_up_to_64_distinct_codes() {
    let one = TypedField::from_parts(FieldKind::ChoiceList, codes(1)).unwrap();
    assert_eq!(one.kind(), FieldKind::ChoiceList);
    assert!(TypedField::from_parts(FieldKind::ChoiceList, codes(MAX_FIELDS)).is_ok());
    assert!(TypedField::from_parts(FieldKind::ChoiceList, codes(MAX_FIELDS + 1)).is_err());
    let repeated = JsonValue::Array(vec![
        JsonValue::String("a".to_owned()),
        JsonValue::String("a".to_owned()),
    ]);
    assert!(TypedField::from_parts(FieldKind::ChoiceList, repeated).is_err());
}

#[test]
fn sec_19_origins_hold_their_members() {
    let a = Origin::new("https://a.example").unwrap();
    let b = Origin::new("https://b.example").unwrap();
    let origins = Origins::new(vec![a.clone()]).unwrap();
    assert_eq!(origins.as_slice(), std::slice::from_ref(&a));
    assert!(origins.contains(&a));
    assert!(!origins.contains(&b));
}

#[test]
fn sec_14_intent_inputs_insert_get_and_fill_up() {
    let mut inputs = IntentInputs::new();
    let first: Labelled<JsonValue> = Trusted::user_direct(JsonValue::Bool(true)).into();
    let second: Labelled<JsonValue> = Trusted::record(JsonValue::Bool(false)).into();
    assert_eq!(inputs.insert(name("a"), first.clone()).unwrap(), None);
    assert_eq!(inputs.get(&name("a")), Some(&first));
    assert_eq!(
        inputs.insert(name("a"), second.clone()).unwrap(),
        Some(first)
    );
    assert_eq!(inputs.len(), 1);
    assert!(inputs.insert(name("b"), second.clone()).unwrap().is_none());
    assert_eq!(inputs.len(), 2);
    let provenance = inputs.provenance();
    assert_eq!(provenance.get(&name("a")), Some(AccessProvenance::Trusted));
    assert_eq!(provenance.len(), 2);
    for i in 2..MAX_INPUTS {
        assert!(
            inputs
                .insert(name(&format!("p{i}")), second.clone())
                .is_ok()
        );
    }
    assert_eq!(inputs.len(), MAX_INPUTS);
    assert_eq!(
        inputs.insert(name("z"), second.clone()),
        Err(second.clone())
    );
    assert_eq!(
        inputs.insert(name("b"), second.clone()).unwrap(),
        Some(second)
    );
    assert_eq!(inputs.len(), MAX_INPUTS);
}

#[test]
fn sec_4_rejection_displays_its_code() {
    for r in Rejection::CHECK_ORDER {
        assert_eq!(r.to_string(), r.code());
    }
}

#[test]
fn sec_13_summary_lang_mismatch_displays_its_rule() {
    assert_eq!(
        SummaryLangMismatch.to_string(),
        "display summary present exactly when summary_lang is not none"
    );
}

#[test]
fn sec_14_access_provenance_and_parameter_map() {
    assert_eq!(AccessProvenance::User.as_str(), "user");
    assert_eq!(AccessProvenance::Trusted.as_str(), "trusted");
    assert_eq!(
        AccessProvenance::UntrustedExternal.as_str(),
        "untrusted-external"
    );
    let direct = Label::Trusted(TrustedLabel::UserDirect);
    let web = external(ExternalSource::Web);
    let map = ParameterProvenance::from_labels([(name("a"), &direct), (name("b"), &web)]);
    assert_eq!(map.get(&name("a")), Some(AccessProvenance::User));
    assert_eq!(
        map.get(&name("b")),
        Some(AccessProvenance::UntrustedExternal)
    );
    assert_eq!(map.len(), 2);
    assert!(!map.is_empty());
    assert!(ParameterProvenance::new().is_empty());
}

#[test]
fn t_36_label_wire_pairs() {
    assert!(Label::Trusted(TrustedLabel::RecordTrusted).is_trusted());
    assert!(!external(ExternalSource::Web).is_trusted());
    let web = Source::External(ExternalSource::Web);
    let email = Source::External(ExternalSource::Email);
    let direct = Source::Trusted(TrustedLabel::UserDirect);
    assert!(Label::from_wire(LabelKind::Mixed, Some(&[web, email])).is_some());
    assert_eq!(Label::from_wire(LabelKind::Mixed, Some(&[web])), None);
    assert_eq!(
        Label::from_wire(LabelKind::Mixed, Some(&[web, direct])),
        None
    );
    assert_eq!(
        Label::from_wire(LabelKind::External(ExternalSource::Web), Some(&[web])),
        Some(external(ExternalSource::Web))
    );
    assert_eq!(
        Label::from_wire(LabelKind::External(ExternalSource::Web), Some(&[web, web])),
        None
    );
    for kind in LabelKind::ALL {
        assert_eq!(kind.to_string(), kind.as_str());
    }
}

#[test]
fn sec_14_second_evidence_lifts_only_memory() {
    let web = external(ExternalSource::Web);
    assert_eq!(
        upgrade_label(&web, Evidence::SecondIndependentEvidence, Target::TaskInput),
        web
    );
    assert_eq!(
        upgrade_label(&web, Evidence::SecondIndependentEvidence, Target::Memory),
        Label::Untrusted(UntrustedLabel::OneInferred)
    );
}

#[test]
fn t_36_variable_references_run_out_after_var_999999() {
    let mut table = VariableTable::new();
    let mut last = None;
    for _ in 0..999_999 {
        last = table.bind(Trusted::user_direct(()));
    }
    assert_eq!(last.unwrap().to_string(), "var_999999");
    assert_eq!(table.bind(Trusted::user_direct(())), None);
}

#[test]
fn t_36_planner_context_returns_its_trusted_values() {
    let mut context = PlannerContext::new();
    context.push_trusted(Trusted::record(5));
    assert_eq!(context.trusted(), &[Trusted::record(5)]);
}

#[test]
fn t_36_opened_values_keep_their_wire_sources() {
    let trusted: Opened<u8> = serde_json::from_value(
        json!({"value": 1, "label": "user.direct", "sources": ["user.direct"]}),
    )
    .unwrap();
    assert!(trusted.conforms());
    let Labelled::Trusted(t) = trusted.into_labelled() else {
        unreachable!()
    };
    assert_eq!(
        t.sources().unwrap().as_slice(),
        &[Source::Trusted(TrustedLabel::UserDirect)]
    );
    let mixed: Opened<u8> = serde_json::from_value(json!({
        "value": 1,
        "label": "external.mixed",
        "sources": ["external.web", "external.email"]
    }))
    .unwrap();
    let Labelled::Untrusted(u) = mixed.into_labelled() else {
        unreachable!()
    };
    assert_eq!(u.sources().unwrap().as_slice().len(), 2);
}

#[test]
fn sec_14_a_map_without_value_is_a_bare_unknown_value() {
    let opened: Opened<serde_json::Value> = serde_json::from_value(json!({"x": 1})).unwrap();
    assert!(!opened.conforms());
    assert_eq!(opened.labelled().label(), Label::UNKNOWN);
    assert_eq!(opened.labelled().expose(), &json!({"x": 1}));
}

#[derive(Debug, PartialEq, Deserialize)]
enum Shape {
    Dot,
    Size(u8),
}

fn open_shape(value: &serde_json::Value) -> Result<Shape, serde_json::Error> {
    serde_json::from_value::<Opened<Shape>>(json!({"value": value, "label": "user.direct"}))
        .map(|o| o.into_labelled().into_value())
}

#[test]
fn t_36_opened_enums_read_unit_and_newtype_variants() {
    assert_eq!(open_shape(&json!("Dot")).unwrap(), Shape::Dot);
    assert_eq!(open_shape(&json!({"Size": 3})).unwrap(), Shape::Size(3));
    assert!(open_shape(&json!({"Size": 3, "Dot": null})).is_err());
    assert!(open_shape(&json!({})).is_err());
}

#[test]
fn t_36_opening_reports_what_it_expected() {
    let err = Opened::<i64>::deserialize(I128Deserializer::<ValueError>::new(1)).unwrap_err();
    assert!(err.to_string().contains("any value"), "{err}");
}

#[test]
fn sec_12_proposed_inputs_count() {
    let inputs: ProposedInputs =
        serde_json::from_value(json!({"a": {"literal": 1}, "b": {"ref": "var_1"}})).unwrap();
    assert_eq!(inputs.len(), 2);
    assert!(!inputs.is_empty());
    let none: ProposedInputs = serde_json::from_value(json!({})).unwrap();
    assert_eq!(none.len(), 0);
    assert!(none.is_empty());
}

#[test]
fn t_31_fractions_below_one_keep_the_leading_zero() {
    assert_eq!(canonicalize(&JsonValue::Float(0.5)).unwrap(), "0.5");
    assert_eq!(canonicalize(&JsonValue::Float(-0.25)).unwrap(), "-0.25");
}
