//! RFC 8785 canonicalisation of [`JsonValue`]: the RFC's number, string and key-order examples and the digest of the fixture input schema (CP-5, CP-16).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::collections::BTreeMap;

use one_proto::ontology::JsonValue;
use one_provenance::intent::jcs::{canonicalize, sha256_digest};

fn text(s: &str) -> JsonValue {
    JsonValue::String(s.to_owned())
}

fn number(n: f64) -> String {
    canonicalize(&JsonValue::Float(n)).unwrap()
}

#[test]
fn t_31_numbers_follow_the_ecmascript_form() {
    let cases = [
        (333_333_333.333_333_3_f64, "333333333.3333333"),
        (1e30, "1e+30"),
        (4.50, "4.5"),
        (2e-3, "0.002"),
        (1e-27, "1e-27"),
        (-0.0, "0"),
        (0.0, "0"),
        (1e21, "1e+21"),
        (1e20, "100000000000000000000"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (-1.5, "-1.5"),
        (123.0, "123"),
        (5e-324, "5e-324"),
        (1.797_693_134_862_315_7e308, "1.7976931348623157e+308"),
        (295_147_905_179_352_830_000.0, "295147905179352830000"),
    ];
    for (n, want) in cases {
        assert_eq!(number(n), want, "{n:e}");
    }
    assert_eq!(canonicalize(&JsonValue::Float(f64::NAN)), None);
    assert_eq!(canonicalize(&JsonValue::Float(f64::INFINITY)), None);
    assert_eq!(
        canonicalize(&JsonValue::Unsigned(9_007_199_254_740_993)).unwrap(),
        "9007199254740992"
    );
    assert_eq!(
        canonicalize(&JsonValue::Unsigned(u64::MAX)).unwrap(),
        "18446744073709552000"
    );
    assert_eq!(canonicalize(&JsonValue::Signed(-42)).unwrap(), "-42");
    assert_eq!(
        canonicalize(&JsonValue::Signed(i64::MIN)).unwrap(),
        "-9223372036854776000"
    );
}

#[test]
#[allow(clippy::excessive_precision, reason = "T-38")]
fn t_31_rfc_8785_example_object() {
    let value = JsonValue::Object(BTreeMap::from([
        (
            "numbers".to_owned(),
            JsonValue::Array(vec![
                JsonValue::Float(333_333_333.333_333_29),
                JsonValue::Float(1e30),
                JsonValue::Float(4.50),
                JsonValue::Float(2e-3),
                JsonValue::Float(0.000_000_000_000_000_000_000_000_001),
            ]),
        ),
        ("string".to_owned(), text("\u{20ac}$\u{f}\nA'B\"\\\\\"/")),
        (
            "literals".to_owned(),
            JsonValue::Array(vec![
                JsonValue::Null,
                JsonValue::Bool(true),
                JsonValue::Bool(false),
            ]),
        ),
    ]));
    assert_eq!(
        canonicalize(&value).unwrap(),
        "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}"
    );
}

#[test]
fn t_31_keys_sort_by_utf16_code_units() {
    let names = [
        "\u{20ac}",
        "\r",
        "\u{fb33}",
        "1",
        "\u{1f600}",
        "\u{80}",
        "\u{f6}",
    ];
    let value = JsonValue::Object(
        names
            .iter()
            .map(|k| ((*k).to_owned(), JsonValue::Null))
            .collect(),
    );
    assert_eq!(
        canonicalize(&value).unwrap(),
        "{\"\\r\":null,\"1\":null,\"\u{80}\":null,\"\u{f6}\":null,\"\u{20ac}\":null,\"\u{1f600}\":null,\"\u{fb33}\":null}"
    );
}

#[test]
fn t_31_strings_escape_only_what_json_requires() {
    assert_eq!(
        canonicalize(&text("\u{8}\t\n\u{c}\r\u{1}\u{1f}\u{7f}\u{2028}<>&")).unwrap(),
        "\"\\b\\t\\n\\f\\r\\u0001\\u001f\u{7f}\u{2028}<>&\""
    );
}

#[test]
fn t_31_digest_is_sha256_of_the_canonical_bytes() {
    let empty = JsonValue::Object(BTreeMap::new());
    assert_eq!(
        sha256_digest(&empty).unwrap().as_str(),
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
    );
}
