//! Property tests of the canonical JSON size: for generated values it equals the length of an independent encoder built on `serde_json` with ECMAScript number form (X-13, X-6, T-38 (3)).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::many_single_char_names,
    reason = "T-38"
)]

use std::borrow::Cow;
use std::collections::BTreeMap;

use one_interaction::json_size::Json;
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed};

fn config() -> Config {
    Config {
        cases: 512,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(6),
        ..Config::default()
    }
}

#[derive(Debug, Clone)]
enum Tree {
    Null,
    Bool(bool),
    UInt(u64),
    Number(f64),
    Str(String),
    Array(Vec<Tree>),
    Object(BTreeMap<String, Tree>),
}

fn number() -> impl Strategy<Value = f64> {
    prop_oneof![
        any::<f64>().prop_filter("finite", |x| x.is_finite()),
        proptest::sample::select(vec![
            0.0,
            -0.0,
            1.0,
            -1.0,
            0.4,
            1e-6,
            9.99e-7,
            1e-7,
            1e20,
            1e21,
            1.5e21,
            123_456.789,
            5e-324,
            f64::MAX,
            f64::MIN_POSITIVE,
        ]),
        (-1e7..1e7_f64),
        (-30_i32..30, 1_u32..1000).prop_map(|(e, m)| f64::from(m) * 10_f64.powi(e)),
    ]
}

fn string() -> impl Strategy<Value = String> {
    prop_oneof![
        "\\PC{0,12}",
        "[\\x00-\\x1f\"\\\\/a-zşğü\u{7f}\u{2028}\u{1F600}]{0,12}",
    ]
}

fn tree() -> impl Strategy<Value = Tree> {
    let leaf = prop_oneof![
        Just(Tree::Null),
        any::<bool>().prop_map(Tree::Bool),
        any::<u64>().prop_map(Tree::UInt),
        number().prop_map(Tree::Number),
        string().prop_map(Tree::Str),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            proptest::collection::vec(inner.clone(), 0..6).prop_map(Tree::Array),
            proptest::collection::btree_map(string(), inner, 0..6).prop_map(Tree::Object),
        ]
    })
}

fn to_json(t: &Tree) -> Json<'_> {
    match t {
        Tree::Null => Json::Null,
        Tree::Bool(b) => Json::Bool(*b),
        Tree::UInt(n) => Json::UInt(*n),
        Tree::Number(x) => Json::Number(*x),
        Tree::Str(s) => Json::Str(Cow::Borrowed(s)),
        Tree::Array(items) => Json::Array(items.iter().map(to_json).collect()),
        Tree::Object(m) => Json::Object(
            m.iter()
                .rev()
                .map(|(k, v)| (k.as_str(), to_json(v)))
                .collect(),
        ),
    }
}

fn ecmascript(x: f64) -> String {
    if x == 0.0 {
        return "0".to_owned();
    }
    let shortest = serde_json::to_string(&x).unwrap();
    let (sign, body) = match shortest.strip_prefix('-') {
        Some(rest) => ("-", rest),
        None => ("", shortest.as_str()),
    };
    let (mantissa, exp) = match body.split_once(['e', 'E']) {
        Some((m, e)) => (m, e.parse::<i32>().unwrap()),
        None => (body, 0),
    };
    let (int, frac) = mantissa.split_once('.').unwrap_or((mantissa, ""));
    let all = format!("{int}{frac}");
    let lead = all.len() - all.trim_start_matches('0').len();
    let digits = all.trim_matches('0');
    let k = i32::try_from(digits.len()).unwrap();
    let n = i32::try_from(int.len()).unwrap() - i32::try_from(lead).unwrap() + exp;
    let out = if k <= n && n <= 21 {
        format!("{digits}{}", "0".repeat(usize::try_from(n - k).unwrap()))
    } else if 0 < n && n <= 21 {
        let (a, b) = digits.split_at(usize::try_from(n).unwrap());
        format!("{a}.{b}")
    } else if -6 < n && n <= 0 {
        format!("0.{}{digits}", "0".repeat(usize::try_from(-n).unwrap()))
    } else {
        let e = n - 1;
        let sign = if e < 0 { '-' } else { '+' };
        let (first, rest) = digits.split_at(1);
        let rest = if rest.is_empty() {
            String::new()
        } else {
            format!(".{rest}")
        };
        format!("{first}{rest}e{sign}{}", e.abs())
    };
    format!("{sign}{out}")
}

fn canonical(t: &Tree) -> String {
    match t {
        Tree::Null => "null".to_owned(),
        Tree::Bool(b) => serde_json::to_string(b).unwrap(),
        Tree::UInt(n) => serde_json::to_string(n).unwrap(),
        Tree::Number(x) => ecmascript(*x),
        Tree::Str(s) => serde_json::to_string(s).unwrap(),
        Tree::Array(items) => format!(
            "[{}]",
            items.iter().map(canonical).collect::<Vec<_>>().join(",")
        ),
        Tree::Object(m) => format!(
            "{{{}}}",
            m.iter()
                .map(|(k, v)| format!("{}:{}", serde_json::to_string(k).unwrap(), canonical(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

#[test]
fn x_13_ecmascript_oracle_matches_known_forms() {
    for (x, form) in [
        (0.4, "0.4"),
        (1.0, "1"),
        (-1.5, "-1.5"),
        (1e-6, "0.000001"),
        (1e-7, "1e-7"),
        (1e20, "100000000000000000000"),
        (1e21, "1e+21"),
        (1.5e21, "1.5e+21"),
        (123_456.789, "123456.789"),
        (5e-324, "5e-324"),
    ] {
        assert_eq!(ecmascript(x), form, "{x}");
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn x_13_canonical_length_equals_the_independent_encoding(t in tree()) {
        let expected = canonical(&t);
        prop_assert!(serde_json::from_str::<serde_json::Value>(&expected).is_ok(), "{expected}");
        prop_assert_eq!(to_json(&t).canonical_len(), expected.len(), "{}", expected);
    }

    #[test]
    fn x_13_number_length_equals_the_ecmascript_form(x in number()) {
        prop_assert_eq!(Json::Number(x).canonical_len(), ecmascript(x).len(), "{}", x);
    }
}
