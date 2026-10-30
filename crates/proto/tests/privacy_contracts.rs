//! Every vector of `conformance/privacy/vectors/promise-diff.json` except the digest one (in `one-provenance`, which holds JCS): narrowing and widening, the change rule and the record's promise version (PV-19, INV-26).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_proto::ontology::Instant;
use one_proto::privacy::{
    Classification, PromiseChange, PromiseTuple, check_change, classify, governing_version,
};
use serde_json::Value;

fn load() -> Vec<Value> {
    let path = format!(
        "{}/../../conformance/privacy/vectors/promise-diff.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn tuples(v: &Value) -> Vec<PromiseTuple> {
    serde_json::from_value(v.clone()).unwrap()
}

fn class(v: &Value) -> Classification {
    serde_json::from_value(v.clone()).unwrap()
}

#[test]
fn pv_19_promise_diff_vectors() {
    let (mut diff, mut change, mut record) = (0, 0, 0);
    for v in load() {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        if input.get("old").is_some() {
            diff += 1;
            let got = classify(&tuples(&input["old"]), &tuples(&input["new"]));
            assert_eq!(got, class(&expected["classification"]), "{d}");
            assert_eq!(got.notice_required(), expected["notice_required"], "{d}");
            assert_eq!(
                got.reconsent_flag_required(),
                expected["reconsent_flag_required"],
                "{d}"
            );
        } else if input.get("change").is_some() {
            change += 1;
            let declared: PromiseChange = serde_json::from_value(input["change"].clone()).unwrap();
            let effective = input["effective_at"].as_str().map_or_else(
                || Instant::from_unix(i64::MAX / 2),
                |s| Instant::parse(s).unwrap(),
            );
            let got = check_change(class(&input["classification"]), &effective, &declared);
            assert!(!expected["accept"].as_bool().unwrap());
            assert_eq!(got.unwrap_err().as_str(), expected["reason"], "{d}");
        } else if input.get("record").is_some() {
            record += 1;
            let version = governing_version(
                u32::try_from(input["record"]["promise_version"].as_u64().unwrap()).unwrap(),
                u32::try_from(input["current_version"].as_u64().unwrap()).unwrap(),
            )
            .unwrap();
            let allowed = match version {
                1 => input["v1_allows"].as_bool().unwrap(),
                2 => input["v2_allows"].as_bool().unwrap(),
                other => panic!("version {other}"),
            };
            assert_eq!(allowed, expected["allowed"], "{d}");
        } else {
            assert!(input.get("promise").is_some(), "{d}");
        }
    }
    assert_eq!((diff, change, record), (11, 3, 2));
}

#[test]
fn inv_26_a_record_never_names_a_version_not_yet_in_force() {
    assert_eq!(governing_version(3, 2), None);
    assert_eq!(governing_version(0, 2), None);
    assert_eq!(governing_version(2, 2), Some(2));
}
