//! Every vector of `conformance/tee/vectors/rebuild-diff.json`: a rebuild equal to the live structure in any order raises no alarm, and a missing, extra or changed entry each raises it with its count (OP-1 (2), OP-18).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use one_tee::domain::rebuild::{Diff, Entry, diff};
use serde_json::Value;

fn fixed<const N: usize>(v: &Value) -> [u8; N] {
    let s = v.as_str().unwrap();
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}

fn entries(v: &Value) -> Vec<Entry> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|e| Entry {
            id: fixed(&e["id"]),
            sources: e["sources"]
                .as_array()
                .unwrap()
                .iter()
                .map(|s| (fixed(&s[0]), u32::try_from(s[1].as_u64().unwrap()).unwrap()))
                .collect(),
            digest: fixed(&e["digest"]),
        })
        .collect()
}

#[test]
fn op_1_rebuild_diff_vectors() {
    let path = format!(
        "{}/../../conformance/tee/vectors/rebuild-diff.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let all: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for v in all.as_array().unwrap() {
        let d = v["description"].as_str().unwrap();
        let x = &v["expected"];
        let got = diff(
            &entries(&v["input"]["live"]),
            &entries(&v["input"]["rebuilt"]),
        );
        let want = Diff {
            missing: x["missing"].as_u64().unwrap(),
            extra: x["extra"].as_u64().unwrap(),
            changed: x["changed"].as_u64().unwrap(),
        };
        assert_eq!(got, want, "{d}");
        assert_eq!(got.alarm(), x["alarm"].as_bool().unwrap(), "{d}");
    }
}
