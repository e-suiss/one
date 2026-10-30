//! Every schema vector of `conformance/recovery/vectors/recovery-method.schema.json` through the typed recovery path (PV-12, PV-14, Access E52 (2)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_proto::recovery::RecoveryMethod;
use serde_json::Value;

#[test]
fn pv_12_recovery_method_schema_vectors() {
    let path = format!(
        "{}/../../conformance/recovery/vectors/recovery-method.schema.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let vectors: Vec<Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let (mut valid, mut invalid) = (0, 0);
    for v in vectors {
        let d = v["description"].as_str().unwrap();
        let parsed = serde_json::from_value::<RecoveryMethod>(v["input"].clone());
        if v["valid"].as_bool().unwrap() {
            let typed = parsed.unwrap_or_else(|e| panic!("rejected: {d}: {e}"));
            assert_eq!(
                serde_json::to_value(&typed).unwrap(),
                v["input"],
                "round trip: {d}"
            );
            valid += 1;
        } else {
            assert!(parsed.is_err(), "accepted: {d}");
            invalid += 1;
        }
    }
    assert_eq!((valid, invalid), (6, 10));
}
