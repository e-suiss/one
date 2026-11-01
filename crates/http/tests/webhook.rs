//! Every vector of `conformance/webhook/vectors/webhook.json`: the shared Suiss webhook profile verifies a `v1a` signature under a listed key within five minutes and refuses a changed body or id, another key, an old or future timestamp and a `v1` HMAC alone (Access TN-136, E-3).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use one_http::webhook::{Delivery, verify};
use serde_json::Value;

#[test]
fn access_tn_136_webhook_vectors() {
    let path = format!(
        "{}/../../conformance/webhook/vectors/webhook.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let all: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for v in all.as_array().unwrap() {
        let d = v["description"].as_str().unwrap();
        let i = &v["input"];
        let keys: Vec<[u8; 32]> = i["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|k| {
                STANDARD
                    .decode(k.as_str().unwrap())
                    .unwrap()
                    .try_into()
                    .unwrap()
            })
            .collect();
        let delivery = Delivery {
            id: i["webhook_id"].as_str().unwrap(),
            timestamp: i["webhook_timestamp"].as_str().unwrap(),
            signature: i["webhook_signature"].as_str().unwrap(),
            body: i["body"].as_str().unwrap().as_bytes(),
        };
        let got = verify(&delivery, &keys, i["now"].as_i64().unwrap());
        assert_eq!(
            got.is_ok(),
            v["expected"]["valid"].as_bool().unwrap(),
            "{d}: {got:?}"
        );
    }
}
