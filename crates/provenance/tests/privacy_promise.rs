//! Every published privacy promise under `conformance/privacy/promise/`: its digest is the SHA-256 of its JCS form without `digest`, its version and address follow the file name, and each version is checked against the one before (PV-19, INV-26).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_proto::ontology::JsonValue;
use one_proto::privacy::{Promise, PromiseDigest, digest_input};
use one_provenance::intent::jcs::canonicalize;
use sha2::{Digest as _, Sha256};

fn dir() -> String {
    format!("{}/../../conformance/privacy", env!("CARGO_MANIFEST_DIR"))
}

fn digest(document: &JsonValue) -> PromiseDigest {
    let text = canonicalize(&digest_input(document).unwrap()).unwrap();
    PromiseDigest::from_sha256(&Sha256::digest(text.as_bytes()).into())
}

fn published() -> Vec<(JsonValue, Promise)> {
    let mut out = Vec::new();
    for n in 1_u32.. {
        let path = format!("{}/promise/v{n}.json", dir());
        let Ok(text) = std::fs::read_to_string(&path) else {
            break;
        };
        let document: JsonValue = serde_json::from_str(&text).unwrap();
        let promise: Promise = serde_json::from_str(&text).unwrap();
        assert_eq!(promise.version, n, "{path}");
        assert_eq!(promise.url, Promise::expected_url(n), "{path}");
        out.push((document, promise));
    }
    out
}

#[test]
fn pv_19_every_promise_carries_its_jcs_digest_and_follows_its_predecessor() {
    let promises = published();
    assert_ne!(promises.len(), 0);
    let extra = std::fs::read_dir(format!("{}/promise", dir()))
        .unwrap()
        .count();
    assert_eq!(
        extra,
        promises.len(),
        "promise files are v1.json, v2.json, ... without gaps"
    );
    let mut previous: Option<&Promise> = None;
    for (document, promise) in &promises {
        assert_eq!(digest(document), promise.digest, "v{}", promise.version);
        promise.check_succession(previous).unwrap();
        previous = Some(promise);
    }
}

#[test]
fn pv_19_digest_vector() {
    let path = format!("{}/vectors/promise-diff.json", dir());
    let vectors: Vec<serde_json::Value> =
        serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let mut seen = 0;
    for v in vectors
        .iter()
        .filter(|v| v["input"].get("promise").is_some())
    {
        let file = v["input"]["promise"].as_str().unwrap();
        let text = std::fs::read_to_string(format!("{}/{file}", dir())).unwrap();
        let document: JsonValue = serde_json::from_str(&text).unwrap();
        assert_eq!(
            digest(&document).as_str(),
            v["expected"]["digest"].as_str().unwrap()
        );
        seen += 1;
    }
    assert_eq!(seen, 1);
}
