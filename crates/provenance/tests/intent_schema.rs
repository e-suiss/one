//! Every schema vector of `conformance/intent`: valid inputs round-trip byte-exact through serde, invalid ones are rejected (SEC-4, SEC-12, SEC-13, SEC-19, T-31, T-36 (2, 6)).

#![allow(clippy::unwrap_used, reason = "T-38")]

mod intent_common;

use intent_common::{Boon, description, fixture, json, round_trips, vectors};
use one_provenance::intent::{
    InputSchemaValidator, IntentModelOutput, ModelContext, Origin, OriginSet, Origins,
    QuarantineModelOutput, QuarantineOutput, TypedIntent, jcs,
};
use serde::Serialize;
use serde::de::DeserializeOwned;

fn check<T: Serialize + DeserializeOwned>(rel: &str) -> usize {
    let all = vectors(rel);
    for v in &all {
        let parsed = round_trips::<T>(&v["input"]);
        assert_eq!(
            parsed.is_ok(),
            v["valid"].as_bool().unwrap(),
            "{}: {:?}",
            description(v),
            parsed.err()
        );
    }
    all.len()
}

#[test]
fn sec_4_typed_intent_schema_vectors() {
    assert_eq!(check::<TypedIntent>("vectors/typed-intent.schema.json"), 20);
}

#[test]
fn sec_12_intent_model_output_schema_vectors() {
    assert_eq!(
        check::<IntentModelOutput>("vectors/intent-model-output.schema.json"),
        13
    );
}

#[test]
fn sec_13_quarantine_model_output_schema_vectors() {
    assert_eq!(
        check::<QuarantineModelOutput>("vectors/quarantine-model-output.schema.json"),
        14
    );
}

#[test]
fn t_36_quarantine_output_schema_vectors() {
    assert_eq!(
        check::<QuarantineOutput>("vectors/quarantine-output.schema.json"),
        18
    );
}

#[test]
fn sec_12_model_context_schema_vectors() {
    assert_eq!(
        check::<ModelContext>("vectors/model-context.schema.json"),
        27
    );
}

#[test]
fn t_31_fixture_input_schema_vectors() {
    let schema = fixture();
    let all = vectors("vectors/fixture-message-send-input.schema.json");
    for v in &all {
        assert_eq!(
            Boon.conforms(&schema, &json(&v["input"])),
            v["valid"].as_bool().unwrap(),
            "{}",
            description(v)
        );
    }
    assert_eq!(all.len(), 3);
}

#[test]
fn t_31_fixture_digest_is_the_jcs_sha256_the_vectors_pin() {
    let schema = fixture();
    assert_eq!(
        schema.digest().as_str(),
        "sha256:9208e7e569f2c65a5fce5f035c6b2c9fa8c22b5d95c46ac91472d2cd7d081a11"
    );
    assert_eq!(
        schema.id().as_str(),
        "https://suiss.app/schemas/one/intent/fixture/message-send-input/v1.json"
    );
    assert_eq!(
        jcs::sha256_digest(schema.document()).as_ref(),
        Some(schema.digest())
    );
}

#[test]
fn sec_19_origins_are_https_hosts_without_path() {
    for ok in [
        "https://mail.example.com",
        "https://a.b",
        "https://xn--bcher-kva.example:8443",
        "https://mail.example.com:1",
        "https://mail.example.com:444",
        "https://mail.example.com:65535",
    ] {
        assert!(Origin::new(ok).is_some(), "{ok}");
    }
    for bad in [
        "http://mail.example.com",
        "https://localhost",
        "https://Mail.example.com",
        "https://mail.example.com/",
        "https://mail.example.com/path?q=1",
        "https://user@mail.example.com",
        "https://mail.example.com:0443",
        "https://mail.example.com:443",
        "https://mail.example.com:65536",
        "https://mail.example.com:99999",
        "https://mail.example.com:",
        "https://mail.example.com:123456",
        "https://-a.example.com",
        "https://a..example.com",
        "wss://mail.example.com",
    ] {
        assert!(Origin::new(bad).is_none(), "{bad}");
    }
}

#[test]
fn sec_19_origins_normalise_to_the_canonical_form() {
    let canonical = Origin::new("https://mail.example.com").unwrap();
    for written in [
        "https://mail.example.com",
        "HTTPS://Mail.Example.COM",
        "https://mail.example.com/",
        "https://mail.example.com:443",
        "https://mail.example.com:443/",
    ] {
        assert_eq!(
            Origin::normalise(written).as_ref(),
            Some(&canonical),
            "{written}"
        );
    }
    for bad in [
        "http://mail.example.com",
        "https://mail.example.com/inbox",
        "https://mail.example.com?q=1",
        "https://mail.example.com#x",
        "https://ma\u{ef}l.example.com",
    ] {
        assert!(Origin::normalise(bad).is_none(), "{bad}");
    }
    assert_eq!(
        Origin::normalise("https://mail.example.com:8443")
            .unwrap()
            .as_str(),
        "https://mail.example.com:8443"
    );
}

#[test]
fn sec_19_origin_lists_hold_at_most_64_distinct_origins_compared_as_sets() {
    let origin = |i: usize| Origin::new(&format!("https://o{i}.example.com")).unwrap();
    let full: Vec<Origin> = (0..64).map(origin).collect();
    assert!(Origins::new(full.clone()).is_some());
    let mut over = full.clone();
    over.push(origin(64));
    assert!(Origins::new(over).is_none());
    assert!(Origins::new(vec![origin(1), origin(1)]).is_none());
    let wire = serde_json::json!({ "read": [], "write": (0..65).map(|i| format!("https://o{i}.example.com")).collect::<Vec<_>>() });
    assert!(serde_json::from_value::<OriginSet>(wire).is_err());
    let ab = Origins::new(vec![origin(1), origin(2)]).unwrap();
    let ba = Origins::new(vec![origin(2), origin(1)]).unwrap();
    assert_eq!(ab, ba);
    assert_ne!(ab, Origins::new(vec![origin(1)]).unwrap());
}
