//! The Access Decision Profile client: every vector of `conformance/access/vectors/adp-decision.json` and `discovery.json`, the request body against L1-ADP-5 to L1-ADP-8, and an Actor Intent Statement One signs that Access's own verifier accepts for exactly that request (E-2, E-3, E-14, A-2, SEC-1).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use std::collections::BTreeMap;

use access_kernel::ais::{AisError, Expected, verify};
use access_kernel::combinator::{Capacity, Mode};
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue, intent_digest};
use access_kernel::json::b64url_encode;
use access_kernel::meta::{ExerciseBasis, HoldingRef};
use access_kernel::model::{ActionRef, EqValue, Id, ResourceRef, Window};
use one_access_client::adp::{AdpError, Evaluation};
use one_access_client::decision::{Decision, NoAllow, decide};
use one_access_client::discovery::{DiscoveryError, read};
use one_access_client::{access_kernel, ais};
use serde_json::{Value, json};
use suiss_crypto::digest::Digest;
use suiss_crypto::signer::{Signer as _, SoftSigner};

fn vectors(name: &str) -> Vec<Value> {
    let path = format!(
        "{}/../../conformance/access/vectors/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(path).unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn mode(word: &str) -> Mode {
    match word {
        "commit" => Mode::Commit,
        "continue" => Mode::Continue,
        "check" => Mode::Check,
        other => panic!("mode {other}"),
    }
}

#[test]
fn e_14_decision_vectors() {
    for v in vectors("adp-decision.json") {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let x = &v["expected"];
        let body = input.get("raw").map_or_else(
            || serde_json::to_vec(&input["body"]).unwrap(),
            |r| r.as_str().unwrap().as_bytes().to_vec(),
        );
        let status = u16::try_from(input["status"].as_u64().unwrap()).unwrap();
        let got = decide(mode(input["mode"].as_str().unwrap()), status, &body);
        assert_eq!(got.allows(), x["allows"].as_bool().unwrap(), "{d}");
        match (x["decision"].as_str().unwrap(), &got) {
            ("allow", Decision::Allow { .. }) => {}
            ("deny", Decision::Deny { blockers }) => {
                assert_eq!(
                    u64::try_from(blockers.len()).ok(),
                    x["blockers"].as_u64(),
                    "{d}"
                );
            }
            ("require_action", Decision::RequireAction { blockers, unmet }) => {
                assert_eq!(
                    u64::try_from(blockers.len()).ok(),
                    x["blockers"].as_u64(),
                    "{d}"
                );
                assert_eq!(u64::try_from(unmet.len()).ok(), x["unmet"].as_u64(), "{d}");
            }
            ("no_allow", Decision::NoAllow(reason)) => {
                match (x["reason"].as_str().unwrap(), reason) {
                    ("malformed", NoAllow::Malformed) => {}
                    ("status", NoAllow::Status(s, code)) => {
                        assert_eq!(Some(u64::from(*s)), x["status"].as_u64(), "{d}");
                        assert_eq!(code.as_deref(), x["code"].as_str(), "{d}");
                    }
                    other => panic!("{d}: {other:?}"),
                }
            }
            other => panic!("{d}: {other:?}"),
        }
    }
}

#[test]
fn e_3_discovery_vectors() {
    for v in vectors("discovery.json") {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let body = serde_json::to_vec(&input["body"]).unwrap();
        let got = read(input["issuer"].as_str().unwrap(), &body);
        let x = &v["expected"];
        match (x.get("error").and_then(Value::as_str), got) {
            (None, Ok(doc)) => assert_eq!(doc.evaluation, x["evaluation"].as_str().unwrap(), "{d}"),
            (Some("issuer"), Err(DiscoveryError::Issuer))
            | (Some("origin"), Err(DiscoveryError::Origin))
            | (Some("capability"), Err(DiscoveryError::Capability))
            | (Some("malformed"), Err(DiscoveryError::Malformed)) => {}
            (want, got) => panic!("{d}: want {want:?}, got {got:?}"),
        }
    }
}

fn intent() -> IntentEnvelope {
    let mut params = BTreeMap::new();
    params.insert(
        "amount".to_owned(),
        ParamValue::Amount {
            value: 1250,
            unit: "TRY".to_owned(),
        },
    );
    params.insert(
        "to".to_owned(),
        ParamValue::Eq(EqValue::Text("shop:item-1".to_owned())),
    );
    IntentEnvelope {
        action: ActionRef {
            namespace: "shop".to_owned(),
            name: "order".to_owned(),
            major: 1,
            schema: Digest([3; 32]),
        },
        resources: vec![ResourceRef {
            namespace: "shop".to_owned(),
            path: vec!["cart".to_owned(), "7".to_owned()],
            incarnation: 0,
        }],
        params,
        opaque: BTreeMap::new(),
        recipient: None,
        purpose: None,
        context: ContextRefs {
            step: Some(Digest([9; 32])),
            ..ContextRefs::default()
        },
        validity: Window {
            from: 1_000,
            until: 61_000,
        },
    }
}

fn basis() -> ExerciseBasis {
    ExerciseBasis::Holding(HoldingRef {
        grant: Id([1; 16]),
        holder: Id([2; 16]),
        since: 42,
    })
}

#[test]
fn e_14_request_body_follows_the_profile() {
    let intent = intent();
    let nonce = [5_u8; 16];
    let request = Evaluation {
        domain: Digest([4; 32]),
        mode: Mode::Commit,
        nonce: &nonce,
        ais: Some(b"sign1"),
        basis: basis(),
        capacity: Capacity::Own,
        intent: &intent,
        exercise: None,
    };
    let body = request.to_json().unwrap();
    assert_eq!(body["action"]["name"], "order");
    assert_eq!(body["resource"], json!({ "type": "shop", "id": "cart/7" }));
    let c = &body["context"];
    assert_eq!(c["domain"], b64url_encode(&[4; 32]));
    assert_eq!(c["mode"], "commit");
    assert_eq!(c["nonce"], b64url_encode(&nonce));
    assert_eq!(c["ais"], b64url_encode(b"sign1"));
    assert_eq!(c["capacity"], "own");
    assert_eq!(
        c["basis"],
        json!({ "holding": { "grant": b64url_encode(&[1; 16]), "holder": b64url_encode(&[2; 16]), "since": 42 } })
    );
    assert_eq!(
        c["intent"]["params"],
        json!({ "amount": { "amount": { "value": 1250, "unit": "TRY" } }, "to": { "eq": "shop:item-1" } })
    );
    assert_eq!(
        c["intent"]["context"],
        json!({ "step": b64url_encode(&[9; 32]) })
    );
    assert_eq!(
        c["intent"]["validity"],
        json!({ "from": 1000, "until": 61000 })
    );
    assert!(c.get("exercise").is_none());
    assert!(c["intent"].get("digest").is_none());
}

#[test]
fn e_14_a_malformed_request_is_never_sent() {
    let intent = intent();
    let short = [5_u8; 15];
    let base = Evaluation {
        domain: Digest([4; 32]),
        mode: Mode::Commit,
        nonce: &short,
        ais: None,
        basis: basis(),
        capacity: Capacity::Own,
        intent: &intent,
        exercise: None,
    };
    assert_eq!(base.to_json(), Err(AdpError::Nonce));
    let nonce = [5_u8; 16];
    let cont = Evaluation {
        nonce: &nonce,
        mode: Mode::Continue,
        ..base.clone()
    };
    assert_eq!(cont.to_json(), Err(AdpError::Exercise));
    let mut empty = intent.clone();
    empty.resources.clear();
    let none = Evaluation {
        nonce: &nonce,
        intent: &empty,
        ..base
    };
    assert_eq!(none.to_json(), Err(AdpError::NoResource));
}

#[test]
fn e_14_access_accepts_the_statement_one_signs_and_only_for_that_request() {
    let intent = intent();
    let nonce = [6_u8; 32];
    for (signer, _) in [
        SoftSigner::generate_ed25519().unwrap(),
        SoftSigner::generate_p256().unwrap(),
    ] {
        let request = Evaluation {
            domain: Digest([4; 32]),
            mode: Mode::Commit,
            nonce: &nonce,
            ais: None,
            basis: basis(),
            capacity: Capacity::Own,
            intent: &intent,
            exercise: None,
        };
        let sign1 = ais::sign(&signer, "pep:one-server", &request, 5_000).unwrap();
        let digest = intent_digest(&intent).unwrap();
        let b = basis();
        let expected = Expected {
            domain: &Digest([4; 32]),
            nonce: &nonce,
            intent: &digest,
            mode: Mode::Commit,
            pep: "pep:one-server",
            capacity: Capacity::Own,
            basis: &b,
            exercise: None,
        };
        let key = signer.public_key();
        assert!(verify(&sign1, &key, &expected, 5_000).is_ok());
        let other = Expected {
            pep: "pep:someone-else",
            ..expected
        };
        assert!(matches!(
            verify(&sign1, &key, &other, 5_000),
            Err(AisError::Mismatch("pep"))
        ));
        let mut changed = intent.clone();
        changed.validity.until = 62_000;
        let changed_digest = intent_digest(&changed).unwrap();
        let other = Expected {
            intent: &changed_digest,
            ..expected
        };
        assert!(matches!(
            verify(&sign1, &key, &other, 5_000),
            Err(AisError::Mismatch("intent"))
        ));
    }
}

fn boundary(id: &str) -> (Vec<String>, Vec<String>) {
    let path = format!(
        "{}/../../conformance/boundaries/fields.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let t: toml::Table = std::fs::read_to_string(path).unwrap().parse().unwrap();
    let strings = |v: &toml::Value| -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    };
    let b = t["boundary"]
        .as_array()
        .unwrap()
        .iter()
        .find(|b| b["id"].as_str() == Some(id))
        .unwrap();
    (strings(&b["fields"]), strings(&t["forbidden"]))
}

fn walk(v: &Value, named_by_schema: bool, allowed: &[String], forbidden: &[String]) {
    match v {
        Value::Object(m) => {
            for (k, inner) in m {
                assert!(!forbidden.contains(k), "forbidden field {k}");
                assert!(
                    named_by_schema || allowed.contains(k),
                    "field {k} is not in the access boundary"
                );
                walk(inner, k == "params" || k == "opaque", allowed, forbidden);
            }
        }
        Value::Array(items) => {
            for item in items {
                walk(item, false, allowed, forbidden);
            }
        }
        _ => {}
    }
}

#[test]
fn e_37_the_request_carries_only_access_boundary_fields() {
    let (allowed, forbidden) = boundary("access");
    let mut intent = intent();
    intent.recipient = Some(Id([8; 16]));
    intent.purpose = Some(access_kernel::model::PurposeRef::Code("order".to_owned()));
    intent.opaque.insert("note".to_owned(), Digest([7; 32]));
    let nonce = [5_u8; 16];
    for (mode, exercise) in [
        (Mode::Commit, None),
        (Mode::Continue, Some(Digest([1; 32]))),
        (Mode::Check, None),
    ] {
        let request = Evaluation {
            domain: Digest([4; 32]),
            mode,
            nonce: &nonce,
            ais: Some(b"sign1"),
            basis: basis(),
            capacity: Capacity::For(Id([3; 16])),
            intent: &intent,
            exercise,
        };
        walk(&request.to_json().unwrap(), false, &allowed, &forbidden);
    }
}
