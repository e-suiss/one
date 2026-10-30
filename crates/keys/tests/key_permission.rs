//! Every vector of `conformance/keys/vectors/key-permission.json`: the deterministic body and its COSE form, decoding, admission at start and at resume, and the job queue row (PV-65, A-13, T-27 (7), Access E31, Access E59).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

mod common;

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::time::Duration;

use common::{diag, encode, fixed, hex, load, unhex};
use one_keys::app::{Attested, CheckError, SignedPermission, check};
use one_keys::domain::cose::{PROTECTED, body_digest, cose_sign1, sig_structure};
use one_keys::domain::permission::{JobContext, MandateState, Refusal, admit, queue_row};
use one_keys::ports::{LiveState, PermissionSignature, PermissionStatus};
use one_parse::{Limits, ParseError};
use one_proto::data_class::RetentionClass;
use one_proto::key_permission::{PermissionBody, PermissionId};
use one_provenance::ExternalSource;
use one_runtime::UnixNanos;
use one_testkit::VirtualClock;
use serde_json::Value;

const PATH: &str = "keys/vectors/key-permission.json";

fn decode(body_diag: &str) -> Result<PermissionBody, ParseError> {
    let bytes = encode(&diag(body_diag));
    one_parse::key_permission::parse(&bytes, &Limits::DEFAULT, ExternalSource::One)
        .map(one_provenance::Untrusted::into_value)
}

fn mandate(v: &Value) -> Option<MandateState> {
    match v.as_str() {
        None => None,
        Some("active") => Some(MandateState::Active),
        Some("revoked") => Some(MandateState::Revoked),
        Some("narrowed") => Some(MandateState::Narrowed),
        Some("expired") => Some(MandateState::Expired),
        Some(other) => panic!("mandate state {other}"),
    }
}

fn shredded(v: &Value) -> Vec<RetentionClass> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|c| RetentionClass::from_name(c.as_str().unwrap()).unwrap())
        .collect()
}

#[test]
fn pv_65_key_permission_vectors() {
    let mut ops: BTreeMap<String, usize> = BTreeMap::new();
    for v in load(PATH) {
        let description = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        let op = input["op"].as_str().unwrap();
        *ops.entry(op.to_owned()).or_default() += 1;
        let body_diag = input["body_diag"].as_str().unwrap();
        match op {
            "encode" => {
                let body = decode(body_diag).unwrap();
                let bytes = body.encode();
                assert_eq!(
                    hex(&bytes),
                    expected["body"].as_str().unwrap(),
                    "{description}"
                );
                assert_eq!(
                    hex(&body_digest(&bytes)),
                    expected["body_digest"].as_str().unwrap(),
                    "{description}"
                );
                if let Some(protected) = expected["protected"].as_str() {
                    assert_eq!(hex(&PROTECTED), protected);
                    assert_eq!(
                        hex(&sig_structure(&bytes)),
                        expected["sig_structure"].as_str().unwrap()
                    );
                    let signature: [u8; 64] = fixed(expected["signature"].as_str().unwrap());
                    let kid = unhex(input["kid"].as_str().unwrap());
                    assert_eq!(
                        hex(&cose_sign1(&kid, &bytes, &signature)),
                        expected["cose_sign1"].as_str().unwrap()
                    );
                }
            }
            "decode" => {
                assert_eq!(expected["reason"], "not_deterministic", "{description}");
                assert!(
                    matches!(decode(body_diag), Err(ParseError::NonCanonical(_))),
                    "{description}"
                );
            }
            "admit" | "resume" => {
                let body = decode(body_diag).unwrap();
                let state = &input["state"];
                let measurement: [u8; 48] = fixed(state["attested_measurement"].as_str().unwrap());
                let job_key: [u8; 32] = fixed(state["attested_job_key_digest"].as_str().unwrap());
                let shredded = shredded(&state["shredded_classes"]);
                let ctx = JobContext {
                    now: state["now"].as_u64().unwrap(),
                    signature_valid: state["signature"] == "valid",
                    attested_measurement: &measurement,
                    attested_job_key_digest: &job_key,
                    withdrawn: state["withdrawn"].as_bool().unwrap(),
                    mandate: mandate(&state["mandate"]),
                    shredded: &shredded,
                };
                let got = admit(&body, &ctx);
                if expected["admit"].as_bool().unwrap() {
                    assert!(got.is_ok(), "{description}: {got:?}");
                } else {
                    let refusal = got.unwrap_err();
                    assert_eq!(refusal.as_str(), expected["reason"], "{description}");
                    if let Some(z) = expected["zeroize"].as_bool() {
                        assert_eq!(refusal.zeroizes(), z, "{description}");
                    }
                }
            }
            "job_row" => {
                let body = decode(body_diag).unwrap();
                let row = queue_row(&body);
                let plain = expected["plain"].as_object().unwrap();
                assert_eq!(plain.len(), 1, "{description}");
                assert_eq!(
                    row.permission_id.to_string(),
                    plain["permission_id"].as_str().unwrap()
                );
            }
            other => panic!("unknown op {other}"),
        }
    }
    let counts: Vec<(&str, usize)> = ops.iter().map(|(k, v)| (k.as_str(), *v)).collect();
    assert_eq!(
        counts,
        [
            ("admit", 18),
            ("decode", 1),
            ("encode", 2),
            ("job_row", 1),
            ("resume", 1)
        ]
    );
}

struct Signer(bool);

impl PermissionSignature for Signer {
    fn verify(&self, kid: &[u8], sig_structure: &[u8], _: &[u8; 64]) -> bool {
        self.0 && kid == b"kb-test-instance-1" && sig_structure.starts_with(&[0x84])
    }
}

struct Access(LiveState);

impl PermissionStatus for Access {
    type Error = Infallible;

    fn live_state(&self, _: &PermissionId) -> Result<LiveState, Infallible> {
        Ok(self.0.clone())
    }
}

#[test]
fn pv_65_signed_permission_is_checked_through_the_ports() {
    let v = &load(PATH)[0];
    let body = decode(v["input"]["body_diag"].as_str().unwrap()).unwrap();
    let payload = body.encode();
    let signature: [u8; 64] = fixed(v["expected"]["signature"].as_str().unwrap());
    let kid = unhex(v["input"]["kid"].as_str().unwrap());
    let permission = SignedPermission {
        body: &body,
        payload: &payload,
        kid: &kid,
        signature: &signature,
    };
    let attested = Attested {
        measurement: &body.tee_measurement,
        job_key_digest: &body.job_key_digest,
    };
    let live = Access(LiveState {
        withdrawn: false,
        mandate: None,
        shredded: Vec::new(),
    });
    let clock = VirtualClock::new(UnixNanos(1_793_584_800_000_000_000));
    assert!(check(&clock, &Signer(true), &live, &permission, &attested).is_ok());
    assert_eq!(
        check(&clock, &Signer(false), &live, &permission, &attested),
        Err(CheckError::Refused(Refusal::Signature))
    );
    let mut other = payload.clone();
    other.push(0);
    let tampered = SignedPermission {
        payload: &other,
        ..permission
    };
    assert_eq!(
        check(&clock, &Signer(true), &live, &tampered, &attested),
        Err(CheckError::Refused(Refusal::Signature))
    );
    assert!(clock.advance(Duration::from_hours(24)));
    assert_eq!(
        check(&clock, &Signer(true), &live, &permission, &attested),
        Err(CheckError::Refused(Refusal::Expired))
    );
}
