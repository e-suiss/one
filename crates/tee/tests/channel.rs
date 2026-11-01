//! Every vector of `conformance/tee/vectors/hpke.json` through the request channel: the HPKE request to an admitted node, the route as additional data, the response under the request's export, and the refusals before attestation and for a key the report does not carry (SEC-27, PV-11).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use one_hpke::{Kem, KeyPair, report_data};
use one_proto::ontology::Instant;
use one_tee::channel::{
    AttestedNode, ChannelError, Request, ResponseKey, open_request, request_info, route_aad,
    seal_request, seal_request_with,
};
use one_tee::domain::attestation::{Evidence, MinTcb, Policy, Rejection, SnpTcb, Tcb};
use one_tee::domain::roots::Profile;
use serde_json::Value;

const NOW: &str = "2026-11-01T00:00:00Z";
const MEASUREMENT: [u8; 48] = [7; 48];
const ZERO: SnpTcb = SnpTcb {
    bootloader: 0,
    tee: 0,
    snp: 0,
    microcode: 0,
};

fn load() -> Vec<Value> {
    let full = format!(
        "{}/../../conformance/tee/vectors/hpke.json",
        env!("CARGO_MANIFEST_DIR")
    );
    serde_json::from_str::<Value>(&std::fs::read_to_string(full).unwrap())
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn bytes(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap())
}

fn hex(b: &[u8]) -> String {
    b.iter().fold(String::new(), |mut s, x| {
        s.push_str(&format!("{x:02x}"));
        s
    })
}

fn evidence(report: [u8; 64]) -> Evidence {
    Evidence {
        eat_profile: one_tee::domain::attestation::EAT_PROFILE.to_owned(),
        iat: Instant::parse(NOW).unwrap(),
        platform: "amd-sev-snp".to_owned(),
        measurement: MEASUREMENT,
        tcb: Tcb::Snp(ZERO),
        report_data: report,
        dbgstat: "disabled-since-boot".to_owned(),
        chain_root: "amd-ark-genoa".to_owned(),
        gpus: Vec::new(),
    }
}

fn admit(public: &[u8], report: [u8; 64]) -> Result<AttestedNode, ChannelError> {
    let log = [MEASUREMENT];
    let unused = [0_u8; 64];
    AttestedNode::admit(
        public,
        &evidence(report),
        &Policy {
            profile: Profile::Release,
            now: Instant::parse(NOW).unwrap(),
            max_age_secs: 300,
            min_tcb: MinTcb::Snp(ZERO),
            log: &log,
            expected_report_data: &unused,
            gpu_log: &[],
            gpu_models: &[],
        },
    )
}

#[test]
fn sec_27_request_channel_vectors() {
    let all = load();
    let mut response_key = None;
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        if let Some(h) = input["hpke"].as_object() {
            let pk = bytes(&h["pkRm"]);
            assert_eq!(hex(&request_info(&pk)), h["info"].as_str().unwrap(), "{d}");
            let node = admit(&pk, report_data(&pk)).unwrap();
            let ephemeral = KeyPair::from_private(Kem::X25519, &bytes(&h["skEm"])).unwrap();
            let aad = bytes(&h["aad"]);
            let (request, response) =
                seal_request_with(&ephemeral, &node, &aad, &bytes(&h["pt"])).unwrap();
            assert_eq!(hex(&request.enc), expected["pkEm"].as_str().unwrap(), "{d}");
            assert_eq!(hex(&request.ct), expected["ct"].as_str().unwrap(), "{d}");
            let tee = KeyPair::from_private(Kem::X25519, &bytes(&h["skRm"])).unwrap();
            let (plain, inside) = open_request(&tee, &request, &aad).unwrap();
            assert_eq!(*plain, bytes(&h["pt"]), "{d}");
            assert_eq!(inside.expose(), response.expose(), "{d}");
            assert!(open_request(&tee, &request, b"other route").is_err(), "{d}");
            if let Some(x) = expected["exports"].as_array().and_then(|a| a.first()) {
                assert_eq!(
                    hex(response.expose()),
                    x["exported_value"].as_str().unwrap(),
                    "{d}"
                );
                response_key = Some((response.expose().to_vec(), request.enc.clone()));
            }
        } else if let Some(key) = input["response_key"].as_str() {
            let (want_key, enc) = response_key.clone().unwrap();
            assert_eq!(hex(&want_key), key, "{d}");
            let response = ResponseKey::from_parts(&want_key, &enc);
            let mut aad = b"one/tee/response/v1\0".to_vec();
            aad.extend_from_slice(&enc);
            assert_eq!(hex(&aad), input["aad"].as_str().unwrap(), "{d}");
            let nonce: [u8; 12] = bytes(&input["nonce"]).try_into().unwrap();
            let plain = response.open(nonce, &bytes(&expected["ct"])).unwrap();
            assert_eq!(*plain, bytes(&input["pt"]), "{d}");
            let other = ResponseKey::from_parts(&want_key, b"another request");
            assert!(other.open(nonce, &bytes(&expected["ct"])).is_err(), "{d}");
        } else if let Some(want) = expected["report_data"].as_str() {
            let pk = bytes(&input["node_public_key"]);
            assert_eq!(hex(&report_data(&pk)), want, "{d}");
        } else {
            let pk = bytes(&input["node_public_key"]);
            let report: [u8; 64] = match input["report_data"].as_str() {
                Some(rd) => unhex(rd).try_into().unwrap(),
                None => [0; 64],
            };
            assert_eq!(expected["send"], false, "{d}");
            assert_eq!(
                admit(&pk, report),
                Err(ChannelError::NotAttested(Rejection::ReportDataMismatch)),
                "{d}"
            );
        }
    }
    assert!(response_key.is_some());
}

#[test]
fn sec_27_a_response_round_trips_and_stays_with_its_request() {
    let tee = KeyPair::generate(Kem::X25519).unwrap();
    let pk = tee.public_key().unwrap();
    let node = admit(&pk, report_data(&pk)).unwrap();
    let aad = route_aad("retrieve");
    let (request, response) = seal_request(&node, &aad, b"query").unwrap();
    let (plain, inside) = open_request(&tee, &request, &aad).unwrap();
    assert_eq!(*plain, b"query");
    let (nonce, ct) = inside.seal(b"answer").unwrap();
    assert_eq!(*response.open(nonce, &ct).unwrap(), b"answer");
    let (second, _) = seal_request(&node, &aad, b"query").unwrap();
    assert_ne!(second.enc, request.enc);
    let forged = Request {
        enc: second.enc,
        ct: request.ct,
    };
    assert!(open_request(&tee, &forged, &aad).is_err());
}

#[test]
fn pv_11_stale_evidence_admits_no_node() {
    let pk = KeyPair::generate(Kem::X25519)
        .unwrap()
        .public_key()
        .unwrap();
    let mut e = evidence(report_data(&pk));
    e.iat = Instant::parse("2026-10-01T00:00:00Z").unwrap();
    let log = [MEASUREMENT];
    let unused = [0_u8; 64];
    let got = AttestedNode::admit(
        &pk,
        &e,
        &Policy {
            profile: Profile::Release,
            now: Instant::parse(NOW).unwrap(),
            max_age_secs: 300,
            min_tcb: MinTcb::Snp(ZERO),
            log: &log,
            expected_report_data: &unused,
            gpu_log: &[],
            gpu_models: &[],
        },
    );
    assert_eq!(got, Err(ChannelError::NotAttested(Rejection::Stale)));
}
