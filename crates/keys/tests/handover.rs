//! Every vector of `conformance/keys/vectors/kek-device.json` and `permission-wrap.json`, and the attestation binding of `conformance/tee/vectors/hpke.json`: Secure Enclave, StrongBox and passkey copies of the KEK, the refusal of an operator-held wrap, and a DEK sealed only to an attested job key for one permission body and one class (PV-5, PV-61, PV-65, SEC-27).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

mod common;

use common::{fixed, hex, load, unhex};
use one_hpke::{Kem, KeyPair};
use one_keys::device::{
    EnclaveCopy, Holder, open_enclave_copy, passkey_wrapping_key, prf_input, seal_to_enclave,
    seal_to_enclave_with, unwrap_passkey_copy, wrap_for_device, wrap_for_passkey,
};
use one_keys::job_key::{
    AttestedJobKey, JobKeyError, SealedDek, open_dek, report_data, seal_dek, seal_dek_with,
};
use one_keys::seal::key_from_slice;
use one_proto::data_class::RetentionClass;
use serde_json::Value;
use suiss_crypto::secret::Secret;

fn secret(v: &Value) -> Secret<[u8; 32]> {
    key_from_slice(&unhex(v.as_str().unwrap())).unwrap()
}

fn bytes(v: &Value) -> Vec<u8> {
    unhex(v.as_str().unwrap())
}

#[test]
fn pv_5_kek_device_vectors() {
    let all = load("keys/vectors/kek-device.json");
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        match input["op"].as_str().unwrap() {
            "wrap_device" => match Holder::from_name(input["holder"].as_str().unwrap()) {
                Ok(Holder::SecureEnclave) => {
                    let h = &input["hpke"];
                    let ephemeral = KeyPair::from_private(Kem::P256, &bytes(&h["skEm"])).unwrap();
                    let kek_id = input["kek_id"].as_str().unwrap();
                    let kek = secret(&input["kek"]);
                    let copy =
                        seal_to_enclave_with(&ephemeral, kek_id, &kek, &bytes(&h["pkRm"])).unwrap();
                    assert_eq!(hex(&copy.enc), expected["pkEm"].as_str().unwrap(), "{d}");
                    assert_eq!(hex(&copy.ct), expected["ct"].as_str().unwrap(), "{d}");
                    let device = KeyPair::from_private(Kem::P256, &bytes(&h["skRm"])).unwrap();
                    let back = open_enclave_copy(&device, kek_id, &copy).unwrap();
                    assert!(back.ct_eq(&kek), "{d}");
                    assert!(
                        open_enclave_copy(&device, "kek_other", &copy).is_err(),
                        "{d}"
                    );
                }
                Ok(Holder::StrongBox | Holder::Tpm) => {
                    let wrapped =
                        wrap_for_device(&secret(&input["device_key"]), &secret(&input["kek"]))
                            .unwrap();
                    assert_eq!(hex(&wrapped), expected["wrapped"].as_str().unwrap(), "{d}");
                }
                Ok(other) => panic!("{d}: unexpected holder {other:?}"),
                Err(e) => assert_eq!(e.as_str(), expected["error"].as_str().unwrap(), "{d}"),
            },
            "wrap_passkey" => {
                assert_eq!(
                    hex(&prf_input()),
                    input["prf_eval_first"].as_str().unwrap(),
                    "{d}"
                );
                let prf = secret(&input["prf_output"]);
                let kek_id = input["kek_id"].as_str().unwrap();
                let key = passkey_wrapping_key(&prf, kek_id).unwrap();
                assert_eq!(
                    hex(key.expose()),
                    expected["wrapping_key"].as_str().unwrap(),
                    "{d}"
                );
                let kek = secret(&input["kek"]);
                let wrapped = wrap_for_passkey(&prf, kek_id, &kek).unwrap();
                assert_eq!(hex(&wrapped), expected["wrapped"].as_str().unwrap(), "{d}");
                assert!(
                    unwrap_passkey_copy(&prf, kek_id, &wrapped)
                        .unwrap()
                        .ct_eq(&kek)
                );
                assert!(
                    unwrap_passkey_copy(&prf, "kek_other", &wrapped).is_err(),
                    "{d}"
                );
            }
            "prf_input" => {
                assert_eq!(
                    hex(&prf_input()),
                    expected["prf_eval_first"].as_str().unwrap(),
                    "{d}"
                );
            }
            op => panic!("{d}: unknown op {op}"),
        }
    }
    assert_eq!(all.len(), 5);
}

#[test]
fn pv_5_a_fresh_enclave_copy_opens_only_on_its_device() {
    let device = KeyPair::generate(Kem::P256).unwrap();
    let other = KeyPair::generate(Kem::P256).unwrap();
    let kek = Secret::new([5_u8; 32]);
    let copy: EnclaveCopy = seal_to_enclave("kek_1", &kek, &device.public_key().unwrap()).unwrap();
    assert!(
        open_enclave_copy(&device, "kek_1", &copy)
            .unwrap()
            .ct_eq(&kek)
    );
    assert!(open_enclave_copy(&other, "kek_1", &copy).is_err());
}

fn class(v: &Value) -> RetentionClass {
    RetentionClass::from_name(v.as_str().unwrap()).unwrap()
}

#[test]
fn pv_65_permission_wrap_vectors() {
    let all = load("keys/vectors/permission-wrap.json");
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        match input["op"].as_str().unwrap() {
            "seal_dek" if input["hpke"].is_object() => {
                let h = &input["hpke"];
                let body = bytes(&input["permission_body"]);
                assert_eq!(
                    hex(&one_keys::domain::cose::body_digest(&body)),
                    h["info"].as_str().unwrap(),
                    "{d}"
                );
                let pk = bytes(&h["pkRm"]);
                let job = AttestedJobKey::bind(&pk, &report_data(&pk)).unwrap();
                let ephemeral = KeyPair::from_private(Kem::X25519, &bytes(&h["skEm"])).unwrap();
                let dek = secret(&input["dek"]);
                let c = class(&input["class"]);
                let sealed = seal_dek_with(&ephemeral, &job, &body, c, &dek).unwrap();
                assert_eq!(hex(&sealed.enc), expected["pkEm"].as_str().unwrap(), "{d}");
                assert_eq!(hex(&sealed.ct), expected["ct"].as_str().unwrap(), "{d}");
                let tee = KeyPair::from_private(Kem::X25519, &bytes(&h["skRm"])).unwrap();
                assert!(
                    open_dek(&tee, &body, c, &sealed).unwrap().ct_eq(&dek),
                    "{d}"
                );
            }
            "seal_dek" => {
                let fleet = KeyPair::generate(Kem::X25519)
                    .unwrap()
                    .public_key()
                    .unwrap();
                let other = KeyPair::generate(Kem::X25519)
                    .unwrap()
                    .public_key()
                    .unwrap();
                let got = AttestedJobKey::bind(&fleet, &report_data(&other)).map(|_| ());
                assert_eq!(
                    got.map_err(JobKeyError::as_str),
                    Err(expected["error"].as_str().unwrap()),
                    "{d}"
                );
            }
            "open_dek" => {
                let tee = KeyPair::from_private(Kem::X25519, &bytes(&input["skRm"])).unwrap();
                let sealed = SealedDek {
                    enc: bytes(&input["enc"]),
                    ct: bytes(&input["ct"]),
                };
                let mut info_body = None;
                for s in &all {
                    if s["input"]["op"] == "seal_dek" && s["input"]["hpke"]["info"] == input["info"]
                    {
                        info_body = Some(bytes(&s["input"]["permission_body"]));
                    }
                }
                let body = info_body.unwrap_or_else(|| b"another permission body".to_vec());
                let got = open_dek(&tee, &body, class(&input["class"]), &sealed).map(|_| ());
                assert_eq!(
                    got.map_err(JobKeyError::as_str),
                    Err(expected["error"].as_str().unwrap()),
                    "{d}"
                );
            }
            op => panic!("{d}: unknown op {op}"),
        }
    }
    assert_eq!(all.len(), 5);
}

#[test]
fn sec_27_report_data_binds_the_job_key() {
    for v in load("tee/vectors/hpke.json") {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let Some(pk) = input["node_public_key"].as_str().map(unhex) else {
            continue;
        };
        let expected = &v["expected"];
        if let Some(want) = expected["report_data"].as_str() {
            assert_eq!(hex(&report_data(&pk)), want, "{d}");
            assert!(AttestedJobKey::bind(&pk, &fixed(want)).is_ok(), "{d}");
        } else if let Some(rd) = input["report_data"].as_str() {
            assert_eq!(
                AttestedJobKey::bind(&pk, &fixed(rd)),
                Err(JobKeyError::RecipientNotAttested),
                "{d}"
            );
        }
    }
}

#[test]
fn pv_65_a_dek_opens_only_for_its_permission_and_class() {
    let tee = KeyPair::generate(Kem::X25519).unwrap();
    let pk = tee.public_key().unwrap();
    let job = AttestedJobKey::bind(&pk, &report_data(&pk)).unwrap();
    let dek = Secret::new([9_u8; 32]);
    let sealed = seal_dek(&job, b"body", RetentionClass::OneMemory, &dek).unwrap();
    assert!(
        open_dek(&tee, b"body", RetentionClass::OneMemory, &sealed)
            .unwrap()
            .ct_eq(&dek)
    );
    assert!(open_dek(&tee, b"other", RetentionClass::OneMemory, &sealed).is_err());
    assert!(open_dek(&tee, b"body", RetentionClass::OneModel, &sealed).is_err());
}
