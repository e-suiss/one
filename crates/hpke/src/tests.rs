#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::format_collect,
    reason = "T-38"
)]

use serde_json::Value;

use super::*;

fn load(path: &str) -> Vec<Value> {
    let full = format!("{}/../../conformance/{path}", env!("CARGO_MANIFEST_DIR"));
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

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn field(v: &Value, k: &str) -> Vec<u8> {
    unhex(v[k].as_str().unwrap_or(""))
}

fn check_seal(h: &Value, expected: &Value, pt: &[u8], d: &str) {
    let kem = Kem::from_id(u16::try_from(h["kem_id"].as_u64().unwrap()).unwrap()).unwrap();
    assert_eq!(h["kdf_id"].as_u64(), Some(u64::from(KDF_ID)), "{d}");
    assert_eq!(h["aead_id"].as_u64(), Some(u64::from(AEAD_ID)), "{d}");
    assert_eq!(h["mode"].as_u64(), Some(0), "{d}");
    let ephemeral = KeyPair::from_private(kem, &field(h, "skEm")).unwrap();
    let recipient = KeyPair::from_private(kem, &field(h, "skRm")).unwrap();
    assert_eq!(
        hex(&recipient.public_key().unwrap()),
        h["pkRm"].as_str().unwrap(),
        "{d}"
    );
    let info = field(h, "info");
    let aad = field(h, "aad");
    let (enc, mut sender) = setup_sender_with(&ephemeral, &field(h, "pkRm"), &info).unwrap();
    assert_eq!(hex(&enc), expected["pkEm"].as_str().unwrap(), "{d}");
    assert_eq!(
        hex(&sender.secrets.0),
        expected["shared_secret"].as_str().unwrap(),
        "{d}"
    );
    assert_eq!(
        hex(&sender.secrets.1),
        expected["key"].as_str().unwrap(),
        "{d}"
    );
    assert_eq!(
        hex(&sender.base_nonce),
        expected["base_nonce"].as_str().unwrap(),
        "{d}"
    );
    if let Some(e) = expected["exporter_secret"].as_str() {
        assert_eq!(hex(&sender.exporter), e, "{d}");
    }
    let ct = sender.seal(&aad, pt).unwrap();
    assert_eq!(hex(&ct), expected["ct"].as_str().unwrap(), "{d}");
    let mut receiver = setup_receiver(&recipient, &enc, &info).unwrap();
    assert_eq!(*receiver.open(&aad, &ct).unwrap(), pt, "{d}");
    for x in expected["exports"].as_array().into_iter().flatten() {
        let len = usize::try_from(x["L"].as_u64().unwrap()).unwrap();
        let got = sender.export(&field(x, "exporter_context"), len).unwrap();
        assert_eq!(hex(&got), x["exported_value"].as_str().unwrap(), "{d}");
        assert_eq!(
            *receiver.export(&field(x, "exporter_context"), len).unwrap(),
            *got
        );
    }
}

// SEC-27
#[test]
fn sec_27_tee_request_vectors() {
    let mut seen = 0;
    for v in load("tee/vectors/hpke.json") {
        if v["input"]["hpke"].is_object() {
            let d = v["description"].as_str().unwrap();
            let h = &v["input"]["hpke"];
            check_seal(h, &v["expected"], &field(h, "pt"), d);
            seen += 1;
        }
    }
    assert_eq!(seen, 2);
}

// PV-65
#[test]
fn pv_65_permission_wrap_vectors() {
    let mut seen = 0;
    for v in load("keys/vectors/permission-wrap.json") {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        match (input["op"].as_str().unwrap(), input["hpke"].is_object()) {
            ("seal_dek", true) => {
                check_seal(&input["hpke"], &v["expected"], &field(input, "dek"), d);
                seen += 1;
            }
            ("open_dek", _) => {
                let recipient = KeyPair::from_private(Kem::X25519, &field(input, "skRm")).unwrap();
                let mut ctx =
                    setup_receiver(&recipient, &field(input, "enc"), &field(input, "info"))
                        .unwrap();
                assert_eq!(
                    ctx.open(&field(input, "aad"), &field(input, "ct"))
                        .map(|_| ()),
                    Err(HpkeError::Open),
                    "{d}"
                );
                seen += 1;
            }
            _ => {}
        }
    }
    assert_eq!(seen, 4);
}

// PV-5
#[test]
fn pv_5_secure_enclave_copy_vector() {
    let v = &load("keys/vectors/kek-device.json")[0];
    assert_eq!(v["input"]["holder"], "secure_enclave");
    check_seal(
        &v["input"]["hpke"],
        &v["expected"],
        &field(&v["input"], "kek"),
        v["description"].as_str().unwrap(),
    );
}

#[test]
fn sec_27_sequence_and_tampering() {
    let recipient = KeyPair::generate(Kem::X25519).unwrap();
    let pk = recipient.public_key().unwrap();
    let (enc, mut sender) = setup_sender(Kem::X25519, &pk, b"info").unwrap();
    let first = sender.seal(b"a", b"one").unwrap();
    let second = sender.seal(b"a", b"one").unwrap();
    assert_ne!(first, second);
    let mut receiver = setup_receiver(&recipient, &enc, b"info").unwrap();
    assert_eq!(*receiver.open(b"a", &first).unwrap(), b"one");
    assert_eq!(*receiver.open(b"a", &second).unwrap(), b"one");
    let mut other = setup_receiver(&recipient, &enc, b"other").unwrap();
    assert_eq!(other.open(b"a", &first).map(|_| ()), Err(HpkeError::Open));
    let mut wrong_aad = setup_receiver(&recipient, &enc, b"info").unwrap();
    assert_eq!(
        wrong_aad.open(b"b", &first).map(|_| ()),
        Err(HpkeError::Open)
    );
    let p256 = KeyPair::generate(Kem::P256).unwrap();
    assert_eq!(
        setup_sender(Kem::X25519, &p256.public_key().unwrap(), b"").map(|_| ()),
        Err(HpkeError::Key)
    );
    assert_eq!(
        sender.export(b"x", 70_000).map(|_| ()),
        Err(HpkeError::Length)
    );
}
