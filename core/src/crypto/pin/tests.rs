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

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn params(p: &Value) -> PinParams {
    assert_eq!(p["variant"], "argon2id");
    assert_eq!(p["version"], 19);
    PinParams {
        memory_kib: u32::try_from(p["memory_kib"].as_u64().unwrap()).unwrap(),
        iterations: u32::try_from(p["iterations"].as_u64().unwrap()).unwrap(),
        lanes: u32::try_from(p["lanes"].as_u64().unwrap()).unwrap(),
        tag_length: usize::try_from(p["tag_length"].as_u64().unwrap()).unwrap(),
    }
}

// PV-12
#[test]
fn pv_12_argon2id_vectors() {
    let path = format!(
        "{}/../conformance/recovery/vectors/argon2id.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let all: Vec<Value> = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        let p = params(&input["params"]);
        if let Some(password) = input["password"].as_str() {
            let tag = argon2id(
                &unhex(password),
                &unhex(input["salt"].as_str().unwrap()),
                &unhex(input["secret"].as_str().unwrap()),
                &unhex(input["associated_data"].as_str().unwrap()),
                p,
            )
            .unwrap();
            assert_eq!(hex(&tag), expected["tag"].as_str().unwrap(), "{d}");
            continue;
        }
        let salt: [u8; 16] = unhex(input["salt"].as_str().unwrap()).try_into().unwrap();
        match stretch(input["pin"].as_str().unwrap(), &salt, p) {
            Ok(keys) => {
                let tag = format!(
                    "{}{}",
                    hex(&*keys.access_key),
                    hex(&*keys.encryption_key_seed)
                );
                assert_eq!(tag, expected["tag"].as_str().unwrap(), "{d}");
                if let Some(a) = expected["access_key"].as_str() {
                    assert_eq!(hex(&*keys.access_key), a, "{d}");
                    assert_eq!(
                        hex(&*keys.encryption_key_seed),
                        expected["encryption_key_seed"].as_str().unwrap(),
                        "{d}"
                    );
                }
            }
            Err(e) => assert_eq!(e.as_str(), expected["error"].as_str().unwrap(), "{d}"),
        }
    }
    assert_eq!(all.len(), 7);
}
