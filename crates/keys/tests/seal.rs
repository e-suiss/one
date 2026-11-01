//! Every vector of `conformance/keys/vectors/wrap.json` and `record-key.json` through the real AES-256 Key Wrap, HKDF-SHA256 and AES-256-GCM of the shared Suiss envelope, and record and class shreds over a key store that only drops wrapped copies (OP-4, OP-5, M-25, PV-15).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

mod common;

use std::collections::BTreeMap;

use common::{fixed, hex, load, unhex};
use one_keys::seal::{
    KeyError, Part, PartRef, WRAPPED_LEN, key_from_slice, open_part, part_key, seal_part, unwrap,
    wrap,
};
use one_proto::data_class::RetentionClass;
use serde_json::Value;
use suiss_crypto::envelope::{self, AAD_CONTEXT, Dek, Sealed};
use suiss_crypto::secret::Secret;

const OWNER: &str = "pty_01k742sgz8ea9tc04vraj0cqss";

fn secret(v: &Value) -> Secret<[u8; 32]> {
    key_from_slice(&unhex(v.as_str().unwrap())).unwrap()
}

fn class(v: &Value) -> RetentionClass {
    RetentionClass::from_name(v.as_str().unwrap()).unwrap()
}

fn sealed(input: &Value) -> Sealed {
    Sealed {
        nonce: fixed(input["nonce"].as_str().unwrap()),
        ciphertext: unhex(input["ciphertext"].as_str().unwrap()),
    }
}

fn fresh(n: u8) -> Secret<[u8; 32]> {
    Secret::new([n; 32])
}

#[test]
fn op_4_wrap_vectors() {
    let all = load("keys/vectors/wrap.json");
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        let kek = secret(&input["kek"]);
        let got = match input["op"].as_str().unwrap() {
            "wrap" => key_from_slice(&unhex(input["key"].as_str().unwrap()))
                .and_then(|key| wrap(&kek, &key))
                .map(|w| hex(&w)),
            "unwrap" => {
                unwrap(&kek, &unhex(input["wrapped"].as_str().unwrap())).map(|k| hex(k.expose()))
            }
            op => panic!("{d}: unknown op {op}"),
        };
        match got {
            Ok(out) => {
                let want = expected["wrapped"]
                    .as_str()
                    .or_else(|| expected["key"].as_str())
                    .unwrap();
                assert_eq!(out, want, "{d}");
            }
            Err(e) => assert_eq!(e.as_str(), expected["error"].as_str().unwrap(), "{d}"),
        }
    }
    assert_eq!(all.len(), 7);
}

#[test]
fn op_4_record_part_vectors() {
    let all = load("keys/vectors/record-key.json");
    let mut seen = 0_usize;
    for v in &all {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        match input["op"].as_str().unwrap() {
            "seal_part" => {
                let record_key = secret(&input["record_key"]);
                let part = PartRef {
                    owner: input["owner"].as_str().unwrap(),
                    record: input["record"].as_str().unwrap(),
                    class: class(&input["class"]),
                    part: Part::from_name(input["part"].as_str().unwrap()).unwrap(),
                    version: u32::try_from(input["part_version"].as_u64().unwrap()).unwrap(),
                };
                let key = part_key(&record_key, &part).unwrap();
                assert_eq!(
                    hex(key.secret().expose()),
                    expected["part_key"].as_str().unwrap(),
                    "{d}"
                );
                assert_eq!(
                    hex(&part.context()),
                    input["context"].as_str().unwrap(),
                    "{d}"
                );
                let mut aad = AAD_CONTEXT.to_vec();
                aad.extend_from_slice(&part.context());
                assert_eq!(hex(&aad), expected["aad"].as_str().unwrap(), "{d}");
                let golden = Sealed {
                    nonce: fixed(input["nonce"].as_str().unwrap()),
                    ciphertext: unhex(expected["ciphertext"].as_str().unwrap()),
                };
                let plaintext = unhex(input["plaintext"].as_str().unwrap());
                assert_eq!(
                    *open_part(&record_key, &part, &golden).unwrap(),
                    plaintext,
                    "{d}"
                );
                let again = seal_part(&record_key, &part, &plaintext).unwrap();
                assert_ne!(again.nonce, golden.nonce, "{d}");
                assert_eq!(*open_part(&record_key, &part, &again).unwrap(), plaintext);
                seen = seen.saturating_add(1);
            }
            "derive_part_key" => {
                let part = PartRef {
                    owner: OWNER,
                    record: "mem_01k742vmbgez2rfct5dmnr31vp",
                    class: RetentionClass::OneMemory,
                    part: Part::from_name(input["part"].as_str().unwrap()).unwrap(),
                    version: u32::try_from(input["part_version"].as_u64().unwrap()).unwrap(),
                };
                let key = part_key(&secret(&input["record_key"]), &part).unwrap();
                assert_eq!(
                    hex(key.secret().expose()),
                    expected["part_key"].as_str().unwrap(),
                    "{d}"
                );
                seen = seen.saturating_add(1);
            }
            "open_part" => {
                let key = Dek::from_secret(secret(&input["part_key"]));
                let aad = unhex(input["aad"].as_str().unwrap());
                let context = aad.strip_prefix(AAD_CONTEXT).unwrap();
                assert!(
                    envelope::open_body(&key, context, &sealed(input)).is_err(),
                    "{d}"
                );
                assert_eq!(expected["error"], "open", "{d}");
                seen = seen.saturating_add(1);
            }
            "shred_record" => {
                shred_record(input, expected, d);
                seen = seen.saturating_add(1);
            }
            "shred_class" => {
                shred_class(input, expected, d);
                seen = seen.saturating_add(1);
            }
            "rebuild_index" => {
                rebuild_index(input, expected, d);
                seen = seen.saturating_add(1);
            }
            op => panic!("{d}: unknown op {op}"),
        }
    }
    assert_eq!(seen, all.len());
}

struct Store {
    kek: Secret<[u8; 32]>,
    deks: BTreeMap<RetentionClass, Option<[u8; WRAPPED_LEN]>>,
    keys: BTreeMap<String, (RetentionClass, Option<[u8; WRAPPED_LEN]>)>,
    parts: Vec<(String, Part, Sealed)>,
}

impl Store {
    fn new() -> Self {
        Self {
            kek: fresh(1),
            deks: BTreeMap::new(),
            keys: BTreeMap::new(),
            parts: Vec::new(),
        }
    }

    fn dek(&mut self, class: RetentionClass) -> Option<Secret<[u8; 32]>> {
        let n = u8::try_from(self.deks.len()).unwrap().saturating_add(10);
        let wrapped = *self
            .deks
            .entry(class)
            .or_insert_with(|| Some(wrap(&fresh(1), &fresh(n)).unwrap()));
        wrapped.map(|w| unwrap(&self.kek, &w).unwrap())
    }

    fn add(&mut self, record: &str, class: RetentionClass, parts: &[Part]) {
        let dek = self.dek(class).unwrap();
        let n = u8::try_from(self.keys.len()).unwrap().saturating_add(100);
        let record_key = fresh(n);
        self.keys.insert(
            record.to_owned(),
            (class, Some(wrap(&dek, &record_key).unwrap())),
        );
        for &part in parts {
            let at = PartRef {
                owner: OWNER,
                record,
                class,
                part,
                version: 1,
            };
            let s = seal_part(&record_key, &at, record.as_bytes()).unwrap();
            self.parts.push((record.to_owned(), part, s));
        }
    }

    fn record_key(&mut self, record: &str) -> Option<Secret<[u8; 32]>> {
        let (class, wrapped) = *self.keys.get(record)?;
        let dek = self.dek(class)?;
        wrapped.map(|w| unwrap(&dek, &w).unwrap())
    }

    fn readable(&mut self, record: &str) -> Vec<&'static str> {
        let Some(key) = self.record_key(record) else {
            return Vec::new();
        };
        let class = self.keys[record].0;
        self.parts
            .iter()
            .filter(|(r, _, _)| r == record)
            .filter(|(_, part, s)| {
                let at = PartRef {
                    owner: OWNER,
                    record,
                    class,
                    part: *part,
                    version: 1,
                };
                open_part(&key, &at, s).is_ok()
            })
            .map(|(_, part, _)| part.as_str())
            .collect()
    }
}

fn shred_record(input: &Value, expected: &Value, d: &str) {
    let class = class(&input["class"]);
    let mut store = Store::new();
    for r in input["records"].as_array().unwrap() {
        let parts: Vec<Part> = r["parts"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| Part::from_name(p.as_str().unwrap()).unwrap())
            .collect();
        store.add(r["record"].as_str().unwrap(), class, &parts);
    }
    let gone = input["shred"].as_str().unwrap();
    store.keys.get_mut(gone).unwrap().1 = None;
    for (record, parts) in expected["readable"].as_object().unwrap() {
        let want: Vec<&str> = parts
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p.as_str().unwrap())
            .collect();
        assert_eq!(store.readable(record), want, "{d}: {record}");
    }
    assert_eq!(expected["erasure_log"]["scope"], "record", "{d}");
}

fn shred_class(input: &Value, expected: &Value, d: &str) {
    let mut store = Store::new();
    for r in input["records"].as_array().unwrap() {
        store.add(
            r["record"].as_str().unwrap(),
            class(&r["class"]),
            &[Part::Content],
        );
    }
    store.deks.insert(class(&input["class"]), None);
    for (record, readable) in expected["readable"].as_object().unwrap() {
        assert_eq!(
            !store.readable(record).is_empty(),
            readable.as_bool().unwrap(),
            "{d}: {record}"
        );
    }
    assert_eq!(expected["erasure_log"]["scope"], "class", "{d}");
}

fn rebuild_index(input: &Value, expected: &Value, d: &str) {
    let mut store = Store::new();
    let sources: Vec<&str> = input["sources"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    for s in &sources {
        store.add(
            s,
            RetentionClass::OneMemory,
            &[Part::Content, Part::Embedding],
        );
    }
    for f in input["forgotten"].as_array().unwrap() {
        store.keys.get_mut(f.as_str().unwrap()).unwrap().1 = None;
    }
    let indexed: Vec<&str> = sources
        .iter()
        .copied()
        .filter(|s| store.readable(s).contains(&"embedding"))
        .collect();
    let want: Vec<&str> = expected["indexed"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_str().unwrap())
        .collect();
    assert_eq!(indexed, want, "{d}");
}

#[test]
fn op_4_a_part_opens_only_in_its_own_place() {
    let key = fresh(7);
    let at = PartRef {
        owner: OWNER,
        record: "mem_01k742vmbgez2rfct5dmnr31vp",
        class: RetentionClass::OneMemory,
        part: Part::Content,
        version: 1,
    };
    let s = seal_part(&key, &at, b"x").unwrap();
    for moved in [
        PartRef {
            owner: "pty_other",
            ..at
        },
        PartRef {
            class: RetentionClass::OneSensitive,
            ..at
        },
        PartRef {
            part: Part::Summary,
            ..at
        },
        PartRef { version: 2, ..at },
    ] {
        assert_eq!(open_part(&key, &moved, &s).map(|_| ()), Err(KeyError::Open));
    }
    assert_eq!(
        open_part(&fresh(8), &at, &s).map(|_| ()),
        Err(KeyError::Open)
    );
}
