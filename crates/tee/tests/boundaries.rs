//! The TEE boundary types of `conformance/tee/boundary-types.toml`: `Sealed` serializes, clones and shows only its parts' sizes; `Unsealed` comes only out of the frame and prints `[unsealed]` (T-27 (3), T-6, SEC-27).

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use one_tee::frame::{UnsealError, unseal};
use one_tee::ports::{OpenError, Opener};
use one_tee::{RecordKeyId, Sealed, Unsealed};

struct Xor;

impl Opener for Xor {
    fn open(
        &self,
        id: RecordKeyId,
        aad: &[u8],
        ct: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), OpenError> {
        if id.0 == [0; 16] {
            return Err(OpenError::NoKey);
        }
        if aad != b"one/record/v1" {
            return Err(OpenError::Tag);
        }
        out.extend(ct.iter().map(|b| b ^ 0x5a));
        Ok(())
    }
}

fn sealed(id: u8, plain: &[u8]) -> Sealed<String> {
    Sealed::from_parts(
        RecordKeyId([id; 16]),
        b"one/record/v1".to_vec(),
        plain.iter().map(|b| b ^ 0x5a).collect(),
    )
}

fn text(bytes: &[u8]) -> Option<String> {
    String::from_utf8(bytes.to_vec()).ok()
}

#[test]
fn t_27_unsealed_debug_is_masked_and_content_stays_inside() {
    let opener = Xor;
    let u: Unsealed<String> = unseal(&opener, &sealed(1, b"a private note"), text).unwrap();
    assert_eq!(format!("{u:?}"), "[unsealed]");
    assert_eq!(u.expose(), "a private note");
    let len = u.map(String::len);
    assert_eq!(format!("{len:?}"), "[unsealed]");
    assert_eq!(*len.expose(), 14);
}

#[test]
fn t_27_unseal_refusals_name_no_content() {
    let opener = Xor;
    assert_eq!(
        unseal(&opener, &sealed(0, b"x"), text).unwrap_err(),
        UnsealError::Open(OpenError::NoKey)
    );
    let wrong_aad = Sealed::<String>::from_parts(RecordKeyId([1; 16]), b"other".to_vec(), vec![1]);
    assert_eq!(
        unseal(&opener, &wrong_aad, text).unwrap_err(),
        UnsealError::Open(OpenError::Tag)
    );
    assert_eq!(
        unseal(&opener, &sealed(1, &[0xff]), text).unwrap_err(),
        UnsealError::Decode
    );
}

#[test]
fn t_27_sealed_serializes_clones_and_debugs_only_sizes() {
    let s = sealed(7, b"a private note");
    let json = serde_json::to_string(&s).unwrap();
    let back: Sealed<String> = serde_json::from_str(&json).unwrap();
    assert_eq!(back, s);
    assert_eq!(s.clone(), s);
    let debug = format!("{s:?}");
    assert_eq!(
        debug,
        "Sealed { record_key_id: 07070707070707070707070707070707, aad_len: 13, ciphertext_len: 14 }"
    );
    assert!(!debug.contains("private"));
}

#[test]
fn t_27_unsealed_is_send() {
    fn send<T: Send>() {}
    send::<Unsealed<String>>();
}
