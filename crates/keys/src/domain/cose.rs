//! The `COSE_Sign1` (ES256) envelope of a key permission: the protected header, the `Sig_structure` the device Instance signs and the tagged message (RFC 9052 §4.2, PV-65).

use one_proto::cbor::{Writer, encode};
use sha2::{Digest as _, Sha256};

/// The CBOR tag of `COSE_Sign1`.
pub const COSE_SIGN1_TAG: u64 = 18;

/// The protected header `{1: -7}`: algorithm ES256.
pub const PROTECTED: [u8; 3] = [0xa1, 0x01, 0x26];

/// The `kid` header label.
const KID: u64 = 4;

/// The bytes the device Instance signs: `["Signature1", protected, h'', payload]`.
#[must_use]
pub fn sig_structure(payload: &[u8]) -> Vec<u8> {
    encode(|w| {
        w.array(4)
            .text("Signature1")
            .bytes(&PROTECTED)
            .bytes(&[])
            .bytes(payload);
    })
}

/// The tagged `COSE_Sign1` message carrying `kid` in the unprotected header.
#[must_use]
pub fn cose_sign1(kid: &[u8], payload: &[u8], signature: &[u8; 64]) -> Vec<u8> {
    let mut unprotected = Writer::new();
    unprotected.map(vec![(
        encode(|w| {
            w.unsigned(KID);
        }),
        encode(|w| {
            w.bytes(kid);
        }),
    )]);
    encode(|w| {
        w.tag(COSE_SIGN1_TAG)
            .array(4)
            .bytes(&PROTECTED)
            .raw(&unprotected.into_bytes())
            .bytes(payload)
            .bytes(signature);
    })
}

/// The SHA-256 of the deterministic body bytes: the HPKE `info` the DEKs are wrapped under (PV-65).
#[must_use]
pub fn body_digest(body: &[u8]) -> [u8; 32] {
    Sha256::digest(body).into()
}
