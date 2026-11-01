//! The PKCS#11 store against a real SoftHSM token: a KEK generated or imported inside the token wraps and unwraps DEKs with the same RFC 3394 bytes as the software path, a wrap under another KEK does not unwrap, and a P-256 signing key signs inside the token (T-51, T-27 (9), OP-4).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use std::path::PathBuf;

use one_keys::hsm::{Kek as _, KeyStore, Signer as _};
use one_keys::seal::wrap;
use suiss_crypto::cose::PublicKey;
use suiss_crypto::envelope::Dek;
use suiss_crypto::secret::Secret;

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set; the test job starts SoftHSM"))
}

fn store() -> KeyStore {
    KeyStore::open(
        &PathBuf::from(var("ONE_TEST_PKCS11_MODULE")),
        &var("ONE_TEST_PKCS11_TOKEN"),
        &Secret::new(var("ONE_TEST_PKCS11_PIN")),
    )
    .unwrap()
}

#[test]
fn t_51_an_imported_kek_wraps_like_the_software_path() {
    let store = store();
    let value = [0x63_u8; 32];
    let kek = store.import_kek("t51-import", &Secret::new(value)).unwrap();
    let dek = Dek::from_secret(Secret::new([0x86_u8; 32]));
    let wrapped = kek.wrap(&dek).unwrap();
    let software = wrap(&Secret::new(value), dek.secret()).unwrap();
    assert_eq!(wrapped, software);
    assert!(kek.unwrap(&wrapped).unwrap().secret().ct_eq(dek.secret()));
    assert!(store.import_kek("t51-import", &Secret::new(value)).is_err());
}

#[test]
fn t_51_a_generated_kek_never_opens_another_keks_wrap() {
    let store = store();
    let one = store.generate_kek("t51-generated-1").unwrap();
    let two = store.generate_kek("t51-generated-2").unwrap();
    let dek = Dek::from_secret(Secret::new([0x11_u8; 32]));
    let wrapped = one.wrap(&dek).unwrap();
    assert!(one.unwrap(&wrapped).unwrap().secret().ct_eq(dek.secret()));
    assert!(two.unwrap(&wrapped).is_err());
    let mut tampered = wrapped.clone();
    tampered[0] ^= 1;
    assert!(one.unwrap(&tampered).is_err());
    assert_eq!(
        store.kek("t51-generated-1").unwrap().id(),
        "t51-generated-1"
    );
}

#[test]
fn t_51_a_signing_key_signs_inside_the_token() {
    let store = store();
    let signer = store.generate_p256("t51-signer").unwrap();
    let message = b"one/t51/v1";
    let signature = signer.sign(message).unwrap();
    let PublicKey::P256(key) = signer.public_key() else {
        panic!("not a P-256 key");
    };
    assert!(
        suiss_crypto::sig::p256(
            &suiss_crypto::aws::AwsLcBackend,
            &key,
            message,
            &signature,
            true
        )
        .is_ok()
    );
    assert!(
        suiss_crypto::sig::p256(
            &suiss_crypto::aws::AwsLcBackend,
            &key,
            b"another message",
            &signature,
            true
        )
        .is_err()
    );
}
