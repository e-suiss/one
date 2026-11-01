//! Server key access only through PKCS#11 (T-51, T-27 (9)): process secrets, signing keys and server-side wrapping keys live in an HSM, `SoftHSM` locally and in CI, reached through the shared Suiss PKCS#11 store; no cloud KMS API exists in this code. The user KEK never reaches it (PV-5).

pub use suiss_crypto::envelope::Kek;
pub use suiss_crypto::pkcs11::{HsmError, HsmKek, HsmSigner, KeyStore};
pub use suiss_crypto::signer::Signer;
