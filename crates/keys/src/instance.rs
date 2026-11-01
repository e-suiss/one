//! The device Instance keys a permission's `COSE_Sign1` is checked against (PV-65, Access E31): ES256 over the `Sig_structure` through the shared Suiss signature checks on the aws-lc-rs backend, with the CR-53 range checks before the curve operation.

use std::collections::BTreeMap;

use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::sig;

use crate::ports::PermissionSignature;

/// The P-256 public keys of the user's device Instances, by `kid`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InstanceKeys {
    keys: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl InstanceKeys {
    /// No keys.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
    }

    /// Adds the SEC1 public key of the Instance named `kid`, as Access reports it.
    pub fn insert(&mut self, kid: &[u8], public_key_sec1: &[u8]) {
        self.keys.insert(kid.to_vec(), public_key_sec1.to_vec());
    }
}

impl PermissionSignature for InstanceKeys {
    fn verify(&self, kid: &[u8], sig_structure: &[u8], signature: &[u8; 64]) -> bool {
        self.keys.get(kid).is_some_and(|key| {
            sig::p256(&AwsLcBackend, key, sig_structure, signature, false).is_ok()
        })
    }
}
