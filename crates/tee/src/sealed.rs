//! [`Sealed`]: an encrypted value with its record key id and AAD context, the only form personal content takes outside the TEE, and [`LeavesTee`], the bound every outside-TEE port puts on what it accepts (T-27 (3), T-6).

use core::fmt;
use core::marker::PhantomData;

use serde::{Deserialize, Serialize};

/// The id of the record key a value is sealed under.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RecordKeyId(pub [u8; 16]);

impl fmt::Debug for RecordKeyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// An encrypted `T`: nonce and ciphertext, the record key id and the AAD context; it serializes and travels outside the TEE.
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct Sealed<T> {
    record_key_id: RecordKeyId,
    aad: Vec<u8>,
    ciphertext: Vec<u8>,
    #[serde(skip)]
    value: PhantomData<fn() -> T>,
}

impl<T> Sealed<T> {
    /// Wraps the parts the key layer produced when sealing.
    #[must_use]
    pub const fn from_parts(record_key_id: RecordKeyId, aad: Vec<u8>, ciphertext: Vec<u8>) -> Self {
        Self {
            record_key_id,
            aad,
            ciphertext,
            value: PhantomData,
        }
    }

    /// The record key id, for shred.
    #[must_use]
    pub const fn record_key_id(&self) -> RecordKeyId {
        self.record_key_id
    }

    /// The AAD context the ciphertext is bound to.
    #[must_use]
    pub fn aad(&self) -> &[u8] {
        &self.aad
    }

    /// Nonce and ciphertext.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl<T> Clone for Sealed<T> {
    fn clone(&self) -> Self {
        Self::from_parts(
            self.record_key_id,
            self.aad.clone(),
            self.ciphertext.clone(),
        )
    }
}

impl<T> PartialEq for Sealed<T> {
    fn eq(&self, other: &Self) -> bool {
        self.record_key_id == other.record_key_id
            && self.aad == other.aad
            && self.ciphertext == other.ciphertext
    }
}

impl<T> Eq for Sealed<T> {}

impl<T> fmt::Debug for Sealed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sealed")
            .field("record_key_id", &self.record_key_id)
            .field("aad_len", &self.aad.len())
            .field("ciphertext_len", &self.ciphertext.len())
            .finish()
    }
}

mod boundary {
    #[allow(unreachable_pub, reason = "T-27 (3)")]
    pub trait Crossing {}
}

/// A value that may leave the TEE: an outside-TEE port accepts only these, so an [`crate::Unsealed`] never reaches one.
pub trait LeavesTee: boundary::Crossing {}

impl<T> boundary::Crossing for Sealed<T> {}

impl<T> LeavesTee for Sealed<T> {}
