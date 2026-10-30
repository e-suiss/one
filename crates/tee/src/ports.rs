//! The TEE layer's ports: report verification and normalization, opening sealed bytes with the record key, and the outbox, which takes only values that may leave the TEE (T-27 (2, 3, 5), SEC-27).

use crate::domain::attestation::Evidence;
use crate::sealed::{LeavesTee, RecordKeyId};

/// Verifies a raw report's signature and certificate chain and returns its normalized claims; the AMD, Intel, NVIDIA and simulator adapters implement it.
pub trait Attestation {
    /// Why a report did not verify.
    type Error;

    /// The normalized evidence of `raw_report` with its certificate `chain`.
    ///
    /// # Errors
    /// The report's signature or chain does not verify.
    fn normalize(&self, raw_report: &[u8], chain: &[Vec<u8>]) -> Result<Evidence, Self::Error>;
}

/// Why the key port did not open a ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpenError {
    /// The record key is unknown or shredded.
    NoKey,
    /// The authentication tag does not verify under the AAD.
    Tag,
}

/// Opens ciphertext with the record key inside the TEE; the shared Suiss crypto crate implements it.
pub trait Opener {
    /// Writes the plaintext of `ciphertext` under `aad` into `out`.
    ///
    /// # Errors
    /// [`OpenError`].
    fn open(
        &self,
        record_key_id: RecordKeyId,
        aad: &[u8],
        ciphertext: &[u8],
        out: &mut Vec<u8>,
    ) -> Result<(), OpenError>;
}

/// The outbox: outside-TEE code hands it events after the transaction commits, so it takes only values that may leave the TEE.
pub trait Outbox {
    /// Why an event was not queued.
    type Error;

    /// Queues `payload` as an event of `event_type`.
    ///
    /// # Errors
    /// The event was not queued.
    fn enqueue<P: LeavesTee + ?Sized>(
        &self,
        event_type: &str,
        payload: &P,
    ) -> Result<(), Self::Error>;
}
