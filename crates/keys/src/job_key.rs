//! Handing a class DEK to a TEE job (PV-65, PV-61, SEC-27): the DEK is sealed with HPKE DHKEM(X25519) to a job key only after the attestation report carries that key's digest, with `info` the SHA-256 of the permission body and the class name as additional data, so it opens only for that permission and that class.

pub use one_hpke::report_data;
use one_hpke::{HpkeError, Kem, KeyPair, setup_receiver, setup_sender, setup_sender_with};
use one_proto::data_class::RetentionClass;
use sha2::{Digest as _, Sha256};
use suiss_crypto::secret::Secret;

use crate::seal::key_from_slice;

/// Why a DEK is not handed over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum JobKeyError {
    /// The key's digest is not the verified report's `report_data`: a fleet key or any key outside the attested TEE.
    RecipientNotAttested,
    /// The HPKE seal or open failed.
    Hpke(HpkeError),
}

impl JobKeyError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RecipientNotAttested => "recipient_not_attested",
            Self::Hpke(e) => e.as_str(),
        }
    }
}

impl From<HpkeError> for JobKeyError {
    fn from(e: HpkeError) -> Self {
        Self::Hpke(e)
    }
}

/// A TEE job key bound to a verified attestation report.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestedJobKey {
    public: Vec<u8>,
}

impl AttestedJobKey {
    /// Binds `public_key` to the `report_data` of an attestation report the caller verified.
    ///
    /// # Errors
    /// [`JobKeyError::RecipientNotAttested`] when the report carries another key.
    pub fn bind(public_key: &[u8], verified_report_data: &[u8; 64]) -> Result<Self, JobKeyError> {
        if report_data(public_key) == *verified_report_data {
            Ok(Self {
                public: public_key.to_vec(),
            })
        } else {
            Err(JobKeyError::RecipientNotAttested)
        }
    }

    /// The public key.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public
    }
}

/// A DEK sealed to a job key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedDek {
    /// The HPKE encapsulation.
    pub enc: Vec<u8>,
    /// The sealed DEK with its tag.
    pub ct: Vec<u8>,
}

fn info(permission_body: &[u8]) -> [u8; 32] {
    Sha256::digest(permission_body).into()
}

/// Seals `dek` of `class` for the job that runs under the permission whose body is `permission_body`.
///
/// # Errors
/// [`JobKeyError::Hpke`].
pub fn seal_dek(
    job_key: &AttestedJobKey,
    permission_body: &[u8],
    class: RetentionClass,
    dek: &Secret<[u8; 32]>,
) -> Result<SealedDek, JobKeyError> {
    let (enc, mut ctx) = setup_sender(Kem::X25519, &job_key.public, &info(permission_body))?;
    let ct = ctx.seal(class.as_str().as_bytes(), dek.expose())?;
    Ok(SealedDek { enc, ct })
}

/// Seals `dek` with the given ephemeral key, which is never reused.
///
/// # Errors
/// [`JobKeyError::Hpke`].
pub fn seal_dek_with(
    ephemeral: &KeyPair,
    job_key: &AttestedJobKey,
    permission_body: &[u8],
    class: RetentionClass,
    dek: &Secret<[u8; 32]>,
) -> Result<SealedDek, JobKeyError> {
    let (enc, mut ctx) = setup_sender_with(ephemeral, &job_key.public, &info(permission_body))?;
    let ct = ctx.seal(class.as_str().as_bytes(), dek.expose())?;
    Ok(SealedDek { enc, ct })
}

/// Opens a sealed DEK inside the TEE with the job's key pair.
///
/// # Errors
/// [`JobKeyError::Hpke`] for another permission body, another class or another key.
pub fn open_dek(
    job: &KeyPair,
    permission_body: &[u8],
    class: RetentionClass,
    sealed: &SealedDek,
) -> Result<Secret<[u8; 32]>, JobKeyError> {
    let mut ctx = setup_receiver(job, &sealed.enc, &info(permission_body))?;
    let dek = ctx.open(class.as_str().as_bytes(), &sealed.ct)?;
    key_from_slice(&dek).map_err(|_| JobKeyError::Hpke(HpkeError::Open))
}
