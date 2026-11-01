//! The Actor Intent Statement (L2-AIS-1 to L2-AIS-3): One's Instance signs the domain, nonce, intent digest, mode, PEP, capacity, basis, signing time and, for `continue`, the Exercise, as a `COSE_Sign1` with `kid` the RFC 7638 thumbprint of its key; the signer is a port, so the Instance key stays in the HSM (T-51).

use access_kernel::ais::{CONTENT_TYPE, Statement};
use access_kernel::codec::Canonical as _;
use access_kernel::intent::intent_digest;
use access_kernel::verify::key_scope::thumbprint;
use suiss_crypto::signer::{SignError, Signer, sign_sign1};

use crate::adp::Evaluation;

/// Why a statement was not signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AisSignError {
    /// The intent or statement does not encode.
    Encode,
    /// The signer refused.
    Sign(SignError),
}

/// Signs the statement for `request`, addressed to the PEP `pep`, at `iat` milliseconds.
///
/// # Errors
/// [`AisSignError`].
pub fn sign(
    signer: &dyn Signer,
    pep: &str,
    request: &Evaluation<'_>,
    iat: u64,
) -> Result<Vec<u8>, AisSignError> {
    let statement = Statement {
        domain: request.domain,
        nonce: request.nonce.to_vec(),
        intent: intent_digest(request.intent).map_err(|_| AisSignError::Encode)?,
        mode: request.mode,
        pep: pep.to_owned(),
        capacity: request.capacity,
        basis: request.basis,
        iat,
        exercise: request.exercise,
    };
    let payload = statement.to_bytes().map_err(|_| AisSignError::Encode)?;
    let kid = thumbprint(&signer.public_key());
    sign_sign1(signer, kid, CONTENT_TYPE, &payload).map_err(AisSignError::Sign)
}
