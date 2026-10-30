//! Admission of a signed key permission through the ports: the clock, the Instance signature and Access's live state (PV-65, Access E31).

use one_proto::key_permission::PermissionBody;
use one_runtime::Clock;

use crate::domain::cose::sig_structure;
use crate::domain::permission::{Admitted, JobContext, Refusal, admit};
use crate::ports::{PermissionSignature, PermissionStatus};

/// A permission as the device sent it: the body, its deterministic bytes, the signer's `kid` and the signature.
#[derive(Debug, Clone, Copy)]
pub struct SignedPermission<'a> {
    /// The decoded body.
    pub body: &'a PermissionBody,
    /// The body's deterministic CBOR bytes, the signed payload.
    pub payload: &'a [u8],
    /// The device Instance key id.
    pub kid: &'a [u8],
    /// The ES256 signature.
    pub signature: &'a [u8; 64],
}

/// What the TEE attested about the job it runs.
#[derive(Debug, Clone, Copy)]
pub struct Attested<'a> {
    /// The TEE image measurement.
    pub measurement: &'a [u8; 48],
    /// The SHA-256 of the job key.
    pub job_key_digest: &'a [u8; 32],
}

/// Why a job does not start or does not continue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckError<E> {
    /// The permission does not open the job.
    Refused(Refusal),
    /// Access could not be asked; the job waits.
    Status(E),
}

/// Checks a signed permission at job start or at a resume point.
///
/// # Errors
/// [`CheckError::Refused`] with the first refusal, or [`CheckError::Status`] when Access cannot be asked.
pub fn check<S, P>(
    clock: &dyn Clock,
    signer: &S,
    status: &P,
    permission: &SignedPermission<'_>,
    attested: &Attested<'_>,
) -> Result<Admitted, CheckError<P::Error>>
where
    S: PermissionSignature + ?Sized,
    P: PermissionStatus + ?Sized,
{
    let signature_valid = permission.body.encode() == permission.payload
        && signer.verify(
            permission.kid,
            &sig_structure(permission.payload),
            permission.signature,
        );
    let live = status
        .live_state(&permission.body.permission_id)
        .map_err(CheckError::Status)?;
    let now = u64::try_from(clock.now().0 / 1_000_000_000).unwrap_or(u64::MAX);
    admit(
        permission.body,
        &JobContext {
            now,
            signature_valid,
            attested_measurement: attested.measurement,
            attested_job_key_digest: attested.job_key_digest,
            withdrawn: live.withdrawn,
            mandate: live.mandate,
            shredded: &live.shredded,
        },
    )
    .map_err(CheckError::Refused)
}
