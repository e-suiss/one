//! Admission of a time-bound key permission at job start and at every resume point: signature, closed purpose and class lists, a window of at most 24 hours, the exact TEE measurement, the attested job key, the live Mandate, withdrawal and shredded classes (PV-65, PV-61, A-13, Access E31, Access E59).

use one_proto::data_class::RetentionClass;
use one_proto::key_permission::{MAX_WINDOW_SECS, PermissionBody, PermissionId, Purpose};

/// The live state of a permission's Mandate as Access reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MandateState {
    /// The Mandate stands and covers the job.
    Active,
    /// The Mandate was revoked.
    Revoked,
    /// The Mandate was narrowed below the job.
    Narrowed,
    /// The Mandate expired.
    Expired,
}

/// Everything the admission rule reads besides the body.
#[derive(Debug, Clone, Copy)]
pub struct JobContext<'a> {
    /// The current time, seconds since the Unix epoch, read through the `Clock` port.
    pub now: u64,
    /// Whether the body's signature verified under the device Instance key.
    pub signature_valid: bool,
    /// The measurement of the TEE image the job runs in, from its own attestation.
    pub attested_measurement: &'a [u8; 48],
    /// The SHA-256 of the job key the TEE attested.
    pub attested_job_key_digest: &'a [u8; 32],
    /// Whether the user withdrew the permission (Access E31).
    pub withdrawn: bool,
    /// The Mandate's live state; `None` when the body names none.
    pub mandate: Option<MandateState>,
    /// The classes shredded since the permission was given.
    pub shredded: &'a [RetentionClass],
}

/// Why a permission does not open, or no longer opens, its job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Refusal {
    /// The signature does not verify under the device Instance key.
    Signature,
    /// `expires_at` is not after `not_before`.
    WindowEmpty,
    /// The window is longer than 24 hours.
    WindowTooLong,
    /// The purpose is not on the closed list.
    UnknownPurpose,
    /// A class is not a One class.
    UnknownClass,
    /// A state-changing purpose without a Mandate reference.
    MandateRequired,
    /// The job runs in another TEE image than the one the permission names.
    MeasurementMismatch,
    /// The attested job key is not the one the permission names.
    JobKeyMismatch,
    /// The window has not started.
    NotYetValid,
    /// The window has ended.
    Expired,
    /// The user withdrew the permission.
    Withdrawn,
    /// A class of the permission was shredded.
    ClassShredded,
    /// The Mandate was revoked, narrowed or expired.
    MandateInactive,
}

impl Refusal {
    /// The reason as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Signature => "signature",
            Self::WindowEmpty => "window_empty",
            Self::WindowTooLong => "window_too_long",
            Self::UnknownPurpose => "unknown_purpose",
            Self::UnknownClass => "unknown_class",
            Self::MandateRequired => "mandate_required",
            Self::MeasurementMismatch => "measurement_mismatch",
            Self::JobKeyMismatch => "job_key_mismatch",
            Self::NotYetValid => "not_yet_valid",
            Self::Expired => "expired",
            Self::Withdrawn => "withdrawn",
            Self::ClassShredded => "class_shredded",
            Self::MandateInactive => "mandate_inactive",
        }
    }

    /// Whether the TEE zeroizes the job key and its DEK copies: the permission was live and has fallen (PV-65).
    #[must_use]
    pub const fn zeroizes(self) -> bool {
        matches!(
            self,
            Self::Expired | Self::Withdrawn | Self::ClassShredded | Self::MandateInactive
        )
    }
}

/// An admitted job: its typed purpose and classes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The purpose.
    pub purpose: Purpose,
    /// The classes the job may open.
    pub classes: Vec<RetentionClass>,
}

/// Checks a permission at job start or at a resume point.
///
/// # Errors
/// The first [`Refusal`] that applies.
pub fn admit(body: &PermissionBody, ctx: &JobContext<'_>) -> Result<Admitted, Refusal> {
    if !ctx.signature_valid {
        return Err(Refusal::Signature);
    }
    if body.expires_at <= body.not_before {
        return Err(Refusal::WindowEmpty);
    }
    if body.expires_at.saturating_sub(body.not_before) > MAX_WINDOW_SECS {
        return Err(Refusal::WindowTooLong);
    }
    let purpose = body.typed_purpose().ok_or(Refusal::UnknownPurpose)?;
    let classes = body.typed_classes().ok_or(Refusal::UnknownClass)?;
    if purpose.requires_mandate() && body.mandate_ref.is_none() {
        return Err(Refusal::MandateRequired);
    }
    if &body.tee_measurement != ctx.attested_measurement {
        return Err(Refusal::MeasurementMismatch);
    }
    if &body.job_key_digest != ctx.attested_job_key_digest {
        return Err(Refusal::JobKeyMismatch);
    }
    if ctx.now < body.not_before {
        return Err(Refusal::NotYetValid);
    }
    if ctx.now >= body.expires_at {
        return Err(Refusal::Expired);
    }
    if ctx.withdrawn {
        return Err(Refusal::Withdrawn);
    }
    if classes.iter().any(|c| ctx.shredded.contains(c)) {
        return Err(Refusal::ClassShredded);
    }
    if purpose.requires_mandate() && ctx.mandate != Some(MandateState::Active) {
        return Err(Refusal::MandateInactive);
    }
    Ok(Admitted { purpose, classes })
}

/// What a job queue row holds of its permission: the id alone (T-27 (7)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct QueueRow {
    /// The permission the job runs under.
    pub permission_id: PermissionId,
}

/// The queue row of a job running under `body`.
#[must_use]
pub const fn queue_row(body: &PermissionBody) -> QueueRow {
    QueueRow {
        permission_id: body.permission_id,
    }
}
