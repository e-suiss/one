//! The key layer's ports: the device Instance signature check and the live permission state Access reports; implementations come from the shared Suiss crypto crate and the Access client (T-27 (2), Access E31, Access E59).

use one_proto::data_class::RetentionClass;
use one_proto::key_permission::PermissionId;

use crate::domain::permission::MandateState;

/// Verifies the device Instance's ES256 signature over a permission's `Sig_structure`.
pub trait PermissionSignature: Send + Sync {
    /// Whether `signature` verifies over `sig_structure` under the Instance key named by `kid`.
    fn verify(&self, kid: &[u8], sig_structure: &[u8], signature: &[u8; 64]) -> bool;
}

/// The state of a permission that Access holds and the TEE asks for at job start and every resume point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveState {
    /// Whether the user withdrew the permission.
    pub withdrawn: bool,
    /// The Mandate's state; `None` when the permission names none.
    pub mandate: Option<MandateState>,
    /// The classes shredded since the permission was given.
    pub shredded: Vec<RetentionClass>,
}

/// Asks Access for a permission's live state.
pub trait PermissionStatus {
    /// The port's failure; the job waits rather than running on a guess.
    type Error;

    /// The live state of `permission`.
    ///
    /// # Errors
    /// Access cannot be asked.
    fn live_state(&self, permission: &PermissionId) -> Result<LiveState, Self::Error>;
}
