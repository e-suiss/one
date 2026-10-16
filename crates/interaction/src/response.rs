//! `InteractionResponse`: the single answer shape from every surface, signed with the device key and idempotent (X-22, X-18, X-19, C-26, A-29).

use alloc::string::String;

use one_proto::ontology::{InstanceRef, OpaqueId, PartyRef};
use one_proto::{DeviceId, InteractionId};
use serde::{Deserialize, Serialize};

use crate::common::{ActionId, Nonce, Timestamp};
use one_proto::interaction_types::Authentication;
use one_proto::interaction_types::SurfaceClass;

/// The answering Access identity: the user's own Party and Instance.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Responder {
    /// Party.
    pub party: PartyRef,
    /// Instance.
    pub instance: InstanceRef,
}

/// User verification evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum UserVerification {
    None,
    Biometric,
    Pin,
    WristDetect,
}

/// Human presence gesture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Presence {
    None,
    Tap,
    Hold,
    TwoStep,
    Voice,
}

/// Evidence level of an answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// Authentication.
    pub authentication: Authentication,
    /// User verification.
    pub user_verification: UserVerification,
    /// Presence gesture.
    pub presence_gesture: Presence,
}

/// Signature algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Algorithm {
    /// ECDSA P-256 with SHA-256.
    #[serde(rename = "ES256")]
    Es256,
}

/// Detached `COSE_Sign1` device signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    /// Algorithm.
    pub alg: Algorithm,
    /// Access `KeyBinding` identifier.
    pub kid: OpaqueId,
    /// base64url `COSE_Sign1`.
    pub cose_sign1: String,
}

/// An answer to an Interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InteractionResponse {
    /// Interaction.
    pub interaction_id: InteractionId,
    /// Answered version.
    pub interaction_version: u32,
    /// Chosen action.
    pub action: ActionId,
    /// Responder.
    pub responder: Responder,
    /// Answer nonce.
    pub nonce: Nonce,
    /// Device.
    pub device_id: DeviceId,
    /// Surface class.
    pub surface_class: SurfaceClass,
    /// Evidence.
    pub evidence: Evidence,
    /// Answer time.
    pub responded_at: Timestamp,
    /// Signature.
    pub signature: Signature,
}

impl InteractionResponse {
    /// True if both carry the same signed payload: every field except `signature`.
    #[must_use]
    pub fn same_payload(&self, other: &Self) -> bool {
        self.interaction_id == other.interaction_id
            && self.interaction_version == other.interaction_version
            && self.action == other.action
            && self.responder == other.responder
            && self.nonce == other.nonce
            && self.device_id == other.device_id
            && self.surface_class == other.surface_class
            && self.evidence == other.evidence
            && self.responded_at == other.responded_at
    }
}
