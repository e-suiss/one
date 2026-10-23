//! The suspended-negotiation handle: protected header and claims types and the issuer's checks over decoded claims in contract order — missing, malformed, tampered, expired, binding, digest, replayed — with single use consumed only when the reply is accepted (OO-5; OD-63 #9).

use serde::{Deserialize, Serialize};

use super::wire::{Did, Digest, HandleCompact, Party, Refusal, Uuid7};
use crate::ontology::JsonObject;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;

/// `alg` `dir`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Alg {
    /// Direct encryption with the issuer's key.
    #[serde(rename = "dir")]
    Dir,
}

/// `enc` `A256GCM`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Enc {
    /// AES-256-GCM.
    #[serde(rename = "A256GCM")]
    A256Gcm,
}

/// `typ` `one-federation-handle+jwe`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Typ {
    /// The handle type.
    #[serde(rename = "one-federation-handle+jwe")]
    OneFederationHandle,
}

checked_string!(
    /// An issuer-local key identifier.
    Kid,
    "kid",
    |s| (1..=64).contains(&s.len())
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
);

/// The decoded JWE protected header; the AEAD additional data (OO-5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedHeader {
    /// `dir`.
    pub alg: Alg,
    /// `A256GCM`.
    pub enc: Enc,
    /// The key identifier.
    pub kid: Kid,
    /// The handle type.
    pub typ: Typ,
}

/// The claims format version `1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct ClaimsV1;

impl TryFrom<u8> for ClaimsV1 {
    type Error = ContractViolation;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value == 1 {
            Ok(Self)
        } else {
            Err(ContractViolation("claims version"))
        }
    }
}

impl From<ClaimsV1> for u8 {
    fn from(_: ClaimsV1) -> Self {
        1
    }
}

/// The kind of the suspended message: only kinds that await a reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SuspendedKind {
    /// An offer.
    Offer,
    /// A counter-offer.
    CounterOffer,
    /// A query.
    Query,
}

/// The decrypted handle claims (OO-5).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HandleClaims {
    /// The claims format version.
    pub v: ClaimsV1,
    /// The single-use identifier.
    pub jti: Uuid7,
    /// The issuing agent.
    pub iss: Did,
    /// The person the issuing agent acts for.
    pub sub: Did,
    /// The agent expected to reply.
    pub aud: Did,
    /// The person the replying agent must act for.
    pub rcp: Did,
    /// The chain.
    pub cid: Uuid7,
    /// The suspended message's offer version.
    pub ver: u32,
    /// The suspended message's kind.
    pub knd: SuspendedKind,
    /// The suspended message's digest.
    pub dig: Digest,
    /// Issued at, Unix seconds.
    pub iat: u64,
    /// Expiry, Unix seconds.
    pub exp: u64,
    /// Issuer-private resumption state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub st: Option<JsonObject>,
}

/// The longest handle lifetime: the message's own, at most 7 days (OD-63 #9).
pub const MAX_HANDLE_LIFETIME_SECONDS: u64 = 604_800;

/// The most members of the issuer state.
pub const MAX_STATE_MEMBERS: usize = 16;

/// What the issuer holds after opening an echoed handle at the crypto boundary.
#[derive(Clone, Copy, PartialEq)]
pub struct OpenedHandle<'a> {
    /// The handle text echoed in `inReplyTo.handle`, if any.
    pub compact: Option<&'a str>,
    /// The decoded protected header, `None` when it breaks the header contract.
    pub header: Option<&'a ProtectedHeader>,
    /// The AEAD tag verified under the issuer's key for `kid`.
    pub aead_verified: bool,
    /// The decrypted claims, `None` when they break the claims contract.
    pub claims: Option<&'a HandleClaims>,
}

/// The reply the handle must be bound to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyBinding<'a> {
    /// The reply's sender.
    pub reply_sender: &'a Party,
    /// The reply's recipient.
    pub reply_recipient: &'a Party,
    /// The reply's correlation identifier.
    pub correlation_id: &'a Uuid7,
    /// The reply's `inReplyTo.offerVersion`.
    pub in_reply_to_version: u32,
    /// The reply's `inReplyTo.digest`.
    pub in_reply_to_digest: &'a Digest,
    /// The suspended message's expiry, truncated to Unix seconds.
    pub suspended_expires_at: Option<u64>,
    /// The issuer's clock, Unix seconds; no grace period.
    pub now: u64,
}

/// The issuer's set of spent handle identifiers, kept until each handle's expiry.
pub trait SpentHandles {
    /// True when the identifier was already used.
    fn is_spent(&self, jti: &Uuid7) -> bool;
}

impl SpentHandles for [Uuid7] {
    fn is_spent(&self, jti: &Uuid7) -> bool {
        self.contains(jti)
    }
}

/// A verified, not yet consumed handle.
#[derive(Clone, Debug, PartialEq, Eq)]
#[must_use]
pub struct VerifiedHandle {
    jti: Uuid7,
    exp: u64,
}

/// A spent-set entry to record atomically with acceptance of the reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpentEntry {
    /// The spent identifier.
    pub jti: Uuid7,
    /// Keep the entry until this Unix second.
    pub keep_until: u64,
}

impl VerifiedHandle {
    /// Consumes the handle when the rest of the reply is accepted; a reply refused for any reason leaves it unspent.
    ///
    /// # Errors
    /// Returns the downstream refusal unchanged.
    pub fn consume(self, downstream: Result<(), Refusal>) -> Result<SpentEntry, Refusal> {
        downstream.map(|()| SpentEntry {
            jti: self.jti,
            keep_until: self.exp,
        })
    }
}

/// Verifies an echoed handle in contract order (OO-5).
///
/// # Errors
/// Returns the first failing check's refusal.
pub fn verify_handle<S: SpentHandles + ?Sized>(
    opened: &OpenedHandle<'_>,
    binding: &ReplyBinding<'_>,
    spent: &S,
) -> Result<VerifiedHandle, Refusal> {
    let compact = opened.compact.ok_or(Refusal::HandleMissing)?;
    HandleCompact::parse(compact).map_err(|_| Refusal::HandleMalformed)?;
    opened.header.ok_or(Refusal::HandleMalformed)?;
    // OO-5
    if !opened.aead_verified {
        return Err(Refusal::HandleTampered);
    }
    let claims = opened.claims.ok_or(Refusal::HandleMalformed)?;
    let lifetime_ok = claims
        .exp
        .checked_sub(claims.iat)
        .is_some_and(|l| l <= MAX_HANDLE_LIFETIME_SECONDS);
    let state_ok = claims
        .st
        .as_ref()
        .is_none_or(|st| st.len() <= MAX_STATE_MEMBERS);
    let expiry_ok = binding.suspended_expires_at.is_none_or(|e| e == claims.exp);
    if !(lifetime_ok && state_ok && expiry_ok) {
        return Err(Refusal::HandleMalformed);
    }
    if binding.now > claims.exp {
        return Err(Refusal::HandleExpired);
    }
    let bound = claims.aud == binding.reply_sender.agent
        && claims.rcp == binding.reply_sender.person
        && claims.iss == binding.reply_recipient.agent
        && claims.sub == binding.reply_recipient.person
        && &claims.cid == binding.correlation_id
        && claims.ver == binding.in_reply_to_version;
    if !bound {
        return Err(Refusal::HandleBindingMismatch);
    }
    if &claims.dig != binding.in_reply_to_digest {
        return Err(Refusal::HandleDigestMismatch);
    }
    if spent.is_spent(&claims.jti) {
        return Err(Refusal::HandleReplayed);
    }
    Ok(VerifiedHandle {
        jti: claims.jti.clone(),
        exp: claims.exp,
    })
}

impl core::fmt::Debug for OpenedHandle<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedHandle")
            .field("compact", &self.compact.map(|_| "[masked]"))
            .field("header", &self.header.map(|_| "[masked]"))
            .field("aead_verified", &self.aead_verified)
            .field("claims", &self.claims.map(|_| "[masked]"))
            .finish()
    }
}
