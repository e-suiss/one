//! The shared Suiss webhook profile on the receiving side (Access TN-136, E-3): the signed content is `webhook-id`, `.`, `webhook-timestamp`, `.` and the raw body; `webhook-signature` lists space separated signatures and one `v1a` (`Ed25519`) signature under a key the sender's discovery document lists verifies the delivery; One shares no secret with a sibling, so `v1` (HMAC) never verifies; the timestamp must lie within five minutes of the trusted time. A webhook is a notice, never an authority source (INV-24): its receipt is deduplicated by `webhook-id` and its content is read again from the owner.

use aws_lc_rs::signature::{ED25519, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// How far the timestamp may be from the trusted time, in seconds.
pub const TOLERANCE_SECS: i64 = 300;

/// The headers of one delivery and its raw body.
#[derive(Debug, Clone, Copy)]
pub struct Delivery<'a> {
    /// `webhook-id`.
    pub id: &'a str,
    /// `webhook-timestamp`, Unix seconds.
    pub timestamp: &'a str,
    /// `webhook-signature`.
    pub signature: &'a str,
    /// The raw body, as received.
    pub body: &'a [u8],
}

/// Why a delivery is refused; the sender gets no detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WebhookError {
    /// The timestamp is not a number or lies outside the tolerance.
    Timestamp,
    /// No `v1a` signature verifies under a listed key.
    Signature,
}

/// Verifies `delivery` under the sender's `Ed25519` `keys` at Unix time `now`.
///
/// # Errors
/// [`WebhookError`].
pub fn verify(delivery: &Delivery<'_>, keys: &[[u8; 32]], now: i64) -> Result<(), WebhookError> {
    if !delivery.timestamp.bytes().all(|b| b.is_ascii_digit()) || delivery.timestamp.is_empty() {
        return Err(WebhookError::Timestamp);
    }
    let seconds: i64 = delivery
        .timestamp
        .parse()
        .map_err(|_| WebhookError::Timestamp)?;
    if now.abs_diff(seconds) > TOLERANCE_SECS.unsigned_abs() {
        return Err(WebhookError::Timestamp);
    }
    let mut signed = Vec::with_capacity(
        delivery
            .id
            .len()
            .saturating_add(delivery.timestamp.len())
            .saturating_add(delivery.body.len())
            .saturating_add(2),
    );
    signed.extend_from_slice(delivery.id.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(delivery.timestamp.as_bytes());
    signed.push(b'.');
    signed.extend_from_slice(delivery.body);
    let verified = delivery
        .signature
        .split(' ')
        .filter_map(|s| s.strip_prefix("v1a,"))
        .filter_map(|s| STANDARD.decode(s).ok())
        .any(|sig| {
            keys.iter().any(|k| {
                UnparsedPublicKey::new(&ED25519, k)
                    .verify(&signed, &sig)
                    .is_ok()
            })
        });
    if verified {
        Ok(())
    } else {
        Err(WebhookError::Signature)
    }
}
