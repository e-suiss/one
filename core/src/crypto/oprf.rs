//! The OPRF of the PIN vault (PV-12; RFC 9497 mode 0x00, ristretto255-SHA512): the client blinds the PIN's access key, each realm evaluates with its share of the OPRF key, the client combines a threshold of evaluations with Lagrange coefficients at 0 and finalizes; a realm sees only a blinded element.

#![allow(
    clippy::arithmetic_side_effects,
    reason = "scalar and point operations are modular group arithmetic"
)]

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity as _;
use sha2::{Digest as _, Sha512};
use zeroize::Zeroizing;

/// The RFC 9497 context string of mode 0x00 with ristretto255-SHA512.
pub const CONTEXT: &[u8] = b"OPRFV1-\x00-ristretto255-SHA512";

/// Why an OPRF step is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OprfError {
    /// An element is the identity or not a canonical ristretto255 encoding, or a scalar is not canonical or zero.
    InvalidElement,
    /// Fewer evaluations than the threshold.
    BelowThreshold,
    /// Two evaluations name the same realm coordinate, or a coordinate is 0.
    DuplicateX,
    /// The input is longer than the encoding allows.
    InputLength,
}

impl OprfError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidElement => "invalid_element",
            Self::BelowThreshold => "below_threshold",
            Self::DuplicateX => "duplicate_x",
            Self::InputLength => "input_length",
        }
    }
}

fn expand_message_xmd(msg: &[u8], dst: &[u8]) -> Result<[u8; 64], OprfError> {
    let dst_len = u8::try_from(dst.len()).map_err(|_| OprfError::InputLength)?;
    let b0 = Sha512::new()
        .chain_update([0_u8; 128])
        .chain_update(msg)
        .chain_update(64_u16.to_be_bytes())
        .chain_update([0_u8])
        .chain_update(dst)
        .chain_update([dst_len])
        .finalize();
    let b1 = Sha512::new()
        .chain_update(b0)
        .chain_update([1_u8])
        .chain_update(dst)
        .chain_update([dst_len])
        .finalize();
    Ok(b1.into())
}

fn hash_to_group(input: &[u8]) -> Result<RistrettoPoint, OprfError> {
    let mut dst = b"HashToGroup-".to_vec();
    dst.extend_from_slice(CONTEXT);
    let uniform = expand_message_xmd(input, &dst)?;
    let point = RistrettoPoint::from_uniform_bytes(&uniform);
    if point == RistrettoPoint::identity() {
        return Err(OprfError::InvalidElement);
    }
    Ok(point)
}

fn element(bytes: &[u8]) -> Result<RistrettoPoint, OprfError> {
    let point = CompressedRistretto::from_slice(bytes)
        .map_err(|_| OprfError::InvalidElement)?
        .decompress()
        .ok_or(OprfError::InvalidElement)?;
    if point == RistrettoPoint::identity() {
        return Err(OprfError::InvalidElement);
    }
    Ok(point)
}

fn scalar(bytes: [u8; 32]) -> Result<Scalar, OprfError> {
    let s: Option<Scalar> = Scalar::from_canonical_bytes(bytes).into();
    s.filter(|s| *s != Scalar::ZERO)
        .ok_or(OprfError::InvalidElement)
}

/// A blinded input, kept by the client until the evaluations return.
pub struct Blinded {
    blind: Scalar,
    input: Zeroizing<Vec<u8>>,
    /// The element sent to every realm.
    pub element: [u8; 32],
}

/// Blinds `input` (the PIN's access key) with a scalar from 64 bytes of the randomness port, or with the canonical `blind` the vectors give.
///
/// # Errors
/// [`OprfError::InvalidElement`], [`OprfError::InputLength`].
pub fn blind(input: &[u8], blind: &Blind) -> Result<Blinded, OprfError> {
    let r = match blind {
        Blind::Wide(bytes) => Scalar::from_bytes_mod_order_wide(bytes),
        Blind::Canonical(bytes) => scalar(*bytes)?,
    };
    if r == Scalar::ZERO {
        return Err(OprfError::InvalidElement);
    }
    let element = (hash_to_group(input)? * r).compress().to_bytes();
    Ok(Blinded {
        blind: r,
        input: Zeroizing::new(input.to_vec()),
        element,
    })
}

/// Where a blind comes from.
pub enum Blind {
    /// 64 uniformly random bytes, reduced modulo the group order.
    Wide([u8; 64]),
    /// A canonical nonzero scalar.
    Canonical([u8; 32]),
}

/// A realm's evaluation of a blinded element with its key share `key`.
///
/// # Errors
/// [`OprfError::InvalidElement`].
pub fn evaluate(key: [u8; 32], blinded_element: &[u8]) -> Result<[u8; 32], OprfError> {
    Ok((element(blinded_element)? * scalar(key)?)
        .compress()
        .to_bytes())
}

/// One realm's evaluation with the realm's share coordinate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Evaluation {
    /// The realm's share coordinate, never 0.
    pub x: u64,
    /// The evaluated element.
    pub element: [u8; 32],
}

/// Combines at least `threshold` evaluations by Lagrange interpolation at 0 over ristretto255 scalars.
///
/// # Errors
/// [`OprfError`].
pub fn combine(evaluations: &[Evaluation], threshold: usize) -> Result<[u8; 32], OprfError> {
    if evaluations.len() < threshold.max(1) {
        return Err(OprfError::BelowThreshold);
    }
    let mut seen = Vec::new();
    for e in evaluations {
        if e.x == 0 || seen.contains(&e.x) {
            return Err(OprfError::DuplicateX);
        }
        seen.push(e.x);
    }
    let mut sum = RistrettoPoint::identity();
    for e in evaluations {
        let xi = Scalar::from(e.x);
        let mut weight = Scalar::ONE;
        for other in evaluations {
            if other.x != e.x {
                let xm = Scalar::from(other.x);
                weight *= xm * (xm - xi).invert();
            }
        }
        sum += element(&e.element)? * weight;
    }
    if sum == RistrettoPoint::identity() {
        return Err(OprfError::InvalidElement);
    }
    Ok(sum.compress().to_bytes())
}

/// Unblinds the (combined) evaluated element and hashes it with the input into the 64-byte output.
///
/// # Errors
/// [`OprfError::InvalidElement`], [`OprfError::InputLength`].
pub fn finalize(
    blinded: &Blinded,
    evaluated_element: &[u8],
) -> Result<Zeroizing<[u8; 64]>, OprfError> {
    let unblinded = (element(evaluated_element)? * blinded.blind.invert())
        .compress()
        .to_bytes();
    let input_len = u16::try_from(blinded.input.len()).map_err(|_| OprfError::InputLength)?;
    let out = Sha512::new()
        .chain_update(input_len.to_be_bytes())
        .chain_update(blinded.input.as_slice())
        .chain_update(32_u16.to_be_bytes())
        .chain_update(unblinded)
        .chain_update(b"Finalize")
        .finalize();
    Ok(Zeroizing::new(out.into()))
}

#[cfg(test)]
mod tests;
