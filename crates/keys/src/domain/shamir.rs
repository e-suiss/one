//! Threshold sharing of a secret over GF(2^8) with the AES polynomial 0x11b, one polynomial per byte (PV-12): the PIN vault's realm shares and the recovery contact's 2-of-2 with the account share. Field arithmetic runs in constant time; the coefficients come from the caller's randomness port.

/// One share: its coordinate and one byte per secret byte.
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
    /// The coordinate, never 0.
    pub x: u8,
    /// The share bytes.
    pub y: Vec<u8>,
}

impl core::fmt::Debug for Share {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Share {{ x: {}, y: [redacted] }}", self.x)
    }
}

/// Why a split or combine is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ShamirError {
    /// A coordinate is 0, where the secret lives.
    XZero,
    /// Two shares have the same coordinate.
    DuplicateX,
    /// Fewer shares than the threshold.
    BelowThreshold,
    /// The threshold is below 2 or above the number of shares, or the coefficients do not fit it.
    Threshold,
    /// The shares or coefficients differ in length from the secret.
    Length,
}

impl ShamirError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::XZero => "x_zero",
            Self::DuplicateX => "duplicate_x",
            Self::BelowThreshold => "below_threshold",
            Self::Threshold => "threshold",
            Self::Length => "length",
        }
    }
}

const fn mask(bit: u8) -> u8 {
    0_u8.wrapping_sub(bit & 1)
}

fn mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut p = 0_u8;
    for _ in 0..8 {
        p ^= a & mask(b);
        let carry = mask(a.wrapping_shr(7));
        a = a.wrapping_shl(1) ^ (0x1b & carry);
        b = b.wrapping_shr(1);
    }
    p
}

fn inv(a: u8) -> u8 {
    let mut result = 1_u8;
    let mut base = a;
    let mut e = 254_u8;
    for _ in 0..8 {
        result = (mul(result, base) & mask(e)) | (result & !mask(e));
        base = mul(base, base);
        e = e.wrapping_shr(1);
    }
    result
}

fn distinct(xs: impl IntoIterator<Item = u8>) -> Result<(), ShamirError> {
    let mut seen = [false; 256];
    for x in xs {
        if x == 0 {
            return Err(ShamirError::XZero);
        }
        let slot = seen.get_mut(usize::from(x)).ok_or(ShamirError::XZero)?;
        if *slot {
            return Err(ShamirError::DuplicateX);
        }
        *slot = true;
    }
    Ok(())
}

/// Splits `secret` into one share per coordinate of `xs`, any `threshold` of which recover it; `coefficients` are the `threshold - 1` higher-degree coefficients, each as long as the secret, drawn fresh from the randomness port.
///
/// # Errors
/// [`ShamirError`].
pub fn split(
    secret: &[u8],
    threshold: u8,
    xs: &[u8],
    coefficients: &[Vec<u8>],
) -> Result<Vec<Share>, ShamirError> {
    distinct(xs.iter().copied())?;
    let k = usize::from(threshold);
    if k < 2 || k > xs.len() || coefficients.len() != k.saturating_sub(1) {
        return Err(ShamirError::Threshold);
    }
    if coefficients.iter().any(|c| c.len() != secret.len()) {
        return Err(ShamirError::Length);
    }
    Ok(xs
        .iter()
        .map(|&x| {
            let y = secret
                .iter()
                .enumerate()
                .map(|(i, &s)| {
                    let mut acc = 0_u8;
                    for c in coefficients.iter().rev() {
                        acc = mul(acc, x) ^ c.get(i).copied().unwrap_or(0);
                    }
                    mul(acc, x) ^ s
                })
                .collect();
            Share { x, y }
        })
        .collect())
}

/// Recovers the secret from at least `threshold` shares by Lagrange interpolation at 0.
///
/// # Errors
/// [`ShamirError`].
pub fn combine(shares: &[Share], threshold: u8) -> Result<Vec<u8>, ShamirError> {
    if threshold < 2 {
        return Err(ShamirError::Threshold);
    }
    if shares.len() < usize::from(threshold) {
        return Err(ShamirError::BelowThreshold);
    }
    distinct(shares.iter().map(|s| s.x))?;
    let len = shares.first().map_or(0, |s| s.y.len());
    if shares.iter().any(|s| s.y.len() != len) {
        return Err(ShamirError::Length);
    }
    let mut secret = vec![0_u8; len];
    for (j, share) in shares.iter().enumerate() {
        let mut weight = 1_u8;
        for (m, other) in shares.iter().enumerate() {
            if m != j {
                weight = mul(weight, mul(other.x, inv(other.x ^ share.x)));
            }
        }
        for (out, &y) in secret.iter_mut().zip(&share.y) {
            *out ^= mul(y, weight);
        }
    }
    Ok(secret)
}
