//! The `trust/v1` formula: a Beta(1, 1) posterior mean over source-weighted, recency-decayed evidence, raised by user confirmation and capped by source and contradictions, rounded to six decimals in binary64 with ties to even (M-13, M-14, M-8).

use serde::{Deserialize, Serialize};

use super::fields::SourceKind;
use crate::ontology::time::{Instant, Span};

/// The formula version.
pub const VERSION: &str = "trust/v1";
/// Prior alpha.
pub const PRIOR_ALPHA: f64 = 1.0;
/// Prior beta.
pub const PRIOR_BETA: f64 = 1.0;
/// Recency half-life in days.
pub const HALF_LIFE_DAYS: f64 = 180.0;
/// Weight of a user confirmation.
pub const CONFIRMATION_WEIGHT: f64 = 20.0;
/// Each contradiction halves the cap.
pub const CONTRADICTION_CAP_BASE: f64 = 0.5;
/// Output decimals.
pub const DECIMALS: u32 = 6;

const SECONDS_PER_DAY: u64 = 86_400;
const HALF_LIFE_SECS: u64 = 180 * SECONDS_PER_DAY;

/// The evidence weight of a source kind.
#[must_use]
pub const fn source_weight(kind: SourceKind) -> f64 {
    match kind {
        SourceKind::UserStatement => 20.0,
        SourceKind::UserBehaviour | SourceKind::ConnectedSource => 1.0,
        SourceKind::ExternalContent | SourceKind::Import => 0.5,
    }
}

/// The trust ceiling of a source kind without user confirmation.
#[must_use]
pub const fn source_ceiling(kind: SourceKind) -> f64 {
    match kind {
        SourceKind::UserStatement => 1.0,
        SourceKind::UserBehaviour | SourceKind::ConnectedSource => 0.95,
        SourceKind::ExternalContent | SourceKind::Import => 0.6,
    }
}

/// The only inputs of the formula; anything else, including a model's verbal confidence, is rejected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustInput {
    /// Source kind.
    pub source_kind: SourceKind,
    /// Observations, at least 1.
    pub observation_count: u32,
    /// Supporting observations.
    pub supporting_count: u32,
    /// Last observation.
    pub last_observed_at: Instant,
    /// User confirmation, if any.
    pub user_confirmed_at: Option<Instant>,
    /// Contradicting records.
    pub contradicting_count: u32,
    /// The clock, given explicitly.
    pub as_of: Instant,
}

/// Why the formula refused its input.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustError {
    /// `supporting_count > observation_count` or `observation_count < 1`.
    InvalidEvidence,
    /// `last_observed_at` or `user_confirmed_at` after `as_of`.
    FutureEvidence,
    /// A field outside the input schema, or a missing one.
    UnknownInput,
}

fn u64_to_f64(v: u64) -> f64 {
    let hi = u32::try_from(v.checked_shr(32).unwrap_or(0)).unwrap_or(u32::MAX);
    let lo = u32::try_from(v & 0xffff_ffff).unwrap_or(0);
    f64::from(hi) * 4_294_967_296.0 + f64::from(lo)
}

fn exp_neg(x: f64) -> f64 {
    let mut term = 1.0_f64;
    let mut sum = 1.0_f64;
    for k in 1..=30_u32 {
        term = term * -x / f64::from(k);
        sum += term;
    }
    sum
}

fn half_powers(n: u64) -> f64 {
    let mut out = 1.0_f64;
    for _ in 0..n.min(1100) {
        out *= 0.5;
    }
    out
}

/// `2 ^ (-span / half_life)`, the recency factor.
#[must_use]
pub fn recency(span: Span) -> f64 {
    let whole = span.secs.checked_div(HALF_LIFE_SECS).unwrap_or(0);
    let rest = span.secs.checked_rem(HALF_LIFE_SECS).unwrap_or(0);
    let frac_secs = u64_to_f64(rest) + f64::from(span.nanos) / 1e9;
    let frac = frac_secs / u64_to_f64(HALF_LIFE_SECS);
    half_powers(whole) * exp_neg(frac * core::f64::consts::LN_2)
}

/// Rounds a value in `0..=1` to six decimals, nearest with ties to even, on its exact binary64 value.
#[must_use]
pub fn round6(p: f64) -> f64 {
    if !(0.0..=1.0).contains(&p) {
        return p;
    }
    let bits = p.to_bits();
    let exp = bits.checked_shr(52).unwrap_or(0) & 0x7ff;
    let frac = bits & 0x000f_ffff_ffff_ffff;
    let (mantissa, shift) = if exp == 0 {
        (frac, 1074_u64)
    } else {
        (frac | 0x0010_0000_0000_0000, 1075_u64.saturating_sub(exp))
    };
    if shift == 0 {
        return p;
    }
    if shift >= 128 {
        return 0.0;
    }
    let scaled = u128::from(mantissa).saturating_mul(1_000_000);
    let s = u32::try_from(shift).unwrap_or(127);
    let mut q = scaled.checked_shr(s).unwrap_or(0);
    let mask = 1_u128.checked_shl(s).unwrap_or(0).saturating_sub(1);
    let rem = scaled & mask;
    let half = 1_u128.checked_shl(s.saturating_sub(1)).unwrap_or(0);
    if rem > half || (rem == half && q & 1 == 1) {
        q = q.saturating_add(1);
    }
    f64::from(u32::try_from(q).unwrap_or(1_000_000)) / 1e6
}

/// Computes `trust/v1`.
///
/// # Errors
/// [`TrustError::InvalidEvidence`] for impossible counts and [`TrustError::FutureEvidence`] for evidence after `as_of`.
pub fn trust_v1(input: &TrustInput) -> Result<f64, TrustError> {
    if input.observation_count < 1 || input.supporting_count > input.observation_count {
        return Err(TrustError::InvalidEvidence);
    }
    let since_last = input
        .as_of
        .since(&input.last_observed_at)
        .ok_or(TrustError::FutureEvidence)?;
    let since_confirmed = match &input.user_confirmed_at {
        Some(at) => Some(input.as_of.since(at).ok_or(TrustError::FutureEvidence)?),
        None => None,
    };
    let w = source_weight(input.source_kind);
    let r = recency(since_last);
    let against = input
        .observation_count
        .saturating_sub(input.supporting_count);
    let mut alpha = PRIOR_ALPHA + w * r * f64::from(input.supporting_count);
    let beta = PRIOR_BETA + w * r * f64::from(against);
    if let Some(span) = since_confirmed {
        alpha += CONFIRMATION_WEIGHT * recency(span);
    }
    let mut p = alpha / (alpha + beta);
    let ceiling = if since_confirmed.is_some() {
        1.0
    } else {
        source_ceiling(input.source_kind)
    };
    p = p.min(ceiling);
    if input.contradicting_count >= 1 {
        let mut cap = 1.0_f64;
        for _ in 0..input.contradicting_count.min(1100) {
            cap *= CONTRADICTION_CAP_BASE;
        }
        p = p.min(cap);
    }
    Ok(round6(p))
}
