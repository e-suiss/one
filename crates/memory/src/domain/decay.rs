//! Decay (M-23, `conformance/memory/decay-v1.toml`): the retrieval priority of a record falls with time since its last use at a half-life set by its time kind, rises with how often it was used and with a recent user confirmation, and never deletes or archives it.

use one_proto::memory::fields::TimeKind;
use one_proto::memory::trust::round6;
use one_proto::ontology::time::Instant;

const SECONDS_PER_DAY: f64 = 86_400.0;
const RECENCY_WEIGHT: f64 = 0.6;
const FREQUENCY_WEIGHT: f64 = 0.25;
const CONFIRMATION_WEIGHT: f64 = 0.15;
const FREQUENCY_SATURATION: f64 = 5.0;
const CONFIRMATION_HALF_LIFE_DAYS: f64 = 365.0;

/// The half-life of a record's last use, in days, by time kind.
#[must_use]
pub const fn use_half_life_days(kind: TimeKind) -> f64 {
    match kind {
        TimeKind::Permanent => 180.0,
        TimeKind::Current => 30.0,
        TimeKind::Seasonal => 365.0,
        TimeKind::OneOff => 14.0,
        TimeKind::Past => 90.0,
    }
}

/// The input of `decay/v1`.
#[derive(Debug, Clone, PartialEq)]
pub struct DecayInput {
    /// The record's time kind.
    pub time_kind: TimeKind,
    /// The time the priority is computed at.
    pub as_of: Instant,
    /// The last use, or the recording time of a record never used.
    pub last_used_at: Instant,
    /// How many times retrieval used it.
    pub use_count: u32,
    /// The last user confirmation.
    pub last_confirmed_at: Option<Instant>,
}

/// Why a priority was not computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum DecayError {
    /// A use or confirmation after `as_of`.
    #[error("evidence after the time of computation")]
    FutureEvidence,
}

fn days_since(as_of: &Instant, earlier: &Instant) -> Result<f64, DecayError> {
    let span = as_of.since(earlier).ok_or(DecayError::FutureEvidence)?;
    let secs = u32::try_from(span.secs).map_or(f64::from(u32::MAX), f64::from);
    Ok((secs + f64::from(span.nanos) / 1e9) / SECONDS_PER_DAY)
}

/// The retrieval priority in `0..=1`, rounded to six decimals.
///
/// # Errors
/// [`DecayError::FutureEvidence`].
pub fn priority(input: &DecayInput) -> Result<f64, DecayError> {
    let used = days_since(&input.as_of, &input.last_used_at)?;
    let recency = (-used / use_half_life_days(input.time_kind)).exp2();
    let frequency = ((1.0 + f64::from(input.use_count)).log2() / FREQUENCY_SATURATION).min(1.0);
    let confirmation = match &input.last_confirmed_at {
        None => 0.0,
        Some(at) => (-days_since(&input.as_of, at)? / CONFIRMATION_HALF_LIFE_DAYS).exp2(),
    };
    Ok(round6(
        RECENCY_WEIGHT * recency
            + FREQUENCY_WEIGHT * frequency
            + CONFIRMATION_WEIGHT * confirmation,
    ))
}
