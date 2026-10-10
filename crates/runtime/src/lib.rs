//! The Clock and Rng ports through which all code reads time and randomness (T-27 (2)).
#![no_std]

use core::time::Duration;

/// Wall-clock time as nanoseconds since the Unix epoch, UTC.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixNanos(pub u128);

impl UnixNanos {
    /// The time `d` after `self`, or `None` on overflow (T-28 (4)).
    #[must_use]
    pub fn checked_add(self, d: Duration) -> Option<Self> {
        self.0.checked_add(d.as_nanos()).map(Self)
    }

    /// The time elapsed from `earlier` to `self`, or `None` if `earlier` is later
    /// or the difference does not fit a [`Duration`].
    #[must_use]
    pub fn checked_since(self, earlier: Self) -> Option<Duration> {
        let nanos = self.0.checked_sub(earlier.0)?;
        let secs = u64::try_from(nanos / 1_000_000_000).ok()?;
        let sub = u32::try_from(nanos % 1_000_000_000).ok()?;
        Some(Duration::new(secs, sub))
    }
}

/// A monotonic instant: an offset from an arbitrary, process-local origin.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Monotonic(pub Duration);

/// The time port (T-27 (2)).
pub trait Clock: Send + Sync {
    /// The current wall-clock time.
    fn now(&self) -> UnixNanos;

    /// The current monotonic instant, for timeouts and durations.
    fn monotonic(&self) -> Monotonic;
}

/// The randomness port (T-27 (2)).
///
/// Production implementations draw from the operating system's CSPRNG. Key
/// material is generated inside the key layer through the shared Suiss crypto
/// crate, never through this port.
pub trait Rng: Send + Sync {
    /// Fills `dest` with random bytes.
    fn fill(&self, dest: &mut [u8]);
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-28 (4)
    #[test]
    fn t_28_clock_arithmetic_overflow_is_none() {
        assert_eq!(
            UnixNanos(u128::MAX).checked_add(Duration::from_nanos(1)),
            None
        );
        assert_eq!(UnixNanos(1).checked_since(UnixNanos(2)), None);
        assert_eq!(
            UnixNanos(3_000_000_001).checked_since(UnixNanos(1)),
            Some(Duration::from_secs(3))
        );
    }
}
