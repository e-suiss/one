//! The operating-system implementations of the Clock and Rng ports; the only place that reads the wall clock and the OS randomness source (T-27 (2)).

#![allow(clippy::disallowed_methods, reason = "T-27")]

use std::time::{Instant, SystemTime, UNIX_EPOCH};

use one_runtime::{Clock, Monotonic, Rng, UnixNanos};

/// The system clock.
pub(crate) struct SystemClock {
    origin: Instant,
}

impl SystemClock {
    pub(crate) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Clock for SystemClock {
    fn now(&self) -> UnixNanos {
        UnixNanos(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos()),
        )
    }

    fn monotonic(&self) -> Monotonic {
        Monotonic(self.origin.elapsed())
    }
}

/// The operating system's CSPRNG.
pub(crate) struct OsRng;

impl Rng for OsRng {
    fn fill(&self, dest: &mut [u8]) {
        if getrandom::fill(dest).is_err() {
            std::process::abort();
        }
    }
}
