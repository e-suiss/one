//! Virtual clock and fixed-seed generator behind the runtime ports, for tests and deterministic simulation only (T-27 (2), T-38 (5)).

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use one_runtime::{Clock, Monotonic, Rng, UnixNanos};

/// A clock that moves only when [`VirtualClock::advance`] is called.
#[derive(Debug)]
pub struct VirtualClock {
    state: Mutex<(UnixNanos, Duration)>,
}

impl VirtualClock {
    /// A clock showing `start` with the monotonic origin at zero.
    #[must_use]
    pub fn new(start: UnixNanos) -> Self {
        Self {
            state: Mutex::new((start, Duration::ZERO)),
        }
    }

    /// Moves both the wall clock and the monotonic clock forward by `d`.
    /// Returns `false`, leaving the clock unchanged, if either would overflow.
    pub fn advance(&self, d: Duration) -> bool {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        match (state.0.checked_add(d), state.1.checked_add(d)) {
            (Some(wall), Some(mono)) => {
                *state = (wall, mono);
                true
            }
            _ => false,
        }
    }
}

impl Clock for VirtualClock {
    fn now(&self) -> UnixNanos {
        self.state.lock().unwrap_or_else(PoisonError::into_inner).0
    }

    fn monotonic(&self) -> Monotonic {
        Monotonic(self.state.lock().unwrap_or_else(PoisonError::into_inner).1)
    }
}

/// A deterministic generator (`xoshiro256**` seeded through `SplitMix64`).
///
/// Not cryptographic; it exists so that tests and simulations replay exactly.
#[derive(Debug)]
pub struct SeededRng {
    state: Mutex<[u64; 4]>,
}

fn splitmix64(x: &mut u64) -> u64 {
    *x = x.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *x;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

impl SeededRng {
    /// A generator whose output is fully determined by `seed`.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        let mut x = seed;
        let state = [
            splitmix64(&mut x),
            splitmix64(&mut x),
            splitmix64(&mut x),
            splitmix64(&mut x),
        ];
        Self {
            state: Mutex::new(state),
        }
    }

    fn next_u64(s: &mut [u64; 4]) -> u64 {
        let [s0, s1, s2, s3] = *s;
        let result = s1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s1 << 17;
        let mut n = [s0, s1, s2 ^ s0, s3 ^ s1];
        n[1] ^= n[2];
        n[0] ^= n[3];
        n[2] ^= t;
        n[3] = n[3].rotate_left(45);
        *s = n;
        result
    }
}

impl Rng for SeededRng {
    fn fill(&self, dest: &mut [u8]) {
        let mut state = self.state.lock().unwrap_or_else(PoisonError::into_inner);
        for chunk in dest.chunks_mut(8) {
            let bytes = Self::next_u64(&mut state).to_le_bytes();
            for (d, b) in chunk.iter_mut().zip(bytes) {
                *d = b;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-38 (5)
    #[test]
    fn t_38_same_seed_replays_the_same_bytes() {
        let mut first = [0_u8; 37];
        let mut second = [0_u8; 37];
        let mut other = [0_u8; 37];
        SeededRng::new(7).fill(&mut first);
        SeededRng::new(7).fill(&mut second);
        SeededRng::new(8).fill(&mut other);
        assert_eq!(first, second);
        assert_ne!(first, other);
    }

    // T-27 (2)
    #[test]
    fn t_27_virtual_clock_moves_only_when_advanced() {
        let clock = VirtualClock::new(UnixNanos(10));
        assert_eq!(clock.now(), UnixNanos(10));
        assert!(clock.advance(Duration::from_nanos(5)));
        assert_eq!(clock.now(), UnixNanos(15));
        assert_eq!(clock.monotonic(), Monotonic(Duration::from_nanos(5)));
        assert!(!VirtualClock::new(UnixNanos(u128::MAX)).advance(Duration::from_nanos(1)));
    }
}
