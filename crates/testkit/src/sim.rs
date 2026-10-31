//! Deterministic simulation (T-38 (5)): a scheduler that delivers events in virtual-time order, breaks ties and draws faults from the fixed-seed generator, so a seed always replays the same trace; crashes, model outages, attestation failures and lost connectivity are the faults it injects.

use std::cmp::Reverse;
use std::collections::BinaryHeap;
use std::time::Duration;

use one_runtime::{Clock, Rng, UnixNanos};

use crate::{SeededRng, VirtualClock};

/// A fault the scheduler can inject at a step.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Fault {
    /// The acting process stops before its next durable write.
    Crash,
    /// The model service does not answer.
    ModelOutage,
    /// The TEE attestation does not verify; nothing may be sent (PV-11).
    AttestationFailure,
    /// The device or a sibling product is unreachable.
    Offline,
}

impl Fault {
    /// Every fault.
    pub const ALL: [Self; 4] = [
        Self::Crash,
        Self::ModelOutage,
        Self::AttestationFailure,
        Self::Offline,
    ];
}

/// A seeded, virtual-time event scheduler.
#[derive(Debug)]
pub struct Sim<E> {
    clock: VirtualClock,
    rng: SeededRng,
    queue: BinaryHeap<Reverse<(UnixNanos, u64, u64)>>,
    events: Vec<Option<E>>,
    fault_per_mille: u64,
    faults: Vec<Fault>,
}

impl<E> Sim<E> {
    /// A simulation starting at `start` whose ties and faults come from `seed`; each step faults with probability `fault_per_mille` / 1000, drawn from `faults`.
    #[must_use]
    pub fn new(seed: u64, start: UnixNanos, fault_per_mille: u16, faults: &[Fault]) -> Self {
        Self {
            clock: VirtualClock::new(start),
            rng: SeededRng::new(seed),
            queue: BinaryHeap::new(),
            events: Vec::new(),
            fault_per_mille: u64::from(fault_per_mille.min(1000)),
            faults: faults.to_vec(),
        }
    }

    /// The simulation clock, to hand to code under test.
    #[must_use]
    pub const fn clock(&self) -> &VirtualClock {
        &self.clock
    }

    /// A uniform draw in `0..n`; `0` when `n` is `0`.
    pub fn below(&self, n: u64) -> u64 {
        let mut bytes = [0_u8; 8];
        self.rng.fill(&mut bytes);
        u64::from_le_bytes(bytes).checked_rem(n).unwrap_or(0)
    }

    /// Schedules `event` to happen `after` from now; same-time events are ordered by the seed.
    pub fn schedule(&mut self, after: Duration, event: E) {
        let at = self
            .clock
            .now()
            .checked_add(after)
            .unwrap_or(UnixNanos(u128::MAX));
        let index = u64::try_from(self.events.len()).unwrap_or(u64::MAX);
        let tie = self.below(u64::MAX);
        self.events.push(Some(event));
        self.queue.push(Reverse((at, tie, index)));
    }

    /// The next event with the time it happens, moving the clock there; `None` when nothing is scheduled.
    pub fn step(&mut self) -> Option<(UnixNanos, E)> {
        loop {
            let Reverse((at, _, index)) = self.queue.pop()?;
            let slot = usize::try_from(index)
                .ok()
                .and_then(|i| self.events.get_mut(i));
            let Some(event) = slot.and_then(Option::take) else {
                continue;
            };
            if let Some(wait) = at.checked_since(self.clock.now()) {
                self.clock.advance(wait);
            }
            return Some((at, event));
        }
    }

    /// Whether this step faults, and with which fault.
    pub fn fault(&self) -> Option<Fault> {
        if self.faults.is_empty() || self.below(1000) >= self.fault_per_mille {
            return None;
        }
        let n = u64::try_from(self.faults.len()).unwrap_or(1);
        usize::try_from(self.below(n))
            .ok()
            .and_then(|i| self.faults.get(i))
            .copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // T-38 (5)
    #[test]
    fn t_38_events_come_in_time_order_and_replay_per_seed() {
        let trace = |seed| {
            let mut sim = Sim::new(seed, UnixNanos(0), 300, &Fault::ALL);
            for i in 0..20_u64 {
                sim.schedule(Duration::from_millis(i % 4), i);
            }
            let mut out = Vec::new();
            let mut last = UnixNanos(0);
            while let Some((at, e)) = sim.step() {
                assert!(at >= last);
                assert_eq!(sim.clock().now(), at);
                last = at;
                out.push((e, sim.fault()));
            }
            out
        };
        assert_eq!(trace(1), trace(1));
        assert_ne!(trace(1), trace(2));
        assert_eq!(trace(1).len(), 20);
    }
}
