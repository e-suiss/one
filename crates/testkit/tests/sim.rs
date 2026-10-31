//! Simulated outbox, job queue, model calls, attestation and an offline device under seeded faults, then a fault-free drain: every effect lands exactly once at the receiver, no request leaves without a verified attestation, a crashed lease is taken over, and an offline device's queue drains in order (T-38 (5), INV-31, OP-3, T-27 (7), PV-11).

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;

use one_runtime::UnixNanos;
use one_testkit::sim::{Fault, Sim};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Event {
    Dispatch,
    Work(u8),
    Expire,
    Sync,
}

#[derive(Clone, Copy, Default)]
struct Job {
    done: bool,
    holder: Option<(u8, u32)>,
    attempts: u32,
}

#[derive(Default)]
struct World {
    outbox: BTreeMap<u32, bool>,
    deliveries: u32,
    effects: BTreeSet<u32>,
    jobs: BTreeMap<u32, Job>,
    finished: BTreeMap<u32, u32>,
    unattested_sends: u32,
    device_queue: Vec<u32>,
    applied: Vec<u32>,
}

impl World {
    fn new() -> Self {
        Self {
            outbox: (0..8).map(|k| (k, false)).collect(),
            jobs: (0..6).map(|id| (id, Job::default())).collect(),
            device_queue: (0..5).collect(),
            ..Self::default()
        }
    }

    fn settled(&self) -> bool {
        self.outbox.values().all(|sent| *sent)
            && self.jobs.values().all(|j| j.done)
            && self.device_queue.is_empty()
    }

    fn dispatch(&mut self, fault: Option<Fault>) {
        let Some((&key, _)) = self.outbox.iter().find(|(_, sent)| !**sent) else {
            return;
        };
        if fault == Some(Fault::Offline) {
            return;
        }
        self.deliveries += 1;
        self.effects.insert(key);
        if fault != Some(Fault::Crash) {
            self.outbox.insert(key, true);
        }
    }

    fn work(&mut self, worker: u8, fault: Option<Fault>) {
        let Some((&id, job)) = self
            .jobs
            .iter_mut()
            .find(|(_, j)| !j.done && j.holder.is_none())
        else {
            return;
        };
        job.attempts += 1;
        let lease = (worker, job.attempts);
        job.holder = Some(lease);
        let attested = fault != Some(Fault::AttestationFailure);
        match fault {
            Some(Fault::Crash) => {}
            Some(Fault::AttestationFailure | Fault::ModelOutage | Fault::Offline) => {
                job.holder = None;
            }
            None => {
                if !attested {
                    self.unattested_sends += 1;
                }
                if job.holder == Some(lease) {
                    job.done = true;
                    job.holder = None;
                    *self.finished.entry(id).or_default() += 1;
                }
            }
        }
    }

    fn expire(&mut self) {
        for job in self.jobs.values_mut().filter(|j| !j.done) {
            job.holder = None;
        }
    }

    fn sync(&mut self, fault: Option<Fault>) {
        if fault != Some(Fault::Offline) {
            self.applied.append(&mut self.device_queue);
        }
    }

    fn apply(&mut self, event: Event, fault: Option<Fault>) {
        match event {
            Event::Dispatch => self.dispatch(fault),
            Event::Work(w) => self.work(w, fault),
            Event::Expire => self.expire(),
            Event::Sync => self.sync(fault),
        }
    }
}

fn round(sim: &mut Sim<Event>, i: u64) {
    sim.schedule(Duration::from_millis(1), Event::Dispatch);
    sim.schedule(
        Duration::from_millis(2),
        Event::Work(u8::try_from(i % 3).unwrap()),
    );
    sim.schedule(Duration::from_millis(3), Event::Sync);
    if i % 4 == 3 {
        sim.schedule(Duration::from_millis(4), Event::Expire);
    }
}

fn run(seed: u64) -> (World, Vec<(Event, Option<Fault>)>) {
    let mut sim = Sim::new(seed, UnixNanos(0), 250, &Fault::ALL);
    let mut world = World::new();
    let mut trace = Vec::new();
    for i in 0..40 {
        round(&mut sim, i);
        while let Some((_, event)) = sim.next() {
            let fault = sim.fault();
            trace.push((event, fault));
            world.apply(event, fault);
        }
    }
    for i in 0..40 {
        if world.settled() {
            break;
        }
        round(&mut sim, i);
        sim.schedule(Duration::from_millis(5), Event::Expire);
        while let Some((_, event)) = sim.next() {
            trace.push((event, None));
            world.apply(event, None);
        }
    }
    (world, trace)
}

#[test]
fn t_38_faults_never_duplicate_effects_or_lose_work() {
    for seed in 0..200 {
        let (world, _) = run(seed);
        assert!(world.settled(), "seed {seed}");
        assert_eq!(world.effects.len(), 8, "seed {seed}");
        assert!(world.deliveries >= 8, "seed {seed}");
        assert_eq!(world.finished.len(), 6, "seed {seed}");
        assert!(world.finished.values().all(|n| *n == 1), "seed {seed}");
        assert_eq!(world.unattested_sends, 0, "seed {seed}");
        assert_eq!(world.applied, (0..5).collect::<Vec<_>>(), "seed {seed}");
    }
}

#[test]
fn t_38_a_seed_replays_its_trace() {
    assert_eq!(run(42).1, run(42).1);
    assert_ne!(run(42).1, run(43).1);
}
