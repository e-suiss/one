//! The pure vectors of `conformance/recovery`: every guess-limit vector of `attempts.json` and the coordination vectors of `vault.json` (PV-12, PV-13, PV-14, PV-15).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    clippy::too_many_lines,
    reason = "T-38"
)]

mod common;

use common::load;
use one_keys::domain::recovery::{GuessCounter, GuessLimit, GuessResult, wait_after_failure};
use one_keys::domain::vault::{
    EXHAUSTION, RealmGuesses, RealmSite, RecoveryPlan, agreed_version, plan_recovery, register,
    shred,
};
use one_proto::recovery::{RealmName, RecoveryStatus};
use serde_json::Value;

fn realm(s: &str) -> RealmName {
    RealmName::parse(s).unwrap()
}

fn realms(v: &Value) -> Vec<RealmName> {
    v.as_array()
        .unwrap()
        .iter()
        .map(|r| realm(r.as_str().unwrap()))
        .collect()
}

fn names(v: &[RealmName]) -> Vec<&str> {
    v.iter().map(RealmName::as_str).collect()
}

fn abc() -> Vec<RealmName> {
    ["a", "b", "c"].map(realm).to_vec()
}

fn limit(input: &Value) -> GuessLimit {
    GuessLimit::new(u8::try_from(input["policy"]["max_guesses"].as_u64().unwrap()).unwrap())
        .unwrap()
}

/// Plays the attempts one realm sees, each after any wait has passed; returns the counter, the waits seen and the time of the last attempt.
fn play(limit: GuessLimit, attempts: &[Value]) -> (GuessCounter, Vec<(u8, u64)>, bool, u64) {
    let mut counter = GuessCounter::new(limit);
    let mut waits = Vec::new();
    let mut destroyed = false;
    let mut now = 1_000;
    for a in attempts {
        now += counter.retry_after(now);
        match counter.guess(now, a == "ok") {
            GuessResult::Failed { wait: Some(w), .. } => waits.push((counter.used(), w)),
            GuessResult::Destroyed => destroyed = true,
            GuessResult::Wait { .. } => panic!("a played guess never waits"),
            _ => {}
        }
    }
    (counter, waits, destroyed, now)
}

#[test]
fn pv_12_guess_limit_vectors() {
    let mut seen = 0;
    for v in load("recovery/vectors/attempts.json") {
        let d = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        seen += 1;
        if input["op"] == "set_limit" {
            let current =
                GuessLimit::new(u8::try_from(input["current"].as_u64().unwrap()).unwrap()).unwrap();
            let requested = u8::try_from(input["requested"].as_u64().unwrap()).unwrap();
            match current.lower_to(requested) {
                Ok(l) => {
                    assert!(expected["accepted"].as_bool().unwrap(), "{d}");
                    assert_eq!(
                        u64::from(l.get()),
                        expected["max_guesses"].as_u64().unwrap(),
                        "{d}"
                    );
                }
                Err(r) => {
                    assert!(!expected["accepted"].as_bool().unwrap(), "{d}");
                    assert_eq!(r.as_str(), expected["reason"], "{d}");
                }
            }
        } else if input.get("guesses_used").is_some() {
            let used: Vec<(RealmName, u8)> = input["guesses_used"]
                .as_object()
                .unwrap()
                .iter()
                .map(|(k, n)| (realm(k), u8::try_from(n.as_u64().unwrap()).unwrap()))
                .collect();
            let mut guesses = RealmGuesses::new(limit(input), used);
            if let Some(remaining) = expected["guesses_remaining"].as_u64() {
                assert_eq!(u64::from(guesses.remaining()), remaining, "{d}");
            }
            if let Some(attempts) = input["attempts"].as_array() {
                let mut deleted = Vec::new();
                for a in attempts {
                    assert_eq!(a["result"], "fail");
                    deleted = guesses.fail(&realms(&a["realms"])).deleted;
                }
                assert_eq!(
                    names(&deleted),
                    realms(&expected["deleted"])
                        .iter()
                        .map(RealmName::as_str)
                        .collect::<Vec<_>>(),
                    "{d}"
                );
            }
        } else if input.get("threshold").is_some() {
            let mut guesses = RealmGuesses::new(limit(input), abc().into_iter().map(|r| (r, 0)));
            for a in input["attempts"].as_array().unwrap() {
                assert_eq!(a["result"], "fail");
                assert_eq!(guesses.fail(&realms(&a["realms"])).deleted.len(), 0);
            }
            for (k, n) in expected["guesses_used"].as_object().unwrap() {
                assert_eq!(
                    u64::from(guesses.used(&realm(k))),
                    n.as_u64().unwrap(),
                    "{d}"
                );
            }
        } else {
            let attempts = input["attempts"].as_array().unwrap();
            let (counter, waits, destroyed, last) = play(limit(input), attempts);
            if let Some(after) = input["next_guess_after_seconds"].as_u64() {
                let result = counter.clone_guess(last + after);
                assert_eq!(expected["status"], "wait", "{d}");
                assert_eq!(
                    result,
                    GuessResult::Wait {
                        retry_after: expected["retry_after"].as_u64().unwrap()
                    },
                    "{d}"
                );
                assert_eq!(
                    u64::from(counter.remaining()),
                    expected["guesses_remaining"].as_u64().unwrap(),
                    "{d}"
                );
                continue;
            }
            if let Some(remaining) = expected["guesses_remaining"].as_u64() {
                assert_eq!(u64::from(counter.remaining()), remaining, "{d}");
            }
            if let Some(deleted) = expected["deleted"].as_bool() {
                assert_eq!(destroyed, deleted, "{d}");
            }
            if let Some(w) = expected["waits"].as_array() {
                assert_eq!(waits.len(), w.len(), "{d}");
            }
            if let Some(map) = expected["waits_after_failure"].as_object() {
                let want: Vec<(u8, u64)> = map
                    .iter()
                    .map(|(k, s)| (k.parse().unwrap(), s.as_u64().unwrap()))
                    .collect();
                assert_eq!(waits, want, "{d}");
                for (n, s) in &want {
                    assert_eq!(wait_after_failure(*n), Some(*s));
                }
            }
        }
    }
    assert_eq!(seen, 14);
}

trait CloneGuess {
    fn clone_guess(&self, now: u64) -> GuessResult;
}

impl CloneGuess for GuessCounter {
    fn clone_guess(&self, now: u64) -> GuessResult {
        let mut c = *self;
        let r = c.guess(now, true);
        assert_eq!(c, *self, "a refused guess changes nothing");
        r
    }
}

#[test]
fn pv_12_vault_coordination_vectors() {
    let mut covered = Vec::new();
    for v in load("recovery/vectors/vault.json") {
        let d = v["description"].as_str().unwrap().to_owned();
        let input = &v["input"];
        let expected = &v["expected"];
        match input["op"].as_str().unwrap() {
            "register" => {
                let sites: Vec<RealmSite> = input["realms"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, s)| RealmSite {
                        realm: realm(k),
                        host: s["host"].as_str().unwrap().to_owned(),
                        operator: s["operator"].as_str().unwrap().to_owned(),
                    })
                    .collect();
                let threshold = u8::try_from(input["threshold"].as_u64().unwrap()).unwrap();
                let got = register(&sites, threshold).unwrap();
                assert_eq!(got, realms(&expected["registered"]), "{d}");
                let shared: Vec<RealmSite> = sites
                    .iter()
                    .map(|s| RealmSite {
                        operator: "one operator".to_owned(),
                        ..s.clone()
                    })
                    .collect();
                assert!(register(&shared, threshold).is_err());
                assert!(register(&sites, 3).is_err());
                covered.push(d);
            }
            "recover" if input.get("versions").is_some() => {
                let versions: Vec<(RealmName, String)> = input["versions"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, s)| (realm(k), s.as_str().unwrap().to_owned()))
                    .collect();
                let (version, used) = agreed_version(&versions).unwrap();
                assert_eq!(version, expected["version"].as_str().unwrap(), "{d}");
                assert_eq!(used, realms(&expected["use"]), "{d}");
                covered.push(d);
            }
            "recover" if input.get("guesses_remaining").is_some() => {
                let used: Vec<(RealmName, u8)> = input["guesses_remaining"]
                    .as_object()
                    .unwrap()
                    .iter()
                    .map(|(k, n)| (realm(k), 10 - u8::try_from(n.as_u64().unwrap()).unwrap()))
                    .collect();
                let mut guesses = RealmGuesses::new(GuessLimit::DEFAULT, used);
                let RecoveryPlan::Proceed { contact, .. } = plan_recovery(&abc(), &abc()) else {
                    panic!("{d}");
                };
                let after = guesses.fail(&contact);
                assert_eq!(after.deleted, realms(&expected["deleted"]), "{d}");
                assert_eq!(EXHAUSTION.access_method, RecoveryStatus::Unusable);
                assert_eq!(expected["access_method"], "unusable");
                assert_eq!(
                    Some(EXHAUSTION.show_remaining_paths),
                    expected["show_remaining_paths"].as_bool()
                );
                covered.push(d);
            }
            "recover" => {
                let plan = plan_recovery(&abc(), &realms(&input["reachable"]));
                if expected["recovered"].as_bool().unwrap() {
                    let RecoveryPlan::Proceed {
                        contact,
                        reregister,
                    } = plan
                    else {
                        panic!("{d}");
                    };
                    if let Some(n) = expected["contacted"].as_u64() {
                        assert_eq!(contact.len() as u64, n, "{d}");
                    }
                    assert_eq!(
                        reregister,
                        expected["reregister"].as_bool().unwrap_or(false),
                        "{d}"
                    );
                } else {
                    assert_eq!(plan, RecoveryPlan::Unavailable, "{d}");
                    assert_eq!(expected["reason"], "unavailable");
                    assert_eq!(expected["guesses_counted"], 0);
                }
                covered.push(d);
            }
            "shred" => {
                let s = shred(&abc(), &realms(&input["reachable"]));
                assert_eq!(s.deleted, realms(&expected["deleted"]), "{d}");
                let log = &expected["erasure_log"];
                assert_eq!(s.scope, log["scope"], "{d}");
                let open: Vec<(&str, &str)> = s
                    .open_copies
                    .iter()
                    .map(|c| (c.holder, c.realm.as_str()))
                    .collect();
                let want: Vec<(&str, &str)> = log["open_copies"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|c| (c["holder"].as_str().unwrap(), c["ref"].as_str().unwrap()))
                    .collect();
                assert_eq!(open, want, "{d}");
                covered.push(d);
            }
            "compromise" | "operator_open" | "recover3" => {}
            other => panic!("unknown op {other}"),
        }
    }
    assert_eq!(covered.len(), 7, "{covered:?}");
}
