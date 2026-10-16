//! Property tests of the task state machine over arbitrary event sequences up to 32 events, batch halting and the effective budget (CP-3, CP-4, CP-6, INV-30, INV-32, T-38 (3)).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::cmp::Ordering;
use std::num::NonZeroU32;

use one_proto::money::{Currency, Decimal, Money};
use one_proto::task::{
    BatchEntry, BatchRejection, BudgetRejection, EventBody, EventKind, RejectCode, Reported, STAYS,
    StepId, StepReason, StepStatus, TRANSITIONS, TaskEvent, TaskState, batch, derive_events,
    effective_amount, effective_steps,
};
use proptest::prelude::*;
use proptest::test_runner::{Config, RngSeed, TestCaseError};
use serde_json::{Value, json};

fn config() -> Config {
    Config {
        cases: 512,
        failure_persistence: None,
        rng_seed: RngSeed::Fixed(3),
        ..Config::default()
    }
}

fn alphabet() -> Vec<Value> {
    let r = |kind: &str, id: &str| json!({"ref": kind, "id": id});
    let done = json!({"status": "done", "outcome": {"subject": "execution", "certainty": "confirmed", "value": "succeeded", "confirmation": r("ClaimRef", "c-1")}});
    let confirmed = json!({"subject": "effect", "certainty": "confirmed", "value": "occurred", "confirmation": r("ExecutionReportRef", "rep-9")});
    let mut out = vec![json!({"kind": "task_created", "source": "one", "plan_version": 1})];
    for step in ["s1", "s2", "s3"] {
        out.push(json!({"kind": "step_started", "source": "executor", "step_id": step, "effectful": false}));
        out.push(
            json!({"kind": "step_finished", "source": "executor", "step_id": step, "result": done}),
        );
        out.push(json!({"kind": "step_outcome_reported", "source": "executor", "step_id": step, "outcome": confirmed}));
    }
    for wp in ["wp-1", "wp-2"] {
        out.push(json!({"kind": "wait_opened", "source": "one", "wait": "user", "waitpoint_ref": r("WaitpointRef", wp), "reason": "approval"}));
        out.push(json!({"kind": "wait_opened", "source": "one", "wait": "external", "waitpoint_ref": r("WaitpointRef", wp), "reason": "peer_reply"}));
        out.push(json!({"kind": "wait_resolved", "source": "relay", "waitpoint_ref": r("WaitpointRef", wp), "continuation_ref": r("DecisionRecordRef", "k-1")}));
        out.push(json!({"kind": "wait_expired", "source": "relay", "waitpoint_ref": r("WaitpointRef", wp)}));
    }
    out.extend([
        json!({"kind": "pause_requested", "source": "user"}),
        json!({"kind": "pause_requested", "source": "user"}),
        json!({"kind": "pause_confirmed", "source": "executor", "execution_report_ref": r("ExecutionReportRef", "rep-1")}),
        json!({"kind": "resumed", "source": "one", "continuation_ref": r("DecisionRecordRef", "k-2")}),
        json!({"kind": "checkpoint_recorded", "source": "executor", "checkpoint_ref": r("CheckpointRef", "ck-1")}),
        json!({"kind": "completion_verified", "source": "one", "evidence_ref": r("ClaimRef", "c-2")}),
        json!({"kind": "task_failed", "source": "executor", "reason": "step_unknown"}),
        json!({"kind": "task_cancelled", "source": "user", "cause": "user"}),
        json!({"kind": "task_cancelled", "source": "access", "cause": "authority_revoked"}),
    ]);
    out
}

fn event(body: &Value, seq: u64) -> TaskEvent {
    let mut v = body.clone();
    v["task_id"] = json!("task_01k7n51z01e40r200000000000");
    v["seq"] = json!(seq);
    v["at"] = json!("2026-10-16T09:00:00Z");
    serde_json::from_value(v).unwrap()
}

fn history() -> impl Strategy<Value = Vec<TaskEvent>> {
    let n = alphabet().len();
    let first = prop_oneof![9 => Just(0_usize), 1 => 0..n];
    (first, proptest::collection::vec(0..n, 0..32)).prop_map(|(first, rest)| {
        let a = alphabet();
        std::iter::once(first)
            .chain(rest)
            .zip(1_u64..)
            .map(|(k, seq)| event(&a[k], seq))
            .collect()
    })
}

fn admitted(from: TaskState, body: &EventBody, to: TaskState) -> bool {
    let wait = match body {
        EventBody::WaitOpened { reason, .. } => Some(reason.kind()),
        _ => None,
    };
    let kind = body.kind();
    let moved = TRANSITIONS.iter().any(|t| {
        t.event == kind
            && t.from.contains(&from)
            && t.to == to
            && (t.when.is_none() || t.when == wait)
    });
    let stayed = from == to
        && STAYS
            .iter()
            .any(|s| s.event == kind && s.within.contains(&from));
    moved || stayed
}

fn check_walk(events: &[TaskEvent]) -> Result<(), TestCaseError> {
    let mut state: Option<TaskState> = None;
    let mut first_rejection = None;
    for k in 0..events.len() {
        let result = derive_events(&events[..=k]);
        if let Some(rejection) = first_rejection {
            prop_assert_eq!(result, Err(rejection));
            continue;
        }
        match result {
            Err(rejection) => {
                if state.is_some_and(TaskState::is_terminal)
                    && !matches!(
                        events[k].body.kind(),
                        EventKind::StepOutcomeReported | EventKind::TaskCreated
                    )
                {
                    prop_assert_eq!(rejection.code, RejectCode::EventAfterTerminal);
                }
                first_rejection = Some(rejection);
            }
            Ok(derived) => {
                let next = derived.state;
                let body = &events[k].body;
                match state {
                    None => {
                        prop_assert_eq!(body.kind(), EventKind::TaskCreated);
                        prop_assert_eq!(next, TaskState::Pending);
                    }
                    Some(prev) => {
                        prop_assert!(
                            admitted(prev, body, next),
                            "{prev:?} --{:?}--> {next:?}",
                            body.kind()
                        );
                        if prev.is_terminal() {
                            prop_assert_eq!(next, prev);
                            prop_assert_eq!(body.kind(), EventKind::StepOutcomeReported);
                        }
                    }
                }
                prop_assert!(!derived.stopping || next == TaskState::Running);
                prop_assert_eq!(
                    derived.wait_reason.is_some(),
                    matches!(next, TaskState::WaitingUser | TaskState::WaitingExternal)
                );
                state = Some(next);
            }
        }
    }
    Ok(())
}

fn guided(choices: &[(usize, bool)]) -> Vec<TaskEvent> {
    let a = alphabet();
    let mut events = vec![event(&a[0], 1)];
    for &(k, keep_illegal) in choices {
        let seq = u64::try_from(events.len()).unwrap() + 1;
        events.push(event(&a[k], seq));
        if derive_events(&events).is_err() {
            if keep_illegal {
                break;
            }
            events.pop();
        }
    }
    events
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn cp_3_arbitrary_sequences_never_reach_an_illegal_state(events in history()) {
        check_walk(&events)?;
    }

    #[test]
    fn cp_3_guided_walks_up_to_32_events_stay_in_the_table(
        choices in proptest::collection::vec((0..alphabet().len(), proptest::bool::weighted(0.05)), 0..31)
    ) {
        let events = guided(&choices);
        prop_assert!(events.len() <= 32);
        check_walk(&events)?;
        let mut prev: Option<TaskState> = None;
        let mut requested_since_running = false;
        for k in 0..events.len() {
            let Ok(derived) = derive_events(&events[..=k]) else { break };
            let kind = events[k].body.kind();
            if derived.state == TaskState::Paused && prev != Some(TaskState::Paused) {
                prop_assert_eq!(kind, EventKind::PauseConfirmed);
                prop_assert!(requested_since_running);
            }
            if derived.state == TaskState::Running && prev != Some(TaskState::Running) {
                requested_since_running = false;
            }
            if kind == EventKind::PauseRequested {
                requested_since_running = true;
            }
            prev = Some(derived.state);
        }
    }

    #[test]
    fn inv_30_paused_only_after_pause_confirmed(events in history()) {
        let mut prev: Option<TaskState> = None;
        let mut requested_since_running = false;
        for k in 0..events.len() {
            let Ok(derived) = derive_events(&events[..=k]) else { break };
            let kind = events[k].body.kind();
            if derived.state == TaskState::Paused && prev != Some(TaskState::Paused) {
                prop_assert_eq!(kind, EventKind::PauseConfirmed);
                prop_assert!(requested_since_running);
            }
            if derived.state == TaskState::Running && prev != Some(TaskState::Running) {
                requested_since_running = false;
            }
            if kind == EventKind::PauseRequested {
                requested_since_running = true;
            }
            prev = Some(derived.state);
        }
    }
}

fn steps(n: usize) -> Vec<StepId> {
    (0..n)
        .map(|i| StepId::parse(&format!("s{i}")).unwrap())
        .collect()
}

fn report() -> impl Strategy<Value = Option<Reported>> {
    prop_oneof![
        2 => Just(None),
        4 => Just(Some(Reported::Done)),
        1 => Just(Some(Reported::Failed)),
        1 => Just(Some(Reported::Unknown)),
    ]
}

fn status(r: Reported) -> StepStatus {
    match r {
        Reported::Done => StepStatus::Done,
        Reported::Failed => StepStatus::Failed,
        Reported::Unknown => StepStatus::Unknown,
    }
}

fn decimal() -> impl Strategy<Value = Decimal> {
    (0_u64..1_000_000, proptest::option::of("[0-9]{1,8}")).prop_map(|(int, frac)| {
        let text = match frac {
            Some(f) => format!("{int}.{f}"),
            None => format!("{int}"),
        };
        Decimal::parse(&text).unwrap()
    })
}

fn money(currency: &'static str) -> impl Strategy<Value = Money> {
    decimal().prop_map(move |value| Money {
        value,
        currency: Currency::parse(currency).unwrap(),
    })
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn cp_6_batch_halts_at_the_first_failed_or_unknown_step(
        reports in proptest::collection::vec(report(), 1..12),
        order_seed in any::<u64>(),
    ) {
        let order = steps(reports.len());
        let mut reported: Vec<(StepId, Reported)> = order
            .iter()
            .zip(&reports)
            .filter_map(|(s, r)| r.map(|r| (s.clone(), r)))
            .collect();
        let len = reported.len().max(1);
        reported.rotate_left(usize::try_from(order_seed).unwrap_or(0) % len);
        let halt = reports
            .iter()
            .position(|r| matches!(r, Some(Reported::Failed | Reported::Unknown)));
        let late = halt.and_then(|h| (h + 1..reports.len()).find(|&i| reports[i].is_some()));
        match batch(&order, &reported) {
            Err(BatchRejection::RanAfterHalt(step)) => {
                prop_assert_eq!(Some(step), late.map(|i| order[i].clone()));
            }
            Err(BatchRejection::NotInBatch(step)) => prop_assert!(false, "{step:?} is in the batch"),
            Ok(entries) => {
                prop_assert!(late.is_none());
                let mut expected: Vec<BatchEntry> = Vec::new();
                for (i, (step, r)) in order.iter().zip(&reports).enumerate() {
                    match (halt, r) {
                        (Some(h), _) if i > h => expected.push(BatchEntry {
                            step: step.clone(),
                            status: StepStatus::NotRun,
                            reason: Some(if reports[h] == Some(Reported::Failed) {
                                StepReason::EarlierStepFailed
                            } else {
                                StepReason::EarlierStepUnknown
                            }),
                        }),
                        (_, Some(r)) => expected.push(BatchEntry {
                            step: step.clone(),
                            status: status(*r),
                            reason: None,
                        }),
                        (_, None) => {}
                    }
                }
                prop_assert_eq!(entries, expected);
            }
        }
        let stranger = StepId::parse("outside").unwrap();
        let mut outside = reported.clone();
        outside.push((stranger.clone(), Reported::Done));
        prop_assert_eq!(batch(&order, &outside), Err(BatchRejection::NotInBatch(stranger)));
    }

    #[test]
    fn cp_4_effective_budget_is_the_narrower_one(
        m in proptest::option::of(1_u32..1000),
        r in proptest::option::of(1_u32..1000),
        a in proptest::option::of(money("TRY")),
        b in proptest::option::of(money("TRY")),
        other in money("EUR"),
    ) {
        let (ms, rs) = (m.and_then(NonZeroU32::new), r.and_then(NonZeroU32::new));
        match effective_steps(ms, rs) {
            Err(e) => {
                prop_assert_eq!(e, BudgetRejection::NoBudget);
                prop_assert!(ms.is_none() && rs.is_none());
            }
            Ok(steps) => {
                prop_assert!(ms.is_none_or(|x| steps <= x) && rs.is_none_or(|x| steps <= x));
                prop_assert!(Some(steps) == ms || Some(steps) == rs);
            }
        }
        match effective_amount(a.as_ref(), b.as_ref()) {
            Err(e) => {
                prop_assert_eq!(e, BudgetRejection::NoBudget);
                prop_assert!(a.is_none() && b.is_none());
            }
            Ok(amount) => {
                for side in [&a, &b].into_iter().flatten() {
                    prop_assert_ne!(amount.compare(side), Some(Ordering::Greater));
                }
                prop_assert!(Some(&amount) == a.as_ref() || Some(&amount) == b.as_ref());
            }
        }
        if let Some(a) = &a {
            prop_assert_eq!(
                effective_amount(Some(a), Some(&other)),
                Err(BudgetRejection::CurrencyMismatch)
            );
        }
    }
}
