//! The transition table against `state-machine.toml`, and every event sequence of length up to four checked against the table rows (CP-3, INV-30, INV-32).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::collections::BTreeSet;

use one_proto::task::{
    EventBody, EventKind, STAYS, StopCommand, TRANSITIONS, TaskEvent, TaskState, derive_events,
    stop_command,
};
use serde_json::{Value, json};

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Row {
    event: String,
    when: Option<String>,
    from: Vec<String>,
    to: Option<String>,
    guard: Option<String>,
}

fn table() -> String {
    let path = format!(
        "{}/../../conformance/task/state-machine.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read_to_string(path).unwrap()
}

fn unquote(v: &str) -> String {
    v.trim().trim_matches('"').to_owned()
}

fn list(v: &str) -> Vec<String> {
    v.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(unquote)
        .filter(|s| !s.is_empty())
        .collect()
}

fn rows(header: &str) -> Vec<Row> {
    let text = table();
    let mut out = Vec::new();
    for block in text.split("[[").skip(1) {
        let Some((name, body)) = block.split_once("]]") else {
            continue;
        };
        if name != header {
            continue;
        }
        let mut row = Row::default();
        for line in body.lines() {
            let Some((k, v)) = line.split_once(" = ") else {
                continue;
            };
            match k.trim() {
                "event" => row.event = unquote(v),
                "from" | "in" => row.from = list(v),
                "to" => row.to = Some(unquote(v)),
                "guard" => row.guard = Some(unquote(v)),
                "when" => {
                    row.when = Some(unquote(v.split_once('=').unwrap().1.trim_end_matches('}')));
                }
                _ => {}
            }
        }
        out.push(row);
    }
    out
}

#[test]
fn cp_3_transition_and_stay_rows_match_state_machine_toml() {
    let transitions: Vec<Row> = TRANSITIONS
        .iter()
        .map(|t| Row {
            event: t.event.as_str().to_owned(),
            when: t.when.map(|w| w.as_str().to_owned()),
            from: t.from.iter().map(|s| s.as_str().to_owned()).collect(),
            to: Some(t.to.as_str().to_owned()),
            guard: t.guard.map(|g| g.as_str().to_owned()),
        })
        .collect();
    assert_eq!(transitions, rows("transition"));
    let stays: Vec<Row> = STAYS
        .iter()
        .map(|s| Row {
            event: s.event.as_str().to_owned(),
            when: None,
            from: s.within.iter().map(|x| x.as_str().to_owned()).collect(),
            to: None,
            guard: s.guard.map(|g| g.as_str().to_owned()),
        })
        .collect();
    assert_eq!(stays, rows("stay"));
}

#[test]
fn inv_32_stop_rows_match_state_machine_toml_and_are_never_refused() {
    let text = table();
    let mut covered = Vec::new();
    let (transitions, stays) = (rows("transition"), rows("stay"));
    for block in text.split("[[").skip(1) {
        let Some(("stop", body)) = block.split_once("]]") else {
            continue;
        };
        let field = |key: &str| {
            body.lines()
                .find_map(|l| l.strip_prefix(&format!("{key} = ")).map(str::to_owned))
        };
        let states = list(&field("in").unwrap());
        let command = StopCommand::from_wire(&unquote(&field("command").unwrap())).unwrap();
        let writes = field("writes").map(|w| unquote(&w));
        for state in &states {
            let s = TaskState::from_wire(state).unwrap();
            assert_eq!(stop_command(s), command, "{state}");
            match (&writes, command) {
                (None, StopCommand::AlreadyOver) => assert!(s.is_terminal()),
                (Some(event), StopCommand::RequestPause | StopCommand::Cancel) => assert!(
                    transitions
                        .iter()
                        .chain(&stays)
                        .any(|r| &r.event == event && r.from.contains(state)),
                    "{state}: {event}"
                ),
                other => panic!("{state}: {other:?}"),
            }
            covered.push(s);
        }
    }
    covered.sort();
    let mut all = TaskState::ALL.to_vec();
    all.sort();
    assert_eq!(covered, all);
}

#[test]
fn cp_3_states_and_reject_codes_match_state_machine_toml() {
    let text = table();
    let names = |header: &str, key: &str| -> Vec<String> {
        text.split("[[")
            .skip(1)
            .filter_map(|b| b.split_once("]]"))
            .filter(|(n, _)| *n == header)
            .filter_map(|(_, body)| {
                body.lines()
                    .find_map(|l| l.strip_prefix(&format!("{key} = ")).map(unquote))
            })
            .collect()
    };
    let states: Vec<String> = TaskState::ALL
        .iter()
        .map(|s| s.as_str().to_owned())
        .collect();
    assert_eq!(states, names("state", "name"));
    let terminal: Vec<bool> = TaskState::ALL.iter().map(|s| s.is_terminal()).collect();
    let toml_terminal: Vec<bool> = names("state", "terminal")
        .iter()
        .map(|t| t == "true")
        .collect();
    assert_eq!(terminal, toml_terminal);
    let codes: Vec<String> = one_proto::task::RejectCode::ALL
        .iter()
        .map(|c| c.as_str().to_owned())
        .collect();
    assert_eq!(codes, names("reject", "code"));
    let guards: Vec<String> = one_proto::task::Guard::ALL
        .iter()
        .map(|g| g.as_str().to_owned())
        .collect();
    assert_eq!(guards, names("guard", "name"));
}

fn alphabet() -> Vec<Value> {
    let r = |kind: &str, id: &str| json!({"ref": kind, "id": id});
    let done = json!({"status": "done", "outcome": {"subject": "execution", "certainty": "confirmed", "value": "succeeded", "confirmation": r("ClaimRef", "c-1")}});
    let confirmed = json!({"subject": "effect", "certainty": "confirmed", "value": "occurred", "confirmation": r("ExecutionReportRef", "rep-9")});
    vec![
        json!({"kind": "task_created", "source": "one", "plan_version": 1}),
        json!({"kind": "step_started", "source": "executor", "step_id": "s1", "effectful": false}),
        json!({"kind": "step_started", "source": "executor", "step_id": "s2", "effectful": true, "decision_ref": r("DecisionRecordRef", "d-1"), "exercise_ref": r("ExerciseRef", "e-1")}),
        json!({"kind": "step_finished", "source": "executor", "step_id": "s1", "result": done}),
        json!({"kind": "step_outcome_reported", "source": "executor", "step_id": "s1", "outcome": confirmed}),
        json!({"kind": "wait_opened", "source": "one", "wait": "user", "waitpoint_ref": r("WaitpointRef", "wp-1"), "reason": "approval"}),
        json!({"kind": "wait_opened", "source": "one", "wait": "user", "waitpoint_ref": r("WaitpointRef", "wp-2"), "reason": "authentication"}),
        json!({"kind": "wait_opened", "source": "one", "wait": "external", "waitpoint_ref": r("WaitpointRef", "wp-1"), "reason": "peer_reply"}),
        json!({"kind": "wait_resolved", "source": "relay", "waitpoint_ref": r("WaitpointRef", "wp-1"), "continuation_ref": r("DecisionRecordRef", "k-1")}),
        json!({"kind": "wait_expired", "source": "relay", "waitpoint_ref": r("WaitpointRef", "wp-1")}),
        json!({"kind": "pause_requested", "source": "user"}),
        json!({"kind": "pause_confirmed", "source": "executor", "execution_report_ref": r("ExecutionReportRef", "rep-1")}),
        json!({"kind": "resumed", "source": "one", "continuation_ref": r("DecisionRecordRef", "k-2")}),
        json!({"kind": "checkpoint_recorded", "source": "executor", "checkpoint_ref": r("CheckpointRef", "ck-1")}),
        json!({"kind": "completion_verified", "source": "one", "evidence_ref": r("ClaimRef", "c-2")}),
        json!({"kind": "task_failed", "source": "executor", "reason": "step_unknown"}),
        json!({"kind": "task_cancelled", "source": "user", "cause": "user"}),
        json!({"kind": "task_cancelled", "source": "access", "cause": "authority_revoked"}),
    ]
}

fn event(body: &Value, seq: u64) -> TaskEvent {
    let mut v = body.clone();
    v["task_id"] = json!("task_01k7n51z01e40r200000000000");
    v["seq"] = json!(seq);
    v["at"] = json!("2026-10-16T09:00:00Z");
    serde_json::from_value(v).unwrap()
}

fn admitted(from: TaskState, body: &EventBody, to: TaskState, toml: &(Vec<Row>, Vec<Row>)) -> bool {
    let kind = body.kind().as_str();
    let wait = match body {
        EventBody::WaitOpened { reason, .. } => Some(reason.kind().as_str().to_owned()),
        _ => None,
    };
    let (transitions, stays) = toml;
    let moved = transitions.iter().any(|t| {
        t.event == kind
            && t.from.iter().any(|f| f == from.as_str())
            && (t.when.is_none() || t.when == wait)
            && t.to.as_deref() == Some(to.as_str())
    });
    let stayed = from == to
        && stays
            .iter()
            .any(|s| s.event == kind && s.from.iter().any(|f| f == from.as_str()));
    moved || stayed
}

#[test]
fn cp_3_no_sequence_up_to_four_events_leaves_the_table() {
    let toml = (rows("transition"), rows("stay"));
    let alphabet = alphabet();
    let n = alphabet.len();
    let mut reached = BTreeSet::new();
    let mut accepted = 0_usize;
    let mut total = 0_usize;
    for len in 1..=4_u32 {
        for code in 0..n.pow(len) {
            let mut c = code;
            let events: Vec<TaskEvent> = (0..len)
                .map(|i| {
                    let e = event(&alphabet[c % n], u64::from(i) + 1);
                    c /= n;
                    e
                })
                .collect();
            total += 1;
            let Ok(last) = derive_events(&events) else {
                continue;
            };
            accepted += 1;
            assert_eq!(events[0].body.kind(), EventKind::TaskCreated);
            let mut state = TaskState::Pending;
            for k in 1..events.len() {
                let next = derive_events(&events[..=k]).unwrap().state;
                assert!(
                    admitted(state, &events[k].body, next, &toml),
                    "{state:?} --{:?}--> {next:?} is not a table row",
                    events[k].body.kind()
                );
                if state.is_terminal() {
                    assert_eq!(state, next);
                    assert_eq!(events[k].body.kind(), EventKind::StepOutcomeReported);
                }
                if next == TaskState::Paused && state != TaskState::Paused {
                    assert_eq!(events[k].body.kind(), EventKind::PauseConfirmed);
                    assert!(
                        events[..k]
                            .iter()
                            .any(|e| e.body.kind() == EventKind::PauseRequested)
                    );
                }
                state = next;
            }
            assert_eq!(state, last.state);
            assert!(TaskState::ALL.contains(&state));
            reached.insert(state);
        }
    }
    assert_eq!(total, n + n.pow(2) + n.pow(3) + n.pow(4));
    assert!(accepted > 0);
    assert_eq!(reached.len(), TaskState::ALL.len());
}

#[test]
fn inv_30_paused_needs_a_request_and_the_executor_confirmation() {
    let a = alphabet();
    let events: Vec<TaskEvent> = [0, 1, 10, 11]
        .iter()
        .enumerate()
        .map(|(i, &k)| event(&a[k], i as u64 + 1))
        .collect();
    assert_eq!(derive_events(&events).unwrap().state, TaskState::Paused);
    let skipped: Vec<TaskEvent> = [0, 1, 11]
        .iter()
        .enumerate()
        .map(|(i, &k)| event(&a[k], i as u64 + 1))
        .collect();
    assert!(derive_events(&skipped).is_err());
}
