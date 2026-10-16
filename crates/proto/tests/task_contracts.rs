//! Every schema and behaviour vector of `conformance/task` through the typed task record, outcomes, step results, state derivation, projections, batches and budgets (CP-3, CP-4, CP-6, INV-30, C-27).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use core::num::NonZeroU32;

use one_proto::money::Currency;
use one_proto::money::Decimal;
use one_proto::money::Money;
use one_proto::task::{
    BatchRejection, BudgetRejection, HistoryEntry, Outcome, RejectCode, Reported, StepId,
    StepResult, StopCommand, Task, TaskEvent, TaskState, WaitReason, batch, derive,
    effective_amount, effective_steps, project, refused_submission, stop_command,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

fn load(path: &str) -> Vec<Value> {
    let full = format!(
        "{}/../../conformance/task/{path}",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(&full).unwrap();
    serde_json::from_str::<Value>(&text)
        .unwrap()
        .as_array()
        .unwrap()
        .clone()
}

fn schema_vectors<T: DeserializeOwned + Serialize>(path: &str) -> (usize, usize) {
    let (mut valid, mut invalid) = (0, 0);
    for v in load(path) {
        let input = &v["input"];
        let description = v["description"].as_str().unwrap();
        let parsed = serde_json::from_value::<T>(input.clone());
        if v["valid"].as_bool().unwrap() {
            let typed = parsed.unwrap_or_else(|e| panic!("{path}: rejected: {description}: {e}"));
            assert_eq!(
                &serde_json::to_value(&typed).unwrap(),
                input,
                "{path}: round trip: {description}"
            );
            valid += 1;
        } else {
            assert!(parsed.is_err(), "{path}: accepted: {description}");
            invalid += 1;
        }
    }
    (valid, invalid)
}

#[test]
fn cp_4_task_schema_vectors() {
    assert_eq!(schema_vectors::<Task>("vectors/task.json"), (9, 29));
}

#[test]
fn cp_6_step_result_schema_vectors() {
    assert_eq!(
        schema_vectors::<StepResult>("vectors/step-result.json"),
        (4, 8)
    );
}

#[test]
fn inv_30_outcome_schema_vectors() {
    assert_eq!(schema_vectors::<Outcome>("vectors/outcome.json"), (7, 8));
}

fn history(events: &Value) -> Vec<HistoryEntry> {
    events
        .as_array()
        .unwrap()
        .iter()
        .map(|e| match serde_json::from_value::<TaskEvent>(e.clone()) {
            Ok(event) => {
                assert_eq!(
                    &serde_json::to_value(&event).unwrap(),
                    e,
                    "event round trip"
                );
                HistoryEntry::Valid(event)
            }
            Err(_) => HistoryEntry::SchemaInvalid {
                seq: e["seq"].as_u64(),
            },
        })
        .collect()
}

#[test]
fn cp_3_state_derivation_vectors() {
    let all = load("vectors/state-derivation.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let derived = derive(&history(&v["input"]));
        let expected = &v["expected"];
        if let Some(state) = expected.get("state") {
            let derived = derived.unwrap_or_else(|r| panic!("{description}: rejected {r:?}"));
            assert_eq!(
                derived.state.as_str(),
                state.as_str().unwrap(),
                "{description}"
            );
        } else {
            let rejected = &expected["rejected"];
            let r = derived
                .err()
                .unwrap_or_else(|| panic!("{description}: accepted"));
            assert_eq!(
                r.code.as_str(),
                rejected["code"].as_str().unwrap(),
                "{description}"
            );
            assert_eq!(r.seq, rejected["seq"].as_u64(), "{description}");
            assert_eq!(
                r.guard.map(one_proto::task::Guard::as_str),
                rejected.get("guard").and_then(Value::as_str),
                "{description}"
            );
        }
    }
    assert_eq!(all.len(), 47);
}

#[test]
fn cp_3_pause_request_shows_stopping_until_the_executor_confirms() {
    let all = load("vectors/state-derivation.json");
    let requested = all
        .iter()
        .find(|v| v["description"] == "Pause requested only: still running and shown as stopping")
        .unwrap();
    let derived = derive(&history(&requested["input"])).unwrap();
    assert_eq!(
        (derived.state, derived.stopping),
        (TaskState::Running, true)
    );
}

#[test]
fn inv_30_paused_written_by_anyone_but_the_executor_is_schema_invalid() {
    let all = load("vectors/state-derivation.json");
    let forged = all
        .iter()
        .find(|v| v["description"] == "Paused written by One instead of the Executor is rejected")
        .unwrap();
    let last = forged["input"].as_array().unwrap().last().unwrap().clone();
    assert!(serde_json::from_value::<TaskEvent>(last).is_err());
    assert_eq!(
        derive(&history(&forged["input"])).unwrap_err().code,
        RejectCode::SchemaInvalid
    );
}

#[test]
fn inv_32_stop_cancels_in_pending_and_waiting_and_pauses_while_running() {
    assert_eq!(stop_command(TaskState::Pending), StopCommand::Cancel);
    assert_eq!(stop_command(TaskState::WaitingUser), StopCommand::Cancel);
    assert_eq!(
        stop_command(TaskState::WaitingExternal),
        StopCommand::Cancel
    );
    assert_eq!(stop_command(TaskState::Running), StopCommand::RequestPause);
    assert_eq!(stop_command(TaskState::Paused), StopCommand::AlreadyPaused);
    for s in [
        TaskState::Completed,
        TaskState::Failed,
        TaskState::Cancelled,
    ] {
        assert_eq!(stop_command(s), StopCommand::AlreadyOver);
    }
}

#[test]
fn cp_3_projection_vectors() {
    let all = load("vectors/projection.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        if input.get("intake").is_some() {
            let refused = refused_submission();
            assert!(refused.mcp_tasks.is_none(), "{description}");
            assert_eq!(expected["mcp_tasks"], "none", "{description}");
            assert_eq!(
                refused.a2a_task.as_str(),
                expected["a2a_task"],
                "{description}"
            );
            continue;
        }
        let state = TaskState::from_wire(input["state"].as_str().unwrap()).unwrap();
        if input.get("inbound").is_some() {
            assert_eq!(state.as_str(), expected["state"], "{description}");
            continue;
        }
        let reason = input
            .get("wait_reason")
            .map(|r| WaitReason::from_wire(r.as_str().unwrap()).unwrap());
        let p = project(state, reason);
        assert_eq!(p.mcp_tasks.as_str(), expected["mcp_tasks"], "{description}");
        assert_eq!(p.a2a_task.as_str(), expected["a2a_task"], "{description}");
        assert_eq!(
            p.status_message.as_str(),
            expected["status_message"],
            "{description}"
        );
        assert_eq!(
            p.caller_answer_accepted,
            expected
                .get("caller_answer_accepted")
                .and_then(Value::as_bool)
        );
    }
    assert_eq!(all.len(), 14);
}

#[test]
fn cp_6_batch_vectors() {
    let all = load("vectors/batch.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let order: Vec<StepId> = v["input"]["order"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| StepId::parse(s.as_str().unwrap()).unwrap())
            .collect();
        let reported: Vec<(StepId, Reported)> = v["input"]["reported"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, s)| {
                let status = match s.as_str().unwrap() {
                    "done" => Reported::Done,
                    "failed" => Reported::Failed,
                    "unknown" => Reported::Unknown,
                    other => panic!("{other}"),
                };
                (StepId::parse(k).unwrap(), status)
            })
            .collect();
        let expected = &v["expected"];
        match batch(&order, &reported) {
            Ok(entries) => {
                let got: serde_json::Map<String, Value> = entries
                    .iter()
                    .map(|e| {
                        let mut m = serde_json::Map::new();
                        m.insert("status".into(), e.status.as_str().into());
                        if let Some(r) = e.reason {
                            m.insert("reason".into(), r.as_str().into());
                        }
                        (e.step.as_str().to_owned(), Value::Object(m))
                    })
                    .collect();
                assert_eq!(&Value::Object(got), expected, "{description}");
            }
            Err(BatchRejection::RanAfterHalt(step)) => {
                assert_eq!(expected["rejected"], "ran_after_halt", "{description}");
                assert_eq!(expected["step"], step.as_str(), "{description}");
            }
            Err(other) => panic!("{description}: {other:?}"),
        }
    }
    assert_eq!(all.len(), 5);
}

fn try_money(v: &Value) -> Option<Money> {
    v.as_u64().map(|n| Money {
        value: Decimal::parse(&n.to_string()).unwrap(),
        currency: Currency::parse("TRY").unwrap(),
    })
}

#[test]
fn cp_4_budget_vectors() {
    let all = load("vectors/budget.json");
    for v in &all {
        let description = v["description"].as_str().unwrap();
        let input = &v["input"];
        let expected = &v["expected"];
        let amount = description.starts_with("Amount");
        let got: Result<u64, BudgetRejection> = if amount {
            let m = try_money(&input["mandate"]);
            let r = try_money(&input["requested"]);
            effective_amount(m.as_ref(), r.as_ref()).map(|e| e.value.as_str().parse().unwrap())
        } else {
            let n = |x: &Value| {
                x.as_u64()
                    .map(|n| NonZeroU32::new(u32::try_from(n).unwrap()).unwrap())
            };
            effective_steps(n(&input["mandate"]), n(&input["requested"]))
                .map(|e| u64::from(e.get()))
        };
        match got {
            Ok(effective) => assert_eq!(
                expected["effective"].as_u64(),
                Some(effective),
                "{description}"
            ),
            Err(BudgetRejection::NoBudget) => {
                assert_eq!(expected["rejected"], "no_budget", "{description}");
                assert!(expected["effective"].is_null(), "{description}");
            }
            Err(other) => panic!("{description}: {other:?}"),
        }
    }
    assert_eq!(all.len(), 7);
}

#[test]
fn cp_4_amount_budget_in_two_currencies_is_rejected() {
    let try_ = Money {
        value: Decimal::parse("10").unwrap(),
        currency: Currency::parse("TRY").unwrap(),
    };
    let eur = Money {
        value: Decimal::parse("10").unwrap(),
        currency: Currency::parse("EUR").unwrap(),
    };
    assert_eq!(
        effective_amount(Some(&try_), Some(&eur)),
        Err(BudgetRejection::CurrencyMismatch)
    );
    let small = Money {
        value: Decimal::parse("9.99").unwrap(),
        currency: Currency::parse("TRY").unwrap(),
    };
    assert_eq!(
        effective_amount(Some(&try_), Some(&small)),
        Ok(small.clone())
    );
    assert_eq!(effective_amount(Some(&small), Some(&try_)), Ok(small));
}
