//! Instruction counts of deriving the task state from 100 and 1000 events; a rise over 5 % fails the run (T-45 (1, 3), CP-3, INV-30).

#![allow(missing_docs, reason = "T-45")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "T-45")]

use std::hint::black_box;

use gungraun::{
    Callgrind, EventKind, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};
use one_proto::task::{Derived, Rejection, TaskEvent, TaskState, derive_events};
use serde_json::{Value, json};

fn round(k: usize) -> Vec<Value> {
    let r = |kind: &str, id: String| json!({"ref": kind, "id": id});
    let step = format!("s{k}");
    let wait = format!("wp-{k}");
    let done = json!({"status": "done", "outcome": {"subject": "execution", "certainty": "confirmed", "value": "succeeded", "confirmation": r("ClaimRef", format!("c-{k}"))}});
    vec![
        json!({"kind": "step_started", "source": "executor", "step_id": step, "effectful": false}),
        json!({"kind": "checkpoint_recorded", "source": "executor", "checkpoint_ref": r("CheckpointRef", format!("ck-{k}"))}),
        json!({"kind": "step_finished", "source": "executor", "step_id": step, "result": done}),
        json!({"kind": "wait_opened", "source": "one", "wait": "user", "waitpoint_ref": r("WaitpointRef", wait.clone()), "reason": "approval"}),
        json!({"kind": "wait_resolved", "source": "relay", "waitpoint_ref": r("WaitpointRef", wait), "continuation_ref": r("DecisionRecordRef", format!("k-{k}"))}),
        json!({"kind": "pause_requested", "source": "user"}),
        json!({"kind": "pause_confirmed", "source": "executor", "execution_report_ref": r("ExecutionReportRef", format!("rep-{k}"))}),
        json!({"kind": "resumed", "source": "one", "continuation_ref": r("DecisionRecordRef", format!("k-r{k}"))}),
    ]
}

fn history(n: usize) -> Vec<TaskEvent> {
    let created = json!({"kind": "task_created", "source": "one", "plan_version": 1});
    let bodies = std::iter::once(created).chain((0..).flat_map(round));
    let events: Vec<TaskEvent> = bodies
        .take(n)
        .zip(1_u64..)
        .map(|(mut v, seq)| {
            v["task_id"] = json!("task_01k7n51z01e40r200000000000");
            v["seq"] = json!(seq);
            v["at"] = json!("2026-10-16T09:00:00Z");
            serde_json::from_value(v).unwrap()
        })
        .collect();
    assert_ne!(derive_events(&events).unwrap().state, TaskState::Failed);
    events
}

#[library_benchmark]
#[benches::events(args = [100, 1000], setup = history)]
fn derive_history(events: Vec<TaskEvent>) -> Result<Derived, Rejection> {
    black_box(derive_events(black_box(&events)))
}

library_benchmark_group!(name = state_machine, benchmarks = derive_history);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 5.0)])),
    library_benchmark_groups = state_machine
);
