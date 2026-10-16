//! Task operations: state derivation from the event history and the MCP and A2A projection (CP-3, CP-42, CP-44, INV-30, INV-32, C-27).

use one_proto::task::{
    HistoryEntry, TaskEvent, TaskState, WaitReason, derive as derive_history,
    project as projection, refused_submission, stop_command,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{object, parse};
use crate::CoreError;

fn entry(event: Value) -> HistoryEntry {
    let seq = event.get("seq").and_then(Value::as_u64);
    serde_json::from_value::<TaskEvent>(event)
        .map_or(HistoryEntry::SchemaInvalid { seq }, HistoryEntry::Valid)
}

pub(super) fn derive(input: Value) -> Result<Value, CoreError> {
    let Value::Array(events) = input else {
        return Err(CoreError::InvalidInput("events"));
    };
    let history: Vec<HistoryEntry> = events.into_iter().map(entry).collect();
    Ok(match derive_history(&history) {
        Ok(d) => {
            let mut m = Map::new();
            m.insert("state".to_owned(), Value::from(d.state.as_str()));
            m.insert(
                "stop".to_owned(),
                Value::from(stop_command(d.state).as_str()),
            );
            m.insert("stopping".to_owned(), Value::Bool(d.stopping));
            if let Some(reason) = d.wait_reason {
                m.insert("wait_reason".to_owned(), Value::from(reason.as_str()));
            }
            Value::Object(m)
        }
        Err(r) => {
            let mut m = Map::new();
            m.insert("code".to_owned(), Value::from(r.code.as_str()));
            if let Some(seq) = r.seq {
                m.insert("seq".to_owned(), Value::from(seq));
            }
            if let Some(guard) = r.guard {
                m.insert("guard".to_owned(), Value::from(guard.as_str()));
            }
            object([("rejected", Value::Object(m))])
        }
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum Intake {
    SubmissionRefusedBeforeTaskExists,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectInput {
    #[serde(default)]
    state: Option<String>,
    #[serde(default)]
    wait_reason: Option<String>,
    #[serde(default)]
    intake: Option<Intake>,
    #[serde(default)]
    inbound: Option<Value>,
}

pub(super) fn project(input: Value) -> Result<Value, CoreError> {
    let input: ProjectInput = parse(input, "projection input")?;
    if let Some(Intake::SubmissionRefusedBeforeTaskExists) = input.intake {
        let refused = refused_submission();
        return Ok(object([
            (
                "mcp_tasks",
                Value::from(refused.mcp_tasks.map_or("none", |s| s.as_str())),
            ),
            ("a2a_task", Value::from(refused.a2a_task.as_str())),
        ]));
    }
    let state = input
        .state
        .as_deref()
        .and_then(TaskState::from_wire)
        .ok_or(CoreError::InvalidInput("state"))?;
    if input.inbound.is_some() {
        return Ok(object([("state", Value::from(state.as_str()))]));
    }
    let reason = match input.wait_reason.as_deref() {
        None => None,
        Some(r) => Some(WaitReason::from_wire(r).ok_or(CoreError::InvalidInput("wait_reason"))?),
    };
    let p = projection(state, reason);
    let mut m = Map::new();
    m.insert("mcp_tasks".to_owned(), Value::from(p.mcp_tasks.as_str()));
    m.insert("a2a_task".to_owned(), Value::from(p.a2a_task.as_str()));
    m.insert(
        "status_message".to_owned(),
        Value::from(p.status_message.as_str()),
    );
    if let Some(accepted) = p.caller_answer_accepted {
        m.insert("caller_answer_accepted".to_owned(), Value::Bool(accepted));
    }
    Ok(Value::Object(m))
}
