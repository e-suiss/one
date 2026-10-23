//! A2A: messages from another agent are labelled `external.agent`, from another One `external.one`; the One↔One profile reuses the federation vectors (T-36 (4), SEC-14, OO-4).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::format_push_string,
    clippy::format_collect,
    reason = "T-38"
)]

mod common;

use std::path::Path;

use common::{assert_label, tight};
use one_parse::a2a::{self, Part, SendResult};
use one_parse::jsonrpc::Outcome;
use one_parse::{Limits, ParseError};
use one_proto::federation::task::TaskState;
use serde_json::Value;

const MESSAGE: &[u8] = br#"{
  "messageId": "m-1",
  "contextId": "c-1",
  "role": "ROLE_AGENT",
  "parts": [
    {"text": "Your flight is booked.", "mediaType": "text/plain"},
    {"data": {"price": 120}},
    {"url": "https://example.test/t.pdf", "filename": "t.pdf", "mediaType": "application/pdf"},
    {"raw": "AAAA"}
  ],
  "metadata": {"x": 1},
  "extensions": ["https://example.test/ext"]
}"#;

const TASK: &[u8] = br#"{
  "id": "t-1",
  "contextId": "c-1",
  "status": {"state": "TASK_STATE_COMPLETED", "timestamp": "2026-10-12T09:00:00Z"},
  "artifacts": [{"artifactId": "a-1", "name": "ticket", "parts": [{"text": "PNR X1"}]}],
  "history": [{"messageId": "m-0", "role": "ROLE_USER", "parts": [{"text": "book it"}]}],
  "kind": "task"
}"#;

#[test]
fn t_36_a2a_agent_message_is_labelled_agent() {
    let v = a2a::parse_agent_message(MESSAGE, &Limits::DEFAULT).unwrap();
    assert_label(&v, "external.agent");
    let m = v.expose();
    assert_eq!(m.message_id.as_str(), "m-1");
    assert_eq!(m.parts.len(), 4);
    assert!(matches!(&m.parts[0], Part::Text { text, .. } if text == "Your flight is booked."));
    assert!(matches!(&m.parts[2], Part::Url { filename: Some(f), .. } if f == "t.pdf"));
    assert!(matches!(&m.parts[3], Part::Raw { .. }));
}

#[test]
fn t_36_a2a_agent_task_is_labelled_agent() {
    let v = a2a::parse_agent_task(TASK, &Limits::DEFAULT).unwrap();
    assert_label(&v, "external.agent");
    assert_eq!(v.expose().status.state, TaskState::Completed);
    assert_eq!(v.expose().artifacts.len(), 1);
    assert_eq!(v.expose().history.len(), 1);
}

#[test]
fn t_36_a2a_send_response_is_labelled_agent() {
    let mut body = br#"{"jsonrpc":"2.0","id":3,"result":{"task":"#.to_vec();
    body.extend_from_slice(TASK);
    body.extend_from_slice(b"}}");
    let v = a2a::parse_agent_response(&body, &Limits::DEFAULT).unwrap();
    assert_label(&v, "external.agent");
    assert!(
        matches!(&v.expose().outcome, Outcome::Result(SendResult::Task(t)) if t.id.as_str() == "t-1")
    );
}

#[test]
fn t_36_a2a_part_with_two_contents_is_rejected() {
    let bad = br#"{"messageId":"m","role":"ROLE_USER","parts":[{"text":"a","url":"b"}]}"#;
    assert!(a2a::parse_agent_message(bad, &tight()).is_err());
    let empty = br#"{"messageId":"m","role":"ROLE_USER","parts":[{}]}"#;
    assert!(a2a::parse_agent_message(empty, &tight()).is_err());
}

#[test]
fn sec_13_a2a_limits_are_enforced() {
    assert_eq!(
        a2a::parse_agent_message(
            MESSAGE,
            &Limits {
                max_bytes: 32,
                ..Limits::DEFAULT
            }
        )
        .unwrap_err(),
        ParseError::TooLarge
    );
    assert_eq!(
        a2a::parse_agent_task(
            TASK,
            &Limits {
                max_depth: 2,
                ..Limits::DEFAULT
            }
        )
        .unwrap_err(),
        ParseError::TooDeep
    );
    assert_eq!(
        a2a::parse_agent_message(
            MESSAGE,
            &Limits {
                max_items: 8,
                ..Limits::DEFAULT
            }
        )
        .unwrap_err(),
        ParseError::TooManyItems
    );
}

fn vectors(rel: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .join(rel);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

#[test]
fn t_36_a2a_one_messages_follow_the_federation_vectors() {
    let mut seen = (0, 0);
    for v in vectors("open/federation/vectors/schema/message.json") {
        let bytes = serde_json::to_vec(&v["input"]).unwrap();
        let result = a2a::parse_one_message(&bytes, &Limits::DEFAULT);
        if v["valid"].as_bool().unwrap() {
            assert_label(&result.unwrap(), "external.one");
            seen.0 += 1;
        } else {
            assert!(result.is_err(), "{}", v["description"]);
            seen.1 += 1;
        }
    }
    assert_eq!(seen, (6, 12));
}

#[test]
fn t_36_a2a_one_tasks_follow_the_federation_vectors() {
    let mut seen = (0, 0);
    for v in vectors("open/federation/vectors/schema/task.json") {
        let bytes = serde_json::to_vec(&v["input"]).unwrap();
        let result = a2a::parse_one_task(&bytes, &Limits::DEFAULT);
        if v["valid"].as_bool().unwrap() {
            assert_label(&result.unwrap(), "external.one");
            seen.0 += 1;
        } else {
            assert!(result.is_err(), "{}", v["description"]);
            seen.1 += 1;
        }
    }
    assert_eq!(seen, (7, 8));
}
