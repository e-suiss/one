//! Stage 6 end to end: a multi-step task picks each step's path, asks Access for every step and reaches the Executor only on an allow, hands a CAPTCHA to the user and goes on under the continuation, stops only when the Executor confirms the pause and resumes under a new decision, while a denied step never reaches the Executor and an offline command waits (CP-3, CP-5, CP-9, CP-10, CP-11, CP-12, CP-32, CP-44, INV-32).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "T-38"
)]

use std::cell::RefCell;
use std::num::NonZeroU32;

use one_access_client::decision::Decision;
use one_proto::capability::PathType;
use one_proto::ontology::Instant;
use one_proto::task::{
    RouteLocation, RoutePath, StopCommand, TaskEvent, TaskState, WaitReason, derive_events,
    stop_command,
};
use one_task::app::{Before, Prepared, Submit, prepare, submit};
use one_task::domain::gate::{Permit, Stop};
use one_task::domain::handoff::{Block, DEFAULT_WAIT_SECS, WHILE_HELD, WhileHeld, on_block};
use one_task::domain::path::{Offer, Platform, Site, Situation};
use one_task::domain::resume::{Resume, resume};
use one_task::ports::Executor;
use serde_json::{Value, json};
use suiss_crypto::digest::Digest;

const TASK: &str = "task_01k7n51z01e40r200000000000";

#[derive(Default)]
struct Recorder(RefCell<Vec<(&'static str, Digest)>>);

impl Executor<&'static str> for Recorder {
    type Error = ();

    fn execute(&self, permit: &Permit<&'static str>) -> Result<(), ()> {
        self.0
            .borrow_mut()
            .push((*permit.intent(), *permit.exercise()));
        Ok(())
    }
}

fn allow(n: u8) -> Decision {
    Decision::Allow {
        exercise: Some(Digest([n; 32])),
        advisory: false,
        basis_ref: None,
        consistency_token: None,
    }
}

fn offer(path: PathType) -> Offer {
    Offer {
        path,
        working: true,
        app_function: false,
        allowlisted: false,
    }
}

fn before(offers: &[Offer], used: u32) -> Before<'_> {
    Before {
        online: true,
        used,
        budget: NonZeroU32::new(50).unwrap(),
        offers,
        site: Site::default(),
        situation: Situation {
            platform: Platform::Android,
            needs_session: false,
            user_present: true,
        },
    }
}

fn ready(prepared: Prepared) -> (RoutePath, RouteLocation) {
    match prepared {
        Prepared::Ready { route, .. } => (route.path, route.location),
        other => panic!("{other:?}"),
    }
}

struct History(Vec<TaskEvent>);

impl History {
    fn push(&mut self, source: &str, kind: &str, mut fields: Value) {
        let seq = self.0.len().checked_add(1).unwrap();
        let at = Instant::from_unix(
            1_793_000_000_i64
                .checked_add(i64::try_from(seq).unwrap())
                .unwrap(),
        );
        let body = fields.as_object_mut().unwrap();
        body.insert("task_id".into(), json!(TASK));
        body.insert("seq".into(), json!(seq));
        body.insert("at".into(), json!(at.to_string()));
        body.insert("source".into(), json!(source));
        body.insert("kind".into(), json!(kind));
        self.0.push(serde_json::from_value(fields).unwrap());
    }

    fn started(&mut self, step: &str, n: u8) {
        self.push(
            "executor",
            "step_started",
            json!({
                "step_id": step, "effectful": true,
                "decision_ref": { "ref": "DecisionRecordRef", "id": format!("dec-{n}") },
                "exercise_ref": { "ref": "ExerciseRef", "id": format!("ex-{n}") }
            }),
        );
    }

    fn finished(&mut self, step: &str) {
        self.push(
            "executor",
            "step_finished",
            json!({
                "step_id": step,
                "result": { "status": "done", "outcome": {
                    "subject": "effect", "certainty": "confirmed", "value": "occurred",
                    "confirmation": { "ref": "ClaimRef", "id": format!("claim-{step}") }
                } }
            }),
        );
    }

    fn state(&self) -> (TaskState, bool) {
        let d = derive_events(&self.0).unwrap();
        (d.state, d.stopping)
    }
}

#[test]
fn cp_5_cp_11_cp_32_a_multi_step_task_picks_its_path_asks_access_each_step_is_stopped_and_taken_over()
 {
    let executor = Recorder::default();
    let mut history = History(Vec::new());
    history.push("one", "task_created", json!({ "plan_version": 1 }));
    assert_eq!(history.state(), (TaskState::Pending, false));

    let api = [offer(PathType::Browser), offer(PathType::Api)];
    assert_eq!(
        ready(prepare(&before(&api, 0)).unwrap()),
        (RoutePath::Api, RouteLocation::CloudExecutor)
    );
    submit(&executor, Ok("look up the order"), &allow(1)).unwrap();
    history.started("s1", 1);
    history.finished("s1");
    assert_eq!(history.state(), (TaskState::Running, false));

    let browser = [offer(PathType::Browser)];
    assert_eq!(
        ready(prepare(&before(&browser, 1)).unwrap()),
        (RoutePath::CloudBrowser, RouteLocation::CloudMicrovm)
    );
    submit(&executor, Ok("book the room"), &allow(2)).unwrap();
    history.started("s2", 2);
    let now = Instant::from_unix(1_793_000_100);
    let takeover = on_block(Block::Captcha, now, DEFAULT_WAIT_SECS).unwrap();
    assert_eq!(takeover.reason, WaitReason::Takeover);
    history.push(
        "one",
        "wait_opened",
        json!({ "wait": "user", "reason": "takeover",
                "waitpoint_ref": { "ref": "WaitpointRef", "id": "wp-captcha" } }),
    );
    assert_eq!(history.state(), (TaskState::WaitingUser, false));
    assert_eq!(
        WHILE_HELD,
        WhileHeld {
            screenshots: false,
            model_context: false
        }
    );
    history.push(
        "relay",
        "wait_resolved",
        json!({ "waitpoint_ref": { "ref": "WaitpointRef", "id": "wp-captcha" },
                "continuation_ref": { "ref": "DecisionRecordRef", "id": "cont-captcha" } }),
    );
    assert_eq!(history.state(), (TaskState::Running, false));
    let profile_ends = Instant::from_unix(1_793_600_000);
    assert_eq!(
        resume(&("room 12", 4_200), &("room 12", 4_200), now, profile_ends),
        Resume::GoOn
    );
    history.finished("s2");

    let message = [offer(PathType::Mcp)];
    assert_eq!(
        ready(prepare(&before(&message, 2)).unwrap()),
        (RoutePath::Mcp, RouteLocation::CloudExecutor)
    );
    assert_eq!(
        submit(
            &executor,
            Ok("tell the hotel"),
            &Decision::Deny {
                blockers: Vec::new()
            }
        ),
        Err(Submit::Stopped(Stop::Denied))
    );
    submit(&executor, Ok("tell the hotel"), &allow(3)).unwrap();
    history.started("s3", 3);

    let (state, _) = history.state();
    assert_eq!(stop_command(state), StopCommand::RequestPause);
    history.push("user", "pause_requested", json!({}));
    assert_eq!(history.state(), (TaskState::Running, true));
    history.push(
        "executor",
        "pause_confirmed",
        json!({ "execution_report_ref": { "ref": "ExecutionReportRef", "id": "rep-pause" } }),
    );
    assert_eq!(history.state(), (TaskState::Paused, false));
    history.push(
        "one",
        "resumed",
        json!({ "continuation_ref": { "ref": "DecisionRecordRef", "id": "cont-resume" } }),
    );
    assert_eq!(history.state(), (TaskState::Running, false));
    history.finished("s3");
    history.push(
        "one",
        "completion_verified",
        json!({ "evidence_ref": { "ref": "ClaimRef", "id": "claim-s3" } }),
    );
    assert_eq!(history.state(), (TaskState::Completed, false));

    let sent: Vec<_> = executor.0.borrow().iter().map(|(i, _)| *i).collect();
    assert_eq!(
        sent,
        ["look up the order", "book the room", "tell the hotel"]
    );
    let exercises: Vec<_> = executor.0.borrow().iter().map(|(_, e)| *e).collect();
    assert_eq!(
        exercises,
        [Digest([1; 32]), Digest([2; 32]), Digest([3; 32])]
    );
}

#[test]
fn cp_10_cp_36_cp_9_offline_spent_or_session_bound_steps_never_reach_access() {
    let api = [offer(PathType::Api)];
    let offline = Before {
        online: false,
        ..before(&api, 0)
    };
    assert_eq!(prepare(&offline).unwrap(), Prepared::Held);
    assert_eq!(prepare(&before(&api, 50)).unwrap(), Prepared::BudgetSpent);
    let browser = [offer(PathType::Browser)];
    let away = Before {
        situation: Situation {
            platform: Platform::Android,
            needs_session: true,
            user_present: false,
        },
        ..before(&browser, 0)
    };
    assert_eq!(
        prepare(&away).unwrap(),
        Prepared::WaitForUser {
            offer: 0,
            path: RoutePath::CloudBrowser
        }
    );
    assert!(matches!(
        prepare(&before(&[], 0)).unwrap(),
        Prepared::Handoff { .. }
    ));
}
