//! The execution rules: the path order and place, the origin set, the Rule of Two, the step budget, the handover at a block, effect replay, resuming, sub-agent narrowing and the planner's control fields (CP-9, CP-12, CP-13, CP-14, CP-32, CP-36, CP-43, CP-45, CP-46, SEC-12, SEC-18, SEC-19, M-2).

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use std::collections::BTreeSet;
use std::num::NonZeroU32;

use one_proto::TaskId;
use one_proto::capability::{CapabilityName, PathType};
use one_proto::money::Money;
use one_proto::ontology::{Instant, ProvenanceLabel};
use one_proto::task::{
    FailureReason, Origin, OriginSet, RouteLocation, RoutePath, Step, StepId, StepReason,
    WaitReason,
};
use one_provenance::{ExternalSource, Label, LabelKind, ProposedInput, VarRef};
use one_task::domain::budget::{DEFAULT_STEPS, Spend, budget, next};
use one_task::domain::effect::{Check, Replay, Seen, after_check, key, replay};
use one_task::domain::handoff::{
    Block, DEFAULT_WAIT_SECS, MAX_WAIT_SECS, MIN_WAIT_SECS, WHILE_HELD, WhileHeld, on_block,
    on_expiry, wait_secs,
};
use one_task::domain::origins::{Use, Widen, allows, derive, widen};
use one_task::domain::path::{Choice, Handoff, Offer, Platform, Site, Situation, choose};
use one_task::domain::plan::{BoundToVariable, ControlField, control, from_memory, joined};
use one_task::domain::resume::{Resume, resume, snapshot_ends};
use one_task::domain::split::{PARTS, Reach, Verdict, check, may_use_now};
use one_task::domain::subagent::{Asker, Refused, Scope, narrow};
use serde_json::json;

fn offer(path: PathType) -> Offer {
    Offer {
        path,
        working: true,
        app_function: false,
        allowlisted: false,
    }
}

fn cloud() -> Situation {
    Situation {
        platform: Platform::Android,
        needs_session: false,
        user_present: true,
    }
}

fn run(choice: &Choice) -> (usize, RoutePath, RouteLocation) {
    match choice {
        Choice::Run { offer, route } => (*offer, route.path, route.location),
        other => panic!("{other:?}"),
    }
}

#[test]
fn cp_12_the_first_working_path_wins_in_the_fixed_order() {
    let offers = [
        offer(PathType::Browser),
        offer(PathType::OsIntent),
        offer(PathType::Mcp),
    ];
    let got = choose(&offers, Site::default(), cloud()).unwrap();
    assert_eq!(run(&got), (2, RoutePath::Mcp, RouteLocation::CloudExecutor));
    let mut broken = offers;
    broken[2].working = false;
    let got = choose(&broken, Site::default(), cloud()).unwrap();
    assert_eq!(
        run(&got),
        (1, RoutePath::OsIntent, RouteLocation::LocalExecutor)
    );
    broken[1].working = false;
    let got = choose(&broken, Site::default(), cloud()).unwrap();
    assert_eq!(
        run(&got),
        (0, RoutePath::CloudBrowser, RouteLocation::CloudMicrovm)
    );
    broken[0].working = false;
    let got = choose(&broken, Site::default(), cloud()).unwrap();
    assert!(matches!(
        got,
        Choice::Handoff { why: Handoff::NoPath, ref route }
            if route.path == RoutePath::Handoff && route.location == RouteLocation::User
    ));
}

#[test]
fn cp_13_t_22_an_os_intent_runs_only_on_android_and_an_app_function_only_when_allowlisted() {
    let intent = [offer(PathType::OsIntent), offer(PathType::Browser)];
    for platform in [Platform::Ios, Platform::Desktop, Platform::Offline] {
        let situation = Situation {
            platform,
            ..cloud()
        };
        let got = choose(&intent, Site::default(), situation).unwrap();
        assert_eq!(run(&got).1, RoutePath::CloudBrowser, "{platform:?}");
    }
    let mut function = intent;
    function[0].app_function = true;
    assert_eq!(
        run(&choose(&function, Site::default(), cloud()).unwrap()).1,
        RoutePath::CloudBrowser
    );
    function[0].allowlisted = true;
    assert_eq!(
        run(&choose(&function, Site::default(), cloud()).unwrap()).1,
        RoutePath::OsIntent
    );
}

#[test]
fn cp_14_a_site_that_forbids_or_blocks_agents_is_handed_to_the_user() {
    let browser = [offer(PathType::Browser)];
    let terms = Site {
        terms_forbid_agents: true,
        blocks_agents: false,
    };
    assert!(matches!(
        choose(&browser, terms, cloud()).unwrap(),
        Choice::Handoff {
            why: Handoff::TermsForbidAgents,
            ..
        }
    ));
    let blocks = Site {
        terms_forbid_agents: false,
        blocks_agents: true,
    };
    assert!(matches!(
        choose(&browser, blocks, cloud()).unwrap(),
        Choice::Handoff {
            why: Handoff::BlockedBySite,
            ..
        }
    ));
    let api = [offer(PathType::Api), offer(PathType::Browser)];
    assert_eq!(
        run(&choose(&api, terms, cloud()).unwrap()).1,
        RoutePath::Api
    );
}

#[test]
fn cp_9_a_session_step_runs_locally_with_the_user_and_waits_without_them() {
    let browser = [offer(PathType::Browser)];
    let here = Situation {
        needs_session: true,
        ..cloud()
    };
    assert_eq!(
        run(&choose(&browser, Site::default(), here).unwrap()).2,
        RouteLocation::LocalExecutor
    );
    let away = Situation {
        user_present: false,
        ..here
    };
    assert_eq!(
        choose(&browser, Site::default(), away).unwrap(),
        Choice::WaitForUser {
            offer: 0,
            path: RoutePath::CloudBrowser
        }
    );
    let unattended = Situation {
        needs_session: false,
        user_present: false,
        ..cloud()
    };
    assert_eq!(
        run(&choose(&browser, Site::default(), unattended).unwrap()).2,
        RouteLocation::CloudMicrovm
    );
}

fn origin(text: &str) -> Origin {
    Origin::parse(text).unwrap()
}

fn step(id: &str, read: &[&str], write: &[&str]) -> Step {
    let reads: Vec<_> = read.iter().map(|o| json!(o)).collect();
    let writes: Vec<_> = write.iter().map(|o| json!(o)).collect();
    serde_json::from_value(json!({
        "id": id,
        "capability": { "name": "app.suiss.travel.lodging.book", "version": "2026-10-01" },
        "action": {
            "namespace": "app.suiss.travel.lodging.book",
            "name": "primary",
            "version": "2026-10-01",
            "schema_digest": "sha256:abababababababababababababababababababababababababababababababab"
        },
        "effectful": false,
        "inputs": [],
        "state": "planned",
        "route": { "path": "cloud_browser", "location": "cloud_microvm", "reason": "cp-9" },
        "origin_set": { "read": reads, "write": writes }
    }))
    .unwrap()
}

#[test]
fn sec_19_the_origin_set_comes_from_the_plan_and_denies_everything_outside_it() {
    let steps = [
        step("s1", &["https://hotel.example"], &[]),
        step("s2", &["https://hotel.example"], &["https://book.example"]),
    ];
    let set = derive(&steps).unwrap();
    assert_eq!(
        set,
        OriginSet {
            read: vec![origin("https://hotel.example")],
            write: vec![origin("https://book.example")],
        }
    );
    assert!(allows(&set, &origin("https://hotel.example"), Use::Read));
    assert!(allows(&set, &origin("https://book.example"), Use::Read));
    assert!(!allows(&set, &origin("https://hotel.example"), Use::Write));
    assert!(!allows(&set, &origin("https://evil.example"), Use::Read));
    let user = LabelKind::from_proto(ProvenanceLabel::UserDirect)
        .single()
        .unwrap();
    let web = Label::Untrusted(one_provenance::UntrustedLabel::External(
        ExternalSource::Web,
    ));
    assert_eq!(
        widen(&set, &origin("https://hotel.example"), Use::Read, &web),
        None
    );
    assert_eq!(
        widen(&set, &origin("https://other.example"), Use::Read, &user),
        Some(Widen::NewDecision)
    );
    assert_eq!(
        widen(&set, &origin("https://other.example"), Use::Write, &web),
        Some(Widen::UserApproval)
    );
}

#[test]
fn sec_18_all_three_split_or_go_to_the_user() {
    let two = Reach {
        untrusted_input: true,
        private_data: true,
        outside_effect: false,
    };
    assert_eq!(check(two, true), Verdict::Fits);
    let three = Reach {
        outside_effect: true,
        ..two
    };
    assert_eq!(check(three, true), Verdict::Split(PARTS));
    assert!(PARTS.iter().all(|p| !p.all_three()));
    assert!(
        PARTS
            .iter()
            .filter(|p| p.untrusted_input)
            .all(|p| !p.private_data && !p.outside_effect)
    );
    assert_eq!(check(three, false), Verdict::Approval);
    assert!(may_use_now(true, false));
    assert!(!may_use_now(false, false));
    assert!(may_use_now(false, true));
}

#[test]
fn cp_36_the_budget_is_the_narrower_and_a_spent_budget_asks_the_user() {
    assert_eq!(DEFAULT_STEPS.get(), 50);
    assert_eq!(budget(None, None).unwrap(), DEFAULT_STEPS);
    let ten = NonZeroU32::new(10).unwrap();
    assert_eq!(budget(Some(ten), None).unwrap(), ten);
    assert_eq!(budget(None, Some(ten)).unwrap(), ten);
    assert_eq!(
        budget(Some(NonZeroU32::new(80).unwrap()), None).unwrap(),
        DEFAULT_STEPS
    );
    assert_eq!(next(0, ten), Spend::Go { left: 9 });
    assert_eq!(next(9, ten), Spend::Go { left: 0 });
    assert_eq!(next(10, ten), Spend::AskUser);
    assert_eq!(next(u32::MAX, ten), Spend::AskUser);
}

fn at(text: &str) -> Instant {
    Instant::parse(text).unwrap()
}

#[test]
fn cp_32_a_block_waits_for_the_user_and_an_expired_wait_stops_with_its_reason() {
    assert_eq!(wait_secs(None, None), DEFAULT_WAIT_SECS);
    assert_eq!(DEFAULT_WAIT_SECS, 86_400);
    assert_eq!(wait_secs(Some(3_600), None), 3_600);
    assert_eq!(wait_secs(Some(3_600), Some(7_200)), 7_200);
    assert_eq!(wait_secs(Some(1), None), MIN_WAIT_SECS);
    assert_eq!(wait_secs(None, Some(u32::MAX)), MAX_WAIT_SECS);
    let opened = at("2026-11-05T09:00:00Z");
    let captcha = on_block(Block::Captcha, opened, DEFAULT_WAIT_SECS).unwrap();
    assert_eq!(captcha.reason, WaitReason::Takeover);
    assert_eq!(captcha.expires_at, at("2026-11-06T09:00:00Z"));
    assert_eq!(
        on_block(Block::TwoFactor, opened, MIN_WAIT_SECS)
            .unwrap()
            .reason,
        WaitReason::Authentication
    );
    assert_eq!(
        on_expiry(Block::BotWall),
        (StepReason::WaitExpired, FailureReason::BlockedBySite)
    );
    assert_eq!(
        on_expiry(Block::Login),
        (StepReason::WaitExpired, FailureReason::CriterionUnreachable)
    );
    assert_eq!(
        WHILE_HELD,
        WhileHeld {
            screenshots: false,
            model_context: false
        }
    );
}

#[test]
fn cp_43_a_recorded_effect_is_never_repeated_and_an_open_one_is_checked_first() {
    assert_eq!(replay(Seen::NotSent), Replay::Send);
    assert_eq!(replay(Seen::Recorded), Replay::Keep);
    assert_eq!(replay(Seen::SentUnrecorded), Replay::Check);
    assert_eq!(after_check(Check::Occurred), Replay::Keep);
    assert_eq!(after_check(Check::DidNotOccur), Replay::SendAgain);
    assert_eq!(
        after_check(Check::Unverifiable),
        Replay::Unknown(StepReason::CrashUnverified)
    );
    let task = TaskId::parse("task_01k7n51z01e40r200000000000").unwrap();
    let s = StepId::parse("s1").unwrap();
    assert_eq!(key(task, &s), key(task, &s));
    assert_ne!(key(task, &s), key(task, &StepId::parse("s2").unwrap()));
}

#[test]
fn cp_45_a_resumed_page_is_checked_again_and_a_snapshot_never_outlives_its_profile() {
    let now = at("2026-11-05T09:00:00Z");
    let ends = at("2026-11-12T09:00:00Z");
    assert_eq!(
        resume(&("cart", 120), &("cart", 120), now, ends),
        Resume::GoOn
    );
    assert_eq!(
        resume(&("cart", 120), &("cart", 135), now, ends),
        Resume::AskUser
    );
    assert_eq!(
        resume(&("cart", 120), &("cart", 120), ends, ends),
        Resume::Fresh
    );
    let later = at("2026-12-01T00:00:00Z");
    assert_eq!(snapshot_ends(later, ends), ends);
    assert_eq!(snapshot_ends(now, ends), now);
}

fn names(list: &[&str]) -> BTreeSet<CapabilityName> {
    list.iter()
        .map(|n| CapabilityName::parse(n).unwrap())
        .collect()
}

fn money(value: &str) -> Money {
    serde_json::from_value(json!({ "value": value, "currency": "TRY" })).unwrap()
}

#[test]
fn cp_46_a_sub_agent_only_narrows_and_never_grants_itself() {
    let one = Scope {
        capabilities: names(&[
            "app.suiss.travel.flight.search",
            "app.suiss.travel.flight.book",
        ]),
        steps: NonZeroU32::new(50).unwrap(),
        amount: Some(money("5000.00")),
    };
    let travel = Scope {
        capabilities: names(&["app.suiss.travel.flight.search"]),
        steps: NonZeroU32::new(20).unwrap(),
        amount: None,
    };
    assert_eq!(narrow(&one, travel.clone(), Asker::One), Ok(travel.clone()));
    assert_eq!(
        narrow(&one, travel.clone(), Asker::SubAgent),
        Err(Refused::SelfGrant)
    );
    let wider = Scope {
        capabilities: names(&["app.suiss.commerce.purchase"]),
        ..travel.clone()
    };
    assert_eq!(narrow(&one, wider, Asker::User), Err(Refused::Capability));
    let longer = Scope {
        steps: NonZeroU32::new(51).unwrap(),
        ..travel.clone()
    };
    assert_eq!(narrow(&one, longer, Asker::User), Err(Refused::Steps));
    let richer = Scope {
        amount: Some(money("5000.01")),
        ..travel.clone()
    };
    assert_eq!(narrow(&one, richer, Asker::User), Err(Refused::Amount));
    let poor = Scope {
        amount: None,
        ..one.clone()
    };
    let spending = Scope {
        amount: Some(money("1.00")),
        ..travel
    };
    assert_eq!(narrow(&poor, spending, Asker::One), Err(Refused::Amount));
}

#[test]
fn sec_12_a_control_field_never_takes_a_variable_and_memory_keeps_its_label() {
    let literal: ProposedInput<&str> = ProposedInput::Literal("app.suiss.communication.email.send");
    assert_eq!(
        control(ControlField::Capability, &literal),
        Ok(&"app.suiss.communication.email.send")
    );
    let bound: ProposedInput<&str> = ProposedInput::Ref(VarRef::parse("var_3").unwrap());
    for field in [
        ControlField::Capability,
        ControlField::Action,
        ControlField::Recipient,
        ControlField::Runs,
    ] {
        assert_eq!(control(field, &bound), Err(BoundToVariable(field)));
    }
    let memory = from_memory(ProvenanceLabel::UserMemory);
    assert!(memory.is_trusted());
    assert_eq!(memory.kind().to_proto(), ProvenanceLabel::UserMemory);
    let inferred = from_memory(ProvenanceLabel::OneInferred);
    assert!(!inferred.is_trusted());
    let email = Label::Untrusted(one_provenance::UntrustedLabel::External(
        ExternalSource::Email,
    ));
    assert_eq!(joined([&memory, &email]), email);
    assert_eq!(joined([]), Label::UNKNOWN);
}

fn table(key: &str) -> String {
    let path = format!(
        "{}/../../conformance/task/execution-v1.toml",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = std::fs::read_to_string(path).unwrap();
    let line = text
        .lines()
        .find(|l| l.split('=').next().map(str::trim) == Some(key))
        .unwrap_or_else(|| panic!("no {key}"));
    line.split('=').nth(1).unwrap().trim().to_owned()
}

#[test]
fn cp_32_cp_36_the_execution_table_holds_the_code_values() {
    assert_eq!(table("default_steps"), DEFAULT_STEPS.to_string());
    assert_eq!(table("default_wait_secs"), DEFAULT_WAIT_SECS.to_string());
    assert_eq!(table("min_wait_secs"), MIN_WAIT_SECS.to_string());
    assert_eq!(table("max_wait_secs"), MAX_WAIT_SECS.to_string());
}
