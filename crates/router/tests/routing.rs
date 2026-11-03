//! Routing end to end over the pure gate: a request passes the rule gate and reaches the right role, eliminated options never serve, the fallback order holds, a large model's job never silently goes to the small model, only an adapter that passed its activation gates is attached, and every record satisfies its contract (MF-19, MF-20, MF-21, MF-22, MF-23, MF-24, MF-32, MF-34, MF-37, MF-38, MF-48).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::float_cmp,
    clippy::many_single_char_names,
    reason = "T-38"
)]

use one_proto::model::registry::Registry;
use one_proto::model::request::ModelRequest;
use one_proto::model::roles::ModelRole;
use one_proto::model::routing::{EliminationRule, Fallback, GateResult, Region};
use one_proto::ontology::Instant;
use one_proto::{AdapterId, ModelVersionId};
use one_router::adapters::{Deployment, instances};
use one_router::app::{Route, route};
use one_router::domain::adapter::{Gates, Outcome, Versions};
use one_router::domain::gate::{
    ActiveAdapter, Connectivity, Facts, Family, Grant, Instance, Purpose,
};
use one_router::domain::personality::{Scores, compare};
use serde_json::{Value, json};

const SMALL: &str = "mdl_01m4ezb900f9at0tvpg669f8nd";
const SMALL_2: &str = "mdl_01m4ezb900ejftnde0sfbe3v7q";
const LARGE: &str = "mdl_01m4ezb900eyhave63svcy9vzt";
const LARGE_BACKUP: &str = "mdl_01m4ezb900fvmv9zra2mg2pdj1";
const QUARANTINE: &str = "mdl_01m4a5btkneayawh9ym9pwjqpt";
const OTHER_BASE: &str = "mdl_01k742sgz8fpttyr5nkb810tbn";

fn id(s: &str) -> ModelVersionId {
    ModelVersionId::parse(s).unwrap()
}

fn region(s: &str) -> Region {
    Region::parse(s).unwrap()
}

fn instance(role: ModelRole, version: &str, family: Family) -> Instance {
    Instance {
        role,
        version: id(version),
        family,
        region: region("eu-central"),
        attested_tee: true,
        released: true,
        available: true,
    }
}

fn pool() -> Vec<Instance> {
    vec![
        instance(ModelRole::SmallLm, SMALL, Family::Default),
        instance(ModelRole::LargeLm, LARGE, Family::Default),
        instance(ModelRole::LargeLm, LARGE, Family::Default),
        instance(ModelRole::LargeLm, LARGE_BACKUP, Family::Backup),
        instance(ModelRole::Quarantine, QUARANTINE, Family::Default),
    ]
}

fn facts() -> Facts {
    Facts {
        region: region("eu-central"),
        connectivity: Connectivity::Online,
        grant: Grant::Within,
        personal_training_consent: true,
        child_profile: false,
    }
}

fn adapter(base: &str) -> ActiveAdapter {
    ActiveAdapter {
        id: AdapterId::parse("adp_01m4ezb900ec79j91f792n0pv6").unwrap(),
        base: id(base),
    }
}

fn request(edit: impl FnOnce(&mut Value)) -> ModelRequest {
    let mut v = json!({
        "request_id": "mrq_01m4ezb900emrbphjhbhkq4zc8",
        "capabilities": ["text_generation"],
        "context": {
            "language": "tr",
            "messages": [{
                "role": "user",
                "provenance": "user.direct",
                "content": [{"type": "text", "text": "Yarın 9'a al"}]
            }]
        },
        "latency_budget_ms": 1500,
        "data_class": {"kinds": ["personal"], "sensitive": []},
        "retention_classes": ["one_memory"],
        "mode": {"ephemeral": false, "personalise": true},
        "hints": {"task_kind": "short_answer", "expected_output_tokens": 40}
    });
    edit(&mut v);
    serde_json::from_value(v).unwrap()
}

fn planning(v: &mut Value) {
    v["capabilities"] = json!(["text_generation", "multi_step_planning"]);
    v["hints"] = json!({"task_kind": "planning", "plan_depth": 4, "expected_output_tokens": 1500});
}

fn at() -> Instant {
    Instant::parse("2026-11-03T08:00:00Z").unwrap()
}

fn versions(a: Option<&ActiveAdapter>) -> Versions<ActiveAdapter> {
    Versions {
        active: a.copied(),
        previous: None,
    }
}

fn go(req: &ModelRequest, facts: &Facts, pool: &[Instance], a: Option<&ActiveAdapter>) -> Route {
    let r = route(req, Purpose::Answer, facts, pool, &versions(a), at()).unwrap();
    r.record.validate().unwrap();
    let json = serde_json::to_value(&r.record).unwrap();
    assert!(json.get("content").is_none());
    r
}

fn rules(r: &Route) -> Vec<EliminationRule> {
    r.record
        .memory_part
        .gate
        .eliminated
        .iter()
        .map(|e| e.rule)
        .collect()
}

#[test]
fn a_short_request_passes_the_gate_to_the_small_model_with_the_adapter() {
    let a = adapter(SMALL);
    let r = go(&request(|_| ()), &facts(), &pool(), Some(&a));
    let serve = r.serve.clone().unwrap();
    assert_eq!(serve.model.model_role, ModelRole::SmallLm);
    assert_eq!(serve.model.adapter_id, Some(a.id));
    assert!(!serve.short_answer);
    let m = &r.record.memory_part;
    assert_eq!(m.gate.result, GateResult::Passed);
    assert_eq!(m.fallback, Fallback::None);
    assert_eq!(m.estimate.as_ref().unwrap().small_sufficient, 0.95);
    assert_eq!(r.record.provider_trace_part.hops.len(), 1);
    assert_eq!(
        r.record.provider_trace_part.hops[0].attested_tee,
        Some(true)
    );
}

#[test]
fn a_planning_request_goes_to_the_large_model_without_an_adapter() {
    let a = adapter(SMALL);
    let r = go(&request(planning), &facts(), &pool(), Some(&a));
    let serve = r.serve.clone().unwrap();
    assert_eq!(serve.model.model_role, ModelRole::LargeLm);
    assert_eq!(serve.model.model_version_id, id(LARGE));
    assert_eq!(serve.model.adapter_id, None);
    assert_eq!(serve.instance, 1);
}

#[test]
fn mf_20_ephemeral_and_unpersonalised_requests_carry_no_adapter() {
    let a = adapter(SMALL);
    for mode in [
        json!({"ephemeral": true, "personalise": false}),
        json!({"ephemeral": false, "personalise": false}),
    ] {
        let r = go(&request(|v| v["mode"] = mode), &facts(), &pool(), Some(&a));
        assert_eq!(r.serve.clone().unwrap().model.adapter_id, None);
        assert!(rules(&r).contains(&EliminationRule::Mode));
    }
}

#[test]
fn mf_38_mf_37_no_consent_or_a_child_profile_carries_no_adapter() {
    let a = adapter(SMALL);
    let no_consent = Facts {
        personal_training_consent: false,
        ..facts()
    };
    let child = Facts {
        child_profile: true,
        ..facts()
    };
    for f in [no_consent, child] {
        let r = go(&request(|_| ()), &f, &pool(), Some(&a));
        assert_eq!(r.serve.clone().unwrap().model.adapter_id, None);
        assert_eq!(rules(&r), vec![EliminationRule::Consent]);
    }
}

#[test]
fn an_adapter_of_another_base_is_never_attached() {
    let a = adapter(OTHER_BASE);
    let r = go(&request(|_| ()), &facts(), &pool(), Some(&a));
    assert_eq!(r.serve.clone().unwrap().model.adapter_id, None);
    assert_eq!(rules(&r), vec![EliminationRule::NotReleased]);
}

#[test]
fn mf_24_sensitive_data_reaches_only_an_attested_tee() {
    let mut p = pool();
    p[0].attested_tee = false;
    p.insert(1, instance(ModelRole::SmallLm, SMALL_2, Family::Default));
    let sensitive = request(|v| {
        v["data_class"] = json!({"kinds": ["personal"], "sensitive": ["health"]});
        v["retention_classes"] = json!(["one_memory", "one_sensitive"]);
    });
    let r = go(&sensitive, &facts(), &p, None);
    let serve = r.serve.clone().unwrap();
    assert_eq!(serve.instance, 1);
    assert_eq!(r.record.memory_part.fallback, Fallback::None);
    assert!(rules(&r).contains(&EliminationRule::DataClass));
    assert_eq!(
        r.record.provider_trace_part.hops[0].attested_tee,
        Some(true)
    );
}

#[test]
fn mf_24_device_only_content_is_refused_and_reaches_no_processor() {
    let r = go(
        &request(|v| v["device_only"] = json!(true)),
        &facts(),
        &pool(),
        None,
    );
    assert_eq!(r.serve, None);
    assert_eq!(r.record.memory_part.gate.result, GateResult::Refused);
    assert!(rules(&r).iter().all(|x| *x == EliminationRule::DataClass));
    assert_eq!(r.record.provider_trace_part.hops, Vec::new());
}

#[test]
fn mf_20_offline_queues_and_an_out_of_scope_task_is_refused() {
    let offline = Facts {
        connectivity: Connectivity::Offline,
        ..facts()
    };
    let r = go(&request(|_| ()), &offline, &pool(), None);
    assert_eq!(r.record.memory_part.gate.result, GateResult::QueuedOffline);
    assert_eq!(r.record.memory_part.fallback, Fallback::None);
    for grant in [Grant::OutOfScope, Grant::Exhausted] {
        let f = Facts { grant, ..facts() };
        let r = go(&request(|_| ()), &f, &pool(), None);
        assert_eq!(r.record.memory_part.gate.result, GateResult::Refused);
        assert!(rules(&r).iter().all(|x| *x == EliminationRule::GrantBudget));
    }
}

#[test]
fn mf_20_another_region_is_refused() {
    let f = Facts {
        region: region("us-east"),
        ..facts()
    };
    let r = go(&request(|_| ()), &f, &pool(), None);
    assert_eq!(r.serve, None);
    assert_eq!(r.record.memory_part.gate.result, GateResult::Refused);
}

#[test]
fn mf_3_no_available_model_waits() {
    let mut p = pool();
    for i in &mut p {
        i.available = false;
    }
    let r = go(&request(|_| ()), &facts(), &p, None);
    assert_eq!(r.serve, None);
    assert_eq!(r.record.memory_part.gate.result, GateResult::WaitingNoModel);
    assert_eq!(r.record.memory_part.fallback, Fallback::Wait);
}

#[test]
fn mf_23_fallback_order_other_instance_then_backup_family_then_wait() {
    let mut p = pool();
    p[1].available = false;
    let r = go(&request(planning), &facts(), &p, None);
    assert_eq!(r.serve.as_ref().unwrap().instance, 2);
    assert_eq!(r.record.memory_part.fallback, Fallback::OtherInstance);
    p[2].available = false;
    let r = go(&request(planning), &facts(), &p, None);
    assert_eq!(
        r.serve.as_ref().unwrap().model.model_version_id,
        id(LARGE_BACKUP)
    );
    assert_eq!(r.record.memory_part.fallback, Fallback::BackupFamily);
    p[3].released = false;
    let r = go(&request(planning), &facts(), &p, None);
    assert_eq!(r.serve, None);
    assert_eq!(r.record.memory_part.fallback, Fallback::Wait);
}

#[test]
fn mf_23_a_large_job_gets_a_labelled_short_answer_only_when_the_small_model_can() {
    let mut p = pool();
    for i in &mut p[1..4] {
        i.available = false;
    }
    let long =
        request(|v| v["hints"] = json!({"task_kind": "long_text", "expected_output_tokens": 2500}));
    let r = go(&long, &facts(), &p, None);
    assert_eq!(r.serve, None);
    let medium =
        request(|v| v["hints"] = json!({"task_kind": "long_text", "expected_output_tokens": 900}));
    let r = go(&medium, &facts(), &p, None);
    let short = r.serve.clone().unwrap();
    assert!(short.short_answer);
    assert_eq!(short.model.model_role, ModelRole::SmallLm);
    let heavy = request(|v| {
        v["capabilities"] = json!(["text_generation", "long_context"]);
        v["hints"] = json!({"expected_output_tokens": 2500});
    });
    let r = go(&heavy, &facts(), &p, None);
    let short = r.serve.clone().unwrap();
    assert!(short.short_answer);
    assert_eq!(r.record.memory_part.fallback, Fallback::SmallShortAnswer);
    let r = go(&request(planning), &facts(), &p, None);
    assert_eq!(r.serve, None);
    assert_eq!(r.record.memory_part.gate.result, GateResult::WaitingNoModel);
}

#[test]
fn mf_11_the_quarantine_purpose_reaches_only_the_quarantine_role() {
    let a = adapter(SMALL);
    let r = route(
        &request(|_| ()),
        Purpose::Quarantine,
        &facts(),
        &pool(),
        &versions(Some(&a)),
        at(),
    )
    .unwrap();
    let serve = r.serve.clone().unwrap();
    assert_eq!(serve.model.model_role, ModelRole::Quarantine);
    assert_eq!(serve.model.adapter_id, None);
    assert_eq!(r.record.memory_part.estimate, None);
}

#[test]
fn sec_26_only_registry_versions_are_loaded_and_only_released_ones_serve() {
    let entry: Value = serde_json::from_str::<Vec<Value>>(
        &std::fs::read_to_string(format!(
            "{}/../../conformance/model/vectors/registry-entry.json",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap(),
    )
    .unwrap()
    .into_iter()
    .find(|v| v["valid"] == true)
    .unwrap()["input"]
        .clone();
    let mut candidate = entry.clone();
    candidate["model_version_id"] = json!(SMALL_2);
    candidate["status"] = json!("candidate");
    candidate["evaluation"] = json!({"gate": "pending"});
    candidate.as_object_mut().unwrap().remove("signature");
    let registry: Registry = serde_json::from_value(json!({"model": [entry, candidate]})).unwrap();
    registry.validate().unwrap();
    let deploy = |v: &str| Deployment {
        version: id(v),
        family: Family::Default,
        region: region("eu-central"),
        attested_tee: true,
        available: true,
    };
    let got = instances(&registry, &[deploy(SMALL), deploy(SMALL_2), deploy(LARGE)]);
    assert_eq!(got.len(), 2);
    assert!(got[0].released);
    assert!(!got[1].released);
    let r = go(&request(|_| ()), &facts(), &got[1..], None);
    assert_eq!(r.record.memory_part.gate.result, GateResult::WaitingNoModel);
}

#[test]
fn mf_21_offered_tools_count_when_there_is_no_tool_count_hint() {
    let tools = |n: usize| {
        request(move |v| {
            v["capabilities"] = json!(["text_generation", "tool_calling"]);
            v["hints"] = json!({});
            v["tools"] = json!(
                ["one", "two", "three", "four", "five", "six", "seven", "eight", "nine"][..n]
                    .iter()
                    .map(|w| json!({"name": format!("app.suiss.test.{w}"), "version": "2026-10-01", "input_schema": {}}))
                    .collect::<Vec<_>>()
            );
        })
    };
    let one = go(&tools(1), &facts(), &pool(), None);
    let many = go(&tools(9), &facts(), &pool(), None);
    let p = |r: &Route| {
        r.record
            .memory_part
            .estimate
            .as_ref()
            .unwrap()
            .small_sufficient
    };
    assert_eq!(p(&one), 0.85);
    assert_eq!(p(&many), 0.65);
}

#[test]
fn mf_23_a_large_kind_never_goes_to_the_small_model_unlabelled() {
    let r = go(
        &request(|v| v["hints"] = json!({"task_kind": "orchestration"})),
        &facts(),
        &pool(),
        None,
    );
    let serve = r.serve.clone().unwrap();
    assert_eq!(serve.model.model_role, ModelRole::LargeLm);
    assert!(!serve.short_answer);
    let p = r
        .record
        .memory_part
        .estimate
        .as_ref()
        .unwrap()
        .small_sufficient;
    assert!(p >= 0.5);
}

#[test]
fn mf_34_mf_48_only_an_adapter_past_its_gates_is_attached() {
    let a = adapter(SMALL);
    let fine = Scores {
        address: 0.95,
        tone: 0.95,
        length: 0.95,
        rules: 0.95,
        bilingual: 0.95,
    };
    let worse = Scores { tone: 0.91, ..fine };
    let short = request(|_| ());
    let attached = |v: &Versions<ActiveAdapter>| {
        route(&short, Purpose::Answer, &facts(), &pool(), v, at())
            .unwrap()
            .serve
            .unwrap()
            .model
            .adapter_id
    };

    let start = Versions::default();
    let failed = start
        .clone()
        .offer(a, Gates::of(&compare(&fine, None), Some(-0.02), Some(true)));
    assert_eq!(failed.outcome, Outcome::Rejected);
    assert_eq!(attached(&failed.versions), None);
    let pending = start
        .clone()
        .offer(a, Gates::of(&compare(&fine, None), None, Some(true)));
    assert_eq!(pending.outcome, Outcome::Rejected);

    let first = start.offer(a, Gates::of(&compare(&fine, None), Some(-0.01), Some(true)));
    assert_eq!(first.outcome, Outcome::Activated);
    assert_eq!(attached(&first.versions), Some(a.id));

    let next = ActiveAdapter {
        id: AdapterId::parse("adp_01m4ezb900fvmv9zra2mg2pdj1").unwrap(),
        base: id(SMALL),
    };
    let regressed = first.versions.clone().offer(
        next,
        Gates::of(&compare(&worse, Some(&fine)), Some(0.0), Some(true)),
    );
    assert_eq!(regressed.outcome, Outcome::Rejected);
    assert_eq!(attached(&regressed.versions), Some(a.id));

    let forgotten = first.versions.forget();
    assert_eq!(forgotten.outcome, Outcome::Retrain);
    assert_eq!(attached(&forgotten.versions), None);
}
