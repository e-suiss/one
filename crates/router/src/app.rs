//! The router's use case (MF-19, MF-21, MF-22, MF-23): gate the request, let the second stage pick the small or the large model among the options that passed, apply the fixed fallback order and write the content-free routing record; a request is never handed to a model the gate eliminated, and a large model's job never silently goes to the small model.

use one_proto::model::request::ModelRequest;
use one_proto::model::roles::{ModelRef, ModelRole};
use one_proto::model::routing::{
    Estimate, EstimatorVersion, Fallback, Gate as GateRecord, GateResult, Hop, MemoryPart,
    OutcomeSignal, Processor, ProviderTracePart, RoutingOutcome, RoutingRecord,
};
use one_proto::ontology::Instant;
use one_proto::ontology::tags::{OneMemoryClass, OneProviderTraceClass};
use one_proto::ontology::validate::ContractViolation;

use crate::domain::adapter::Versions;
use crate::domain::difficulty::{
    ESTIMATOR_VERSION, Signals, short_answer_allowed, small_enough, small_sufficient,
};
use crate::domain::gate::{
    ActiveAdapter, Candidate, Facts, Family, Gated, Instance, Purpose, gate,
};

/// Where the request goes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Serve {
    /// The index of the chosen instance.
    pub instance: usize,
    /// The role, version and adapter that serve it.
    pub model: ModelRef,
    /// The small model answers a large model's job and the answer is labelled "short answer".
    pub short_answer: bool,
}

/// The routing decision.
#[derive(Debug, Clone, PartialEq)]
pub struct Route {
    /// The record kept for the decision.
    pub record: RoutingRecord,
    /// Where the request goes; `None` when it is refused, queued or waiting.
    pub serve: Option<Serve>,
}

enum Target {
    Role(ModelRole, Option<f64>),
    Short,
    Wait,
}

fn target(request: &ModelRequest, purpose: Purpose, instances: &[Instance], g: &Gated) -> Target {
    let has = |role| {
        g.passed
            .iter()
            .any(|c| instances.get(c.instance).is_some_and(|i| i.role == role))
    };
    let (small, large) = (has(ModelRole::SmallLm), has(ModelRole::LargeLm));
    if purpose != Purpose::Answer || !(small || large) {
        let role = g
            .passed
            .first()
            .and_then(|c| instances.get(c.instance))
            .map_or(ModelRole::SmallLm, |i| i.role);
        return Target::Role(role, None);
    }
    let signals = Signals::of(request);
    let p = small_sufficient(&signals);
    match (small, large) {
        (true, true) if small_enough(&signals, p) => Target::Role(ModelRole::SmallLm, Some(p)),
        (true, true) => Target::Role(ModelRole::LargeLm, Some(p)),
        (true, false) if small_enough(&signals, p) => Target::Role(ModelRole::SmallLm, None),
        (true, false) if short_answer_allowed(&signals, p) => Target::Short,
        (true, false) => Target::Wait,
        _ => Target::Role(ModelRole::LargeLm, None),
    }
}

fn pick(role: ModelRole, instances: &[Instance], passed: &[Candidate]) -> Option<Candidate> {
    passed
        .iter()
        .filter(|c| instances.get(c.instance).is_some_and(|i| i.role == role))
        .min_by_key(|c| {
            let backup = instances
                .get(c.instance)
                .is_some_and(|i| i.family == Family::Backup);
            (backup, c.adapter.is_none(), c.instance)
        })
        .copied()
}

fn fallback(chosen: Candidate, facts: &Facts, instances: &[Instance], short: bool) -> Fallback {
    let Some(at) = instances.get(chosen.instance) else {
        return Fallback::None;
    };
    if short {
        return Fallback::SmallShortAnswer;
    }
    if at.family == Family::Backup {
        return Fallback::BackupFamily;
    }
    let primary = instances.iter().enumerate().find(|(_, i)| {
        i.role == at.role && i.family == Family::Default && i.region == facts.region
    });
    match primary {
        Some((index, i)) if index != chosen.instance && !i.available => Fallback::OtherInstance,
        _ => Fallback::None,
    }
}

/// Routes `request` for `purpose` over `instances`, attaching the active version of `adapters` (the one that passed its activation gates) only where the gate allows it, and records the decision at `at`; another instance counts as a fallback only when the primary one does not answer (MF-23).
///
/// # Errors
/// [`ContractViolation`] when the request or the record breaks its contract.
pub fn route(
    request: &ModelRequest,
    purpose: Purpose,
    facts: &Facts,
    instances: &[Instance],
    adapters: &Versions<ActiveAdapter>,
    at: Instant,
) -> Result<Route, ContractViolation> {
    request.validate()?;
    let g = gate(request, purpose, facts, instances, adapters.active.as_ref());
    let mut result = g.result;
    let mut estimate = None;
    let mut serve = None;
    let mut fallback_taken = if result == GateResult::WaitingNoModel {
        Fallback::Wait
    } else {
        Fallback::None
    };
    if result == GateResult::Passed {
        let (role, short) = match target(request, purpose, instances, &g) {
            Target::Role(role, p) => {
                estimate = p;
                (Some(role), false)
            }
            Target::Short => (Some(ModelRole::SmallLm), true),
            Target::Wait => (None, false),
        };
        if let Some(chosen) = role.and_then(|r| pick(r, instances, &g.passed)) {
            fallback_taken = fallback(chosen, facts, instances, short);
            serve = instances.get(chosen.instance).map(|i| Serve {
                instance: chosen.instance,
                model: ModelRef {
                    model_role: i.role,
                    model_version_id: i.version,
                    adapter_id: chosen.adapter,
                },
                short_answer: short,
            });
        } else {
            result = GateResult::WaitingNoModel;
            fallback_taken = Fallback::Wait;
        }
    }
    let hops = serve
        .as_ref()
        .and_then(|s| instances.get(s.instance))
        .map(|i| Hop {
            processor: Processor::SuissModelServing,
            region: i.region.clone(),
            sub_processor: None,
            attested_tee: Some(i.attested_tee),
            data_class: request.data_class.clone(),
        })
        .into_iter()
        .collect();
    let estimate = estimate
        .map(|p| {
            EstimatorVersion::parse(ESTIMATOR_VERSION).map(|v| Estimate {
                small_sufficient: p,
                estimator_version: v,
            })
        })
        .transpose()?;
    let record = RoutingRecord {
        request_id: request.request_id,
        recorded_at: at,
        memory_part: MemoryPart {
            retention_class: OneMemoryClass,
            data_class: request.data_class.clone(),
            retention_classes: request.retention_classes.clone(),
            device_only: request.device_only,
            gate: GateRecord {
                result,
                eliminated: g.eliminated,
            },
            chosen: serve.as_ref().map(|s| s.model.clone()),
            estimate,
            fallback: fallback_taken,
            outcome: RoutingOutcome {
                signal: OutcomeSignal::Pending,
                at: None,
            },
        },
        provider_trace_part: ProviderTracePart {
            retention_class: OneProviderTraceClass,
            hops,
        },
    };
    record.validate()?;
    Ok(Route { record, serve })
}
