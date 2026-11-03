//! The first-stage rule gate (MF-19, MF-20, MF-24): every serving option is checked against mode, data class, consent, Grant and budget, connectivity, region, release and availability in that fixed order; an option fails on the first rule that holds, is recorded with it, and never reaches the second stage.

use one_proto::model::request::{ModelRequest, RequiredCapability};
use one_proto::model::roles::ModelRole;
use one_proto::model::routing::{Elimination, EliminationRule, GateResult, Region, RoutingOption};
use one_proto::{AdapterId, ModelVersionId};

/// Which family of a role an instance belongs to (MF-9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
    /// The default family.
    Default,
    /// The backup family, served only once it passed the release gate.
    Backup,
}

/// One serving instance as the router sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    /// The role it serves.
    pub role: ModelRole,
    /// The exact model version.
    pub version: ModelVersionId,
    /// Its family.
    pub family: Family,
    /// Its serving region.
    pub region: Region,
    /// It runs inside an attested TEE.
    pub attested_tee: bool,
    /// The registry lists the version as released, signed and passed (MF-52, SEC-26).
    pub released: bool,
    /// It answers now.
    pub available: bool,
}

/// The user's active personal adapter and the small model version it was trained on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ActiveAdapter {
    /// The adapter.
    pub id: AdapterId,
    /// The base version it belongs to.
    pub base: ModelVersionId,
}

/// The Access Grant standing of the task behind a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Grant {
    /// The request serves no task.
    NoTask,
    /// The task is within its Grant and budget.
    Within,
    /// The task is outside its Grant or Mandate.
    OutOfScope,
    /// The Mandate's step or cost budget is spent.
    Exhausted,
}

/// Whether the cloud can be reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Connectivity {
    /// Online.
    Online,
    /// Offline: language work is queued.
    Offline,
}

/// What the gate knows about the user beyond the request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Facts {
    /// The user's region.
    pub region: Region,
    /// Connectivity.
    pub connectivity: Connectivity,
    /// The Grant standing.
    pub grant: Grant,
    /// The personal model training consent switch (MF-38).
    pub personal_training_consent: bool,
    /// A child profile carries no adapter (MF-37).
    pub child_profile: bool,
}

/// What the request is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Purpose {
    /// An answer, an embedding or a speech job, by its capabilities.
    Answer,
    /// The quarantine instance (MF-11).
    Quarantine,
    /// The auditor instance (T-9).
    Auditor,
}

/// An option that passed the gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Candidate {
    /// The index of the instance.
    pub instance: usize,
    /// The adapter attached, small model answers only.
    pub adapter: Option<AdapterId>,
}

/// The gate's outcome.
#[derive(Debug, Clone, PartialEq)]
pub struct Gated {
    /// The options that passed, in instance order, the adapter option first.
    pub passed: Vec<Candidate>,
    /// Every eliminated option with its rule, without repeats.
    pub eliminated: Vec<Elimination>,
    /// The result; `passed` exactly when an option passed.
    pub result: GateResult,
}

/// The roles that may serve `request` for `purpose`.
#[must_use]
pub fn roles(request: &ModelRequest, purpose: Purpose) -> &'static [ModelRole] {
    let has = |c| request.capabilities.contains(&c);
    match purpose {
        Purpose::Quarantine => &[ModelRole::Quarantine],
        Purpose::Auditor => &[ModelRole::SmallLm],
        Purpose::Answer if has(RequiredCapability::Embedding) => &[ModelRole::Embedding],
        Purpose::Answer if has(RequiredCapability::SpeechRecognition) => {
            &[ModelRole::SpeechRecognition]
        }
        Purpose::Answer if has(RequiredCapability::SpeechSynthesis) => {
            &[ModelRole::SpeechSynthesis]
        }
        Purpose::Answer => &[ModelRole::SmallLm, ModelRole::LargeLm],
    }
}

fn rule(
    request: &ModelRequest,
    facts: &Facts,
    instance: &Instance,
    adapter: Option<&ActiveAdapter>,
) -> Option<EliminationRule> {
    let mode = request.mode;
    if adapter.is_some() && (mode.ephemeral || !mode.personalise) {
        return Some(EliminationRule::Mode);
    }
    if request.is_device_only() || (request.data_class.is_sensitive() && !instance.attested_tee) {
        return Some(EliminationRule::DataClass);
    }
    if adapter.is_some() && (!facts.personal_training_consent || facts.child_profile) {
        return Some(EliminationRule::Consent);
    }
    if matches!(facts.grant, Grant::OutOfScope | Grant::Exhausted) {
        return Some(EliminationRule::GrantBudget);
    }
    if facts.connectivity == Connectivity::Offline {
        return Some(EliminationRule::Connectivity);
    }
    if instance.region != facts.region {
        return Some(EliminationRule::Region);
    }
    if !instance.released || adapter.is_some_and(|a| a.base != instance.version) {
        return Some(EliminationRule::NotReleased);
    }
    if !instance.available {
        return Some(EliminationRule::Unavailable);
    }
    None
}

/// Runs the gate over every option of `instances` that can serve `request` for `purpose`.
#[must_use]
pub fn gate(
    request: &ModelRequest,
    purpose: Purpose,
    facts: &Facts,
    instances: &[Instance],
    adapter: Option<&ActiveAdapter>,
) -> Gated {
    let roles = roles(request, purpose);
    let mut passed = Vec::new();
    let mut eliminated: Vec<Elimination> = Vec::new();
    let mut considered = false;
    for (index, instance) in instances.iter().enumerate() {
        if !roles.contains(&instance.role) {
            continue;
        }
        considered = true;
        let adapter_option = (purpose == Purpose::Answer && instance.role == ModelRole::SmallLm)
            .then_some(adapter)
            .flatten();
        for with in adapter_option.into_iter().map(Some).chain([None]) {
            match rule(request, facts, instance, with) {
                None => passed.push(Candidate {
                    instance: index,
                    adapter: with.map(|a| a.id),
                }),
                Some(rule) => {
                    let e = Elimination {
                        option: RoutingOption {
                            model_role: instance.role,
                            model_version_id: Some(instance.version),
                            with_adapter: Some(with.is_some()),
                        },
                        rule,
                    };
                    if !eliminated.contains(&e) {
                        eliminated.push(e);
                    }
                }
            }
        }
    }
    let result = result(!passed.is_empty(), considered, &eliminated);
    Gated {
        passed,
        eliminated,
        result,
    }
}

fn result(passed: bool, considered: bool, eliminated: &[Elimination]) -> GateResult {
    let any = |r: &[EliminationRule]| eliminated.iter().any(|e| r.contains(&e.rule));
    if passed {
        GateResult::Passed
    } else if any(&[EliminationRule::Connectivity]) {
        GateResult::QueuedOffline
    } else if !considered || any(&[EliminationRule::NotReleased, EliminationRule::Unavailable]) {
        GateResult::WaitingNoModel
    } else {
        GateResult::Refused
    }
}
