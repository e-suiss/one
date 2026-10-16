//! The task record: One's single-person work record with the C-19 header; the task state is never a field (CP-1, CP-2, CP-4, CP-9, CP-43, C-19, C-20, SEC-14, SEC-19).

use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::common::{ExecutorEvidence, SnakeName, check_header, checked_record, wire_enum};
use super::outcome::{StepResult, StepStatus};
use crate::capability::CapabilityRef;
use crate::data_class::DataClass;
use crate::data_class::Domain;
use crate::data_class::RetentionClass;
use crate::id::{GoalId, InteractionId, RoutineId, TaskId};
use crate::money::Money;
use crate::ontology::ActionRef;
use crate::ontology::CheckpointRef;
use crate::ontology::CommitmentRef;
use crate::ontology::ExerciseRef;
use crate::ontology::InstanceRef;
use crate::ontology::Instant;
use crate::ontology::JsonValue;
use crate::ontology::MandateRef;
use crate::ontology::PartyRef;
use crate::ontology::ProducedBy;
use crate::ontology::ProvenanceLabel;
use crate::ontology::RecordStatus;
use crate::ontology::TriggerRef;
use crate::ontology::WaitpointRef;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

pub(crate) fn is_step_id(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && text.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-'))
}

fn is_idempotency_key(text: &str) -> bool {
    (16..=128).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn is_route_reason(text: &str) -> bool {
    (1..=256).contains(&text.chars().count())
}

fn is_statement(text: &str) -> bool {
    (1..=512).contains(&text.chars().count())
}

fn is_origin(text: &str) -> bool {
    let Some(host_port) = text.strip_prefix("https://") else {
        return false;
    };
    if text.len() > 262 {
        return false;
    }
    let (host, port) = match host_port.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (host_port, None),
    };
    let port_ok = port.is_none_or(|p| {
        (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()) && !p.starts_with('0')
    });
    let label_ok = |l: &str| {
        let b = l.as_bytes();
        let edge = |c: Option<&u8>| c.is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit());
        (1..=63).contains(&b.len())
            && edge(b.first())
            && edge(b.last())
            && b.iter()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
    };
    let labels: Vec<&str> = host.split('.').collect();
    port_ok && labels.len() >= 2 && labels.iter().all(|l| label_ok(l))
}

crate::ontology::validate::checked_string!(
    /// A plan step identifier, unique within one task.
    StepId,
    "step identifier",
    is_step_id
);
crate::ontology::validate::checked_string!(
    /// The idempotency key of an effectful step (CP-43).
    IdempotencyKey,
    "idempotency key",
    is_idempotency_key
);
crate::ontology::validate::checked_string!(
    /// Why a route was chosen.
    RouteReason,
    "route reason",
    is_route_reason
);
crate::ontology::validate::checked_string!(
    /// The completion statement.
    CriterionStatement,
    "completion statement",
    is_statement
);
crate::ontology::validate::checked_string!(
    /// An `https` origin.
    Origin,
    "https origin",
    is_origin
);

fn check_origins(value: &OriginSet) -> Result<(), ContractViolation> {
    let ok = |list: &[Origin]| list.len() <= 64 && unique(list);
    require(ok(&value.read) && ok(&value.write), "origin set")
}

checked_record!(
    /// The per-task read and write origin set (SEC-19).
    #[derive(Eq)]
    pub struct OriginSet via OriginSetWire = "OriginSetWire", check check_origins {
        /// Origins the task may read.
        pub read: Vec<Origin>,
        /// Origins the task may write.
        pub write: Vec<Origin>,
    }
);

/// Why the task exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "source", rename_all = "snake_case", deny_unknown_fields)]
pub enum Purpose {
    /// The user asked.
    UserRequest {
        /// The request interaction.
        #[serde(rename = "ref")]
        interaction: InteractionId,
        /// The goal the task serves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        serves_goal_id: Option<GoalId>,
    },
    /// A trigger fired.
    Trigger {
        /// The trigger.
        #[serde(rename = "ref")]
        trigger: TriggerRef,
        /// The goal the task serves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        serves_goal_id: Option<GoalId>,
    },
    /// The user accepted a routine suggestion.
    RoutineSuggestion {
        /// The routine.
        #[serde(rename = "ref")]
        routine: RoutineId,
        /// The goal the task serves.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        serves_goal_id: Option<GoalId>,
    },
}

/// A step input with its provenance label (SEC-14).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TypedInput {
    /// The input name.
    pub name: SnakeName,
    /// The value.
    pub value: JsonValue,
    /// Where the value came from.
    pub provenance: ProvenanceLabel,
}

wire_enum!(
    /// The state of a plan step.
    StepState {
        /// Planned.
        Planned = "planned",
        /// Running.
        Running = "running",
        /// Done.
        Done = "done",
        /// Failed.
        Failed = "failed",
        /// Not run.
        NotRun = "not_run",
        /// Unknown.
        Unknown = "unknown",
    }
);

impl StepState {
    /// The result status this state needs, when it needs a result.
    #[must_use]
    pub const fn result_status(self) -> Option<StepStatus> {
        match self {
            Self::Planned | Self::Running => None,
            Self::Done => Some(StepStatus::Done),
            Self::Failed => Some(StepStatus::Failed),
            Self::NotRun => Some(StepStatus::NotRun),
            Self::Unknown => Some(StepStatus::Unknown),
        }
    }
}

wire_enum!(
    /// The execution path of a step.
    RoutePath {
        /// A provider API.
        Api = "api",
        /// An MCP server.
        Mcp = "mcp",
        /// A commerce protocol.
        CommerceProtocol = "commerce_protocol",
        /// An OS intent.
        OsIntent = "os_intent",
        /// The cloud browser.
        CloudBrowser = "cloud_browser",
        /// Handed to the user.
        Handoff = "handoff",
    }
);

wire_enum!(
    /// Where a step runs.
    RouteLocation {
        /// The cloud Executor.
        CloudExecutor = "cloud_executor",
        /// A cloud microVM.
        CloudMicrovm = "cloud_microvm",
        /// The local Executor.
        LocalExecutor = "local_executor",
        /// The user.
        User = "user",
    }
);

/// The chosen route of a step (CP-9).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    /// The path.
    pub path: RoutePath,
    /// The location.
    pub location: RouteLocation,
    /// Why.
    pub reason: RouteReason,
}

fn check_step(step: &Step) -> Result<(), ContractViolation> {
    match (step.state.result_status(), &step.result) {
        (None, None) => {}
        (Some(wanted), Some(result)) => {
            require(result.status() == wanted, "step state matches its result")?;
        }
        _ => return Err(ContractViolation("step result presence follows its state")),
    }
    if step.effectful {
        require(
            step.idempotency_key.is_some(),
            "effectful step needs an idempotency key",
        )?;
        if matches!(
            step.state,
            StepState::Done | StepState::Failed | StepState::Unknown
        ) {
            require(
                step.exercise_ref.is_some(),
                "executed effectful step needs an ExerciseRef",
            )?;
        }
    }
    if step
        .route
        .as_ref()
        .is_some_and(|r| r.path == RoutePath::CloudBrowser)
    {
        require(
            step.origin_set.is_some(),
            "cloud browser route needs an origin set",
        )?;
    }
    Ok(())
}

checked_record!(
    /// One plan step.
    pub struct Step via StepWire = "StepWire", check check_step {
        /// The step identifier.
        pub id: StepId,
        /// The capability.
        pub capability: CapabilityRef,
        /// The action.
        pub action: ActionRef,
        /// Whether the step changes the world.
        pub effectful: bool,
        /// Labelled inputs.
        pub inputs: Vec<TypedInput>,
        /// The step state.
        pub state: StepState,
        /// The result, once the step is over.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub result: Option<StepResult>,
        /// The Access Exercise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub exercise_ref: Option<ExerciseRef>,
        /// The idempotency key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub idempotency_key: Option<IdempotencyKey>,
        /// The route.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub route: Option<Route>,
        /// The origin set.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub origin_set: Option<OriginSet>,
    }
);

fn check_plan(plan: &Plan) -> Result<(), ContractViolation> {
    require(!plan.steps.is_empty(), "plan has at least one step")
}

checked_record!(
    /// The plan.
    pub struct Plan via PlanWire = "PlanWire", check check_plan {
        /// The plan version.
        pub version: NonZeroU32,
        /// The steps in order.
        pub steps: Vec<Step>,
    }
);

wire_enum!(
    /// How completion is checked.
    CompletionCheck {
        /// An Executor claim.
        ExecutorClaim = "executor_claim",
        /// A record reference.
        RecordReference = "record_reference",
        /// An external confirmation.
        ExternalConfirmation = "external_confirmation",
        /// The user confirms.
        UserConfirmation = "user_confirmation",
    }
);

/// The verifiable completion criterion.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompletionCriterion {
    /// What completion means.
    pub statement: CriterionStatement,
    /// How it is checked.
    pub check: CompletionCheck,
    /// The evidence, once verified.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evidence_ref: Option<ExecutorEvidence>,
}

fn check_authority(value: &Authority) -> Result<(), ContractViolation> {
    require(unique(&value.mandate_refs), "mandate references are unique")
}

checked_record!(
    /// The authority bond.
    #[derive(Eq)]
    pub struct Authority via AuthorityWire = "AuthorityWire", check check_authority {
        /// The bound Mandates.
        pub mandate_refs: Vec<MandateRef>,
        /// The trigger, for a trigger-sourced task.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub trigger_ref: Option<TriggerRef>,
    }
);

/// The step budget as the Mandate sets it, as the task requests it and as it applies (CP-4, CP-36).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StepBudget {
    /// The Mandate's step budget.
    #[serde(deserialize_with = "Option::deserialize")]
    pub mandate: Option<NonZeroU32>,
    /// The task's requested budget.
    #[serde(deserialize_with = "Option::deserialize")]
    pub requested: Option<NonZeroU32>,
    /// The narrower of the two.
    pub effective: NonZeroU32,
}

/// The amount budget, with the same three fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AmountBudget {
    /// The Mandate's amount.
    #[serde(deserialize_with = "Option::deserialize")]
    pub mandate: Option<Money>,
    /// The task's requested amount.
    #[serde(deserialize_with = "Option::deserialize")]
    pub requested: Option<Money>,
    /// The narrower of the two.
    pub effective: Money,
}

/// The task budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// Steps.
    pub steps: StepBudget,
    /// Amount.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<AmountBudget>,
}

wire_enum!(
    /// The record type discriminator of a task.
    TaskType {
        /// A task.
        Task = "Task",
    }
);

fn check_task(task: &Task) -> Result<(), ContractViolation> {
    check_header(
        task.version,
        task.supersedes.is_some(),
        task.status,
        task.deleted_at.as_ref(),
        &task.data_class,
        task.retention_class,
    )?;
    task.domain.check()?;
    task.produced_by.check()?;
    if matches!(task.purpose, Purpose::Trigger { .. }) {
        require(
            task.authority.trigger_ref.is_some(),
            "trigger-sourced task names its trigger",
        )?;
    }
    if task.plan.steps.iter().any(|s| s.effectful) {
        require(
            !task.authority.mandate_refs.is_empty(),
            "effectful plan needs a bound Mandate",
        )?;
    }
    require(unique(&task.waits), "waitpoints are unique")?;
    require(unique(&task.sub_agents), "sub-agents are unique")
}

checked_record!(
    /// One's single-person work record (CP-4). The task state is derived from its events, never stored (CP-3).
    pub struct Task via TaskWire = "TaskWire", check check_task {
        /// The record type.
        #[serde(rename = "type")]
        pub record_type: TaskType,
        /// The task identifier.
        pub id: TaskId,
        /// The owner.
        pub owner: PartyRef,
        /// Life areas and project.
        pub domain: Domain,
        /// The data class.
        pub data_class: DataClass,
        /// The retention class.
        pub retention_class: RetentionClass,
        /// The record's provenance.
        pub provenance: ProvenanceLabel,
        /// When the record was written.
        pub recorded_at: Instant,
        /// The record version.
        pub version: NonZeroU32,
        /// The version this one supersedes.
        #[serde(deserialize_with = "Option::deserialize")]
        pub supersedes: Option<TaskId>,
        /// Record lifecycle, not the task state.
        pub status: RecordStatus,
        /// When the record was deleted.
        #[serde(deserialize_with = "Option::deserialize")]
        pub deleted_at: Option<Instant>,
        /// Who produced the record.
        pub produced_by: ProducedBy,
        /// Why the task exists.
        pub purpose: Purpose,
        /// The plan.
        pub plan: Plan,
        /// The completion criterion.
        pub completion_criterion: CompletionCriterion,
        /// The authority bond.
        pub authority: Authority,
        /// Open Relay waitpoints.
        pub waits: Vec<WaitpointRef>,
        /// The last checkpoint.
        #[serde(deserialize_with = "Option::deserialize")]
        pub checkpoint_ref: Option<CheckpointRef>,
        /// The budget.
        pub budget: Budget,
        /// Sub-agent Instances.
        pub sub_agents: Vec<InstanceRef>,
        /// The Work commitment the task prepares.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub commitment_ref: Option<CommitmentRef>,
    }
);
