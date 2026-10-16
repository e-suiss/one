//! The attention decision record: input summary, policy version and thresholds, calibrated value probability, chosen arm with its selection probability, hard constraints, the Relay request and the outcome signal; kept in `one_memory` without content (AT-1, AT-4, AT-24).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use super::catalog::{OneRelayClass, Timing};
use crate::capability::CapabilityName;
use crate::id::{AttentionDecisionId, ModelVersionId, TaskId};
use crate::interaction_types::Interruption;
use crate::model::common::is_snake_word;
use crate::ontology::Instant;
use crate::ontology::tags::OneMemoryClass;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

/// A probability in `[0, 1]`.
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct Probability(f64);

impl Probability {
    /// The value.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Probability {
    type Error = ContractViolation;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if (0.0..=1.0).contains(&value) {
            Ok(Self(value))
        } else {
            Err(ContractViolation("probability outside [0, 1]"))
        }
    }
}

impl From<Probability> for f64 {
    fn from(value: Probability) -> Self {
        value.0
    }
}

/// The selection probability of the chosen arm, in `(0, 1]`; a forced decision has [`Propensity::FORCED`] (AT-24).
#[derive(Clone, Copy, Debug, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "f64", into = "f64")]
pub struct Propensity(f64);

impl Propensity {
    /// The propensity of a decision no policy could have made otherwise.
    pub const FORCED: Self = Self(1.0);

    /// The value.
    #[must_use]
    pub const fn get(self) -> f64 {
        self.0
    }
}

impl TryFrom<f64> for Propensity {
    type Error = ContractViolation;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        if value > 0.0 && value <= 1.0 {
            Ok(Self(value))
        } else {
            Err(ContractViolation("propensity outside (0, 1]"))
        }
    }
}

impl From<Propensity> for f64 {
    fn from(value: Propensity) -> Self {
        value.0
    }
}

/// The five decision arms (AT-1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Arm {
    /// Interrupt now.
    InterruptNow,
    /// At the next break.
    NextBreak,
    /// Into the daily digest.
    Digest,
    /// Saved quietly.
    SaveQuietly,
    /// Discarded; the decision itself is recorded.
    Discard,
}

impl Arm {
    /// True for the arms that notify through Relay.
    #[must_use]
    pub const fn notifies(self) -> bool {
        matches!(self, Self::InterruptNow | Self::NextBreak)
    }
}

checked_string!(
    /// An output type name under `app.suiss.one.output`.
    OutputTypeName,
    "output type name",
    |s| s.strip_prefix("app.suiss.one.output.").is_some_and(|rest| {
        rest.split_once('.')
            .is_some_and(|(a, b)| is_snake_word(a) && is_snake_word(b))
    })
);

/// Where a candidate comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    /// An external event.
    ExternalEvent,
    /// A suggestion.
    Suggestion,
    /// Prepared work.
    PreparedWork,
    /// An approval request.
    ApprovalRequest,
    /// Another app's notification.
    OtherAppNotification,
    /// A process update.
    ProcessUpdate,
}

/// The candidate output.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// The output type.
    pub output_type: OutputTypeName,
    /// The capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability: Option<CapabilityName>,
    /// The task.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<TaskId>,
    /// The source.
    pub source: Source,
    /// It needs action now.
    pub urgent: bool,
    /// The user's critical Grant covers it.
    pub critical_grant: bool,
    /// It touches a special category.
    pub sensitive: bool,
}

/// The device lock state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Lock {
    /// Locked.
    Locked,
    /// Unlocked.
    Unlocked,
    /// Unknown.
    Unknown,
}

/// The focus state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Focus {
    /// On.
    On,
    /// Off.
    Off,
    /// Unknown.
    Unknown,
}

/// The headphone state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Headphones {
    /// Connected.
    Connected,
    /// Disconnected.
    Disconnected,
    /// Unknown.
    Unknown,
}

/// The wearable state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Wearable {
    /// Worn.
    Worn,
    /// Not worn.
    NotWorn,
    /// Unknown.
    Unknown,
}

/// The device state summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Device {
    /// Lock.
    pub lock: Lock,
    /// Focus.
    pub focus: Focus,
    /// Headphones.
    pub headphones: Headphones,
    /// Wearable.
    pub wearable: Wearable,
    /// At a natural break.
    pub at_break: bool,
}

/// The activity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Activity {
    /// Still.
    Still,
    /// Walking.
    Walking,
    /// Running.
    Running,
    /// Cycling.
    Cycling,
    /// In a vehicle.
    InVehicle,
    /// Unknown.
    Unknown,
}

/// The sender's relation to the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SenderRelation {
    /// The user.
    #[serde(rename = "self")]
    Myself,
    /// One.
    One,
    /// Unrecognised.
    Unrecognised,
    /// Recognised.
    Recognised,
    /// Verified.
    Verified,
    /// Trusted.
    Trusted,
    /// An organisation.
    Organisation,
    /// Unknown.
    Unknown,
}

/// The content-free input summary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(clippy::struct_excessive_bools, reason = "mirrors the contract")]
pub struct InputSummary {
    /// Local hour 0–23.
    pub local_hour: u8,
    /// ISO weekday 1–7.
    pub weekday: u8,
    /// Device state.
    pub device: Device,
    /// The calendar is busy.
    pub calendar_busy: bool,
    /// Activity.
    pub activity: Activity,
    /// Sender relation.
    pub sender_relation: SenderRelation,
    /// Inside quiet hours.
    pub quiet_hours: bool,
    /// The type is muted.
    pub type_muted: bool,
    /// The type is in its rest period (AT-23).
    pub in_rest_period: bool,
    /// Interruptions so far today.
    pub interruptions_today: u32,
    /// Remaining daily budget 0–10.
    pub budget_remaining: u8,
    /// Seconds since the last interruption.
    #[serde(deserialize_with = "Option::deserialize")]
    pub seconds_since_last_interruption: Option<u64>,
    /// Seconds since the last output of the same type.
    #[serde(deserialize_with = "Option::deserialize")]
    pub seconds_since_last_same_type: Option<u64>,
}

/// The two thresholds of the decision head, per person and channel (AT-1, AT-2).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Thresholds {
    /// Below it: no notification.
    pub lower: Probability,
    /// At or above it: notify.
    pub upper: Probability,
}

checked_string!(
    /// A policy version.
    PolicyVersion,
    "policy_version",
    |s| {
        let mut chars = s.chars();
        chars
            .next()
            .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
            && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
    }
);

/// The policy that decided.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    /// The policy version.
    pub policy_version: PolicyVersion,
    /// The decision head model version.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version_id: Option<ModelVersionId>,
    /// The thresholds.
    pub thresholds: Thresholds,
}

/// The cloud value estimate (AT-2).
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudEstimate {
    /// It was requested.
    pub requested: bool,
    /// The cloud answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available: Option<bool>,
    /// The estimate.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Probability>,
}

impl CloudEstimate {
    fn validate(&self) -> Result<(), ContractViolation> {
        match (self.requested, self.available, self.value) {
            (false, None, None) | (true, Some(false), None) | (true, Some(true), Some(_)) => Ok(()),
            _ => Err(ContractViolation("cloud_estimate members")),
        }
    }
}

/// Probabilities of the arms the policy could choose.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArmProbabilities {
    /// Interrupt now.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interrupt_now: Option<Probability>,
    /// Next break.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_break: Option<Probability>,
    /// Digest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub digest: Option<Probability>,
    /// Save quietly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub save_quietly: Option<Probability>,
    /// Discard.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub discard: Option<Probability>,
}

/// Exploration state (AT-26).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Exploration {
    /// The user consented to exploration.
    pub allowed: bool,
    /// This decision explored.
    pub explored: bool,
}

/// A hard constraint that applied (AT-8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Constraint {
    /// Quiet hours.
    QuietHours,
    /// Focus.
    Focus,
    /// The type is muted.
    TypeMuted,
    /// The daily budget is spent.
    DailyBudget,
    /// The rest period of the type.
    RestPeriod,
    /// The output expired.
    Expired,
    /// The cloud was offline.
    OfflineCloud,
}

/// The request One sends to Relay for a notifying arm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayRequest {
    /// The Relay class.
    pub relay_class: OneRelayClass,
    /// The level.
    pub interruption: Interruption,
    /// The timing.
    pub timing: Timing,
    /// The longest deferral in seconds, `next_break` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_defer_s: Option<u64>,
    /// When the output stops being worth showing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<Instant>,
    /// Lock screen and voice show only neutral text (AT-13).
    pub sensitive: bool,
}

impl RelayRequest {
    fn validate(&self) -> Result<(), ContractViolation> {
        require(
            (self.timing == Timing::NextBreak) == self.max_defer_s.is_some(),
            "max_defer_s exactly on next_break",
        )?;
        require(self.max_defer_s != Some(0), "max_defer_s")?;
        require(
            self.interruption != Interruption::Critical || self.timing == Timing::Immediate,
            "critical is immediate",
        )
    }
}

/// A written reward signal (AT-21); open, click and session time are absent (AT-22).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Signal {
    /// Not yet known.
    Pending,
    /// Accepted and completed.
    Completed,
    /// Marked useful.
    Useful,
    /// "Not now".
    NotNow,
    /// Muted.
    Muted,
    /// Wrong action or undo.
    WrongActionOrUndo,
    /// "Why did you tell me late?"
    ToldLate,
    /// No signal.
    None,
}

/// The decision outcome.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionOutcome {
    /// The signal.
    pub signal: Signal,
    /// When it was observed; absent while pending.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<Instant>,
}

/// An attention decision record (AT-4, AT-24).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionRecord {
    /// The decision.
    pub decision_id: AttentionDecisionId,
    /// When it was decided.
    pub decided_at: Instant,
    /// Always `one_memory`.
    pub retention_class: OneMemoryClass,
    /// The candidate.
    pub candidate: Candidate,
    /// The input summary.
    pub input_summary: InputSummary,
    /// The policy.
    pub policy: Policy,
    /// The calibrated value probability.
    pub value_probability: Probability,
    /// The cloud estimate.
    pub cloud_estimate: CloudEstimate,
    /// The chosen arm.
    pub chosen_arm: Arm,
    /// The selection probability of the chosen arm.
    pub propensity: Propensity,
    /// The arm probabilities.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arm_probabilities: Option<ArmProbabilities>,
    /// Exploration.
    pub exploration: Exploration,
    /// The hard constraints that applied.
    pub constraints: Vec<Constraint>,
    /// The Relay request, notifying arms only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<RelayRequest>,
    /// The outcome.
    pub outcome: DecisionOutcome,
}

impl DecisionRecord {
    /// Checks the cross-member rules of the decision record contract.
    ///
    /// # Errors
    /// Rejects a record that breaks a rule of `decision-record.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let summary = &self.input_summary;
        let candidate = &self.candidate;
        require(summary.local_hour <= 23, "local_hour")?;
        require((1..=7).contains(&summary.weekday), "weekday")?;
        require(summary.budget_remaining <= 10, "budget_remaining")?;
        require(unique(&self.constraints), "constraints repeated")?;
        self.cloud_estimate.validate()?;
        if let Some(arms) = &self.arm_probabilities {
            require(
                arms.interrupt_now.is_some()
                    || arms.next_break.is_some()
                    || arms.digest.is_some()
                    || arms.save_quietly.is_some()
                    || arms.discard.is_some(),
                "arm_probabilities empty",
            )?;
        }
        require(
            (self.outcome.signal == Signal::Pending) != self.outcome.at.is_some(),
            "outcome at exactly when not pending",
        )?;
        let notifies = self.chosen_arm.notifies();
        require(
            notifies == self.relay.is_some(),
            "relay exactly for notifying arms",
        )?;
        let critical = self
            .relay
            .as_ref()
            .is_some_and(|r| r.interruption == Interruption::Critical);
        if let Some(relay) = &self.relay {
            relay.validate()?;
            let timing = match self.chosen_arm {
                Arm::InterruptNow => Timing::Immediate,
                _ => Timing::NextBreak,
            };
            require(relay.timing == timing, "relay timing follows the arm")?;
            require(
                summary.budget_remaining > 0
                    || matches!(
                        relay.interruption,
                        Interruption::Passive | Interruption::Critical
                    ),
                "spent budget allows only passive or critical",
            )?;
            require(
                !candidate.sensitive || relay.sensitive,
                "sensitive reaches Relay as sensitive",
            )?;
        }
        require(
            !critical || candidate.critical_grant,
            "critical needs the user's Grant",
        )?;
        if self.exploration.explored {
            require(self.exploration.allowed, "exploration needs consent")?;
            require(
                matches!(self.chosen_arm, Arm::Digest | Arm::NextBreak),
                "exploration between digest and next break",
            )?;
            require(
                !candidate.critical_grant && !candidate.urgent,
                "no exploration on urgent or critical output",
            )?;
        }
        let hard = summary.type_muted
            || (summary.quiet_hours && self.chosen_arm == Arm::InterruptNow)
            || (summary.in_rest_period && candidate.source == Source::Suggestion);
        require(
            !hard || !notifies || critical,
            "hard constraint blocks notification",
        )?;
        require(
            candidate.urgent || self.chosen_arm != Arm::InterruptNow || critical,
            "only urgent output interrupts now",
        )
    }
}
