//! Autonomy rules: One's projection of a Mandate behaviour for one capability and one action; there is no global setting (A-1, A-2, A-13, A-18, A-42).

use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::name::CapabilityRef;
use crate::id::InteractionId;
use crate::interaction_types::ConsequenceTier;
use crate::interaction_types::Reversibility;
use crate::money::Money;
use crate::ontology::ActionRef;
use crate::ontology::DecisionRecordRef;
use crate::ontology::Instant;
use crate::ontology::MandateRef;
use crate::ontology::OpaqueId;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;
use crate::task::common::{AutonomyBehaviour, Sha256Digest, checked_record, wire_enum};

wire_enum!(
    /// What a rule's source names.
    SourceKind {
        /// Accounts.
        Account = "account",
        /// Recipients.
        Recipient = "recipient",
        /// Merchants.
        Merchant = "merchant",
        /// Sites.
        Site = "site",
    }
);

fn check_source(value: &RuleSource) -> Result<(), ContractViolation> {
    require(unique(&value.refs), "source references are unique")
}

checked_record!(
    /// The named sources a rule covers.
    #[derive(Eq)]
    pub struct RuleSource via RuleSourceWire = "RuleSourceWire", check check_source {
        /// The kind.
        pub kind: SourceKind,
        /// The references.
        pub refs: Vec<OpaqueId>,
    }
);

wire_enum!(
    /// A weekday.
    Weekday {
        /// Monday.
        Mon = "mon",
        /// Tuesday.
        Tue = "tue",
        /// Wednesday.
        Wed = "wed",
        /// Thursday.
        Thu = "thu",
        /// Friday.
        Fri = "fri",
        /// Saturday.
        Sat = "sat",
        /// Sunday.
        Sun = "sun",
    }
);

wire_enum!(
    /// Whether public holidays count.
    PublicHolidays {
        /// Included.
        Included = "included",
        /// Excluded.
        Excluded = "excluded",
    }
);

fn is_clock(text: &str) -> bool {
    let b = text.as_bytes();
    let digit = |i: usize| b.get(i).is_some_and(u8::is_ascii_digit);
    b.len() == 5
        && b.get(2) == Some(&b':')
        && digit(0)
        && digit(1)
        && digit(3)
        && digit(4)
        && text.get(0..2).is_some_and(|h| h < "24")
        && text.get(3..4).is_some_and(|m| m < "6")
}

fn is_time_zone(text: &str) -> bool {
    (1..=64).contains(&text.chars().count())
}

crate::ontology::validate::checked_string!(
    /// A wall-clock time `HH:MM`.
    ClockTime,
    "clock time",
    is_clock
);
crate::ontology::validate::checked_string!(
    /// A time zone name.
    TimeZone,
    "time zone",
    is_time_zone
);

fn check_window(value: &TimeWindow) -> Result<(), ContractViolation> {
    require(!value.days.is_empty() && unique(&value.days), "window days")
}

checked_record!(
    /// A recurring time window.
    #[derive(Eq)]
    pub struct TimeWindow via TimeWindowWire = "TimeWindowWire", check check_window {
        /// The days.
        pub days: Vec<Weekday>,
        /// From.
        pub from: ClockTime,
        /// To.
        pub to: ClockTime,
        /// The time zone.
        pub time_zone: TimeZone,
        /// Whether public holidays count.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub public_holidays: Option<PublicHolidays>,
    }
);

fn check_context(value: &RuleContext) -> Result<(), ContractViolation> {
    require(
        value.time_windows.is_some() || value.place_refs.is_some() || value.human_present.is_some(),
        "context names a condition",
    )?;
    require(
        value.time_windows.as_ref().is_none_or(|w| !w.is_empty()),
        "time windows",
    )?;
    require(
        value
            .place_refs
            .as_ref()
            .is_none_or(|p| !p.is_empty() && unique(p)),
        "place references",
    )
}

checked_record!(
    /// When a rule applies.
    #[derive(Eq)]
    pub struct RuleContext via RuleContextWire = "RuleContextWire", check check_context {
        /// Time windows.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub time_windows: Option<Vec<TimeWindow>>,
        /// Places.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub place_refs: Option<Vec<OpaqueId>>,
        /// Whether the user is present.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub human_present: Option<bool>,
    }
);

wire_enum!(
    /// The period a rule budget counts over.
    BudgetPeriod {
        /// A day.
        Day = "day",
        /// A week.
        Week = "week",
        /// A month.
        Month = "month",
        /// The rule's lifetime.
        Rule = "rule",
    }
);

fn check_rule_budget(value: &RuleBudget) -> Result<(), ContractViolation> {
    require(
        value.amount_per_exercise.is_some()
            || value.amount_total.is_some()
            || value.count.is_some()
            || value.period.is_some(),
        "budget names a limit",
    )
}

checked_record!(
    /// A rule's budget.
    #[derive(Eq)]
    pub struct RuleBudget via RuleBudgetWire = "RuleBudgetWire", check check_rule_budget {
        /// Per exercise.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub amount_per_exercise: Option<Money>,
        /// In total.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub amount_total: Option<Money>,
        /// How many times.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<NonZeroU32>,
        /// Over which period.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub period: Option<BudgetPeriod>,
    }
);

fn check_risk(value: &RuleRisk) -> Result<(), ContractViolation> {
    require(
        !value.reversibility.is_empty() && unique(&value.reversibility),
        "risk reversibility",
    )
}

checked_record!(
    /// The risk a rule covers.
    #[derive(Eq)]
    pub struct RuleRisk via RuleRiskWire = "RuleRiskWire", check check_risk {
        /// The highest consequence tier.
        pub max_consequence_tier: ConsequenceTier,
        /// The reversibility values covered.
        pub reversibility: Vec<Reversibility>,
    }
);

/// Which request, which statement and when the user pre-approved.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreapprovalOrigin {
    /// The request.
    pub request_ref: InteractionId,
    /// The digest of the approved statement.
    pub statement_digest: Sha256Digest,
    /// When.
    pub approved_at: Instant,
    /// The Access approval act.
    pub approval_act_ref: DecisionRecordRef,
}

/// Why an autonomy rule is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuleRejection {
    /// `act-if-preapproved` without its origin, or an origin on another behaviour.
    PreapprovalOrigin,
    /// An acting rule without a budget.
    ActWithoutBudget,
    /// An acting rule without an end date.
    ActWithoutEnd,
    /// An acting rule without a named source.
    ActWithoutSource,
}

impl RuleRejection {
    const fn what(self) -> &'static str {
        match self {
            Self::PreapprovalOrigin => "pre-approval origin exactly for act-if-preapproved",
            Self::ActWithoutBudget => "an acting rule has a budget",
            Self::ActWithoutEnd => "an acting rule has an end date",
            Self::ActWithoutSource => "an acting rule names its source",
        }
    }
}

/// Checks the A-1 and A-13 constraints of a rule.
///
/// # Errors
/// Returns the first constraint the rule breaks.
pub fn check_autonomy_rule(rule: &AutonomyRule) -> Result<(), RuleRejection> {
    let preapproved = rule.behaviour == AutonomyBehaviour::ActIfPreapproved;
    if preapproved != rule.preapproval_origin.is_some() {
        return Err(RuleRejection::PreapprovalOrigin);
    }
    if matches!(
        rule.behaviour,
        AutonomyBehaviour::Act | AutonomyBehaviour::ActIfPreapproved
    ) {
        if rule.budget.is_none() {
            return Err(RuleRejection::ActWithoutBudget);
        }
        if rule.ends_at.is_none() {
            return Err(RuleRejection::ActWithoutEnd);
        }
        if rule.source.refs.is_empty() {
            return Err(RuleRejection::ActWithoutSource);
        }
    }
    Ok(())
}

fn check_rule(rule: &AutonomyRule) -> Result<(), ContractViolation> {
    check_autonomy_rule(rule).map_err(|r| ContractViolation(r.what()))
}

checked_record!(
    /// One capability, one action, one source set, context, budget and risk, and the behaviour (A-1).
    pub struct AutonomyRule via AutonomyRuleWire = "AutonomyRuleWire", check check_rule {
        /// The Mandate.
        pub mandate_ref: MandateRef,
        /// The capability.
        pub capability: CapabilityRef,
        /// The action.
        pub action: ActionRef,
        /// The sources.
        pub source: RuleSource,
        /// The context.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub context: Option<RuleContext>,
        /// The budget.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub budget: Option<RuleBudget>,
        /// The risk.
        pub risk: RuleRisk,
        /// The behaviour.
        pub behaviour: AutonomyBehaviour,
        /// The pre-approval origin.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub preapproval_origin: Option<PreapprovalOrigin>,
        /// The end date.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub ends_at: Option<Instant>,
    }
);
