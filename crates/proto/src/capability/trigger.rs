//! Triggers: when this happens, do that; bound to one Mandate, never wider, never without an end date (A-13, A-14, A-15).

use core::cmp::Ordering;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use crate::money::Money;
use crate::ontology::ActionRef;
use crate::ontology::Instant;
use crate::ontology::MandateRef;
use crate::ontology::OpaqueId;
use crate::ontology::TriggerRef;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::task::common::{AutonomyBehaviour, checked_record, wire_enum};

wire_enum!(
    /// Where the triggering event comes from.
    EventSourceKind {
        /// A schedule.
        Schedule = "schedule",
        /// A calendar.
        Calendar = "calendar",
        /// E-mail.
        Email = "email",
        /// A price watch.
        PriceWatch = "price_watch",
        /// A Relay event.
        RelayEvent = "relay_event",
        /// A peer One's typed reply.
        OnePeerReply = "one_peer_reply",
    }
);

fn check_event_source(value: &TriggerEventSource) -> Result<(), ContractViolation> {
    require(
        value.kind == EventSourceKind::Schedule || value.reference.is_some(),
        "a non-schedule source names its reference",
    )
}

checked_record!(
    /// The event source.
    #[derive(Eq)]
    pub struct TriggerEventSource via TriggerEventSourceWire = "TriggerEventSourceWire", check check_event_source {
        /// The kind.
        pub kind: EventSourceKind,
        /// The source reference.
        #[serde(rename = "ref", default, skip_serializing_if = "Option::is_none")]
        pub reference: Option<OpaqueId>,
    }
);

wire_enum!(
    /// The shared Suiss restriction language.
    ConditionLanguage {
        /// The only language.
        SuissRestriction = "suiss-restriction",
    }
);

fn is_language_version(text: &str) -> bool {
    (1..=32).contains(&text.chars().count())
}

fn is_expression(text: &str) -> bool {
    (1..=4096).contains(&text.chars().count())
}

crate::ontology::validate::checked_string!(
    /// The restriction language version.
    LanguageVersion,
    "language version",
    is_language_version
);
crate::ontology::validate::checked_string!(
    /// A restriction expression; opaque to One, evaluated by Access.
    Expression,
    "expression",
    is_expression
);

/// The condition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Condition {
    /// The language.
    pub language: ConditionLanguage,
    /// Its version.
    pub language_version: LanguageVersion,
    /// The expression.
    pub expression: Expression,
}

wire_enum!(
    /// What the fixed target is.
    TargetKind {
        /// A site.
        Site = "site",
        /// A recipient.
        Recipient = "recipient",
        /// A merchant.
        Merchant = "merchant",
        /// An account.
        Account = "account",
        /// A resource.
        Resource = "resource",
    }
);

/// The fixed target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// The kind.
    pub kind: TargetKind,
    /// The target.
    #[serde(rename = "ref")]
    pub reference: OpaqueId,
}

/// The one permitted action and its fixed target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TriggerAction {
    /// The action.
    pub action_ref: ActionRef,
    /// The target.
    pub target: Target,
}

fn check_budget(value: &Limit) -> Result<(), ContractViolation> {
    require(
        value.amount.is_some() || value.count.is_some(),
        "budget names a limit",
    )
}

checked_record!(
    /// An amount and/or count ceiling.
    #[derive(Eq)]
    pub struct Limit via LimitWire = "LimitWire", check check_budget {
        /// The amount.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub amount: Option<Money>,
        /// The count.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub count: Option<NonZeroU32>,
    }
);

/// The bound Mandate as One read it from Access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundMandate {
    /// The Mandate.
    pub mandate_ref: MandateRef,
    /// Its behaviour.
    pub behaviour: AutonomyBehaviour,
    /// Its end.
    pub ends_at: Instant,
    /// Its budget.
    pub budget: Limit,
}

/// A trigger (A-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trigger {
    /// The Access trigger, once registered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub trigger_ref: Option<TriggerRef>,
    /// The event source.
    pub event_source: TriggerEventSource,
    /// The condition.
    pub condition: Condition,
    /// The action.
    pub action: TriggerAction,
    /// The budget.
    pub budget: Limit,
    /// The mandatory end.
    pub ends_at: Instant,
    /// The bound Mandate.
    pub mandate: BoundMandate,
}

/// What happens when an accepted trigger fires; the decision is taken again at that moment (A-15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerRun {
    /// One asks Access for a continuation decision and acts on ALLOW.
    DecidesOnFire,
    /// One prepares and asks the user.
    AsksOnFire,
    /// One prepares and hands the work to the user.
    HandsOffOnFire,
}

/// Why a trigger is wider than its Mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerRejection {
    /// It ends after the Mandate.
    EndsAfterMandate,
    /// Its amount or count exceeds the Mandate, or it lacks a limit the Mandate sets.
    BudgetExceedsMandate,
    /// Its amount is in another currency than the Mandate's.
    CurrencyMismatch,
}

/// Checks that a trigger stays inside its Mandate and says how it runs when it fires.
///
/// # Errors
/// Returns the first bound the trigger exceeds.
pub fn check_trigger_bounds(trigger: &Trigger) -> Result<TriggerRun, TriggerRejection> {
    let mandate = &trigger.mandate;
    if trigger.ends_at > mandate.ends_at {
        return Err(TriggerRejection::EndsAfterMandate);
    }
    if let Some(ceiling) = &mandate.budget.amount {
        let amount = trigger
            .budget
            .amount
            .as_ref()
            .ok_or(TriggerRejection::BudgetExceedsMandate)?;
        match amount.compare(ceiling) {
            None => return Err(TriggerRejection::CurrencyMismatch),
            Some(Ordering::Greater) => return Err(TriggerRejection::BudgetExceedsMandate),
            Some(_) => {}
        }
    }
    if let Some(ceiling) = mandate.budget.count {
        let count = trigger
            .budget
            .count
            .ok_or(TriggerRejection::BudgetExceedsMandate)?;
        if count > ceiling {
            return Err(TriggerRejection::BudgetExceedsMandate);
        }
    }
    Ok(match mandate.behaviour {
        AutonomyBehaviour::Act | AutonomyBehaviour::ActIfPreapproved => TriggerRun::DecidesOnFire,
        AutonomyBehaviour::Ask => TriggerRun::AsksOnFire,
        AutonomyBehaviour::Handoff => TriggerRun::HandsOffOnFire,
    })
}
