//! The output type taxonomy and the fixed One → Relay class table: every output type, its row, ceiling and mute scope; unlisted types and the `security` class are never sent (AT-9, AT-23, AT-41, AT-42).

use serde::{Deserialize, Serialize};

use crate::interaction_types::Interruption;

/// The Relay message classes One may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OneRelayClass {
    /// `action_required`.
    ActionRequired,
    /// `transactional`.
    Transactional,
}

/// The delivery timing One asks Relay for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Timing {
    /// Now.
    Immediate,
    /// At the next natural break.
    NextBreak,
}

/// A row of the Relay mapping table.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RowId {
    /// Approval requests.
    ApprovalRequest,
    /// Time-sensitive information about the user's own work.
    OwnWorkInfo,
    /// Progress updates.
    ProgressUpdate,
    /// Output covered by the user's critical Grant.
    CriticalGrant,
}

/// How an output type reaches the user.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// As a Relay notification.
    Relay,
    /// Only inside the running session (AT-41).
    InApp,
}

/// What a mute of the type covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MuteScope {
    /// The type for one capability.
    TypeAndCapability,
    /// The whole type.
    Type,
    /// One task.
    Task,
    /// Cannot be muted.
    None,
}

/// The name of an output type under `app.suiss.one.output`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OutputTypeName(&'static str);

impl OutputTypeName {
    /// The name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl core::fmt::Display for OutputTypeName {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(self.0)
    }
}

/// An output type of the taxonomy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutputType {
    /// The type name.
    pub id: OutputTypeName,
    /// The display title.
    pub title: &'static str,
    /// How it reaches the user.
    pub delivery: Delivery,
    /// The Relay row, Relay delivery only.
    pub row: Option<RowId>,
    /// The type's interruption ceiling, Relay delivery only.
    pub interruption_ceiling: Option<Interruption>,
    /// What a mute covers.
    pub mute_scope: MuteScope,
    /// Whether the user can mute it.
    pub mutable: bool,
    /// Whether it is outside the daily budget.
    pub budget_exempt: bool,
}

/// The output type namespace.
pub const NAMESPACE: &str = "app.suiss.one.output";

const fn relay(
    name: &'static str,
    title: &'static str,
    row: RowId,
    ceiling: Interruption,
    mute_scope: MuteScope,
    budget_exempt: bool,
) -> OutputType {
    OutputType {
        id: OutputTypeName(name),
        title,
        delivery: Delivery::Relay,
        row: Some(row),
        interruption_ceiling: Some(ceiling),
        mute_scope,
        mutable: true,
        budget_exempt,
    }
}

const fn in_app(name: &'static str, title: &'static str) -> OutputType {
    OutputType {
        id: OutputTypeName(name),
        title,
        delivery: Delivery::InApp,
        row: None,
        interruption_ceiling: None,
        mute_scope: MuteScope::None,
        mutable: false,
        budget_exempt: true,
    }
}

use Interruption::{Active, Passive, TimeSensitive};
use MuteScope::{Task, Type, TypeAndCapability};
use RowId::{ApprovalRequest, OwnWorkInfo, ProgressUpdate};

/// The output types (`output-types.toml`).
pub const OUTPUT_TYPES: &[OutputType] = &[
    relay(
        "app.suiss.one.output.approval.request",
        "Approval request",
        ApprovalRequest,
        TimeSensitive,
        TypeAndCapability,
        false,
    ),
    relay(
        "app.suiss.one.output.task.takeover_request",
        "Takeover request",
        ApprovalRequest,
        TimeSensitive,
        TypeAndCapability,
        false,
    ),
    relay(
        "app.suiss.one.output.task.prepared",
        "Prepared work",
        OwnWorkInfo,
        Active,
        TypeAndCapability,
        false,
    ),
    relay(
        "app.suiss.one.output.task.result",
        "Awaited result",
        OwnWorkInfo,
        Active,
        TypeAndCapability,
        false,
    ),
    relay(
        "app.suiss.one.output.task.stopped",
        "Stopped or expired work",
        OwnWorkInfo,
        Active,
        TypeAndCapability,
        false,
    ),
    relay(
        "app.suiss.one.output.travel.change",
        "Travel change",
        OwnWorkInfo,
        TimeSensitive,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.delivery.update",
        "Delivery update",
        OwnWorkInfo,
        TimeSensitive,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.reservation.update",
        "Reservation update",
        OwnWorkInfo,
        TimeSensitive,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.bill.reminder",
        "Bill reminder",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.subscription.renewal",
        "Subscription renewal",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.deadline.reminder",
        "Deadline reminder",
        OwnWorkInfo,
        TimeSensitive,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.reminder.requested",
        "Requested reminder",
        OwnWorkInfo,
        TimeSensitive,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.meeting.preparation",
        "Meeting preparation",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.work.pending_item",
        "Pending Work item",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.routine.suggestion",
        "Routine suggestion",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.rule.suggestion",
        "Rule suggestion",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.attention.regret_question",
        "Was this interruption worth it",
        OwnWorkInfo,
        Active,
        Type,
        false,
    ),
    relay(
        "app.suiss.one.output.digest.ready",
        "Daily digest ready",
        OwnWorkInfo,
        Passive,
        Type,
        true,
    ),
    relay(
        "app.suiss.one.output.task.progress",
        "Progress update",
        ProgressUpdate,
        Passive,
        Task,
        false,
    ),
    in_app(
        "app.suiss.one.output.session.break_reminder",
        "Break reminder",
    ),
    in_app("app.suiss.one.output.session.ai_disclosure", "AI reminder"),
    in_app(
        "app.suiss.one.output.model.change_notice",
        "Model change notice",
    ),
];

/// A row of the Relay mapping table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "mirrors the contract")]
pub struct RelayRow {
    /// The row.
    pub id: RowId,
    /// The Relay class.
    pub relay_class: OneRelayClass,
    /// The row's interruption ceiling.
    pub interruption_ceiling: Interruption,
    /// The ceiling holds only for the registered personal agent; otherwise `active` (Relay CH-68).
    pub requires_personal_agent: bool,
    /// The timing when nothing else applies.
    pub timing_default: Timing,
    /// `immediate` only for urgent output.
    pub timing_immediate_only_if_urgent: bool,
    /// `next_break` carries `max_defer`.
    pub max_defer_required_on_next_break: bool,
    /// The critical Grant row overlays it.
    pub critical_overlay: bool,
}

/// The class rows (`relay-mapping.toml`).
pub const RELAY_ROWS: &[RelayRow] = &[
    RelayRow {
        id: ApprovalRequest,
        relay_class: OneRelayClass::ActionRequired,
        interruption_ceiling: TimeSensitive,
        requires_personal_agent: false,
        timing_default: Timing::NextBreak,
        timing_immediate_only_if_urgent: true,
        max_defer_required_on_next_break: true,
        critical_overlay: true,
    },
    RelayRow {
        id: OwnWorkInfo,
        relay_class: OneRelayClass::Transactional,
        interruption_ceiling: TimeSensitive,
        requires_personal_agent: true,
        timing_default: Timing::NextBreak,
        timing_immediate_only_if_urgent: true,
        max_defer_required_on_next_break: true,
        critical_overlay: true,
    },
    RelayRow {
        id: ProgressUpdate,
        relay_class: OneRelayClass::Transactional,
        interruption_ceiling: Passive,
        requires_personal_agent: false,
        timing_default: Timing::Immediate,
        timing_immediate_only_if_urgent: false,
        max_defer_required_on_next_break: false,
        critical_overlay: false,
    },
];

/// The critical Grant overlay row: the output keeps its class and goes `critical` and `immediate` (AT-6).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CriticalGrantRow {
    /// The interruption level.
    pub interruption: Interruption,
    /// The timing.
    pub timing: Timing,
    /// The rows it overlays.
    pub overlays: &'static [RowId],
    /// It needs the user's Access Grant.
    pub requires_access_grant: bool,
    /// It does not count toward the daily budget.
    pub counts_toward_budget: bool,
}

/// The critical Grant overlay (`relay-mapping.toml` row `critical_grant`).
pub const CRITICAL_GRANT: CriticalGrantRow = CriticalGrantRow {
    interruption: Interruption::Critical,
    timing: Timing::Immediate,
    overlays: &[ApprovalRequest, OwnWorkInfo],
    requires_access_grant: true,
    counts_toward_budget: false,
};

/// Finds an output type; names outside the table or the namespace have none.
#[must_use]
pub fn output_type(name: &str) -> Option<&'static OutputType> {
    OUTPUT_TYPES.iter().find(|t| t.id.as_str() == name)
}

/// Finds a class row.
#[must_use]
pub fn relay_row(id: RowId) -> Option<&'static RelayRow> {
    RELAY_ROWS.iter().find(|r| r.id == id)
}

/// The level lowered to the type's ceiling, its row's ceiling and, without the personal agent registration, `active`; never `critical` (AT-5, AT-42).
#[must_use]
pub fn clamp_to_ceiling(
    output: &OutputType,
    requested: Interruption,
    personal_agent_registered: bool,
) -> Option<Interruption> {
    let row = relay_row(output.row?)?;
    let mut level = requested
        .min(output.interruption_ceiling?)
        .min(row.interruption_ceiling)
        .min(Interruption::TimeSensitive);
    if row.requires_personal_agent && !personal_agent_registered {
        level = level.min(Interruption::Active);
    }
    Some(level)
}

/// A candidate output on its way to Relay.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelayCandidate<'a> {
    /// The output type name.
    pub output_type: &'a str,
    /// The requested level.
    pub interruption: Interruption,
    /// It needs action now.
    pub urgent: bool,
    /// The user's critical Grant covers it.
    pub critical_grant: bool,
    /// One is registered at Access as the person's personal agent.
    pub personal_agent_registered: bool,
}

/// What One sends to Relay for an output.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RelaySend {
    /// The Relay class.
    pub relay_class: OneRelayClass,
    /// The level.
    pub interruption: Interruption,
    /// The timing.
    pub timing: Timing,
    /// `max_defer` must be given.
    pub max_defer_required: bool,
}

/// Maps an output to its Relay request, or `None` when it is never sent: an unlisted type, a name outside the namespace, or an in-app type (AT-41, AT-42).
#[must_use]
pub fn map_to_relay(candidate: &RelayCandidate<'_>) -> Option<RelaySend> {
    let output = output_type(candidate.output_type)?;
    if output.delivery != Delivery::Relay {
        return None;
    }
    let row = relay_row(output.row?)?;
    if candidate.critical_grant && row.critical_overlay && CRITICAL_GRANT.overlays.contains(&row.id)
    {
        return Some(RelaySend {
            relay_class: row.relay_class,
            interruption: CRITICAL_GRANT.interruption,
            timing: CRITICAL_GRANT.timing,
            max_defer_required: false,
        });
    }
    let interruption = clamp_to_ceiling(
        output,
        candidate.interruption,
        candidate.personal_agent_registered,
    )?;
    let timing = if row.timing_immediate_only_if_urgent && candidate.urgent {
        Timing::Immediate
    } else {
        row.timing_default
    };
    Some(RelaySend {
        relay_class: row.relay_class,
        interruption,
        timing,
        max_defer_required: timing == Timing::NextBreak && row.max_defer_required_on_next_break,
    })
}
