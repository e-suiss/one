//! Capability names, versions and negotiation, registry entries with safe schemas, surface declarations, autonomy rules, triggers and the purchase intent (CP-15, CP-16, CP-23, A-1, A-14, A-24, A-42).

mod autonomy;
mod commerce;
mod definition;
mod name;
mod negotiation;
mod schema;
mod surface;
mod trigger;

pub use autonomy::{
    AutonomyRule, BudgetPeriod, ClockTime, PreapprovalOrigin, PublicHolidays, RuleBudget,
    RuleContext, RuleRejection, RuleRisk, RuleSource, SourceKind, TimeWindow, TimeZone, Weekday,
    check_autonomy_rule,
};
pub use commerce::{Delivery, Merchant, Payment, PaymentVia, PurchaseInput, PurchaseItem};
pub use definition::{
    ActionRole, AndroidAppFunction, AppleAppSchema, ApprovalCeiling, AuthorityRequirement,
    CapabilityDefinition, CapabilityDefinitionType, DataAccess, EvaluationResult, Example,
    ExampleLang, McpToolHints, PathType, Projections, Provider, RegistryAction, RegistryRejection,
    SurfaceRequirement, TestStatus, Utterance, Verified, check_registry_entry,
    effective_reversibility,
};
pub use name::{
    CapabilityName, CapabilityRef, CapabilityVersion, Extends, MAX_NAME_LENGTH, NameError,
    NameKind, RESERVED_SEGMENTS, ROOT, ThirdPartyName,
};
pub use negotiation::{Declaration, negotiate};
pub use schema::{
    FORBIDDEN_FIELD_WORDS, TypedSchema, is_forbidden_field_name, is_safe_property_name,
    is_safe_schema,
};
pub use surface::{Signal, SizeBudget, SurfaceCapability, SurfaceCapabilityType, SurfaceKind};
pub use trigger::{
    BoundMandate, Condition, ConditionLanguage, EventSourceKind, Expression, LanguageVersion,
    Limit, Target, TargetKind, Trigger, TriggerAction, TriggerEventSource, TriggerRejection,
    TriggerRun, check_trigger_bounds,
};

/// The first-level categories of the initial taxonomy (OD-63).
pub const CATEGORIES: &[&str] = &[
    "communication",
    "calendar",
    "productivity",
    "transport",
    "travel",
    "food",
    "commerce",
    "information",
    "files",
    "home",
    "media",
    "coding",
    "assistant",
];

/// The capabilities of the initial taxonomy (OD-63).
pub const TAXONOMY: &[&str] = &[
    "app.suiss.communication.message.send",
    "app.suiss.communication.email.draft",
    "app.suiss.communication.email.send",
    "app.suiss.communication.call.place",
    "app.suiss.calendar.event.create",
    "app.suiss.calendar.event.update",
    "app.suiss.calendar.event.delete",
    "app.suiss.calendar.event.propose",
    "app.suiss.calendar.availability.query",
    "app.suiss.productivity.reminder.create",
    "app.suiss.productivity.note.create",
    "app.suiss.productivity.list.add",
    "app.suiss.transport.ride.request",
    "app.suiss.transport.ride.cancel",
    "app.suiss.transport.route.plan",
    "app.suiss.travel.flight.search",
    "app.suiss.travel.flight.book",
    "app.suiss.travel.lodging.search",
    "app.suiss.travel.lodging.book",
    "app.suiss.food.order.place",
    "app.suiss.food.reservation.book",
    "app.suiss.commerce.product.search",
    "app.suiss.commerce.purchase",
    "app.suiss.commerce.order.status",
    "app.suiss.commerce.order.cancel",
    "app.suiss.commerce.return.request",
    "app.suiss.information.web.search",
    "app.suiss.information.page.read",
    "app.suiss.information.weather.query",
    "app.suiss.files.document.read",
    "app.suiss.files.document.share",
    "app.suiss.home.device.control",
    "app.suiss.home.scene.run",
    "app.suiss.media.playback.control",
    "app.suiss.coding.session.start",
    "app.suiss.coding.session.steer",
    "app.suiss.coding.session.stop",
    "app.suiss.assistant.task.submit",
    "app.suiss.assistant.task.status",
];
