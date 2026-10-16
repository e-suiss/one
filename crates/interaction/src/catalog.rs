//! The approved, versioned component catalog One composes; the model fills typed fields and never generates free UI or markup (X-14, X-61).

use serde::{Deserialize, Serialize};

use crate::common::CoreKind;
use one_proto::interaction_types::SurfaceClass;

/// The catalog version.
pub const CATALOG_VERSION: u32 = 1;

/// Approved components.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Component {
    /// One subject with typed facts and its actions.
    Card,
    /// A short ordered list.
    List,
    /// Two to four options side by side.
    Comparison,
    /// Opens the Access trusted approval surface.
    Approval,
    /// Typed fields.
    Form,
    /// Task steps over time.
    Timeline,
    /// A place or route.
    Map,
    /// Live state of one task.
    Progress,
    /// Confirmed outcome of finished work.
    Receipt,
}

impl Component {
    /// Every component in catalog order.
    pub const ALL: [Self; 9] = [
        Self::Card,
        Self::List,
        Self::Comparison,
        Self::Approval,
        Self::Form,
        Self::Timeline,
        Self::Map,
        Self::Progress,
        Self::Receipt,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Card => "card",
            Self::List => "list",
            Self::Comparison => "comparison",
            Self::Approval => "approval",
            Self::Form => "form",
            Self::Timeline => "timeline",
            Self::Map => "map",
            Self::Progress => "progress",
            Self::Receipt => "receipt",
        }
    }
}

/// Typed detail fields a component binds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Bind {
    Amount,
    Counterparty,
    Time,
    TimeRange,
    Place,
    Options,
    Fields,
    Progress,
    Steps,
    Outcome,
    Note,
}

/// A catalog entry (`catalog/components.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ComponentSpec {
    /// Component version.
    pub version: u32,
    /// Purpose.
    pub purpose: &'static str,
    /// Bound detail fields.
    pub binds: &'static [Bind],
    /// Kinds it may present.
    pub kinds: &'static [CoreKind],
    /// Surface classes it renders on.
    pub surfaces: &'static [SurfaceClass],
    /// Most typed facts on a card.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_facts: Option<u32>,
    /// Fewest items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_items: Option<u32>,
    /// Most items.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_items: Option<u32>,
    /// Most attributes per option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_attributes: Option<u32>,
    /// Most form fields.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_fields: Option<u32>,
    /// The approval component opens the Access surface.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opens_access_surface: Option<bool>,
    /// The approval component never collects secrets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub collects_secrets: Option<bool>,
    /// Field types a form never has.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forbidden_field_types: Option<&'static [&'static str]>,
    /// Remote content loads only after the user opens it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub load: Option<&'static str>,
    /// A receipt says done only after Executor confirmation.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done_requires_executor_confirmation: Option<bool>,
}

const fn base(
    purpose: &'static str,
    binds: &'static [Bind],
    kinds: &'static [CoreKind],
    surfaces: &'static [SurfaceClass],
) -> ComponentSpec {
    ComponentSpec {
        version: 1,
        purpose,
        binds,
        kinds,
        surfaces,
        max_facts: None,
        min_items: None,
        max_items: None,
        max_attributes: None,
        max_fields: None,
        opens_access_surface: None,
        collects_secrets: None,
        forbidden_field_types: None,
        load: None,
        done_requires_executor_confirmation: None,
    }
}

use Bind as B;
use CoreKind as K;
use SurfaceClass as S;

const RICH: &[SurfaceClass] = &[S::Phone, S::Desktop];
const RICH_GLASSES: &[SurfaceClass] = &[S::Phone, S::Desktop, S::VoiceGlasses];

const CARD: ComponentSpec = ComponentSpec {
    max_facts: Some(6),
    ..base(
        "One subject with typed facts and its actions",
        &[
            B::Amount,
            B::Counterparty,
            B::Time,
            B::TimeRange,
            B::Place,
            B::Note,
        ],
        &[K::Approval, K::Choice, K::Question, K::Info, K::DigestItem],
        RICH_GLASSES,
    )
};
const LIST: ComponentSpec = ComponentSpec {
    max_items: Some(10),
    ..base(
        "A short ordered list of options or entries",
        &[B::Options, B::Steps],
        &[K::Choice, K::DigestItem, K::Info],
        RICH_GLASSES,
    )
};
const COMPARISON: ComponentSpec = ComponentSpec {
    min_items: Some(2),
    max_items: Some(4),
    max_attributes: Some(8),
    ..base(
        "Two to four options side by side on the same attributes",
        &[B::Options],
        &[K::Comparison],
        RICH,
    )
};
const APPROVAL: ComponentSpec = ComponentSpec {
    opens_access_surface: Some(true),
    collects_secrets: Some(false),
    ..base(
        "Opens the Access trusted approval surface; never collects the approval itself",
        &[B::Amount, B::Counterparty, B::Time, B::Place],
        &[K::Approval],
        &[S::Phone, S::Desktop, S::Watch, S::VoiceCar, S::VoiceGlasses],
    )
};
const FORM: ComponentSpec = ComponentSpec {
    max_fields: Some(20),
    forbidden_field_types: Some(&[
        "password",
        "pin",
        "card_number",
        "one_time_code",
        "credential",
    ]),
    ..base(
        "Typed fields; never a password, PIN, card number or one-time code",
        &[B::Fields],
        &[K::Form],
        RICH,
    )
};
const TIMELINE: ComponentSpec = ComponentSpec {
    max_items: Some(100),
    ..base(
        "Steps of a task over time",
        &[B::Steps, B::TimeRange],
        &[K::Progress, K::Receipt, K::Info],
        RICH,
    )
};
const MAP: ComponentSpec = ComponentSpec {
    load: Some("on_user_open"),
    ..base(
        "A place or route; tiles load only after the user opens the map",
        &[B::Place, B::Options],
        &[K::Info, K::Choice, K::Comparison, K::Receipt],
        RICH,
    )
};
const PROGRESS: ComponentSpec = base(
    "The live state of one ongoing task",
    &[B::Progress, B::Steps],
    &[K::Progress],
    &[S::Phone, S::Desktop, S::Watch, S::VoiceGlasses],
);
const RECEIPT: ComponentSpec = ComponentSpec {
    done_requires_executor_confirmation: Some(true),
    ..base(
        "The confirmed outcome, cost and honest undo label of finished work",
        &[B::Outcome, B::Amount, B::Counterparty, B::Time],
        &[K::Receipt],
        RICH_GLASSES,
    )
};

impl Component {
    /// The catalog entry.
    #[must_use]
    pub const fn spec(self) -> &'static ComponentSpec {
        match self {
            Self::Card => &CARD,
            Self::List => &LIST,
            Self::Comparison => &COMPARISON,
            Self::Approval => &APPROVAL,
            Self::Form => &FORM,
            Self::Timeline => &TIMELINE,
            Self::Map => &MAP,
            Self::Progress => &PROGRESS,
            Self::Receipt => &RECEIPT,
        }
    }
}
