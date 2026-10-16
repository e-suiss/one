//! The numeric surface budget table (`surfaces/budgets.toml`), the projection outcomes and the fixed rule order (X-13, X-4, X-6, X-10, X-19, X-20, X-36, X-45, X-46, OD-63).

use serde::{Deserialize, Serialize};

use crate::common::CoreKind;
use crate::surface::SurfaceTarget;
use one_proto::interaction_types::SurfaceClass;

/// The table schema.
pub const SCHEMA: &str = "https://suiss.app/schemas/one/interaction/surface-budgets/v1.json";
/// Table version.
pub const VERSION: u32 = 1;
/// Text budgets count Unicode code points.
pub const TEXT_UNIT: &str = "unicode_code_point";
/// Byte budgets count UTF-8 bytes of canonical JSON.
pub const BYTE_UNIT: &str = "utf8_canonical_json";

/// A projection outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectionOutcome {
    /// The full projection.
    Full,
    /// The minimal projection with a deep link.
    Minimal,
    /// The neutral sentence (sensitive content on voice).
    Neutral,
    /// The redirect sentence (approval above the surface ceiling).
    Redirect,
    /// Nothing is sent.
    None,
}

/// Every outcome in table order.
pub const OUTCOMES: [ProjectionOutcome; 5] = [
    ProjectionOutcome::Full,
    ProjectionOutcome::Minimal,
    ProjectionOutcome::Neutral,
    ProjectionOutcome::Redirect,
    ProjectionOutcome::None,
];

/// A projection rule; the first that applies decides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Rule {
    /// The device did not declare the target.
    UndeclaredTarget,
    /// Sensitive content on a voice target.
    SensitiveOnVoice,
    /// An approval above the class ceiling.
    ApprovalAboveCeiling,
    /// The kind is not presented on the target.
    KindNotOnTarget,
    /// The target only carries the minimal projection.
    AlwaysMinimal,
    /// The full projection exceeds a budget.
    OverBudget,
    /// The full projection fits.
    Fits,
}

/// The fixed rule order.
pub const ORDER: [Rule; 7] = [
    Rule::UndeclaredTarget,
    Rule::SensitiveOnVoice,
    Rule::ApprovalAboveCeiling,
    Rule::KindNotOnTarget,
    Rule::AlwaysMinimal,
    Rule::OverBudget,
    Rule::Fits,
];

impl Rule {
    /// The outcome of the rule.
    #[must_use]
    pub const fn outcome(self) -> ProjectionOutcome {
        match self {
            Self::UndeclaredTarget => ProjectionOutcome::None,
            Self::SensitiveOnVoice => ProjectionOutcome::Neutral,
            Self::ApprovalAboveCeiling => ProjectionOutcome::Redirect,
            Self::KindNotOnTarget | Self::AlwaysMinimal | Self::OverBudget => {
                ProjectionOutcome::Minimal
            }
            Self::Fits => ProjectionOutcome::Full,
        }
    }
}

/// Fixed TR and EN text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct FixedText {
    /// Turkish.
    pub tr: &'static str,
    /// English.
    pub en: &'static str,
}

/// Targets where sensitive content becomes the neutral sentence (X-20, AT-13).
pub const SENSITIVE_VOICE_TARGETS: [SurfaceTarget; 2] =
    [SurfaceTarget::CarVoice, SurfaceTarget::GlassesVoice];

/// The neutral sentence.
pub const NEUTRAL: FixedText = FixedText {
    tr: "Telefonunda bir şey var.",
    en: "There is something on your phone.",
};

/// The redirect sentence.
pub const REDIRECT: FixedText = FixedText {
    tr: "Bunu telefonundan onaylaman gerekiyor.",
    en: "You need to approve this on your phone.",
};

/// The minimal projection budget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct MinimalBudget {
    /// Sentence length per locale.
    pub sentence_max_chars: u32,
    /// Answer label length.
    pub label_max_chars: u32,
    /// Number of answers.
    pub answers: u32,
    /// A deep link is always carried.
    pub deep_link: bool,
}

/// The minimal projection budget (X-13).
pub const MINIMAL: MinimalBudget = MinimalBudget {
    sentence_max_chars: 120,
    label_max_chars: 12,
    answers: 2,
    deep_link: true,
};

/// Platform of a target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Platform {
    Ios,
    Android,
}

/// One target row; absent values do not apply to the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[allow(missing_docs)]
pub struct TargetBudget {
    pub class: &'static [SurfaceClass],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,
    pub kinds: &'static [CoreKind],
    #[serde(skip_serializing_if = "Option::is_none")]
    pub always_minimal: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub passive_only: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_components: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_choice_options: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_comparison_options: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_form_fields: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_title_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_body_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_status_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_spoken_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_spoken_options: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_actions: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_buttons: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_bytes: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_cover: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_active_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_visible_hours: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chip_max_width_dp: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chip_max_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_view: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rich_approval_card: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lock_screen_sensitive: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lists: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_gesture: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub text: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub visual: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub answer: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primitives: Option<&'static [&'static str]>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub video: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_list_items: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_list_item_chars: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_images: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_load: Option<&'static str>,
}

const EMPTY: TargetBudget = TargetBudget {
    class: &[],
    platform: None,
    kinds: &[],
    always_minimal: None,
    passive_only: None,
    max_components: None,
    max_choice_options: None,
    max_comparison_options: None,
    max_form_fields: None,
    max_title_chars: None,
    max_body_chars: None,
    max_status_chars: None,
    max_chars: None,
    max_spoken_chars: None,
    max_spoken_options: None,
    max_actions: None,
    max_buttons: None,
    max_bytes: None,
    bytes_cover: None,
    max_active_hours: None,
    max_visible_hours: None,
    network: None,
    chip_max_width_dp: None,
    chip_max_chars: None,
    custom_view: None,
    rich_approval_card: None,
    lock_screen_sensitive: None,
    images: None,
    lists: None,
    approval_gesture: None,
    text: None,
    visual: None,
    answer: None,
    primitives: None,
    video: None,
    max_list_items: None,
    max_list_item_chars: None,
    max_images: None,
    image_load: None,
};

use CoreKind as K;
use SurfaceClass as S;

const ALL_KINDS: &[CoreKind] = &CoreKind::ALL;
const VOICE_KINDS: &[CoreKind] = &[
    K::Approval,
    K::Question,
    K::Info,
    K::Progress,
    K::Receipt,
    K::Choice,
];

const WORKSPACE: TargetBudget = TargetBudget {
    class: &[S::Phone, S::Desktop],
    kinds: ALL_KINDS,
    max_components: Some(12),
    max_choice_options: Some(10),
    max_comparison_options: Some(4),
    max_form_fields: Some(20),
    ..EMPTY
};
const NOTIFICATION: TargetBudget = TargetBudget {
    class: &[S::Phone, S::Desktop, S::Watch],
    kinds: &[
        K::Approval,
        K::Choice,
        K::Question,
        K::Info,
        K::Receipt,
        K::Comparison,
        K::Form,
    ],
    max_title_chars: Some(64),
    max_body_chars: Some(120),
    max_actions: Some(2),
    lock_screen_sensitive: Some("relay_neutral_text"),
    always_minimal: Some(true),
    ..EMPTY
};
const LIVE_ACTIVITY: TargetBudget = TargetBudget {
    class: &[S::Phone],
    platform: Some(Platform::Ios),
    kinds: &[K::Progress],
    max_bytes: Some(4096),
    bytes_cover: Some(&["attributes", "content_state"]),
    max_title_chars: Some(40),
    max_status_chars: Some(120),
    max_actions: Some(2),
    max_active_hours: Some(8),
    max_visible_hours: Some(12),
    network: Some(false),
    ..EMPTY
};
const LIVE_UPDATE: TargetBudget = TargetBudget {
    class: &[S::Phone],
    platform: Some(Platform::Android),
    kinds: &[K::Progress],
    chip_max_width_dp: Some(96),
    chip_max_chars: Some(7),
    custom_view: Some(false),
    max_title_chars: Some(40),
    max_body_chars: Some(120),
    max_actions: Some(3),
    rich_approval_card: Some(false),
    ..EMPTY
};
const WIDGET: TargetBudget = TargetBudget {
    class: &[S::Phone],
    kinds: &[K::Progress, K::Info, K::DigestItem],
    max_title_chars: Some(40),
    max_body_chars: Some(80),
    max_actions: Some(1),
    passive_only: Some(true),
    ..EMPTY
};
const MENU_BAR: TargetBudget = TargetBudget {
    class: &[S::Desktop],
    kinds: &[
        K::Approval,
        K::Choice,
        K::Question,
        K::Info,
        K::Progress,
        K::Receipt,
        K::DigestItem,
    ],
    max_title_chars: Some(48),
    max_body_chars: Some(120),
    max_actions: Some(2),
    always_minimal: Some(true),
    ..EMPTY
};
const WATCH_APP: TargetBudget = TargetBudget {
    class: &[S::Watch],
    kinds: ALL_KINDS,
    always_minimal: Some(true),
    max_title_chars: Some(32),
    max_body_chars: Some(120),
    max_actions: Some(2),
    images: Some(0),
    lists: Some(0),
    approval_gesture: Some("hold"),
    ..EMPTY
};
const COMPLICATION: TargetBudget = TargetBudget {
    class: &[S::Watch],
    kinds: &[K::Progress, K::Info, K::DigestItem],
    always_minimal: Some(true),
    max_chars: Some(20),
    max_actions: Some(0),
    ..EMPTY
};
const CAR_VOICE: TargetBudget = TargetBudget {
    class: &[S::VoiceCar],
    kinds: VOICE_KINDS,
    text: Some(false),
    visual: Some(false),
    max_spoken_chars: Some(200),
    max_spoken_options: Some(3),
    answer: Some("binary_voice"),
    ..EMPTY
};
const GLASSES_DISPLAY: TargetBudget = TargetBudget {
    class: &[S::VoiceGlasses],
    kinds: &[
        K::Approval,
        K::Choice,
        K::Question,
        K::Info,
        K::Progress,
        K::Receipt,
        K::DigestItem,
    ],
    primitives: Some(&["text", "image", "list", "button"]),
    video: Some(false),
    max_title_chars: Some(40),
    max_body_chars: Some(160),
    max_list_items: Some(3),
    max_list_item_chars: Some(40),
    max_buttons: Some(2),
    max_images: Some(1),
    image_load: Some("on_user_open"),
    ..EMPTY
};
const GLASSES_VOICE: TargetBudget = TargetBudget {
    class: &[S::VoiceGlasses],
    kinds: VOICE_KINDS,
    max_spoken_chars: Some(200),
    max_spoken_options: Some(3),
    answer: Some("binary_voice"),
    ..EMPTY
};

impl SurfaceTarget {
    /// The budget row of this target.
    #[must_use]
    pub const fn budget(self) -> &'static TargetBudget {
        match self {
            Self::Workspace => &WORKSPACE,
            Self::Notification => &NOTIFICATION,
            Self::LiveActivity => &LIVE_ACTIVITY,
            Self::LiveUpdate => &LIVE_UPDATE,
            Self::Widget => &WIDGET,
            Self::MenuBar => &MENU_BAR,
            Self::WatchApp => &WATCH_APP,
            Self::Complication => &COMPLICATION,
            Self::CarVoice => &CAR_VOICE,
            Self::GlassesDisplay => &GLASSES_DISPLAY,
            Self::GlassesVoice => &GLASSES_VOICE,
        }
    }
}
