//! Surface classes, their modes, projection targets and approval ceilings (`surfaces/surface-classes.toml`) (X-2, X-3, X-5, X-19, X-45, X-46, A-28).

use serde::{Deserialize, Serialize};

use crate::common::MandateFit;
use one_proto::interaction_types::ConsequenceTier;
use one_proto::interaction_types::Reversibility;
use one_proto::interaction_types::SurfaceClass;

/// Interaction modes (X-2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    /// Short daily interaction; minimal projection.
    Presence,
    /// Deep work; full projection.
    Workspace,
    /// Managing One, inside the workspace.
    Control,
}

/// Projection targets of the budget table.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum SurfaceTarget {
    Workspace,
    Notification,
    LiveActivity,
    LiveUpdate,
    Widget,
    MenuBar,
    WatchApp,
    Complication,
    CarVoice,
    GlassesDisplay,
    GlassesVoice,
}

impl SurfaceTarget {
    /// Every target in table order.
    pub const ALL: [Self; 11] = [
        Self::Workspace,
        Self::Notification,
        Self::LiveActivity,
        Self::LiveUpdate,
        Self::Widget,
        Self::MenuBar,
        Self::WatchApp,
        Self::Complication,
        Self::CarVoice,
        Self::GlassesDisplay,
        Self::GlassesVoice,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Workspace => "workspace",
            Self::Notification => "notification",
            Self::LiveActivity => "live_activity",
            Self::LiveUpdate => "live_update",
            Self::Widget => "widget",
            Self::MenuBar => "menu_bar",
            Self::WatchApp => "watch_app",
            Self::Complication => "complication",
            Self::CarVoice => "car_voice",
            Self::GlassesDisplay => "glasses_display",
            Self::GlassesVoice => "glasses_voice",
        }
    }
}

/// Approval ceiling of a class (X-19, Access E49).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Ceiling {
    /// CT0–CT1, reversible or compensable, within the Mandate.
    LowRisk,
    /// Everything, with strong authentication; non-delegable only as a direct act.
    FullWithStrongAuth,
}

/// The cells of an approval ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct CeilingSpec {
    /// Admitted risk classes.
    pub risk: &'static [ConsequenceTier],
    /// Admitted reversibility.
    pub reversibility: &'static [Reversibility],
    /// Admitted Mandate fit.
    pub mandate_fit: &'static [MandateFit],
    /// What happens above it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub otherwise: Option<&'static str>,
    /// How a non-delegable action is answered.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_delegable: Option<&'static str>,
    /// A user setting only tightens it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_setting: Option<&'static str>,
}

const LOW_RISK: CeilingSpec = CeilingSpec {
    risk: &[ConsequenceTier::Ct0, ConsequenceTier::Ct1],
    reversibility: &[Reversibility::Reversible, Reversibility::Compensable],
    mandate_fit: &[MandateFit::Within],
    otherwise: Some("redirect_to_phone_or_desktop"),
    non_delegable: None,
    user_setting: None,
};

const FULL: CeilingSpec = CeilingSpec {
    risk: &[
        ConsequenceTier::Ct0,
        ConsequenceTier::Ct1,
        ConsequenceTier::Ct2,
        ConsequenceTier::Ct3,
    ],
    reversibility: &[
        Reversibility::Reversible,
        Reversibility::Compensable,
        Reversibility::Irreversible,
    ],
    mandate_fit: &[
        MandateFit::Within,
        MandateFit::Exceeds,
        MandateFit::NonDelegable,
    ],
    otherwise: None,
    non_delegable: Some("direct_act_only"),
    user_setting: Some("tighten_only"),
};

impl Ceiling {
    /// The ceiling cells.
    #[must_use]
    pub const fn spec(self) -> &'static CeilingSpec {
        match self {
            Self::LowRisk => &LOW_RISK,
            Self::FullWithStrongAuth => &FULL,
        }
    }

    /// True if an approval with these properties can be given under this ceiling.
    #[must_use]
    pub fn admits(
        self,
        risk: ConsequenceTier,
        reversibility: Reversibility,
        fit: MandateFit,
    ) -> bool {
        let s = self.spec();
        s.risk.contains(&risk)
            && s.reversibility.contains(&reversibility)
            && s.mandate_fit.contains(&fit)
    }
}

/// A class row of `surface-classes.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct ClassSpec {
    /// Example devices.
    pub examples: &'static [&'static str],
    /// Input and output channels.
    pub channels: &'static [&'static str],
    /// Modes.
    pub modes: &'static [Mode],
    /// Projection targets.
    pub targets: &'static [SurfaceTarget],
    /// Approval ceiling.
    pub approval_ceiling: Ceiling,
    /// Strong authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strong_auth: Option<&'static str>,
    /// Default approval gesture.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_gesture_default: Option<&'static str>,
    /// Approval gesture options.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval_gesture_options: Option<&'static [&'static str]>,
    /// Runtime.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<&'static str>,
}

const ALL_MODES: &[Mode] = &[Mode::Presence, Mode::Workspace, Mode::Control];
const PRESENCE: &[Mode] = &[Mode::Presence];

use SurfaceTarget as T;

const PHONE: ClassSpec = ClassSpec {
    examples: &["iPhone", "Android phone", "tablet"],
    channels: &["visual", "voice", "touch"],
    modes: ALL_MODES,
    targets: &[
        T::Workspace,
        T::Notification,
        T::LiveActivity,
        T::LiveUpdate,
        T::Widget,
    ],
    approval_ceiling: Ceiling::FullWithStrongAuth,
    strong_auth: Some("passkey"),
    approval_gesture_default: None,
    approval_gesture_options: None,
    runtime: None,
};
const DESKTOP: ClassSpec = ClassSpec {
    examples: &[
        "macOS",
        "Windows",
        "Linux",
        "web workspace",
        "browser extension",
    ],
    channels: &["visual", "keyboard"],
    targets: &[T::Workspace, T::Notification, T::MenuBar],
    ..PHONE
};
const WATCH: ClassSpec = ClassSpec {
    examples: &["Apple Watch", "Wear OS"],
    channels: &["small_visual", "haptic"],
    modes: PRESENCE,
    targets: &[T::WatchApp, T::Complication, T::Notification],
    approval_ceiling: Ceiling::LowRisk,
    strong_auth: None,
    approval_gesture_default: Some("hold"),
    approval_gesture_options: Some(&["hold", "two_step"]),
    runtime: None,
};
const CAR: ClassSpec = ClassSpec {
    examples: &["CarPlay", "Android Auto"],
    channels: &["voice"],
    targets: &[T::CarVoice],
    approval_gesture_default: None,
    approval_gesture_options: None,
    ..WATCH
};
const GLASSES: ClassSpec = ClassSpec {
    examples: &["Meta glasses", "Android XR glasses"],
    channels: &["voice", "small_visual", "camera"],
    targets: &[T::GlassesDisplay, T::GlassesVoice],
    runtime: Some("projected_from_phone"),
    ..CAR
};

/// Chat is not the canonical unit of interaction (X-5).
pub const CHAT_IS_CANONICAL_UNIT: bool = false;

/// The surface-class rows of X-3, on the shared [`SurfaceClass`].
pub trait ClassRow {
    /// The class row.
    fn spec(self) -> &'static ClassSpec;

    /// The approval ceiling.
    fn ceiling(self) -> Ceiling;

    /// True if the target belongs to this class.
    fn has_target(self, target: SurfaceTarget) -> bool;
}

impl ClassRow for SurfaceClass {
    fn spec(self) -> &'static ClassSpec {
        match self {
            Self::Phone => &PHONE,
            Self::Desktop => &DESKTOP,
            Self::Watch => &WATCH,
            Self::VoiceCar => &CAR,
            Self::VoiceGlasses => &GLASSES,
        }
    }

    fn ceiling(self) -> Ceiling {
        self.spec().approval_ceiling
    }

    fn has_target(self, target: SurfaceTarget) -> bool {
        self.spec().targets.contains(&target)
    }
}
