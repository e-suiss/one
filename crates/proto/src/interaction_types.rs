//! The interaction-level values tasks, capabilities, attention decisions and Interactions share: surface classes, authentication, consequence tiers, reversibility, interruption levels and presentation modalities (X-3, A-24, AT-5).

use serde::{Deserialize, Serialize};

/// A surface class (X-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SurfaceClass {
    /// Phone or tablet.
    #[serde(rename = "phone")]
    Phone,
    /// Desktop, web workspace or browser extension.
    #[serde(rename = "desktop")]
    Desktop,
    /// Watch.
    #[serde(rename = "watch")]
    Watch,
    /// Car voice.
    #[serde(rename = "voice:car")]
    VoiceCar,
    /// Glasses voice.
    #[serde(rename = "voice:glasses")]
    VoiceGlasses,
}

impl SurfaceClass {
    /// Every surface class in contract order.
    pub const ALL: [Self; 5] = [
        Self::Phone,
        Self::Desktop,
        Self::Watch,
        Self::VoiceCar,
        Self::VoiceGlasses,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Phone => "phone",
            Self::Desktop => "desktop",
            Self::Watch => "watch",
            Self::VoiceCar => "voice:car",
            Self::VoiceGlasses => "voice:glasses",
        }
    }

    /// True for the voice classes (car and glasses).
    #[must_use]
    pub const fn is_voice(self) -> bool {
        matches!(self, Self::VoiceCar | Self::VoiceGlasses)
    }
}

/// Authentication evidence, ordered by strength.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Authentication {
    /// None.
    None,
    /// Device unlock.
    DeviceUnlock,
    /// Passkey with user verification.
    Passkey,
}

/// The Access consequence tier, ordered by consequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ConsequenceTier {
    /// No consequence.
    #[serde(rename = "CT0")]
    Ct0,
    /// Low.
    #[serde(rename = "CT1")]
    Ct1,
    /// High.
    #[serde(rename = "CT2")]
    Ct2,
    /// Critical.
    #[serde(rename = "CT3")]
    Ct3,
}

/// Reversibility, a field separate from the consequence tier (A-24, Access E47).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reversibility {
    /// An undo action exists.
    Reversible,
    /// A compensating action exists.
    Compensable,
    /// Neither.
    Irreversible,
}

impl Reversibility {
    /// Every value in contract order.
    pub const ALL: [Self; 3] = [Self::Reversible, Self::Compensable, Self::Irreversible];

    /// The wire string.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reversible => "reversible",
            Self::Compensable => "compensable",
            Self::Irreversible => "irreversible",
        }
    }

    /// Parses the wire string.
    #[must_use]
    pub fn from_wire(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.as_str() == text)
    }
}

/// An interruption level; Relay only lowers it (AT-5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Interruption {
    /// Silent.
    Passive,
    /// Normal notification.
    Active,
    /// Pierces focus as far as the platform allows.
    TimeSensitive,
    /// Pierces silent mode and focus; only with the user's Grant (AT-6).
    Critical,
}

/// A presentation modality.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Modality {
    /// Voice.
    Voice,
    /// Haptic.
    Haptic,
    /// Small visual.
    SmallVisual,
    /// Full visual.
    FullVisual,
}
