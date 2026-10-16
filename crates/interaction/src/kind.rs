//! Interaction kinds: the closed core list with its minimal projection rules, extension kinds and their resolution to a core kind through the registry (X-12, X-13, C-7, AT-42).

use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::catalog::Component;
use crate::common::{CoreKind, ExtensionName};

/// An extension kind: a reverse-DNS name, a version and its core kind (C-7).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionKind {
    /// Extension name.
    pub extension: ExtensionName,
    /// Extension version, at least 1.
    pub version: u32,
    /// The core kind whose rules it inherits.
    pub maps_to: CoreKind,
}

/// The `kind` of an Interaction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Kind {
    /// A core kind.
    Core(CoreKind),
    /// A registered extension.
    Extension(ExtensionKind),
}

impl Kind {
    /// The core kind this kind names or declares, before registry resolution.
    #[must_use]
    pub const fn declared_core(&self) -> CoreKind {
        match self {
            Self::Core(k) => *k,
            Self::Extension(e) => e.maps_to,
        }
    }
}

/// One registry entry (`kind-extensions.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExtensionEntry {
    /// Extension name.
    pub name: ExtensionName,
    /// Extension version.
    pub version: u32,
    /// Core kind mapping.
    pub maps_to: CoreKind,
    /// Meaning.
    pub meaning: String,
    /// Rule that introduced it.
    pub rule: String,
}

/// The extension kind registry; it starts empty (C-7).
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KindRegistry {
    /// Registry format version.
    pub version: u32,
    /// Registered extensions.
    pub extension: Vec<ExtensionEntry>,
}

/// Why a kind does not resolve.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KindError {
    /// No registry entry with that name and version.
    UnregisteredExtension,
    /// The entry maps to another core kind.
    MappingMismatch,
}

impl KindRegistry {
    /// Resolves a kind to the core kind whose rules apply; an extension must be registered with the same name, version and mapping (C-7, X-12).
    ///
    /// # Errors
    /// [`KindError::UnregisteredExtension`] or [`KindError::MappingMismatch`].
    pub fn resolve(&self, kind: &Kind) -> Result<CoreKind, KindError> {
        match kind {
            Kind::Core(k) => Ok(*k),
            Kind::Extension(e) => {
                let entry = self
                    .extension
                    .iter()
                    .find(|r| r.name == e.extension && r.version == e.version)
                    .ok_or(KindError::UnregisteredExtension)?;
                if entry.maps_to == e.maps_to {
                    Ok(entry.maps_to)
                } else {
                    Err(KindError::MappingMismatch)
                }
            }
        }
    }
}

/// Relay message class of a kind (AT-42).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelayClass {
    /// Needs the user's action.
    ActionRequired,
    /// Transactional.
    Transactional,
    /// Not sent through Relay alone.
    None,
}

/// Effect of an answer or action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[allow(missing_docs)]
pub enum Effect {
    Approve,
    Decline,
    Choose,
    Answer,
    Submit,
    Acknowledge,
    Open,
    Dismiss,
    Defer,
    Stop,
    Undo,
    RequestRefund,
}

/// A default binary answer of a kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct AnswerRule {
    /// Effect.
    pub effect: Effect,
    /// Answer value for `answer`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<bool>,
    /// Turkish label.
    pub tr: &'static str,
    /// English label.
    pub en: &'static str,
}

/// Example sentence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct Example {
    /// Turkish.
    pub tr: &'static str,
    /// English.
    pub en: &'static str,
}

/// The fixed rules of a core kind (`kinds.toml`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct KindRule {
    /// Meaning.
    pub meaning: &'static str,
    /// Components that present it.
    pub components: &'static [Component],
    /// Relay message class.
    pub relay_class: RelayClass,
    /// Default yes answer.
    pub yes: AnswerRule,
    /// Default no answer.
    pub no: AnswerRule,
    /// Example minimal sentence.
    pub example: Example,
}

const fn answer(effect: Effect, tr: &'static str, en: &'static str) -> AnswerRule {
    AnswerRule {
        effect,
        value: None,
        tr,
        en,
    }
}

const RULES: [KindRule; 9] = [
    KindRule {
        meaning: "A request for the user's approval of an action an Access request allows",
        components: &[Component::Approval, Component::Card],
        relay_class: RelayClass::ActionRequired,
        yes: answer(Effect::Approve, "Evet", "Yes"),
        no: answer(Effect::Decline, "Hayır", "No"),
        example: Example {
            tr: "180 TL kahve siparişini onaylıyor musun?",
            en: "Do you approve the 180 TL coffee order?",
        },
    },
    KindRule {
        meaning: "A pick among typed options",
        components: &[Component::List, Component::Card],
        relay_class: RelayClass::Transactional,
        yes: answer(Effect::Choose, "Seç", "Pick"),
        no: answer(Effect::Open, "Diğerleri", "Others"),
        example: Example {
            tr: "Saat 19:30 için Lokanta Nar'ı seçeyim mi?",
            en: "Shall I pick Lokanta Nar for 19:30?",
        },
    },
    KindRule {
        meaning: "A question One asks while a task waits",
        components: &[Component::Card],
        relay_class: RelayClass::Transactional,
        yes: AnswerRule {
            value: Some(true),
            ..answer(Effect::Answer, "Evet", "Yes")
        },
        no: AnswerRule {
            value: Some(false),
            ..answer(Effect::Answer, "Hayır", "No")
        },
        example: Example {
            tr: "Toplantıyı yarın sabaha taşıyayım mı?",
            en: "Shall I move the meeting to tomorrow morning?",
        },
    },
    KindRule {
        meaning: "Information for the user with no decision",
        components: &[Component::Card],
        relay_class: RelayClass::Transactional,
        yes: answer(Effect::Acknowledge, "Tamam", "OK"),
        no: answer(Effect::Open, "Aç", "Open"),
        example: Example {
            tr: "Uçuşun iptal edildi; yeni seçenekler telefonunda.",
            en: "Your flight was cancelled; new options are on your phone.",
        },
    },
    KindRule {
        meaning: "Ongoing work shown as one item updated in place",
        components: &[Component::Progress, Component::Timeline],
        relay_class: RelayClass::Transactional,
        yes: answer(Effect::Open, "Aç", "Open"),
        no: answer(Effect::Stop, "Dur", "Stop"),
        example: Example {
            tr: "Kahve siparişin hazırlanıyor.",
            en: "Your coffee order is being prepared.",
        },
    },
    KindRule {
        meaning: "The result of finished work",
        components: &[Component::Receipt],
        relay_class: RelayClass::Transactional,
        yes: answer(Effect::Acknowledge, "Tamam", "OK"),
        no: answer(Effect::Open, "Ayrıntı", "Details"),
        example: Example {
            tr: "Kahve siparişin verildi, 180 TL.",
            en: "Your coffee order was placed, 180 TL.",
        },
    },
    KindRule {
        meaning: "A side-by-side comparison of two to four options",
        components: &[Component::Comparison],
        relay_class: RelayClass::Transactional,
        yes: answer(Effect::Choose, "Seç", "Pick"),
        no: answer(Effect::Open, "Karşılaştır", "Compare"),
        example: Example {
            tr: "En ucuz uçuş 07:10'da, 2.450 TL; onu seçeyim mi?",
            en: "The cheapest flight is at 07:10, 2,450 TL; shall I pick it?",
        },
    },
    KindRule {
        meaning: "Typed fields for the user to fill",
        components: &[Component::Form],
        relay_class: RelayClass::Transactional,
        yes: answer(Effect::Open, "Doldur", "Fill in"),
        no: answer(Effect::Defer, "Sonra", "Later"),
        example: Example {
            tr: "Otel rezervasyonu için iki bilgi eksik.",
            en: "Two details are missing for the hotel booking.",
        },
    },
    KindRule {
        meaning: "One entry of the daily digest",
        components: &[Component::Card, Component::List],
        relay_class: RelayClass::None,
        yes: answer(Effect::Open, "Aç", "Open"),
        no: answer(Effect::Dismiss, "Geç", "Skip"),
        example: Example {
            tr: "Paketin yarın geliyor.",
            en: "Your parcel arrives tomorrow.",
        },
    },
];

impl CoreKind {
    /// The fixed rules of this kind; an extension inherits the rules of its core kind (C-7).
    #[must_use]
    pub const fn rule(self) -> &'static KindRule {
        match self {
            Self::Approval => &RULES[0],
            Self::Choice => &RULES[1],
            Self::Question => &RULES[2],
            Self::Info => &RULES[3],
            Self::Progress => &RULES[4],
            Self::Receipt => &RULES[5],
            Self::Comparison => &RULES[6],
            Self::Form => &RULES[7],
            Self::DigestItem => &RULES[8],
        }
    }
}
