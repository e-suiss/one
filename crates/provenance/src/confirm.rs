//! The single place a label improves: the user's explicit confirmation of a shown value on a trusted surface lifts it to a user label, and independent second evidence lifts `external.*` only to `one.inferred` (SEC-14 (3, 5), SEC-21 (2), SEC-7, SEC-16, T-36 (3)).

use crate::label::{Label, LabelKind, TrustedLabel, UntrustedLabel};
use crate::value::{Trusted, Untrusted};

/// Where the user acted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Surface {
    /// One's trusted confirmation surface.
    TrustedSurface,
    /// A chat reply.
    Chat,
    /// A reply through a messaging channel.
    ChannelReply,
    /// A notification action button.
    NotificationAction,
    /// No user surface.
    None,
}

/// What the confirmed value becomes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Target {
    /// A memory record: the confirmed value becomes `user.memory`.
    Memory,
    /// The user's own input to the task: the confirmed value becomes `user.direct`.
    TaskInput,
}

/// Something offered as a reason to change a label.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Evidence {
    /// The user acted on a surface; `shown` is true only for the value the surface displayed.
    UserConfirmation {
        /// Where the user acted.
        surface: Surface,
        /// Whether this exact value was shown.
        shown: bool,
    },
    /// Access approved the intent; this authorises the action, not its inputs (SEC-14 (5)).
    AccessApproval,
    /// A model said the value is trusted.
    ModelOutput,
    /// The value was summarised.
    Summarise,
    /// The critic model said to continue (SEC-16).
    CriticContinue,
    /// A second piece of evidence from a different, independent source (SEC-21 (2)).
    SecondIndependentEvidence,
    /// A second copy from the same source.
    SameSourceSecondCopy,
}

/// The label after the evidence; anything but an explicit confirmation of the shown value on the trusted surface leaves it unchanged, and second evidence reaches only `one.inferred`.
#[must_use]
pub fn upgrade_label(label: &Label, evidence: Evidence, target: Target) -> Label {
    match evidence {
        Evidence::UserConfirmation {
            surface: Surface::TrustedSurface,
            shown: true,
        } => {
            let to = confirmed_label(target);
            if label.rank() < to.rank() {
                Label::Trusted(to)
            } else {
                label.clone()
            }
        }
        Evidence::SecondIndependentEvidence if target == Target::Memory => match label {
            Label::Untrusted(UntrustedLabel::External(_) | UntrustedLabel::Mixed(_)) => {
                Label::Untrusted(UntrustedLabel::OneInferred)
            }
            other => other.clone(),
        },
        _ => label.clone(),
    }
}

const fn confirmed_label(target: Target) -> TrustedLabel {
    match target {
        Target::Memory => TrustedLabel::UserMemory,
        Target::TaskInput => TrustedLabel::UserDirect,
    }
}

/// Proof that the user explicitly confirmed the shown value on the trusted surface; consumed by one [`ShownConfirmation::confirm`].
#[derive(Debug, PartialEq, Eq)]
pub struct ShownConfirmation {
    target: Target,
}

impl ShownConfirmation {
    /// The proof for a user action; `None` unless it was on the trusted surface and the value was shown.
    #[must_use]
    pub fn new(surface: Surface, shown: bool, target: Target) -> Option<Self> {
        (surface == Surface::TrustedSurface && shown).then_some(Self { target })
    }

    /// Lifts the shown untrusted value the user confirmed to `user.memory` or `user.direct`; the only conversion from [`Untrusted`] to [`Trusted`] (SEC-14 (3, 5), T-36 (3)).
    ///
    /// ```compile_fail
    /// use one_provenance::{ExternalSource, Trusted, TrustedLabel, Untrusted};
    /// let value = Untrusted::external("x", ExternalSource::Web);
    /// let _ = Trusted::with_label(value.into_value(), TrustedLabel::UserDirect);
    /// ```
    pub fn confirm<T>(self, value: Untrusted<T>) -> Confirmed<T> {
        let to = confirmed_label(self.target);
        let record = UpgradeRecord {
            from: value.label().kind(),
            to,
            target: self.target,
        };
        Confirmed {
            value: Trusted::with_label(value.into_value(), to),
            record,
        }
    }
}

/// What a confirmation changed; the caller records it (T-36 (3)).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct UpgradeRecord {
    from: LabelKind,
    to: TrustedLabel,
    target: Target,
}

impl UpgradeRecord {
    /// The label before the confirmation.
    #[must_use]
    pub const fn from(self) -> LabelKind {
        self.from
    }

    /// The label after it.
    #[must_use]
    pub const fn to(self) -> TrustedLabel {
        self.to
    }

    /// What the value became.
    #[must_use]
    pub const fn target(self) -> Target {
        self.target
    }
}

/// A confirmed value and the record of its upgrade.
#[must_use]
pub struct Confirmed<T> {
    value: Trusted<T>,
    record: UpgradeRecord,
}

impl<T> Confirmed<T> {
    /// Splits into the trusted value and the record to persist.
    pub fn into_parts(self) -> (Trusted<T>, UpgradeRecord) {
        (self.value, self.record)
    }
}

impl<T> core::fmt::Debug for Confirmed<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Confirmed")
            .field("value", &self.value)
            .field("record", &self.record)
            .finish()
    }
}

/// Whether a second piece of evidence came from a different source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SecondEvidence {
    /// A different, independent source.
    Independent,
    /// Another copy from the same source.
    SameSource,
}

/// Persists an external memory candidate by second evidence: independent evidence gives `one.inferred`, which stays untrusted (SEC-21 (2), SEC-14 (3)).
pub fn corroborate<T>(value: Untrusted<T>, evidence: SecondEvidence) -> Untrusted<T> {
    match (evidence, value.label()) {
        (SecondEvidence::Independent, UntrustedLabel::External(_) | UntrustedLabel::Mixed(_)) => {
            Untrusted::inferred(value.into_value())
        }
        _ => value,
    }
}
