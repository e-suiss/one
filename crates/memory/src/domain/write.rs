//! Write admission (M-15, M-16, M-18, M-33, PV-21): an explicit "remember" is active and stated at once, background inference is active and inferred except a sensitive record or a behaviour rule, which waits as a candidate, and external content or an import is always a candidate that can never become a behaviour rule; the path must match the record's source kind, so external content or an import cannot come in as a remember or an inference; during a conversation only an explicit "remember" writes, and an ephemeral session writes nothing.

use one_proto::memory::fields::{EpistemicState, Layer, LiveStatus, SourceKind};
use one_proto::ontology::time::Instant;

/// How a record reaches memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum WritePath {
    /// The user said "remember".
    ExplicitRemember,
    /// One inferred it after the session or in the daily consolidation.
    BackgroundInference,
    /// It came from external content.
    ExternalContent,
    /// It came from an import.
    Import,
}

/// When the write happens.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Moment {
    /// While the user is in the conversation, on the hot path.
    Conversation,
    /// After the session or in the daily consolidation.
    Background,
}

/// The session the write comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Session {
    /// A normal session.
    Normal,
    /// An ephemeral session: memory is read, never written (M-33).
    Ephemeral,
}

/// Why a write is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum WriteError {
    /// The session is ephemeral.
    #[error("an ephemeral session writes no memory")]
    Ephemeral,
    /// Only an explicit "remember" writes during a conversation.
    #[error("only an explicit remember writes during a conversation")]
    HotPath,
    /// External content and imports never become behaviour rules.
    #[error("external content never becomes a behaviour rule")]
    OutsideRule,
    /// The write path does not match the record's source kind.
    #[error("the write path does not match the source kind")]
    SourceMismatch,
}

/// Whether `path` may carry a record whose source kind is `source`: an explicit remember is a user statement, external content and imports come only along their own path, and an inference is from anything else.
#[must_use]
pub const fn path_fits(path: WritePath, source: SourceKind) -> bool {
    match path {
        WritePath::ExplicitRemember => matches!(source, SourceKind::UserStatement),
        WritePath::ExternalContent => matches!(source, SourceKind::ExternalContent),
        WritePath::Import => matches!(source, SourceKind::Import),
        WritePath::BackgroundInference => {
            !matches!(source, SourceKind::ExternalContent | SourceKind::Import)
        }
    }
}

/// Refuses a write from an ephemeral session (M-33).
///
/// # Errors
/// [`WriteError::Ephemeral`].
pub fn writable(session: Session) -> Result<(), WriteError> {
    if session == Session::Ephemeral {
        Err(WriteError::Ephemeral)
    } else {
        Ok(())
    }
}

/// The lifecycle and epistemic state a new record starts in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Admitted {
    /// Lifecycle.
    pub status: LiveStatus,
    /// Epistemic state.
    pub epistemic_state: EpistemicState,
}

/// Admits a write of a record in `layer` along `path` at `moment` in `session`; `sensitive` is a record in a sensitive data class.
///
/// # Errors
/// [`WriteError`].
pub fn admit(
    session: Session,
    moment: Moment,
    path: WritePath,
    layer: Layer,
    sensitive: bool,
) -> Result<Admitted, WriteError> {
    writable(session)?;
    if moment == Moment::Conversation && path != WritePath::ExplicitRemember {
        return Err(WriteError::HotPath);
    }
    let (status, epistemic_state) = match path {
        WritePath::ExplicitRemember => (LiveStatus::Active, EpistemicState::Stated),
        WritePath::BackgroundInference if sensitive || layer == Layer::BehaviourRule => {
            (LiveStatus::Candidate, EpistemicState::Inferred)
        }
        WritePath::BackgroundInference => (LiveStatus::Active, EpistemicState::Inferred),
        WritePath::ExternalContent | WritePath::Import => {
            if layer == Layer::BehaviourRule {
                return Err(WriteError::OutsideRule);
            }
            (LiveStatus::Candidate, EpistemicState::Hypothesis)
        }
    };
    Ok(Admitted {
        status,
        epistemic_state,
    })
}

/// How long a `current` record is expected to hold when nobody said, in days (M-22).
pub const CURRENT_DAYS: i64 = 90;

/// The default expected end of a `current` record that starts at `valid_from` (M-22).
#[must_use]
pub fn default_expected_end(valid_from: &Instant) -> Instant {
    Instant::from_unix(
        valid_from
            .unix_secs()
            .saturating_add(CURRENT_DAYS.saturating_mul(86_400)),
    )
}
