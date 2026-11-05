//! Handing over at a block (CP-32, CP-33, CP-44, SEC-22 (6)): at a CAPTCHA, a bot wall, a login or a two-factor screen the cloud browser stops and the work goes to the user through a Relay notification and waitpoint, never solved or disguised; with the user away the task waits as `waiting_user`; when the wait expires the task stops and says why, since silence is not approval; while the user holds the session no screenshot is taken and the model context is closed, and when it comes back the agent reads the page afresh and goes on only under a new Access decision.

use one_proto::ontology::Instant;
use one_proto::task::{FailureReason, StepReason, WaitReason};

/// The default wait for the user: 24 hours (CP-32).
pub const DEFAULT_WAIT_SECS: u32 = 86_400;
/// The shortest wait a user or task may set: 15 minutes.
pub const MIN_WAIT_SECS: u32 = 900;
/// The longest wait a user or task may set: 7 days.
pub const MAX_WAIT_SECS: u32 = 604_800;

/// What stopped the cloud browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Block {
    /// A CAPTCHA.
    Captcha,
    /// A bot wall.
    BotWall,
    /// A login screen.
    Login,
    /// A two-factor screen.
    TwoFactor,
}

/// The handover: what the waitpoint says and when it expires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Takeover {
    /// The waitpoint's reason.
    pub reason: WaitReason,
    /// When the wait expires.
    pub expires_at: Instant,
}

/// While the user holds the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WhileHeld {
    /// Screenshots are taken.
    pub screenshots: bool,
    /// The model sees the page.
    pub model_context: bool,
}

/// The only rule while the user holds the session: no screenshot and no model context.
pub const WHILE_HELD: WhileHeld = WhileHeld {
    screenshots: false,
    model_context: false,
};

/// The wait in seconds: the task's setting over the user's over [`DEFAULT_WAIT_SECS`], kept within [`MIN_WAIT_SECS`] and [`MAX_WAIT_SECS`].
#[must_use]
pub fn wait_secs(user: Option<u32>, task: Option<u32>) -> u32 {
    task.or(user)
        .unwrap_or(DEFAULT_WAIT_SECS)
        .clamp(MIN_WAIT_SECS, MAX_WAIT_SECS)
}

/// The handover for `block` opened at `at` with a wait of `wait` seconds; `None` only past the end of time.
#[must_use]
pub fn on_block(block: Block, at: Instant, wait: u32) -> Option<Takeover> {
    let reason = match block {
        Block::Captcha | Block::BotWall => WaitReason::Takeover,
        Block::Login | Block::TwoFactor => WaitReason::Authentication,
    };
    let expires = at.unix_secs().checked_add(i64::from(wait))?;
    Some(Takeover {
        reason,
        expires_at: Instant::from_unix(expires),
    })
}

/// Why the step and the task end when the wait expired.
#[must_use]
pub const fn on_expiry(block: Block) -> (StepReason, FailureReason) {
    match block {
        Block::Captcha | Block::BotWall => (StepReason::WaitExpired, FailureReason::BlockedBySite),
        Block::Login | Block::TwoFactor => {
            (StepReason::WaitExpired, FailureReason::CriterionUnreachable)
        }
    }
}
