//! PIN guess rules of one vault realm: the limit (default 10, lowered by the user to no less than 3, never raised), the waits after the fifth to ninth failure, reset on success and destruction when the limit is reached (PV-12, PV-13, PV-14).

use one_proto::recovery::{DEFAULT_MAX_GUESSES, MIN_MAX_GUESSES};

/// The waits after the fifth to ninth failed guess, in seconds (PV-12).
pub const WAITS_AFTER_FAILURE: [(u8, u64); 5] =
    [(5, 60), (6, 600), (7, 3_600), (8, 21_600), (9, 86_400)];

/// The wait that follows the `failures`-th consecutive failed guess, if any.
#[must_use]
pub fn wait_after_failure(failures: u8) -> Option<u64> {
    WAITS_AFTER_FAILURE
        .iter()
        .find(|(n, _)| *n == failures)
        .map(|(_, secs)| *secs)
}

/// A guess limit between 3 and 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct GuessLimit(u8);

/// Why a guess limit change is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LimitRefusal {
    /// Below the floor of 3.
    BelowFloor,
    /// Above the current limit: the user only lowers it.
    RaiseNotAllowed,
}

impl LimitRefusal {
    /// The reason as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BelowFloor => "below_floor",
            Self::RaiseNotAllowed => "raise_not_allowed",
        }
    }
}

impl GuessLimit {
    /// The limit a vault starts with.
    pub const DEFAULT: Self = Self(DEFAULT_MAX_GUESSES);

    /// A stored limit.
    ///
    /// # Errors
    /// Outside 3 to 10.
    pub const fn new(value: u8) -> Result<Self, LimitRefusal> {
        if value < MIN_MAX_GUESSES {
            Err(LimitRefusal::BelowFloor)
        } else if value > DEFAULT_MAX_GUESSES {
            Err(LimitRefusal::RaiseNotAllowed)
        } else {
            Ok(Self(value))
        }
    }

    /// The limit as a number.
    #[must_use]
    pub const fn get(self) -> u8 {
        self.0
    }

    /// The user's change from `self` to `requested`.
    ///
    /// # Errors
    /// [`LimitRefusal::BelowFloor`] under 3, [`LimitRefusal::RaiseNotAllowed`] above the current limit.
    pub const fn lower_to(self, requested: u8) -> Result<Self, LimitRefusal> {
        if requested < MIN_MAX_GUESSES {
            Err(LimitRefusal::BelowFloor)
        } else if requested > self.0 {
            Err(LimitRefusal::RaiseNotAllowed)
        } else {
            Ok(Self(requested))
        }
    }
}

/// The result of one guess presented to a realm.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum GuessResult {
    /// Inside a wait: refused and not counted.
    Wait {
        /// Seconds until a guess is taken again.
        retry_after: u64,
    },
    /// The PIN was right; the counter is back to zero.
    Recovered,
    /// The PIN was wrong.
    Failed {
        /// Guesses left.
        remaining: u8,
        /// The wait that now applies, in seconds.
        wait: Option<u64>,
    },
    /// The limit is reached: the realm deletes its record.
    Destroyed,
}

/// One realm's guess counter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct GuessCounter {
    limit: GuessLimit,
    used: u8,
    last_failure_at: Option<u64>,
}

impl GuessCounter {
    /// A fresh counter.
    #[must_use]
    pub const fn new(limit: GuessLimit) -> Self {
        Self {
            limit,
            used: 0,
            last_failure_at: None,
        }
    }

    /// Consecutive failures counted.
    #[must_use]
    pub const fn used(&self) -> u8 {
        self.used
    }

    /// Guesses left.
    #[must_use]
    pub const fn remaining(&self) -> u8 {
        self.limit.get().saturating_sub(self.used)
    }

    /// Whether the record is gone.
    #[must_use]
    pub const fn destroyed(&self) -> bool {
        self.used >= self.limit.get()
    }

    /// Seconds until a guess is taken at `now`; zero when none applies.
    #[must_use]
    pub fn retry_after(&self, now: u64) -> u64 {
        match (self.last_failure_at, wait_after_failure(self.used)) {
            (Some(at), Some(wait)) => at.saturating_add(wait).saturating_sub(now),
            _ => 0,
        }
    }

    /// Presents a guess at `now`; `correct` is whether it matched.
    pub fn guess(&mut self, now: u64, correct: bool) -> GuessResult {
        if self.destroyed() {
            return GuessResult::Destroyed;
        }
        let retry_after = self.retry_after(now);
        if retry_after > 0 {
            return GuessResult::Wait { retry_after };
        }
        if correct {
            self.used = 0;
            self.last_failure_at = None;
            return GuessResult::Recovered;
        }
        self.used = self.used.saturating_add(1);
        self.last_failure_at = Some(now);
        if self.destroyed() {
            GuessResult::Destroyed
        } else {
            GuessResult::Failed {
                remaining: self.remaining(),
                wait: wait_after_failure(self.used),
            }
        }
    }
}
