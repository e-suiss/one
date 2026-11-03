//! The personal adapter's versions `adapter/v1` (MF-31, MF-34, MF-35): a candidate becomes active only when the personality regression, the user's held-out examples and the One behaviour safety set all passed; one previous version is kept for "back to the earlier style", older ones are shredded; forgetting and reset shred every version.

/// The first training needs at least this many eligible examples.
pub const FIRST_TRAINING_MIN_EXAMPLES: u64 = 500;
/// The first training needs at least this many days since the first eligible example.
pub const FIRST_TRAINING_MIN_DAYS: u64 = 14;

/// Whether the first adapter training is due (MF-31).
#[must_use]
pub const fn first_training_due(examples: u64, days: u64) -> bool {
    examples >= FIRST_TRAINING_MIN_EXAMPLES && days >= FIRST_TRAINING_MIN_DAYS
}

/// The three activation gates; `None` is a result that is not in yet and fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Gates {
    /// The personality regression against the user's profile.
    pub personality: Option<bool>,
    /// No regression on the user's own held-out examples.
    pub held_out: Option<bool>,
    /// No regression on the One behaviour safety set.
    pub safety: Option<bool>,
}

impl Gates {
    /// Whether every gate passed.
    #[must_use]
    pub const fn passed(&self) -> bool {
        matches!(
            (self.personality, self.held_out, self.safety),
            (Some(true), Some(true), Some(true))
        )
    }
}

/// The adapter versions in use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Versions<V> {
    /// The active version.
    pub active: Option<V>,
    /// The version kept for going back.
    pub previous: Option<V>,
}

impl<V> Default for Versions<V> {
    fn default() -> Self {
        Self {
            active: None,
            previous: None,
        }
    }
}

/// What a step did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// The candidate became active.
    Activated,
    /// The candidate failed a gate and is shredded.
    Rejected,
    /// The previous version is active again.
    Reverted,
    /// Nothing changed.
    Unchanged,
    /// Every version is shredded; a retraining from the remaining data is due.
    Retrain,
    /// Every version is shredded; the starting models are back.
    Reset,
}

/// The result of a step: the new versions and the versions whose keys are shredded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step<V> {
    /// The versions after the step.
    pub versions: Versions<V>,
    /// The versions to shred, active first.
    pub shredded: Vec<V>,
    /// What happened.
    pub outcome: Outcome,
}

impl<V> Versions<V> {
    /// Offers the trained `candidate` with its gate results.
    #[must_use]
    pub fn offer(self, candidate: V, gates: Gates) -> Step<V> {
        if !gates.passed() {
            return Step {
                versions: self,
                shredded: vec![candidate],
                outcome: Outcome::Rejected,
            };
        }
        Step {
            shredded: self.previous.into_iter().collect(),
            versions: Self {
                active: Some(candidate),
                previous: self.active,
            },
            outcome: Outcome::Activated,
        }
    }

    /// Goes back to the previous version; the version left is shredded.
    #[must_use]
    pub fn revert(self) -> Step<V> {
        match self.previous {
            Some(previous) => Step {
                shredded: self.active.into_iter().collect(),
                versions: Self {
                    active: Some(previous),
                    previous: None,
                },
                outcome: Outcome::Reverted,
            },
            None => Step {
                versions: self,
                shredded: Vec::new(),
                outcome: Outcome::Unchanged,
            },
        }
    }

    /// A permanent forget: every version may hold the forgotten record and is shredded (MF-35).
    #[must_use]
    pub fn forget(self) -> Step<V> {
        self.clear(Outcome::Retrain)
    }

    /// "Reset my personal model".
    #[must_use]
    pub fn reset(self) -> Step<V> {
        self.clear(Outcome::Reset)
    }

    fn clear(self, outcome: Outcome) -> Step<V> {
        Step {
            shredded: self.active.into_iter().chain(self.previous).collect(),
            versions: Self::default(),
            outcome,
        }
    }
}
