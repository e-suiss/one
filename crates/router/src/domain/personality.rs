//! The personality regression `personality-regression/v1` (MF-48, MF-34, MD-9): five profile dimensions in `0..=1`; a configuration passes when every dimension reaches the floor and none drops more than the allowed amount from the active one; a change of the significant size in any dimension is announced.

use one_proto::memory::trust::round6;

/// Every dimension must reach this share.
pub const FLOOR: f64 = 0.9;
/// No dimension may drop more than this from the active configuration.
pub const MAX_DROP: f64 = 0.02;
/// A change this large in any dimension is announced.
pub const SIGNIFICANT: f64 = 0.1;

/// The share of profile checks a configuration satisfies, per dimension.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Scores {
    /// Form of address.
    pub address: f64,
    /// Tone.
    pub tone: f64,
    /// Answer length and format.
    pub length: f64,
    /// Values and approved rules.
    pub rules: f64,
    /// The same personality in Turkish and English.
    pub bilingual: f64,
}

impl Scores {
    const fn all(&self) -> [f64; 5] {
        [
            self.address,
            self.tone,
            self.length,
            self.rules,
            self.bilingual,
        ]
    }

    fn minus(&self, other: &Self) -> Self {
        Self {
            address: round6(self.address - other.address),
            tone: round6(self.tone - other.tone),
            length: round6(self.length - other.length),
            rules: round6(self.rules - other.rules),
            bilingual: round6(self.bilingual - other.bilingual),
        }
    }
}

/// The regression verdict.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Regression {
    /// The candidate passes.
    pub passes: bool,
    /// The difference is significant and is announced.
    pub significant: bool,
    /// Candidate minus active, when a version is active.
    pub delta: Option<Scores>,
}

/// Compares `candidate` with the `active` configuration.
#[must_use]
pub fn compare(candidate: &Scores, active: Option<&Scores>) -> Regression {
    let delta = active.map(|a| candidate.minus(a));
    let floor = candidate.all().iter().all(|s| *s >= FLOOR);
    let drop = delta.is_some_and(|d| d.all().iter().any(|x| *x < -MAX_DROP));
    Regression {
        passes: floor && !drop,
        significant: delta.is_some_and(|d| d.all().iter().any(|x| x.abs() >= SIGNIFICANT)),
        delta,
    }
}
