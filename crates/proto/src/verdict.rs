//! A normative decision is a typed result, not an error: Access `DENY` and `REQUIRE_ACTION`, a router "wait", an attention "to summary", a quarantine schema rejection and an unverified attestation are [`Verdict::Decided`] and never count as errors (T-28 (6)).

/// The result of an operation that may end in a normative decision.
#[derive(Debug, Clone, PartialEq, Eq)]
#[must_use]
pub enum Verdict<T, D> {
    /// The operation went ahead and produced `T`.
    Proceed(T),
    /// A rule decided the outcome; `D` says which decision.
    Decided(D),
}

impl<T, D> Verdict<T, D> {
    /// The value when the operation went ahead.
    pub fn proceeded(self) -> Option<T> {
        match self {
            Self::Proceed(value) => Some(value),
            Self::Decided(_) => None,
        }
    }

    /// The decision when a rule decided.
    pub fn decision(self) -> Option<D> {
        match self {
            Self::Proceed(_) => None,
            Self::Decided(decision) => Some(decision),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum Access {
        Deny,
    }

    #[test]
    fn t_28_decision_is_not_an_error() {
        let denied: Verdict<u8, Access> = Verdict::Decided(Access::Deny);
        assert_eq!(denied.clone().proceeded(), None);
        assert_eq!(denied.decision(), Some(Access::Deny));
        assert_eq!(Verdict::<u8, Access>::Proceed(3).proceeded(), Some(3));
    }
}
