//! The capabilities component's ports: retrieval over capability examples, which is handed only the eligible names (T-27 (2), CP-17).

use std::future::Future;

use one_proto::capability::CapabilityName;

/// Why retrieval failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SearchError {
    /// The search service failed; the planner gets no candidates rather than every capability.
    Unavailable,
}

/// Retrieval over capability examples and meanings.
pub trait Search {
    /// Scores `eligible` against the user's `request`; it is never handed a capability outside them.
    fn scores(
        &mut self,
        request: &str,
        eligible: &[CapabilityName],
    ) -> impl Future<Output = Result<Vec<(CapabilityName, f64)>, SearchError>>;
}
