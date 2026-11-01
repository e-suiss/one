//! The task component's ports: the Executor, which takes only a permit (T-27 (2), E-14, CP-7).

use crate::domain::gate::Permit;

/// The Executor port: it takes only a permit, so nothing reaches it without an Access allow (E-14, CP-7).
pub trait Executor<T> {
    /// Why the Executor did not take the step.
    type Error;

    /// Hands the allowed step to the Executor.
    ///
    /// # Errors
    /// The Executor did not take it; its outcome is unknown until it reports (E-18).
    fn execute(&self, permit: &Permit<T>) -> Result<(), Self::Error>;
}
