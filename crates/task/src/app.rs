//! Handing a step to the Executor (CP-5, E-14): the gate decides, and only its permit reaches the port.

use one_access_client::decision::Decision;
use one_provenance::intent::Rejection;

use crate::domain::gate::{Stop, gate};
use crate::ports::Executor;

/// Why a step was not handed over.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Submit<E> {
    /// The gate stopped it.
    Stopped(Stop),
    /// The Executor did not take it.
    Executor(E),
}

/// Runs the gate for `intent` and `decision`, and hands an allowed step to `executor`.
///
/// # Errors
/// [`Submit::Stopped`] with the gate's reason, or [`Submit::Executor`].
pub fn submit<T, X: Executor<T>>(
    executor: &X,
    intent: Result<T, Rejection>,
    decision: &Decision,
) -> Result<(), Submit<X::Error>> {
    let permit = gate(intent, decision).map_err(Submit::Stopped)?;
    executor.execute(&permit).map_err(Submit::Executor)
}
