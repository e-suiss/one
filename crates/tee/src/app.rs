//! Trusting a node: its report verified and normalized through the `Attestation` port, then checked against the policy at the `Clock` port's time (SEC-27, PV-11).

use one_proto::ontology::Instant;
use one_runtime::Clock;

use crate::domain::attestation::{Evidence, Policy, Rejection, verify};
use crate::ports::Attestation;

/// Why a node is not trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustError<E> {
    /// The report's signature or chain did not verify.
    Report(E),
    /// The claims do not meet the policy.
    Rejected(Rejection),
}

/// The current time of `clock` as an instant.
#[must_use]
pub fn now(clock: &dyn Clock) -> Instant {
    Instant::from_unix(i64::try_from(clock.now().0 / 1_000_000_000).unwrap_or(i64::MAX))
}

/// Verifies a node's report and checks its claims; `policy.now` is replaced by the clock's time.
///
/// # Errors
/// [`TrustError::Report`] or [`TrustError::Rejected`].
pub fn trust_node<A: Attestation + ?Sized>(
    clock: &dyn Clock,
    attestation: &A,
    raw_report: &[u8],
    chain: &[Vec<u8>],
    policy: &Policy<'_>,
) -> Result<Evidence, TrustError<A::Error>> {
    let evidence = attestation
        .normalize(raw_report, chain)
        .map_err(TrustError::Report)?;
    let policy = Policy {
        now: now(clock),
        ..*policy
    };
    verify(&evidence, &policy).map_err(TrustError::Rejected)?;
    Ok(evidence)
}
