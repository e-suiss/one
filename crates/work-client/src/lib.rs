//! The Work public API as One uses it (E-2, T-23): Work publishes no API and no health endpoint yet, so Work is reachable when its base URL answers HTTP at all; an unreachable Work keeps new commitments in the outbox.

/// Why Work counts as unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// No HTTP answer.
    Connect,
}

impl Unreachable {
    /// The stable reason used in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
        }
    }
}

/// Checks that Work at `base` answers, with `client`, which must not follow redirects.
///
/// # Errors
/// [`Unreachable`].
pub async fn reachable(client: &reqwest::Client, base: &str) -> Result<(), Unreachable> {
    client
        .get(base)
        .send()
        .await
        .map(|_| ())
        .map_err(|_| Unreachable::Connect)
}
