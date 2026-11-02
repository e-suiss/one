//! The Relay public API as One uses it (E-2, E-20, T-23): Relay is reachable when its readiness endpoint answers a success; the send families wait for the agent fields of E-21, and an unreachable Relay leaves records and tasks untouched.

/// The readiness path; health endpoints are outside the Relay server API.
pub const READY_PATH: &str = "/readyz";

/// Why Relay counts as unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Unreachable {
    /// No HTTP answer.
    Connect,
    /// An answer whose status is not a success.
    Status(u16),
}

impl Unreachable {
    /// The stable reason used in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Status(_) => "status",
        }
    }
}

/// Checks that Relay at `base` is ready, with `client`, which must not follow redirects.
///
/// # Errors
/// [`Unreachable`].
pub async fn ready(client: &reqwest::Client, base: &str) -> Result<(), Unreachable> {
    let status = client
        .get(format!("{}{READY_PATH}", base.trim_end_matches('/')))
        .send()
        .await
        .map_err(|_| Unreachable::Connect)?
        .status();
    if status.is_success() {
        Ok(())
    } else {
        Err(Unreachable::Status(status.as_u16()))
    }
}
