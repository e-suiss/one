//! Fetching the discovery document (E-2, E-3, T-23): the document is read from the configured issuer with redirects refused, and an Access that does not answer with a document that verifies is unreachable, never a source of configured endpoints.

use crate::discovery::{self, Discovery, DiscoveryError};

/// Why Access counts as unreachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// No HTTP answer.
    Connect,
    /// An answer whose status is not a success.
    Status(u16),
    /// The document was refused.
    Discovery(DiscoveryError),
}

impl FetchError {
    /// The stable reason used in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Connect => "connect",
            Self::Status(_) => "status",
            Self::Discovery(_) => "discovery",
        }
    }
}

/// Fetches and verifies the discovery document of `issuer` with `client`, which must not follow redirects.
///
/// # Errors
/// [`FetchError`].
pub async fn discover(client: &reqwest::Client, issuer: &str) -> Result<Discovery, FetchError> {
    let issuer = issuer.trim_end_matches('/');
    let response = client
        .get(format!("{issuer}{}", discovery::PATH))
        .send()
        .await
        .map_err(|_| FetchError::Connect)?;
    let status = response.status();
    if !status.is_success() {
        return Err(FetchError::Status(status.as_u16()));
    }
    let body = response.bytes().await.map_err(|_| FetchError::Connect)?;
    discovery::read(issuer, &body).map_err(FetchError::Discovery)
}
