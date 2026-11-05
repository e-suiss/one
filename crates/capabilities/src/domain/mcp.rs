//! MCP version and token rules (CP-23, CP-24, SEC-25): One's client talks to servers of the versions in [`SUPPORTED`] at the highest version both sides know, while Suiss's own servers speak only [`LATEST`]; One never declares sampling, roots or logging; on every version a request carries only an Access-issued token bound to that server's resource (RFC 8707) and never passes through an upstream token, so an older version never loosens a rule.

/// The MCP versions One's client speaks, oldest first.
pub const SUPPORTED: [&str; 3] = ["2025-06-18", "2025-11-25", "2026-07-28"];

/// The only version Suiss's own servers speak.
pub const LATEST: &str = "2026-07-28";

/// A client feature.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Feature {
    /// Elicitation, under the CP-30 rules.
    Elicitation,
    /// Sampling: never used.
    Sampling,
    /// Roots: never used.
    Roots,
    /// Logging: never used.
    Logging,
}

/// The features One never declares.
pub const NEVER: [Feature; 3] = [Feature::Sampling, Feature::Roots, Feature::Logging];

/// The version to speak with a server offering `offered`: the highest both know.
#[must_use]
pub fn negotiate(offered: &[&str]) -> Option<&'static str> {
    SUPPORTED
        .iter()
        .rev()
        .copied()
        .find(|v| offered.contains(v))
}

/// The authorization a request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Authorization<'a> {
    /// None.
    None,
    /// An Access-issued token bound to this audience.
    Access {
        /// Its audience.
        audience: &'a str,
    },
    /// An upstream token passed through: never.
    Upstream,
}

/// An outgoing MCP request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Request<'a> {
    /// The negotiated version.
    pub version: &'a str,
    /// The client features it declares.
    pub features: &'a [Feature],
    /// Its authorization.
    pub authorization: Authorization<'a>,
}

/// Why a request is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A version One does not speak.
    Version,
    /// A feature One never declares.
    Feature(Feature),
    /// A token bound to another resource.
    Audience,
    /// An upstream token passed through.
    Passthrough,
}

/// Checks `request` to the server at `resource`; the same rules hold on every version.
///
/// # Errors
/// The first [`Refused`] reason.
pub fn check(resource: &str, request: &Request<'_>) -> Result<(), Refused> {
    if !SUPPORTED.contains(&request.version) {
        return Err(Refused::Version);
    }
    if let Some(f) = request.features.iter().find(|f| NEVER.contains(f)) {
        return Err(Refused::Feature(*f));
    }
    match request.authorization {
        Authorization::Upstream => Err(Refused::Passthrough),
        Authorization::Access { audience } if audience != resource => Err(Refused::Audience),
        Authorization::None | Authorization::Access { .. } => Ok(()),
    }
}
