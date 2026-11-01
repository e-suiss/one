//! The Access discovery document (L1-ADP-11, E-3): endpoints come from `/.well-known/authzen-configuration`, never from configuration; a document from another issuer, an endpoint on another origin or one without the ADP capability is refused, and One does not start without it (E-2).

use serde_json::Value;

/// The discovery path.
pub const PATH: &str = "/.well-known/authzen-configuration";

/// The capability every Access domain One talks to must announce.
pub const ADP_CAPABILITY: &str = "urn:esuiss:access:adp:1";

/// A verified discovery document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// The issuer the document was fetched from.
    pub issuer: String,
    /// The evaluation endpoint.
    pub evaluation: String,
    /// The batch endpoint.
    pub evaluations: Option<String>,
    /// The announced capabilities.
    pub capabilities: Vec<String>,
}

/// Why a discovery document is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DiscoveryError {
    /// The body is not a discovery document.
    Malformed,
    /// `policy_decision_point` is not the issuer it was fetched from.
    Issuer,
    /// An endpoint is not under the issuer's origin.
    Origin,
    /// `urn:esuiss:access:adp:1` is not announced.
    Capability,
}

fn origin(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let end = rest.find('/').unwrap_or(rest.len());
    let host = rest.get(..end)?;
    if host.is_empty() {
        None
    } else {
        url.get(..end.checked_add(8)?)
    }
}

fn same_origin(issuer: &str, endpoint: &str) -> Result<(), DiscoveryError> {
    match (origin(issuer), origin(endpoint)) {
        (Some(a), Some(b)) if a == b => Ok(()),
        _ => Err(DiscoveryError::Origin),
    }
}

/// Reads the document `body` fetched from `issuer`.
///
/// # Errors
/// [`DiscoveryError`].
pub fn read(issuer: &str, body: &[u8]) -> Result<Discovery, DiscoveryError> {
    let v: Value = serde_json::from_slice(body).map_err(|_| DiscoveryError::Malformed)?;
    let field = |name: &str| v.get(name).and_then(Value::as_str).map(str::to_owned);
    let pdp = field("policy_decision_point").ok_or(DiscoveryError::Malformed)?;
    if pdp.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err(DiscoveryError::Issuer);
    }
    let evaluation = field("access_evaluation_endpoint").ok_or(DiscoveryError::Malformed)?;
    same_origin(issuer, &evaluation)?;
    let evaluations = field("access_evaluations_endpoint");
    if let Some(e) = &evaluations {
        same_origin(issuer, e)?;
    }
    let capabilities: Vec<String> = v
        .get("capabilities")
        .and_then(Value::as_array)
        .ok_or(DiscoveryError::Malformed)?
        .iter()
        .map(|c| {
            c.as_str()
                .map(str::to_owned)
                .ok_or(DiscoveryError::Malformed)
        })
        .collect::<Result<_, _>>()?;
    if !capabilities.iter().any(|c| c == ADP_CAPABILITY) {
        return Err(DiscoveryError::Capability);
    }
    Ok(Discovery {
        issuer: pdp,
        evaluation,
        evaluations,
        capabilities,
    })
}
