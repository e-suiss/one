//! Value types of the One Federation extension: `did:web` identifiers, parties, `UUIDv7` message and chain identifiers, digests, schema versions, authority references, message kinds, decline reasons and refusal codes (OO-3, OO-15, OO-16).

use serde::{Deserialize, Serialize};

use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;

/// The One Federation extension URI.
pub const EXTENSION_URI: &str = "https://suiss.app/a2a/one-federation/v1";

/// The extension URI as a wire constant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExtensionUri {
    /// `https://suiss.app/a2a/one-federation/v1`.
    #[serde(rename = "https://suiss.app/a2a/one-federation/v1")]
    OneFederationV1,
}

/// The single-entry `extensions` list of a message or artifact.
pub type Extensions = [ExtensionUri; 1];

/// The `extensions` list naming only this extension.
pub const EXTENSIONS: Extensions = [ExtensionUri::OneFederationV1];

fn is_b64url(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_host_label(label: &str) -> bool {
    let b = label.as_bytes();
    let edge = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=63).contains(&b.len())
        && b.first().is_some_and(edge)
        && b.last().is_some_and(edge)
        && b.iter().all(|c| edge(c) || *c == b'-')
}

fn is_did_web(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("did:web:") else {
        return false;
    };
    let mut segments = rest.split(':');
    let authority = segments.next().unwrap_or_default();
    let (host, port) = match authority.split_once("%3A") {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    s.len() <= 512
        && host.split('.').count() >= 2
        && host.split('.').all(is_host_label)
        && port.is_none_or(|p| (1..=5).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_digit()))
        && segments.all(|seg| {
            !seg.is_empty()
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
        })
}

fn is_uuid7(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 36
        && b.iter().enumerate().all(|(i, c)| match i {
            8 | 13 | 18 | 23 => *c == b'-',
            14 => *c == b'7',
            19 => matches!(c, b'8' | b'9' | b'a' | b'b'),
            _ => c.is_ascii_digit() || (b'a'..=b'f').contains(c),
        })
}

checked_string!(
    /// A `did:web` identifier of a person, organisation or agent.
    Did,
    "did",
    is_did_web
);

checked_string!(
    /// A lower-case RFC 9562 version 7 UUID: A2A `messageId`, the Work correlation identifier, a handle `jti`.
    Uuid7,
    "uuid7",
    is_uuid7
);

checked_string!(
    /// SHA-256 over the JCS form of a message, `sha-256:` and unpadded base64url.
    Digest,
    "digest",
    |s| s
        .strip_prefix("sha-256:")
        .is_some_and(|d| d.len() == 43 && is_b64url(d))
);

checked_string!(
    /// The extension schema version `1.MINOR`.
    SchemaVersion,
    "schemaVersion",
    |s| s.strip_prefix("1.").is_some_and(|minor| {
        minor == "0"
            || ((1..=4).contains(&minor.len())
                && !minor.starts_with('0')
                && minor.bytes().all(|b| b.is_ascii_digit()))
    })
);

impl SchemaVersion {
    /// The minor version.
    #[must_use]
    pub fn minor(&self) -> u16 {
        self.as_str()
            .strip_prefix("1.")
            .and_then(|m| m.parse().ok())
            .unwrap_or(0)
    }
}

/// The highest schema version both peers declare in their Agent Card (OO-4).
#[must_use]
pub fn highest_common_schema_version<'a>(
    ours: &'a [SchemaVersion],
    theirs: &[SchemaVersion],
) -> Option<&'a SchemaVersion> {
    ours.iter()
        .filter(|v| theirs.contains(v))
        .max_by_key(|v| v.minor())
}

checked_string!(
    /// A resolvable authority proof reference, `https://` or `urn:`.
    AuthorityUri,
    "authority ref",
    |s| (8..=1024).contains(&s.len()) && (s.starts_with("https://") || s.starts_with("urn:"))
);

checked_string!(
    /// An A2A task or artifact identifier.
    A2aId,
    "A2A id",
    |s| (1..=128).contains(&s.len())
);

checked_string!(
    /// A BCP 47 language tag.
    LangTag,
    "lang",
    |s| {
        let mut parts = s.split('-');
        parts
            .next()
            .is_some_and(|p| (2..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase()))
            && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    }
);

checked_string!(
    /// A suspended-negotiation handle in JWE compact form with an empty encrypted key (OO-5).
    HandleCompact,
    "handle",
    |s| {
        let parts: alloc::vec::Vec<&str> = s.split('.').collect();
        s.len() <= 2048
            && matches!(
                parts.as_slice(),
                [header, "", iv, ciphertext, tag]
                    if (16..=256).contains(&header.len())
                        && iv.len() == 16
                        && (16..=1600).contains(&ciphertext.len())
                        && tag.len() == 22
                        && is_b64url(header)
                        && is_b64url(iv)
                        && is_b64url(ciphertext)
                        && is_b64url(tag)
            )
    }
);

/// A person and the agent acting for that person (OO-3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Party {
    /// The person's or organisation's identifier.
    pub person: Did,
    /// The agent acting for the person.
    pub agent: Did,
}

/// The authority proof the recipient verifies at Access (OO-3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorityRef {
    /// The resolvable reference.
    #[serde(rename = "ref")]
    pub reference: AuthorityUri,
    /// The digest of the proof.
    pub digest: Digest,
}

/// A typed message kind (OO-15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// Proposes something.
    Offer,
    /// Replaces the open offer with a new version.
    CounterOffer,
    /// Accepts and promises.
    Commitment,
    /// Rejects with a reason code.
    Rejection,
    /// Asks for information.
    Query,
    /// Answers a query.
    Answer,
}

/// A rejection reason; mirrors the Work decline reasons (OD-63 #8).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DeclineReason {
    /// No capacity.
    NoCapacity,
    /// No authority.
    NoAuthority,
    /// Out of scope.
    OutOfScope,
    /// Information is missing.
    MissingInformation,
    /// The terms are unacceptable.
    UnacceptableTerms,
    /// Other.
    Other,
}

/// A protocol-level refusal of a received message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Refusal {
    /// The message breaks the schema.
    SchemaInvalid,
    /// The extension was not activated.
    ExtensionNotActivated,
    /// The schema version is not supported.
    SchemaVersionUnsupported,
    /// The body kind, capability or kind does not match.
    KindMismatch,
    /// The correlation identifier does not match.
    CorrelationMismatch,
    /// The identities do not match.
    IdentityMismatch,
    /// The authority proof does not verify.
    AuthorityInvalid,
    /// The offer version does not advance by exactly one.
    VersionNotMonotonic,
    /// The reply names another version.
    ReplyVersionMismatch,
    /// The reply names another digest.
    DigestMismatch,
    /// The answered message expired.
    OfferExpired,
    /// The expiry is not after the send time or more than 7 days after it.
    ExpiryInvalid,
    /// No Work operation is permitted for the message.
    OperationNotPermitted,
    /// A note cannot become a field value.
    NoteNotConvertible,
    /// The reply carries no handle.
    HandleMissing,
    /// The handle is malformed.
    HandleMalformed,
    /// The handle fails AEAD verification.
    HandleTampered,
    /// The handle expired.
    HandleExpired,
    /// The handle was already used.
    HandleReplayed,
    /// The handle is bound to other parties, chain or version.
    HandleBindingMismatch,
    /// The handle is bound to another message digest.
    HandleDigestMismatch,
    /// First contact is not permitted.
    FirstContactNotPermitted,
}

impl From<ContractViolation> for Refusal {
    fn from(_: ContractViolation) -> Self {
        Self::SchemaInvalid
    }
}
