//! Signed capability packages (CP-21, SEC-24 (2)): a curated package's manifest is JCS JSON carrying a detached Ed25519 `COSE_Sign1` by a Suiss catalog key with the content type [`CONTENT_TYPE`]; a package whose signature does not verify, or that two different Suiss reviewers did not both pass, never enters the catalog; a package acting outside the permissions it declares (origins it may reach, whether it writes) is refused and closed.

use one_proto::ontology::JsonValue;
use one_proto::task::Origin;
use one_proto::task::common::Sha256Digest;
use one_provenance::intent::jcs::{canonicalize, sha256_digest};
use suiss_crypto::aws::AwsLcBackend;
use suiss_crypto::cose::{self, Algorithm, KeySet, PublicKey};
use suiss_crypto::digest::sha256;

/// The `COSE_Sign1` content type of a capability package manifest.
pub const CONTENT_TYPE: &str = "application/one-capability-package+json";

/// Why a package is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    /// A catalog key is not a valid Ed25519 key.
    Key,
    /// The manifest cannot be put in JCS form.
    Manifest,
    /// The signature does not verify under a catalog key.
    Signature,
    /// It lacks two different reviewers.
    Review,
}

/// The Suiss catalog keys, Ed25519 only.
#[derive(Debug, Clone)]
pub struct CatalogKeys(KeySet);

impl CatalogKeys {
    /// The key set holding `keys`, each under the SHA-256 of its public key as its `kid`.
    ///
    /// # Errors
    /// [`Refused::Key`] for a key that is not a valid Ed25519 point.
    pub fn new(keys: impl IntoIterator<Item = [u8; 32]>) -> Result<Self, Refused> {
        let mut set = KeySet::default();
        for key in keys {
            set.insert(sha256(&key), PublicKey::Ed25519(key))
                .map_err(|_| Refused::Key)?;
        }
        set.allowed.insert(Algorithm::Ed25519);
        Ok(Self(set))
    }
}

/// A package that passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Admitted {
    /// The manifest's `sha256:` digest.
    pub manifest: Sha256Digest,
    /// The catalog key that signed it.
    pub kid: [u8; 32],
}

/// Admits a package with `manifest`, its detached `signature` and the two `reviewers` who passed it.
///
/// # Errors
/// [`Refused`] with the first check that failed: the reviewers, the manifest form, then the signature.
pub fn admit(
    keys: &CatalogKeys,
    manifest: &JsonValue,
    signature: &[u8],
    reviewers: [&str; 2],
) -> Result<Admitted, Refused> {
    let [first, second] = reviewers;
    if first.is_empty() || second.is_empty() || first == second {
        return Err(Refused::Review);
    }
    let canonical = canonicalize(manifest).ok_or(Refused::Manifest)?;
    let digest = sha256_digest(manifest).ok_or(Refused::Manifest)?;
    let verified = cose::verify_sign1_detached(
        &AwsLcBackend,
        signature,
        canonical.as_bytes(),
        &keys.0,
        CONTENT_TYPE,
    )
    .map_err(|_| Refused::Signature)?;
    Ok(Admitted {
        manifest: digest,
        kid: verified.kid,
    })
}

/// The permissions a package declares.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Declaration {
    /// The origins it may reach.
    pub origins: Vec<Origin>,
    /// Whether it writes.
    pub writes: bool,
}

/// What a package was seen doing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Behaviour {
    /// It reached an origin.
    Reached(Origin),
    /// It wrote.
    Wrote,
}

/// Whether `seen` stays inside `declared`; anything outside is a reason to refuse and close the package.
#[must_use]
pub fn within(declared: &Declaration, seen: &Behaviour) -> bool {
    match seen {
        Behaviour::Reached(origin) => declared.origins.contains(origin),
        Behaviour::Wrote => declared.writes,
    }
}
