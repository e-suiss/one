//! The versioned privacy promise of `conformance/privacy/promise.schema.json`, the narrowing and widening classifier over its tuples, the change rule and the record's promise version (PV-19, INV-26, Access E60).

use alloc::collections::BTreeSet;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use serde::{Deserialize, Serialize};

use crate::ontology::{Instant, JsonValue};

/// The data a tuple speaks about.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataCategory {
    /// Memory records.
    Memory,
    /// Episodes.
    Episodes,
    /// The behaviour profile.
    Personality,
    /// Personal models.
    PersonalModels,
    /// Task plans.
    TaskPlans,
    /// Raw observations.
    Observations,
    /// The sensitive classes.
    Sensitive,
    /// Model provider traces.
    ProviderTrace,
    /// Browser profiles.
    BrowserProfile,
    /// Export packages.
    ExportPackage,
    /// The plain operational metadata of PV-6.
    OperationalMetadata,
}

/// Why the data is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessingPurpose {
    /// Answering the user's requests.
    ServeRequests,
    /// Memory consolidation.
    Consolidation,
    /// Personal training.
    PersonalTraining,
    /// Re-embedding.
    Reembedding,
    /// Triggers.
    Triggers,
    /// One↔One replies.
    OneToOneReply,
    /// Data subject requests.
    SubjectRequest,
    /// Browser tasks.
    BrowserTasks,
    /// The routing trace.
    RoutingTrace,
    /// Export.
    Export,
    /// Operating the service.
    Operations,
}

/// Where the data is processed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Location {
    /// The user's device.
    UserDevice,
    /// An attested TEE.
    AttestedTee,
    /// The Executor microVM.
    ExecutorMicrovm,
    /// The encrypted store.
    EncryptedStore,
}

/// Who processes the data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Accessor {
    /// The user.
    User,
    /// One.
    One,
    /// The Executor.
    Executor,
    /// A Suiss operator.
    SuissOperator,
}

/// Whether the processing waits for explicit consent; `NotRequired` promises more than `Explicit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Consent {
    /// Processing happens without a separate consent.
    NotRequired,
    /// Processing happens only after explicit consent.
    Explicit,
}

/// One promise tuple: data category, purpose, location, accessor and consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromiseTuple {
    /// The data.
    pub category: DataCategory,
    /// The purpose.
    pub purpose: ProcessingPurpose,
    /// The place.
    pub location: Location,
    /// The processor.
    pub accessor: Accessor,
    /// The consent the processing waits for.
    pub consent: Consent,
}

impl PromiseTuple {
    /// Whether `self` already permits everything `other` permits: the same data, purpose, place and processor, with a consent requirement no stricter.
    #[must_use]
    pub fn covers(&self, other: &Self) -> bool {
        self.category == other.category
            && self.purpose == other.purpose
            && self.location == other.location
            && self.accessor == other.accessor
            && (self.consent == other.consent || self.consent == Consent::NotRequired)
    }
}

/// How a new tuple set compares with the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Classification {
    /// The same tuples.
    Equal,
    /// Every new tuple was already permitted and something was taken away.
    Narrowing,
    /// At least one new tuple was not permitted before.
    Widening,
}

impl Classification {
    /// A widening is announced before it takes effect (PV-19).
    #[must_use]
    pub const fn notice_required(self) -> bool {
        matches!(self, Self::Widening)
    }

    /// A widening carries the re-consent flag (PV-19).
    #[must_use]
    pub const fn reconsent_flag_required(self) -> bool {
        matches!(self, Self::Widening)
    }
}

/// Compares two tuple sets; order and duplicates do not matter and the text is not looked at.
#[must_use]
pub fn classify(old: &[PromiseTuple], new: &[PromiseTuple]) -> Classification {
    if new.iter().any(|n| !old.iter().any(|o| o.covers(n))) {
        return Classification::Widening;
    }
    let a: BTreeSet<&PromiseTuple> = old.iter().collect();
    let b: BTreeSet<&PromiseTuple> = new.iter().collect();
    if a == b {
        Classification::Equal
    } else {
        Classification::Narrowing
    }
}

/// The Turkish and English promise text.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromiseText {
    /// Turkish lines.
    pub tr: Vec<String>,
    /// English lines.
    pub en: Vec<String>,
}

/// What a version after the first declares about its change.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromiseChange {
    /// The version this one replaces.
    pub from_version: u32,
    /// The declared classification.
    pub classification: Classification,
    /// When the widening was announced.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notice_at: Option<Instant>,
    /// Whether data collected under the earlier version needs new consent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconsent: Option<bool>,
}

/// Why a promise version is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ChangeRefusal {
    /// The declared classification is not the computed one.
    ClassificationMismatch,
    /// A widening without its notice date or re-consent flag.
    WideningWithoutNotice,
    /// The notice of a widening is not strictly before the version takes effect.
    NoticeNotBeforeEffect,
    /// `from_version` is not the previous version.
    NotTheNextVersion,
    /// The first version declares a change, or a later version declares none.
    ChangePresence,
}

impl ChangeRefusal {
    /// The reason as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClassificationMismatch => "classification_mismatch",
            Self::WideningWithoutNotice => "widening_without_notice",
            Self::NoticeNotBeforeEffect => "notice_not_before_effect",
            Self::NotTheNextVersion => "not_the_next_version",
            Self::ChangePresence => "change_presence",
        }
    }
}

/// Checks a declared change against the computed classification and the version's effective time.
///
/// # Errors
/// The first [`ChangeRefusal`] that applies.
pub fn check_change(
    computed: Classification,
    effective_at: &Instant,
    change: &PromiseChange,
) -> Result<(), ChangeRefusal> {
    if change.classification != computed {
        return Err(ChangeRefusal::ClassificationMismatch);
    }
    if computed == Classification::Widening {
        let (Some(notice_at), Some(true)) = (&change.notice_at, change.reconsent) else {
            return Err(ChangeRefusal::WideningWithoutNotice);
        };
        if notice_at >= effective_at {
            return Err(ChangeRefusal::NoticeNotBeforeEffect);
        }
    }
    Ok(())
}

/// `sha-256:` and the lower-case hex SHA-256 of the promise's JCS form without `digest`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct PromiseDigest(String);

impl PromiseDigest {
    /// The digest of a SHA-256 value.
    #[must_use]
    pub fn from_sha256(hash: &[u8; 32]) -> Self {
        let mut out = String::from("sha-256:");
        for b in hash {
            let _ = write!(out, "{b:02x}");
        }
        Self(out)
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A malformed promise digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestError;

impl core::fmt::Display for DigestError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("expected sha-256: and 64 lower-case hex digits")
    }
}

impl TryFrom<String> for PromiseDigest {
    type Error = DigestError;

    fn try_from(value: String) -> Result<Self, DigestError> {
        let ok = value.strip_prefix("sha-256:").is_some_and(|h| {
            h.len() == 64
                && h.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        });
        if ok {
            Ok(Self(value))
        } else {
            Err(DigestError)
        }
    }
}

impl From<PromiseDigest> for String {
    fn from(d: PromiseDigest) -> Self {
        d.0
    }
}

/// One published promise version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Promise {
    /// The version, counting up from 1.
    pub version: u32,
    /// `https://suiss.app/one/privacy/promise/v{version}`.
    pub url: String,
    /// When the version takes effect.
    pub effective_at: Instant,
    /// The tuples.
    pub tuples: Vec<PromiseTuple>,
    /// The text.
    pub text: PromiseText,
    /// The change against the previous version; `None` only for version 1.
    pub change: Option<PromiseChange>,
    /// The digest.
    pub digest: PromiseDigest,
}

impl Promise {
    /// The address the version is published at.
    #[must_use]
    pub fn expected_url(version: u32) -> String {
        alloc::format!("https://suiss.app/one/privacy/promise/v{version}")
    }

    /// Checks this version as the successor of `previous` (or as the first when `None`).
    ///
    /// # Errors
    /// The first [`ChangeRefusal`] that applies.
    pub fn check_succession(&self, previous: Option<&Self>) -> Result<(), ChangeRefusal> {
        match (previous, &self.change) {
            (None, None) => Ok(()),
            (Some(prev), Some(change)) => {
                if change.from_version != prev.version
                    || prev.version.checked_add(1) != Some(self.version)
                {
                    return Err(ChangeRefusal::NotTheNextVersion);
                }
                check_change(
                    classify(&prev.tuples, &self.tuples),
                    &self.effective_at,
                    change,
                )
            }
            _ => Err(ChangeRefusal::ChangePresence),
        }
    }
}

/// The JSON a promise digest is computed over: the published document without `digest`; `None` when it is not an object.
#[must_use]
pub fn digest_input(document: &JsonValue) -> Option<JsonValue> {
    let JsonValue::Object(map) = document else {
        return None;
    };
    let mut map = map.clone();
    map.remove("digest");
    Some(JsonValue::Object(map))
}

/// The promise version a job may use a record under: the version the record was collected under, never a later one; `None` when the record names a version that is not yet in force (INV-26).
#[must_use]
pub const fn governing_version(record_version: u32, current_version: u32) -> Option<u32> {
    if record_version >= 1 && record_version <= current_version {
        Some(record_version)
    } else {
        None
    }
}
