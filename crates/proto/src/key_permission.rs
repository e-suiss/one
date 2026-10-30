//! The time-bound key permission body of `conformance/keys/key-permission.cddl` as decoded and its deterministic CBOR form; `purpose` and `classes` stay as written so the admission rule in `one-keys` can name an unknown value, and decoding is `one_parse::key_permission` (PV-65, Access E59).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::cbor::{Writer, encode};
use crate::data_class::RetentionClass;

/// The CBOR tag of a binary UUID (RFC 9562 §4, CBOR tag 37).
pub const UUID_TAG: u64 = 37;

/// The longest permission window: 24 hours (PV-65).
pub const MAX_WINDOW_SECS: u64 = 86_400;

/// A permission identifier: a `UUIDv7` in its 16-byte form.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PermissionId([u8; 16]);

impl PermissionId {
    /// Wraps the bytes of a `UUIDv7`; `None` for any other version or variant.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Option<Self> {
        if bytes[6] >> 4 == 7 && bytes[8] >> 6 == 0b10 {
            Some(Self(bytes))
        } else {
            None
        }
    }

    /// The 16 bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

impl fmt::Display for PermissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, b) in self.0.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                f.write_str("-")?;
            }
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for PermissionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// The closed purpose list (PV-65, Access E59).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Purpose {
    /// Night personal training.
    PersonalTraining,
    /// Memory consolidation.
    Consolidation,
    /// Re-embedding after a model change.
    Reembedding,
    /// A Trigger run.
    Trigger,
    /// A One↔One reply.
    OneToOneReply,
    /// A PV-66 data subject request.
    SubjectRequest,
    /// MLS group membership.
    MlsMembership,
}

impl Purpose {
    /// Every purpose.
    pub const ALL: [Self; 7] = [
        Self::PersonalTraining,
        Self::Consolidation,
        Self::Reembedding,
        Self::Trigger,
        Self::OneToOneReply,
        Self::SubjectRequest,
        Self::MlsMembership,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PersonalTraining => "personal_training",
            Self::Consolidation => "consolidation",
            Self::Reembedding => "reembedding",
            Self::Trigger => "trigger",
            Self::OneToOneReply => "one_to_one_reply",
            Self::SubjectRequest => "subject_request",
            Self::MlsMembership => "mls_membership",
        }
    }

    /// The purpose with this wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == name)
    }

    /// A job that changes state while the user is away needs a live Mandate; reading jobs do not.
    #[must_use]
    pub const fn requires_mandate(self) -> bool {
        matches!(
            self,
            Self::Trigger | Self::OneToOneReply | Self::SubjectRequest | Self::MlsMembership
        )
    }
}

/// A decoded permission body: the fields of `key-permission`, with `purpose` and `classes` as written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionBody {
    /// `permission_id`.
    pub permission_id: PermissionId,
    /// `classes`, in body order.
    pub classes: Vec<String>,
    /// `purpose`.
    pub purpose: String,
    /// `not_before`, seconds since the Unix epoch.
    pub not_before: u64,
    /// `expires_at`, seconds since the Unix epoch.
    pub expires_at: u64,
    /// `tee_measurement`: the SHA-384 TEE image measurement.
    pub tee_measurement: [u8; 48],
    /// `job_key_digest`: the SHA-256 of the TEE job key.
    pub job_key_digest: [u8; 32],
    /// `mandate_ref`, required for a state-changing purpose.
    pub mandate_ref: Option<String>,
}

impl PermissionBody {
    /// The typed purpose, when it is on the closed list.
    #[must_use]
    pub fn typed_purpose(&self) -> Option<Purpose> {
        Purpose::from_name(&self.purpose)
    }

    /// The typed classes, when every class is a One class.
    #[must_use]
    pub fn typed_classes(&self) -> Option<Vec<RetentionClass>> {
        self.classes
            .iter()
            .map(|c| RetentionClass::from_name(c))
            .collect()
    }

    /// The deterministic CBOR bytes of the body: the COSE payload and the input of its digest.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let key = |k: &str| {
            encode(|w| {
                w.text(k);
            })
        };
        let mut entries = alloc::vec![
            (
                key("classes"),
                encode(|w| {
                    w.array(self.classes.len());
                    for c in &self.classes {
                        w.text(c);
                    }
                }),
            ),
            (
                key("purpose"),
                encode(|w| {
                    w.text(&self.purpose);
                })
            ),
            (
                key("expires_at"),
                encode(|w| {
                    w.unsigned(self.expires_at);
                })
            ),
            (
                key("not_before"),
                encode(|w| {
                    w.unsigned(self.not_before);
                })
            ),
            (
                key("permission_id"),
                encode(|w| {
                    w.tag(UUID_TAG).bytes(self.permission_id.as_bytes());
                }),
            ),
            (
                key("job_key_digest"),
                encode(|w| {
                    w.bytes(&self.job_key_digest);
                }),
            ),
            (
                key("tee_measurement"),
                encode(|w| {
                    w.bytes(&self.tee_measurement);
                }),
            ),
        ];
        if let Some(m) = &self.mandate_ref {
            entries.push((
                key("mandate_ref"),
                encode(|w| {
                    w.text(m);
                }),
            ));
        }
        let mut w = Writer::new();
        w.map(entries);
        w.into_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // PV-65
    #[test]
    fn pv_65_permission_id_is_a_uuid_v7() {
        let mut v7 = [0_u8; 16];
        v7[6] = 0x7a;
        v7[8] = 0x88;
        assert!(PermissionId::from_bytes(v7).is_some());
        let mut v4 = v7;
        v4[6] = 0x4a;
        assert!(PermissionId::from_bytes(v4).is_none());
        let mut bad_variant = v7;
        bad_variant[8] = 0xc8;
        assert!(PermissionId::from_bytes(bad_variant).is_none());
    }

    // PV-65
    #[test]
    fn pv_65_state_changing_purposes_need_a_mandate() {
        let needs: Vec<&str> = Purpose::ALL
            .into_iter()
            .filter(|p| p.requires_mandate())
            .map(Purpose::as_str)
            .collect();
        assert_eq!(
            needs,
            [
                "trigger",
                "one_to_one_reply",
                "subject_request",
                "mls_membership"
            ]
        );
    }
}
