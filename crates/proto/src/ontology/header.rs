//! The C-19 common header every canonical record carries, with its `type`, plus the text values records hold (C-19, C-12, M-29).

use alloc::string::String;
use core::num::NonZeroU32;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::concept::Concept;
use super::provenance::ProvenanceLabel;
use super::reference::{InstanceRef, PartyRef};
use super::time::Instant;
use super::validate::{ContractViolation, require};
use crate::data_class::{DataClass, Domain, RetentionClass};
use crate::id::ModelVersionId;

/// Record lifecycle (C-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordStatus {
    /// The record is in use.
    Active,
    /// The record is deleted.
    Deleted,
}

/// Who produced a record version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Actor {
    /// The user.
    User,
    /// One.
    One,
    /// A sub-agent.
    SubAgent,
}

/// The producer of a record version: the user, or One or a sub-agent with its instance, model version and configuration.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProducedBy {
    /// The actor.
    pub actor: Actor,
    /// The producing instance; absent for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<InstanceRef>,
    /// The model version; absent for the user.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_version: Option<ModelVersionId>,
    /// The configuration version, `[a-z0-9][a-z0-9._-]{0,63}`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_version: Option<String>,
}

fn config_version_ok(v: &str) -> bool {
    let b = v.as_bytes();
    let first = |c: &u8| c.is_ascii_lowercase() || c.is_ascii_digit();
    (1..=64).contains(&b.len())
        && b.first().is_some_and(first)
        && b.iter()
            .all(|c| first(c) || matches!(c, b'.' | b'_' | b'-'))
}

impl ProducedBy {
    /// The user produces with no instance or model; One and sub-agents name instance, model version and configuration.
    ///
    /// # Errors
    /// [`ContractViolation`] `produced_by`.
    pub fn check(&self) -> Result<(), ContractViolation> {
        let config_ok = self.config_version.as_deref().is_none_or(config_version_ok);
        let shape = match self.actor {
            Actor::User => self.instance.is_none() && self.model_version.is_none(),
            Actor::One | Actor::SubAgent => {
                self.instance.is_some()
                    && self.model_version.is_some()
                    && self.config_version.is_some()
            }
        };
        require(config_ok && shape, "produced_by")
    }

    /// The user.
    #[must_use]
    pub const fn user() -> Self {
        Self {
            actor: Actor::User,
            instance: None,
            model_version: None,
            config_version: None,
        }
    }
}

/// The C-19 header fields shared by every canonical record; the record type adds `type`, `id`, `status` and `supersedes`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RecordHeader {
    /// The person the record belongs to.
    pub owner: PartyRef,
    /// Life areas and project.
    pub domain: Domain,
    /// Data class.
    pub data_class: DataClass,
    /// Retention class.
    pub retention_class: RetentionClass,
    /// Provenance label.
    pub provenance: ProvenanceLabel,
    /// Transaction time, set by the server.
    pub recorded_at: Instant,
    /// Version, from 1.
    pub version: NonZeroU32,
    /// Privacy promise version in force when the record was collected, from 1 (PV-19).
    pub promise_version: NonZeroU32,
    /// When the record was forgotten; `null` while live.
    pub deleted_at: Option<Instant>,
    /// Producer.
    pub produced_by: ProducedBy,
}

impl RecordHeader {
    /// Checks the C-19 rules of a live record of `concept`: at least one distinct life area, the retention class its data class requires, no `deleted_at`, and a well-formed producer.
    ///
    /// # Errors
    /// The first [`ContractViolation`].
    pub fn check(&self, concept: Concept) -> Result<(), ContractViolation> {
        self.domain.check()?;
        let raw_observation = concept == Concept::Observation
            && self.retention_class == RetentionClass::OneObservation;
        if !raw_observation {
            let want = if self.data_class.is_sensitive() {
                RetentionClass::OneSensitive
            } else {
                RetentionClass::OneMemory
            };
            require(self.retention_class == want, "retention_class")?;
        }
        require(self.deleted_at.is_none(), "deleted_at")?;
        self.produced_by.check()
    }
}

/// A BCP 47 style language tag, `[a-z]{2,3}(-[A-Za-z0-9]{2,8})*`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Lang(String);

/// A malformed text value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TextError;

impl Lang {
    /// Checks the tag form.
    ///
    /// # Errors
    /// Rejects any other form.
    pub fn new(tag: impl Into<String>) -> Result<Self, TextError> {
        let tag = tag.into();
        let mut parts = tag.split('-');
        let primary = parts.next().unwrap_or_default();
        let primary_ok =
            (2..=3).contains(&primary.len()) && primary.bytes().all(|b| b.is_ascii_lowercase());
        let rest_ok = parts
            .all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()));
        if primary_ok && rest_ok {
            Ok(Self(tag))
        } else {
            Err(TextError)
        }
    }

    /// The tag.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Lang {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Lang {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(|_| D::Error::custom("language tag"))
    }
}

/// A product language: Turkish or English.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiLang {
    /// Turkish.
    Tr,
    /// English.
    En,
}

/// A statement in any language tag (M-29).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Statement {
    /// The text.
    pub text: String,
    /// Its language.
    pub lang: Lang,
}

/// A short text in Turkish or English.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LocalText {
    /// The text.
    pub text: String,
    /// Its language.
    pub lang: UiLang,
}
