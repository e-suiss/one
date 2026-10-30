//! Data classes `{kinds, sensitive}`, the PV-20 sensitive classes, the seven retention classes and the life-area domain every record header carries (PV-16, PV-20, C-19, M-7, M-28).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::id::ProjectId;
use crate::ontology::concept::Concept;
use crate::ontology::validate::{ContractViolation, require, unique};

/// What kind of data a record holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataKind {
    /// Not personal; never combined with another kind.
    General,
    /// Personal.
    Personal,
    /// Contact details.
    Contact,
    /// Financial.
    Financial,
    /// Location.
    Location,
    /// Communication content.
    Communication,
    /// A one-time code.
    OneTimeCode,
}

/// A special category of personal data (PV-20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SensitiveClass {
    /// Health.
    Health,
    /// Religion or belief.
    ReligionBelief,
    /// Political opinion.
    PoliticalOpinion,
    /// Sex life or orientation.
    SexLifeOrientation,
    /// Biometric data.
    Biometric,
    /// Precise location history.
    PreciseLocationHistory,
    /// Relationship status.
    RelationshipStatus,
    /// Genetic data.
    Genetic,
    /// Racial or ethnic origin.
    RacialEthnicOrigin,
    /// Philosophical belief or denomination.
    PhilosophicalBeliefDenomination,
    /// Union, association or foundation membership.
    UnionAssociationFoundationMembership,
    /// Criminal conviction or security measure.
    CriminalConvictionSecurityMeasure,
    /// Attire.
    Attire,
}

impl SensitiveClass {
    /// The thirteen PV-20 codes.
    pub const ALL: [Self; 13] = [
        Self::Health,
        Self::ReligionBelief,
        Self::PoliticalOpinion,
        Self::SexLifeOrientation,
        Self::Biometric,
        Self::PreciseLocationHistory,
        Self::RelationshipStatus,
        Self::Genetic,
        Self::RacialEthnicOrigin,
        Self::PhilosophicalBeliefDenomination,
        Self::UnionAssociationFoundationMembership,
        Self::CriminalConvictionSecurityMeasure,
        Self::Attire,
    ];
}

/// A data class that breaks the contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClassError {
    /// No kind.
    EmptyKinds,
    /// A kind or code is repeated.
    Duplicate,
    /// `general` is combined with another kind or a sensitive code.
    GeneralNotAlone,
}

#[derive(Deserialize)]
struct RawDataClass {
    kinds: Vec<DataKind>,
    sensitive: Vec<SensitiveClass>,
}

/// The data class of a record: its kinds and the PV-20 codes it touches (C-19, M-7).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "RawDataClass")]
pub struct DataClass {
    kinds: Vec<DataKind>,
    sensitive: Vec<SensitiveClass>,
}

impl TryFrom<RawDataClass> for DataClass {
    type Error = DataClassError;

    fn try_from(raw: RawDataClass) -> Result<Self, Self::Error> {
        Self::new(raw.kinds, raw.sensitive)
    }
}

impl core::fmt::Display for DataClassError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::EmptyKinds => "data class needs at least one kind",
            Self::Duplicate => "data class repeats a kind or code",
            Self::GeneralNotAlone => "`general` stands alone",
        })
    }
}

impl DataClass {
    /// Builds a data class, keeping the given order.
    ///
    /// # Errors
    /// Rejects no kinds, repeats, or `general` with anything else.
    pub fn new(
        kinds: Vec<DataKind>,
        sensitive: Vec<SensitiveClass>,
    ) -> Result<Self, DataClassError> {
        if kinds.is_empty() {
            return Err(DataClassError::EmptyKinds);
        }
        if !unique(&kinds) || !unique(&sensitive) {
            return Err(DataClassError::Duplicate);
        }
        if kinds.contains(&DataKind::General) && (kinds.len() > 1 || !sensitive.is_empty()) {
            return Err(DataClassError::GeneralNotAlone);
        }
        Ok(Self { kinds, sensitive })
    }

    /// The kinds.
    #[must_use]
    pub fn kinds(&self) -> &[DataKind] {
        &self.kinds
    }

    /// The PV-20 codes.
    #[must_use]
    pub fn sensitive(&self) -> &[SensitiveClass] {
        &self.sensitive
    }

    /// Holds no personal data.
    #[must_use]
    pub fn is_general(&self) -> bool {
        self.kinds.contains(&DataKind::General)
    }

    /// Touches at least one PV-20 code.
    #[must_use]
    pub fn is_sensitive(&self) -> bool {
        !self.sensitive.is_empty()
    }

    /// The class of combined data: the union of kinds and codes; `general` drops out next to any other kind.
    #[must_use]
    pub fn union(&self, other: &Self) -> Self {
        let mut kinds: Vec<DataKind> = Vec::new();
        for k in self.kinds.iter().chain(other.kinds.iter()) {
            if !kinds.contains(k) {
                kinds.push(*k);
            }
        }
        let mut sensitive: Vec<SensitiveClass> = Vec::new();
        for s in self.sensitive.iter().chain(other.sensitive.iter()) {
            if !sensitive.contains(s) {
                sensitive.push(*s);
            }
        }
        if kinds.len() > 1 {
            kinds.retain(|k| *k != DataKind::General);
        }
        Self { kinds, sensitive }
    }
}

/// Where a record is kept and for how long; a separate C-19 header field (PV-16).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionClass {
    /// Memory records and episodes.
    OneMemory,
    /// Personal model artefacts.
    OneModel,
    /// Stored raw observations.
    OneObservation,
    /// Records touching a PV-20 code.
    OneSensitive,
    /// Model provider traces.
    OneProviderTrace,
    /// Browser session profiles.
    OneBrowserProfile,
    /// Training lineage.
    OneTrainingLineage,
}

impl RetentionClass {
    /// The seven classes.
    pub const ALL: [Self; 7] = [
        Self::OneMemory,
        Self::OneModel,
        Self::OneObservation,
        Self::OneSensitive,
        Self::OneProviderTrace,
        Self::OneBrowserProfile,
        Self::OneTrainingLineage,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OneMemory => "one_memory",
            Self::OneModel => "one_model",
            Self::OneObservation => "one_observation",
            Self::OneSensitive => "one_sensitive",
            Self::OneProviderTrace => "one_provider_trace",
            Self::OneBrowserProfile => "one_browser_profile",
            Self::OneTrainingLineage => "one_training_lineage",
        }
    }

    /// The class with this wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|c| c.as_str() == name)
    }

    /// The class a canonical record must carry: a stored raw Observation stays in `one_observation`; otherwise a PV-20 code means `one_sensitive` and anything else `one_memory` (C-19, PV-16).
    #[must_use]
    pub fn for_record(concept: Concept, data_class: &DataClass, raw_stored: bool) -> Self {
        if concept == Concept::Observation && raw_stored {
            Self::OneObservation
        } else if data_class.is_sensitive() {
            Self::OneSensitive
        } else {
            Self::OneMemory
        }
    }
}

/// A life area a record belongs to (M-28).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifeArea {
    /// Work.
    Work,
    /// Health.
    Health,
    /// Finance.
    Finance,
    /// Relationships.
    Relationships,
    /// Home.
    Home,
    /// Travel.
    Travel,
    /// Shopping.
    Shopping,
    /// Learning.
    Learning,
    /// Leisure.
    Leisure,
    /// General.
    General,
}

/// The domain of a record: one or more life areas and an optional project under them (M-28, C-19).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Domain {
    /// Life areas, at least one.
    pub areas: Vec<LifeArea>,
    /// The user project, or `null`.
    #[serde(deserialize_with = "Option::deserialize")]
    pub project: Option<ProjectId>,
}

impl Domain {
    /// At least one life area and no repeats (C-19).
    ///
    /// # Errors
    /// [`ContractViolation`] `domain_areas`.
    pub fn check(&self) -> Result<(), ContractViolation> {
        require(
            !self.areas.is_empty() && unique(&self.areas),
            "domain_areas",
        )
    }
}
