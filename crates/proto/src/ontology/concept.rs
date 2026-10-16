//! The nine canonical concepts, their identifiers and the `{type, id}` node that names one record in a relation (C-1, C-2, C-19, T-28 (5)).

use core::fmt;

use serde::de::Visitor;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::id::{
    AdapterId, AttentionDecisionId, CapabilityId, DeviceId, EpisodeId, EventId, GoalId, IdError,
    InteractionId, MemoryRecordId, ModelRequestId, ModelVersionId, ObservationId, ProjectId,
    RequestId, RoutineId, SurfaceCapabilityId, TaskId,
};

/// A canonical concept; the value of every record's `type` (C-1, C-19).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Concept {
    /// C-10.
    Observation,
    /// C-11.
    Episode,
    /// C-12.
    MemoryRecord,
    /// C-13.
    Goal,
    /// C-14.
    Routine,
    /// C-15.
    Task,
    /// C-16.
    Interaction,
    /// C-17.
    CapabilityDefinition,
    /// C-18.
    SurfaceCapability,
}

impl Concept {
    /// All nine, in contract order.
    pub const ALL: [Self; 9] = [
        Self::Observation,
        Self::Episode,
        Self::MemoryRecord,
        Self::Goal,
        Self::Routine,
        Self::Task,
        Self::Interaction,
        Self::CapabilityDefinition,
        Self::SurfaceCapability,
    ];

    /// The wire name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Observation => "Observation",
            Self::Episode => "Episode",
            Self::MemoryRecord => "MemoryRecord",
            Self::Goal => "Goal",
            Self::Routine => "Routine",
            Self::Task => "Task",
            Self::Interaction => "Interaction",
            Self::CapabilityDefinition => "CapabilityDefinition",
            Self::SurfaceCapability => "SurfaceCapability",
        }
    }

    /// The identifier prefix.
    #[must_use]
    pub const fn id_prefix(self) -> &'static str {
        match self {
            Self::Observation => ObservationId::PREFIX,
            Self::Episode => EpisodeId::PREFIX,
            Self::MemoryRecord => MemoryRecordId::PREFIX,
            Self::Goal => GoalId::PREFIX,
            Self::Routine => RoutineId::PREFIX,
            Self::Task => TaskId::PREFIX,
            Self::Interaction => InteractionId::PREFIX,
            Self::CapabilityDefinition => CapabilityId::PREFIX,
            Self::SurfaceCapability => SurfaceCapabilityId::PREFIX,
        }
    }
}

macro_rules! id_union {
    ($(#[$meta:meta])* $name:ident { $($variant:ident($ty:ty)),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum $name {
            $(
                #[doc = concat!("A `", stringify!($ty), "`.")]
                $variant($ty),
            )*
        }

        impl $name {
            /// Parses by prefix.
            ///
            /// # Errors
            /// Rejects an unknown prefix or a malformed identifier.
            pub fn parse(text: &str) -> Result<Self, IdError> {
                let prefix = text.split_once('_').map(|(p, _)| p).ok_or(IdError::Prefix)?;
                $(if prefix == <$ty>::PREFIX {
                    return <$ty>::parse(text).map(Self::$variant);
                })*
                Err(IdError::Prefix)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                match self {
                    $(Self::$variant(id) => fmt::Display::fmt(id, f),)*
                }
            }
        }

        $(impl From<$ty> for $name {
            fn from(id: $ty) -> Self {
                Self::$variant(id)
            }
        })*

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct V;
                impl Visitor<'_> for V {
                    type Value = $name;
                    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                        f.write_str(stringify!($name))
                    }
                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<$name, E> {
                        $name::parse(v).map_err(|e| E::custom(format_args!("identifier {v:?}: {e:?}")))
                    }
                }
                deserializer.deserialize_str(V)
            }
        }
    };
}

id_union!(
    /// The identifier of any canonical record (C-19).
    CanonicalId {
        Observation(ObservationId),
        Episode(EpisodeId),
        MemoryRecord(MemoryRecordId),
        Goal(GoalId),
        Routine(RoutineId),
        Task(TaskId),
        Interaction(InteractionId),
        CapabilityDefinition(CapabilityId),
        SurfaceCapability(SurfaceCapabilityId),
    }
);

id_union!(
    /// Any identifier One mints (T-28 (5)).
    AnyId {
        Observation(ObservationId),
        Episode(EpisodeId),
        MemoryRecord(MemoryRecordId),
        Goal(GoalId),
        Routine(RoutineId),
        Task(TaskId),
        Interaction(InteractionId),
        CapabilityDefinition(CapabilityId),
        SurfaceCapability(SurfaceCapabilityId),
        Device(DeviceId),
        ModelVersion(ModelVersionId),
        Adapter(AdapterId),
        Request(RequestId),
        Event(EventId),
        Project(ProjectId),
        ModelRequest(ModelRequestId),
        AttentionDecision(AttentionDecisionId),
    }
);

id_union!(
    /// A Goal or a Routine, the only records an entity reference may name (C-23).
    EntityRecordId {
        Goal(GoalId),
        Routine(RoutineId),
    }
);

impl CanonicalId {
    /// The concept the prefix names.
    #[must_use]
    pub const fn concept(&self) -> Concept {
        match self {
            Self::Observation(_) => Concept::Observation,
            Self::Episode(_) => Concept::Episode,
            Self::MemoryRecord(_) => Concept::MemoryRecord,
            Self::Goal(_) => Concept::Goal,
            Self::Routine(_) => Concept::Routine,
            Self::Task(_) => Concept::Task,
            Self::Interaction(_) => Concept::Interaction,
            Self::CapabilityDefinition(_) => Concept::CapabilityDefinition,
            Self::SurfaceCapability(_) => Concept::SurfaceCapability,
        }
    }
}

impl From<EntityRecordId> for CanonicalId {
    fn from(id: EntityRecordId) -> Self {
        match id {
            EntityRecordId::Goal(g) => Self::Goal(g),
            EntityRecordId::Routine(r) => Self::Routine(r),
        }
    }
}

/// One canonical record named by concept and identifier, `{type, id}`; the type always matches the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CanonicalNode(pub CanonicalId);

impl CanonicalNode {
    /// The concept.
    #[must_use]
    pub const fn concept(&self) -> Concept {
        self.0.concept()
    }
}

#[derive(Serialize, Deserialize)]
struct RawNode {
    #[serde(rename = "type")]
    concept: Concept,
    id: CanonicalId,
}

impl Serialize for CanonicalNode {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        RawNode {
            concept: self.concept(),
            id: self.0,
        }
        .serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CanonicalNode {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = RawNode::deserialize(deserializer)?;
        if raw.id.concept() == raw.concept {
            Ok(Self(raw.id))
        } else {
            Err(serde::de::Error::custom(
                "type does not match the identifier prefix",
            ))
        }
    }
}
