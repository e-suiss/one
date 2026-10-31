//! One record, event, sync and API types, checked against the CDDL, JSON Schema and golden vectors under `conformance/` (T-26 (5), T-31).
#![no_std]

extern crate alloc;

pub mod attention;
pub mod capability;
pub mod cbor;
pub mod data_class;
pub mod federation;

pub mod id;
pub mod interaction_types;
pub mod key_permission;
pub mod masked;
pub mod memory;
pub mod model;
pub mod money;
pub mod ontology;
pub mod privacy;
pub mod recovery;
pub mod task;
pub mod verdict;

pub use id::{
    AdapterId, AttentionDecisionId, CapabilityId, DeviceId, EpisodeId, EventId, GoalId, IdError,
    InteractionId, JobId, MemoryRecordId, ModelRequestId, ModelVersionId, ObservationId, ProjectId,
    RequestId, RoutineId, SurfaceCapabilityId, TaskId,
};
pub use masked::Masked;
pub use verdict::Verdict;
