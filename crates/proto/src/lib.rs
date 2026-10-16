//! One record, event, sync and API types, checked against the CDDL, JSON Schema and golden vectors under `conformance/` (T-26 (5), T-31).
#![no_std]

pub mod id;
pub mod masked;
pub mod verdict;

pub use id::{
    AdapterId, CapabilityId, DeviceId, EpisodeId, IdError, InteractionId, MemoryRecordId,
    ModelVersionId, RequestId, TaskId,
};
pub use masked::Masked;
pub use verdict::Verdict;
