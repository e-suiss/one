//! The provider-independent model interface, registry and routing records (MF-6, MF-22, MF-55).

pub mod common;
pub mod embedding;
pub mod registry;
pub mod request;
pub mod response;
pub mod roles;
pub mod routing;

pub use embedding::{EmbeddingModel, EmbeddingVector, Modality};
pub use registry::{Registry, RegistryEntry};
pub use request::ModelRequest;
pub use response::{ModelError, ModelResponse};
pub use roles::{ErrorCode, ModelRef, ModelRole, Placement, Usage};
pub use routing::{MemoryPart, ProviderTracePart, RoutingRecord};
