//! `Interaction` schema types and pure projection rules: closed and extension kinds, the component catalog, surface classes and budgets, the projection decision and response processing (§14, X-12, X-13, X-22, C-25, C-26, T-27 (4)).
#![no_std]

extern crate alloc;

pub mod budget;
pub mod catalog;
pub mod common;
pub mod interaction;
pub mod json_size;
pub mod kind;
pub mod processing;
pub mod projection;
pub mod response;
pub mod surface;
pub mod validate;

pub use budget::{ProjectionOutcome, Rule};
pub use common::{CoreKind, Locale};
pub use interaction::Interaction;
pub use kind::{Kind, KindError, KindRegistry};
pub use one_proto::interaction_types::SurfaceClass;
pub use processing::{Processed, ResponseOutcome, ResponseProcessor};
pub use projection::{Projection, project};
pub use response::InteractionResponse;
pub use surface::SurfaceTarget;
pub use validate::{validate_interaction, validate_response};
