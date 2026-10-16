//! Provenance-labelled values and the label join rule, shared by the server and `one-core` (T-36, SEC-14).
#![no_std]

extern crate alloc;

pub mod access;
pub mod confirm;
mod content;
pub mod intent;
pub mod label;
pub mod planner;
pub mod transform;
pub mod value;

pub use access::{AccessMapping, AccessProvenance, ParameterName, ParameterProvenance};
pub use label::{
    ExternalSource, Label, LabelKind, MixedSources, Source, TrustedLabel, UntrustedLabel,
};
pub use planner::{PlannerContext, ProposedInput, VarRef, VariableTable};
pub use transform::Transform;
pub use value::{Labelled, Opened, Sources, Trusted, Untrusted};
