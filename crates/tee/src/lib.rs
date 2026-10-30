//! The TEE boundary in types and the attestation claim checks: [`Sealed`] travels outside the TEE, [`Unsealed`] exists only inside the job frame, and a node is trusted only through a pinned vendor root, a logged measurement and fresh evidence (T-6, T-27 (3, 10), SEC-27, PV-11).

pub mod app;
pub mod domain;
pub mod frame;
pub mod ports;
pub mod sealed;

pub use frame::Unsealed;
pub use sealed::{LeavesTee, RecordKeyId, Sealed};
