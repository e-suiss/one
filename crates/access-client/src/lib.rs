//! The Access public API as One uses it (T-14, E-4): an Exercise request in the Access Decision Profile (`protocol/l1/adp.md`, `OpenID` `AuthZEN` 1.0) built from an intent envelope, the Actor Intent Statement that makes it the Instance's own, the discovery document and the typed decision; any response that is not a well-formed `allow` is no `allow` (L1-ADP-3, A-2, E-14).

pub mod adp;
pub mod ais;
pub mod decision;
pub mod discovery;

pub use access_kernel;
