//! The task component (CP-5, SEC-1): One plans, Access decides and the Executor executes; [`domain::gate`] is the only way from a typed intent to the Executor port.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
