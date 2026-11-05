//! The task component (CP-5, CP-9, CP-12, SEC-1): One plans, Access decides and the Executor executes; [`app::prepare`] fixes a step's path and place before its Access request, and [`domain::gate`] is the only way from a typed intent to the Executor port.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
