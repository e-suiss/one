//! The capabilities component (CP-15 to CP-30, CP-37 to CP-41, T-4): the registry holds only capabilities that were evaluated and work now, the planner sees only those inside the current Grant and Mandate and only a few retrieved candidates of them, third-party tools are signed and pinned and stop when they change, servers never see each other, and One opens itself to other assistants only under a Grant and the zero-retention condition.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
