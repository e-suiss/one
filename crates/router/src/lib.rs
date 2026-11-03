//! The router component (MF-19, T-10): every model request first passes the rule gate, whose eliminated options never reach the second stage; the second stage picks the small or the large model by the difficulty estimate; the fallback order is fixed and never loosens a rule; each decision is kept as a content-free routing record; and a personal adapter is attached only once its version passed the activation gate.

pub mod adapters;
pub mod app;
pub mod domain;
pub mod ports;
