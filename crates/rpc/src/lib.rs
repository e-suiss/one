//! Internal RPC: the `one.serving.v1` ConnectRPC/Protobuf types and `ModelService` bindings generated from `conformance/rpc`, and their mapping to the canonical model types; Protobuf is never canonical and carries no signed bytes (T-31).

#[allow(
    missing_docs,
    unreachable_pub,
    clippy::all,
    clippy::pedantic,
    clippy::restriction,
    reason = "T-42 (6)"
)]
#[rustfmt::skip]
#[path = "gen/one.serving.v1.rs"]
pub mod serving_v1;

pub mod model;
