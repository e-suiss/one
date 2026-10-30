//! Every parser of external input: limits are checked before and while decoding, never after, and every output is an `Untrusted` value labelled `external.*` (T-26 (5), T-36 (4), SEC-13, SEC-14).
#![no_std]

extern crate alloc;

pub mod a2a;
pub mod calendar;
pub mod cbor;
pub mod document;
pub mod email;
pub mod json;
pub mod jsonrpc;
pub mod key_permission;
pub mod limits;
pub mod mcp;
mod text;

pub use limits::{Limits, ParseError};
