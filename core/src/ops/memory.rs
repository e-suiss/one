//! Memory operations: `trust/v1` and the memory text view (M-6, M-13, INV-14).

use one_proto::memory::text_view::{TextViewRequest, render};
use one_proto::memory::trust::{TrustError, TrustInput, trust_v1 as trust};
use serde_json::Value;

use super::{object, parse, wire};
use crate::CoreError;

pub(super) fn trust_v1(input: Value) -> Result<Value, CoreError> {
    Ok(match serde_json::from_value::<TrustInput>(input) {
        Err(_) => object([("error", wire(&TrustError::UnknownInput)?)]),
        Ok(input) => match trust(&input) {
            Ok(t) => object([("trust", Value::from(t))]),
            Err(e) => object([("error", wire(&e)?)]),
        },
    })
}

pub(super) fn text_view(input: Value) -> Result<Value, CoreError> {
    let request: TextViewRequest = parse(input, "entries")?;
    match render(&request.entries) {
        Ok(view) => wire(&view),
        Err(e) => wire(&e),
    }
}
