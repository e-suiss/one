//! The single client core that Swift, Kotlin and TypeScript call through `UniFFI` and WASM bindings: one stable facade of named operations over canonical JSON bytes (T-16, T-29 (1), T-38 (2)).

pub mod canonical;
mod error;
mod ops;

pub use error::CoreError;
pub use ops::Operation;

use serde_json::{Map, Value};

fn run(operation: &str, input: &[u8]) -> Result<Value, CoreError> {
    let op = Operation::parse(operation).ok_or(CoreError::UnknownOperation)?;
    let value: Value = serde_json::from_slice(input).map_err(|_| CoreError::InvalidJson)?;
    op.run(value)
}

/// Runs `operation` on the JSON `input` and returns its canonical JSON output.
///
/// # Errors
/// An unknown operation name, input that is not JSON, or input that does not match the operation.
pub fn call(operation: &str, input: &[u8]) -> Result<Vec<u8>, CoreError> {
    run(operation, input).map(|output| canonical::to_vec(&output))
}

/// Runs `operation` like [`call`] and always answers with one canonical JSON envelope, `{"ok": output}` or `{"error": {"code": …, "detail": …}}`; these are the bytes every binding compares (T-38 (2)).
#[must_use]
pub fn invoke(operation: &str, input: &[u8]) -> Vec<u8> {
    let mut envelope = Map::new();
    match run(operation, input) {
        Ok(output) => envelope.insert("ok".to_owned(), output),
        Err(e) => envelope.insert("error".to_owned(), e.to_json()),
    };
    canonical::to_vec(&Value::Object(envelope))
}

/// The names of every operation, in a stable order.
#[must_use]
pub fn operations() -> Vec<&'static str> {
    Operation::ALL.iter().map(|op| op.as_str()).collect()
}

/// The canonical JSON array of [`operations`].
#[must_use]
pub fn operations_json() -> Vec<u8> {
    canonical::to_vec(&Value::from(operations()))
}
