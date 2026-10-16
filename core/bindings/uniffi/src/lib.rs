//! The `UniFFI` scaffolding of one-core for Swift and Kotlin: the same facade as WASM, canonical JSON bytes in and out (T-16 (1), T-28 (3), T-29 (1)).

uniffi::setup_scaffolding!("one_core");

/// Why the facade could not run an operation; mirrors [`one_core::CoreError`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error, uniffi::Error)]
#[non_exhaustive]
pub enum CoreError {
    /// The operation name is unknown.
    #[error("unknown_operation")]
    UnknownOperation,
    /// The input bytes are not JSON.
    #[error("invalid_json")]
    InvalidJson,
    /// The input does not match the operation; names the part.
    #[error("invalid_input: {detail}")]
    InvalidInput {
        /// The part of the input.
        detail: String,
    },
}

impl From<one_core::CoreError> for CoreError {
    fn from(e: one_core::CoreError) -> Self {
        match e {
            one_core::CoreError::UnknownOperation => Self::UnknownOperation,
            one_core::CoreError::InvalidJson => Self::InvalidJson,
            one_core::CoreError::InvalidInput(part) => Self::InvalidInput {
                detail: part.to_owned(),
            },
        }
    }
}

/// Runs `operation` on the JSON `input` and returns its canonical JSON output.
///
/// # Errors
/// See [`CoreError`].
#[uniffi::export]
#[allow(clippy::needless_pass_by_value, reason = "T-16 (1)")]
pub fn call(operation: &str, input: Vec<u8>) -> Result<Vec<u8>, CoreError> {
    one_core::call(operation, &input).map_err(CoreError::from)
}

/// Runs `operation` and returns the canonical envelope `{"ok": …}` or `{"error": …}`; the bytes the differential tests compare (T-38 (2)).
#[uniffi::export]
#[must_use]
#[allow(clippy::needless_pass_by_value, reason = "T-16 (1)")]
pub fn invoke(operation: &str, input: Vec<u8>) -> Vec<u8> {
    one_core::invoke(operation, &input)
}

/// The canonical JSON array of every operation name.
#[uniffi::export]
#[must_use]
pub fn operations() -> Vec<u8> {
    one_core::operations_json()
}
