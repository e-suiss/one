//! Facade errors with stable codes; a rejected input is a decision in the output, never an error (T-28 (6)).

use serde_json::{Map, Value};

/// Why the facade could not run an operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// The operation name is not one of [`crate::Operation::ALL`].
    #[error("unknown operation")]
    UnknownOperation,
    /// The input bytes are not one JSON document.
    #[error("input is not JSON")]
    InvalidJson,
    /// The input is JSON but does not match the operation's input shape; names the part.
    #[error("input does not match the operation: {0}")]
    InvalidInput(&'static str),
}

impl CoreError {
    /// The stable code.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::UnknownOperation => "unknown_operation",
            Self::InvalidJson => "invalid_json",
            Self::InvalidInput(_) => "invalid_input",
        }
    }

    /// The part of the input that did not match, for [`CoreError::InvalidInput`].
    #[must_use]
    pub const fn detail(&self) -> Option<&'static str> {
        match self {
            Self::InvalidInput(part) => Some(part),
            Self::UnknownOperation | Self::InvalidJson => None,
        }
    }

    /// `{"code": …, "detail": …}`.
    #[must_use]
    pub fn to_json(&self) -> Value {
        let mut m = Map::new();
        m.insert("code".to_owned(), Value::from(self.code()));
        if let Some(detail) = self.detail() {
            m.insert("detail".to_owned(), Value::from(detail));
        }
        Value::Object(m)
    }
}
