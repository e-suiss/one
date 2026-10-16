//! Self-masking values for secrets, keys, tokens, personal content, prompts, model output and provenance-labelled values: no Display, no serialisation, and Debug prints only a marker (T-28 (7), T-37 (1)).

use core::fmt;

/// A value that never shows itself in logs, errors or telemetry.
#[derive(Clone, PartialEq, Eq)]
pub struct Masked<T>(T);

impl<T> Masked<T> {
    /// Wraps a value.
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Borrows the value for the code that must use it.
    pub const fn expose(&self) -> &T {
        &self.0
    }

    /// Unwraps the value.
    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Masked<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[masked]")
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use std::format;

    use super::*;

    #[test]
    fn t_28_masked_value_never_formats() {
        let secret = Masked::new("hunter2");
        assert_eq!(format!("{secret:?}"), "[masked]");
        assert_eq!(*secret.expose(), "hunter2");
    }
}
