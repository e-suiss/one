//! Shared assertions for the parser tests: the output label and tight limits.

#![allow(clippy::panic, dead_code, reason = "T-38")]

use one_parse::Limits;
use one_provenance::{Untrusted, UntrustedLabel};

pub(crate) fn assert_label<T>(value: &Untrusted<T>, wire: &str) {
    let UntrustedLabel::External(_) = value.label() else {
        panic!("not an external label");
    };
    assert_eq!(value.label().kind().as_str(), wire);
}

pub(crate) const fn tight() -> Limits {
    Limits {
        max_bytes: 4096,
        max_depth: 4,
        max_items: 64,
        max_string: 256,
        max_total: 65_536,
    }
}
