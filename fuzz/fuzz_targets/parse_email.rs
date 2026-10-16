//! The e-mail parser never panics, is deterministic and labels every output on arbitrary input (T-36 (4), SEC-13).
#![no_main]

use libfuzzer_sys::fuzz_target;
use one_parse::Limits;
use one_provenance::{ExternalSource, UntrustedLabel};

fuzz_target!(|data: &[u8]| {
    let first = one_parse::email::parse(data, &Limits::DEFAULT);
    let second = one_parse::email::parse(data, &Limits::DEFAULT);
    assert_eq!(
        first.as_ref().map(|v| v.expose()),
        second.as_ref().map(|v| v.expose())
    );
    if let Ok(v) = first {
        assert_eq!(v.label(), &UntrustedLabel::External(ExternalSource::Email));
    }
});
