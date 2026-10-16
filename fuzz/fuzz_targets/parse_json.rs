//! The JSON parser never panics, is deterministic and labels every output on arbitrary input (T-36 (4), SEC-13).
#![no_main]

use libfuzzer_sys::fuzz_target;
use one_parse::Limits;
use one_provenance::{ExternalSource, UntrustedLabel};

fuzz_target!(|data: &[u8]| {
    let first = one_parse::json::parse(data, &Limits::DEFAULT, ExternalSource::Unknown);
    let second = one_parse::json::parse(data, &Limits::DEFAULT, ExternalSource::Unknown);
    assert_eq!(
        first.as_ref().map(|v| v.expose()),
        second.as_ref().map(|v| v.expose())
    );
    if let Ok(v) = first {
        assert_eq!(
            v.label(),
            &UntrustedLabel::External(ExternalSource::Unknown)
        );
    }
});
