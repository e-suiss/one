//! The document parser never panics and labels every output in every format on arbitrary input (T-36 (4), SEC-13).
#![no_main]

use libfuzzer_sys::fuzz_target;
use one_parse::Limits;
use one_provenance::{ExternalSource, UntrustedLabel};

use one_parse::document::Format;

fuzz_target!(|data: &[u8]| {
    for format in [Format::Plain, Format::Markdown, Format::Html] {
        if let Ok(v) = one_parse::document::parse(data, &Limits::DEFAULT, format) {
            assert_eq!(
                v.label(),
                &UntrustedLabel::External(ExternalSource::Document)
            );
        }
    }
});
