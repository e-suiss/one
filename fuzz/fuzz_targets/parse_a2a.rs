//! The A2A parsers never panic and label agent and One messages on arbitrary input (T-36 (4), SEC-13).
#![no_main]

use libfuzzer_sys::fuzz_target;
use one_parse::Limits;
use one_provenance::{ExternalSource, UntrustedLabel};

fuzz_target!(|data: &[u8]| {
    let agent = UntrustedLabel::External(ExternalSource::Agent);
    let one = UntrustedLabel::External(ExternalSource::One);
    if let Ok(v) = one_parse::a2a::parse_agent_message(data, &Limits::DEFAULT) {
        assert_eq!(v.label(), &agent);
    }
    if let Ok(v) = one_parse::a2a::parse_agent_task(data, &Limits::DEFAULT) {
        assert_eq!(v.label(), &agent);
    }
    if let Ok(v) = one_parse::a2a::parse_agent_response(data, &Limits::DEFAULT) {
        assert_eq!(v.label(), &agent);
    }
    if let Ok(v) = one_parse::a2a::parse_one_message(data, &Limits::DEFAULT) {
        assert_eq!(v.label(), &one);
    }
    if let Ok(v) = one_parse::a2a::parse_one_task(data, &Limits::DEFAULT) {
        assert_eq!(v.label(), &one);
    }
});
