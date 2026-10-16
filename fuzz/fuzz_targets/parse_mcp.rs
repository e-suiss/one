//! The MCP parsers never panic and label tool descriptions and tool output on arbitrary input (T-36 (4), SEC-13).
#![no_main]

use libfuzzer_sys::fuzz_target;
use one_parse::Limits;
use one_provenance::{ExternalSource, UntrustedLabel};

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = one_parse::mcp::parse_tool_list(data, &Limits::DEFAULT) {
        assert_eq!(
            v.label(),
            &UntrustedLabel::External(ExternalSource::ToolDescription)
        );
    }
    if let Ok(v) = one_parse::mcp::parse_tool_result(data, &Limits::DEFAULT) {
        assert_eq!(
            v.label(),
            &UntrustedLabel::External(ExternalSource::ToolOutput)
        );
    }
});
