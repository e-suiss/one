//! Every parser returns a labelled value or an error, never a panic, on every prefix and single-byte corruption of a valid input (T-36 (4), SEC-13).

#![allow(clippy::arithmetic_side_effects, reason = "T-38")]

use one_parse::Limits;
use one_parse::document::Format;
use one_provenance::ExternalSource;

const INPUTS: &[&[u8]] = &[
    br#"{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"a","inputSchema":{}}],"content":[{"type":"text","text":"x"}]}}"#,
    br#"{"messageId":"m","role":"ROLE_USER","parts":[{"text":"a"},{"data":{"k":[1,2]}}]}"#,
    &[0xa2, 0x61, 0x61, 0x82, 0x01, 0xf9, 0x3c, 0x00, 0x61, 0x62, 0xc1, 0x5f],
    b"Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\nContent-Transfer-Encoding: base64\r\n\r\nPGI+aGk8L2I+\r\n--b--\r\n",
    b"Subject: =?utf-8?q?a=C4=9F?= =?x?b?AAAA?=\r\n\r\n<p>&#x110000;&amp</p>",
    b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nATTENDEE;CN=\"a;b\":mailto:x\r\n SUMMARY\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
];

fn all(bytes: &[u8]) {
    let l = Limits::DEFAULT;
    let _ = one_parse::json::parse(bytes, &l, ExternalSource::Unknown);
    let _ = one_parse::cbor::parse(bytes, &l, ExternalSource::Unknown);
    let _ = one_parse::mcp::parse_tool_list(bytes, &l);
    let _ = one_parse::mcp::parse_tool_result(bytes, &l);
    let _ = one_parse::a2a::parse_agent_message(bytes, &l);
    let _ = one_parse::a2a::parse_agent_response(bytes, &l);
    let _ = one_parse::a2a::parse_one_message(bytes, &l);
    let _ = one_parse::email::parse(bytes, &l);
    let _ = one_parse::calendar::parse(bytes, &l);
    for format in [Format::Plain, Format::Markdown, Format::Html] {
        let _ = one_parse::document::parse(bytes, &l, format);
    }
}

#[test]
fn sec_13_prefixes_and_corruptions_never_panic() {
    for input in INPUTS {
        for end in 0..=input.len() {
            all(input.get(..end).unwrap_or_default());
        }
        for at in 0..input.len() {
            for byte in [0x00, 0x22, 0x3c, 0x3d, 0x5c, 0x80, 0xff, 0x9f, 0xbf, 0x0a] {
                let mut copy = input.to_vec();
                if let Some(b) = copy.get_mut(at) {
                    *b = byte;
                }
                all(&copy);
            }
        }
    }
}
