//! Documents: plain text, Markdown and HTML become text labelled `external.document`; limits apply while converting (T-36 (4), SEC-14).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::format_push_string,
    clippy::format_collect,
    reason = "T-38"
)]

mod common;

use common::{assert_label, tight};
use one_parse::document::{self, Format};
use one_parse::{Limits, ParseError};

#[test]
fn t_36_document_outputs_are_labelled_document() {
    for format in [Format::Plain, Format::Markdown, Format::Html] {
        let v = document::parse(b"\xef\xbb\xbfhello\r\nworld", &tight(), format).unwrap();
        assert_label(&v, "external.document");
        assert_eq!(v.expose().format, format);
    }
}

#[test]
fn t_36_document_plain_and_markdown_keep_their_text() {
    let v = document::parse(
        b"# Title\r\n\r\n*bold* [link](https://x.test)\n",
        &tight(),
        Format::Markdown,
    )
    .unwrap();
    assert_eq!(
        v.expose().text,
        "# Title\n\n*bold* [link](https://x.test)\n"
    );
}

#[test]
fn t_36_document_html_becomes_text() {
    let html = b"<!doctype html><html><head><title>t</title><style>p{}</style></head>\
<body><h1>Ba&#351;l&#305;k</h1><p>a &amp; b&nbsp;c</p><!-- hidden --><script>evil()</script>\
<ul><li>one</li><li>two</li></ul>x < y</body></html>";
    let v = document::parse(html, &Limits::DEFAULT, Format::Html).unwrap();
    assert_eq!(v.expose().text, "Başlık\na & b c\none\ntwo\nx < y");
}

#[test]
fn t_36_document_invalid_utf8_is_rejected() {
    assert_eq!(
        document::parse(b"\xff\xfe", &tight(), Format::Plain).unwrap_err(),
        ParseError::Malformed("not utf-8")
    );
}

#[test]
fn sec_13_document_oversize_is_rejected() {
    assert_eq!(
        document::parse(&vec![b'a'; 4097], &tight(), Format::Plain).unwrap_err(),
        ParseError::TooLarge
    );
}

#[test]
fn sec_13_document_too_many_items_is_rejected() {
    assert_eq!(
        document::parse("a\n".repeat(65).as_bytes(), &tight(), Format::Plain).unwrap_err(),
        ParseError::TooManyItems
    );
    assert_eq!(
        document::parse("<b>".repeat(65).as_bytes(), &tight(), Format::Html).unwrap_err(),
        ParseError::TooManyItems
    );
}

#[test]
fn sec_13_document_long_text_is_rejected() {
    assert_eq!(
        document::parse("a".repeat(257).as_bytes(), &tight(), Format::Markdown).unwrap_err(),
        ParseError::StringTooLong
    );
    let limits = Limits {
        max_total: 100,
        ..tight()
    };
    assert_eq!(
        document::parse("a".repeat(200).as_bytes(), &limits, Format::Plain).unwrap_err(),
        ParseError::BudgetExceeded
    );
}
