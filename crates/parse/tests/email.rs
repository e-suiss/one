//! E-mail: headers, text parts and attachment metadata are labelled `external.email`; limits apply while decoding (T-36 (4), SEC-14).

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
use one_parse::email::{self, BodyKind};
use one_parse::{Limits, ParseError};

const MULTIPART: &[u8] = b"From: =?UTF-8?B?QWxpIFnEsWxtYXo=?= <ali@example.test>\r\n\
To: Ay\xc5\x9fe <ayse@example.test>,\r\n bob@example.test\r\n\
Cc: carol@example.test\r\n\
Subject: =?ISO-8859-9?Q?Toplant=FD_saati?= =?UTF-8?Q?_de=C4=9Fi=C5=9Fti?=\r\n\
Date: Mon, 12 Oct 2026 09:00:00 +0300\r\n\
Message-ID: <abc@example.test>\r\n\
MIME-Version: 1.0\r\n\
Content-Type: multipart/mixed; boundary=\"outer\"\r\n\
\r\n\
preamble\r\n\
--outer\r\n\
Content-Type: multipart/alternative; boundary=inner\r\n\
\r\n\
--inner\r\n\
Content-Type: text/plain; charset=utf-8\r\n\
Content-Transfer-Encoding: quoted-printable\r\n\
\r\n\
Merhaba, toplant=C4=B1 saat 10'a al=\r\ndik.\r\n\
--inner\r\n\
Content-Type: text/html; charset=windows-1254\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
PHA+TWVyaGFiYTwvcD48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PHA+dG9wbGFudP08L3A+\r\n\
--inner--\r\n\
--outer\r\n\
Content-Type: application/pdf; name=\"ajanda.pdf\"\r\n\
Content-Disposition: attachment; filename*=utf-8''g%C3%BCndem.pdf\r\n\
Content-Transfer-Encoding: base64\r\n\
\r\n\
JVBERi0=\r\n\
--outer--\r\n\
epilogue\r\n";

#[test]
fn t_36_email_output_is_labelled_email() {
    let v = email::parse(MULTIPART, &Limits::DEFAULT).unwrap();
    assert_label(&v, "external.email");
    let e = v.expose();
    assert_eq!(e.from.as_deref(), Some("Ali Yılmaz <ali@example.test>"));
    assert_eq!(
        e.to.as_deref(),
        Some("Ayşe <ayse@example.test>, bob@example.test")
    );
    assert_eq!(e.cc.as_deref(), Some("carol@example.test"));
    assert_eq!(e.subject.as_deref(), Some("Toplantı saati değişti"));
    assert_eq!(e.date.as_deref(), Some("Mon, 12 Oct 2026 09:00:00 +0300"));
    assert_eq!(
        e.message_id.as_ref().unwrap().as_str(),
        "<abc@example.test>"
    );
    assert_eq!(e.bodies.len(), 2);
    assert_eq!(e.bodies[0].kind, BodyKind::Plain);
    assert_eq!(e.bodies[0].text, "Merhaba, toplantı saat 10'a aldik.");
    assert_eq!(e.bodies[1].kind, BodyKind::Html);
    assert_eq!(e.bodies[1].text, "Merhaba\ntoplantı");
    assert_eq!(e.attachments.len(), 1);
    assert_eq!(e.attachments[0].media_type, "application/pdf");
    assert_eq!(e.attachments[0].filename.as_deref(), Some("gündem.pdf"));
}

#[test]
fn t_36_email_single_part_defaults_to_plain_text() {
    let v = email::parse(b"Subject: hi\n\nline one\nline two", &tight()).unwrap();
    assert_label(&v, "external.email");
    assert_eq!(v.expose().subject.as_deref(), Some("hi"));
    assert_eq!(v.expose().bodies[0].text, "line one\nline two");
}

#[test]
fn t_36_email_multipart_without_boundary_is_rejected() {
    let bad = b"Content-Type: multipart/mixed\r\n\r\nbody";
    assert_eq!(
        email::parse(bad, &tight()).unwrap_err(),
        ParseError::Malformed("multipart without boundary")
    );
}

#[test]
fn sec_13_email_oversize_is_rejected() {
    let big = vec![b'a'; 4097];
    assert_eq!(
        email::parse(&big, &tight()).unwrap_err(),
        ParseError::TooLarge
    );
}

#[test]
fn sec_13_email_too_deep_is_rejected() {
    let mut msg = String::new();
    for i in 0..6 {
        msg.push_str(&format!(
            "Content-Type: multipart/mixed; boundary=b{i}\r\n\r\n--b{i}\r\n"
        ));
    }
    msg.push_str("\r\ntext\r\n");
    assert_eq!(
        email::parse(msg.as_bytes(), &tight()).unwrap_err(),
        ParseError::TooDeep
    );
}

#[test]
fn sec_13_email_too_many_items_is_rejected() {
    let headers: String = (0..65).map(|i| format!("X-H{i}: v\r\n")).collect();
    let msg = format!("{headers}\r\nbody");
    assert_eq!(
        email::parse(msg.as_bytes(), &tight()).unwrap_err(),
        ParseError::TooManyItems
    );
    let mut parts = String::from("Content-Type: multipart/mixed; boundary=b\r\n\r\n");
    for _ in 0..40 {
        parts.push_str("--b\r\n\r\nx\r\n");
    }
    assert_eq!(
        email::parse(parts.as_bytes(), &tight()).unwrap_err(),
        ParseError::TooManyItems
    );
}

#[test]
fn sec_13_email_long_header_and_body_are_rejected() {
    let long = format!("Subject: {}\r\n\r\n", "a".repeat(300));
    assert_eq!(
        email::parse(long.as_bytes(), &tight()).unwrap_err(),
        ParseError::StringTooLong
    );
    let body = format!("Subject: x\r\n\r\n{}", "b".repeat(300));
    assert_eq!(
        email::parse(body.as_bytes(), &tight()).unwrap_err(),
        ParseError::StringTooLong
    );
}
