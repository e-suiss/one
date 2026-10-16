//! iCalendar: event fields are labelled `external.calendar`; limits apply while unfolding and decoding (T-36 (4), SEC-14).

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
use one_parse::calendar;
use one_parse::{Limits, ParseError};

const INVITE: &[u8] = b"BEGIN:VCALENDAR\r\n\
VERSION:2.0\r\n\
PRODID:-//Example//EN\r\n\
BEGIN:VTIMEZONE\r\n\
TZID:Europe/Istanbul\r\n\
END:VTIMEZONE\r\n\
BEGIN:VEVENT\r\n\
UID:evt-1@example.test\r\n\
SUMMARY:Planlama\\, b\xc3\xbct\xc3\xa7e\r\n\
DESCRIPTION:Sat\xc4\xb1r 1\\nSat\xc4\xb1r 2 uzun bir a\r\n \xc3\xa7\xc4\xb1klama\r\n\
LOCATION:Toplant\xc4\xb1 odas\xc4\xb1 3\r\n\
DTSTART;TZID=Europe/Istanbul:20261012T090000\r\n\
DTEND:20261012T070000Z\r\n\
RRULE:FREQ=WEEKLY;COUNT=4\r\n\
ORGANIZER;CN=\"Ali Y\xc4\xb1lmaz\":mailto:ali@example.test\r\n\
ATTENDEE;CN=Ay\xc5\x9fe;RSVP=TRUE:MAILTO:ayse@example.test\r\n\
ATTENDEE:mailto:bob@example.test\r\n\
X-UNKNOWN:ignored\r\n\
BEGIN:VALARM\r\n\
DESCRIPTION:alarm text\r\n\
END:VALARM\r\n\
END:VEVENT\r\n\
END:VCALENDAR\r\n";

#[test]
fn t_36_calendar_output_is_labelled_calendar() {
    let v = calendar::parse(INVITE, &Limits::DEFAULT).unwrap();
    assert_label(&v, "external.calendar");
    let events = &v.expose().events;
    assert_eq!(events.len(), 1);
    let e = &events[0];
    assert_eq!(e.uid.as_deref(), Some("evt-1@example.test"));
    assert_eq!(e.summary.as_deref(), Some("Planlama, bütçe"));
    assert_eq!(
        e.description.as_deref(),
        Some("Satır 1\nSatır 2 uzun bir açıklama")
    );
    assert_eq!(e.location.as_deref(), Some("Toplantı odası 3"));
    let start = e.start.as_ref().unwrap();
    assert_eq!(start.value, "20261012T090000");
    assert_eq!(start.tzid.as_deref(), Some("Europe/Istanbul"));
    assert_eq!(e.end.as_ref().unwrap().value, "20261012T070000Z");
    assert_eq!(e.rrule.as_deref(), Some("FREQ=WEEKLY;COUNT=4"));
    let organizer = e.organizer.as_ref().unwrap();
    assert_eq!(
        (organizer.address.as_str(), organizer.name.as_deref()),
        ("ali@example.test", Some("Ali Yılmaz"))
    );
    assert_eq!(e.attendees.len(), 2);
    assert_eq!(e.attendees[0].address, "ayse@example.test");
    assert_eq!(e.attendees[0].name.as_deref(), Some("Ayşe"));
}

#[test]
fn t_36_calendar_unbalanced_or_unrooted_is_rejected() {
    for bad in [
        &b"BEGIN:VEVENT\r\nEND:VEVENT\r\n"[..],
        b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nEND:VCALENDAR\r\n",
        b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\n",
        b"BEGIN:VCALENDAR\r\nnot a content line\r\nEND:VCALENDAR\r\n",
        b"BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nBEGIN:VEVENT\r\nEND:VEVENT\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n",
        b"\xff",
    ] {
        assert!(calendar::parse(bad, &tight()).is_err());
    }
}

#[test]
fn sec_13_calendar_oversize_is_rejected() {
    assert_eq!(
        calendar::parse(&vec![b'A'; 4097], &tight()).unwrap_err(),
        ParseError::TooLarge
    );
}

#[test]
fn sec_13_calendar_too_deep_is_rejected() {
    let mut text = String::from("BEGIN:VCALENDAR\r\n");
    for i in 0..5 {
        text.push_str(&format!("BEGIN:X{i}\r\n"));
    }
    assert_eq!(
        calendar::parse(text.as_bytes(), &tight()).unwrap_err(),
        ParseError::TooDeep
    );
}

#[test]
fn sec_13_calendar_too_many_items_is_rejected() {
    let mut text = String::from("BEGIN:VCALENDAR\r\n");
    for _ in 0..70 {
        text.push_str("X-A:b\r\n");
    }
    text.push_str("END:VCALENDAR\r\n");
    assert_eq!(
        calendar::parse(text.as_bytes(), &tight()).unwrap_err(),
        ParseError::TooManyItems
    );
}

#[test]
fn sec_13_calendar_long_folded_line_is_rejected() {
    let mut text = String::from("BEGIN:VCALENDAR\r\nBEGIN:VEVENT\r\nSUMMARY:a");
    for _ in 0..30 {
        text.push_str("\r\n bbbbbbbbbbbb");
    }
    text.push_str("\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n");
    assert_eq!(
        calendar::parse(text.as_bytes(), &tight()).unwrap_err(),
        ParseError::StringTooLong
    );
}
