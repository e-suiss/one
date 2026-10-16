//! A bounded RFC 5545 iCalendar parser for the event fields One reads: UID, SUMMARY, DESCRIPTION, LOCATION, DTSTART, DTEND, ORGANIZER, ATTENDEE and RRULE as text; labelled `external.calendar`.

use alloc::string::String;
use alloc::vec::Vec;

use one_provenance::{ExternalSource, Untrusted};

use crate::limits::{Budget, Limits, ParseError};
use crate::text::Out;

/// A date or date-time value as sent, with its time zone identifier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DateText {
    /// The value text, e.g. `20261012T090000Z`.
    pub value: String,
    /// The `TZID` parameter.
    pub tzid: Option<String>,
}

/// An organizer or attendee.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Participant {
    /// The calendar address with any `mailto:` prefix removed.
    pub address: String,
    /// The `CN` parameter.
    pub name: Option<String>,
}

/// One `VEVENT`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Event {
    /// `UID`.
    pub uid: Option<String>,
    /// `SUMMARY`, unescaped.
    pub summary: Option<String>,
    /// `DESCRIPTION`, unescaped.
    pub description: Option<String>,
    /// `LOCATION`, unescaped.
    pub location: Option<String>,
    /// `DTSTART`.
    pub start: Option<DateText>,
    /// `DTEND`.
    pub end: Option<DateText>,
    /// `ORGANIZER`.
    pub organizer: Option<Participant>,
    /// Every `ATTENDEE`.
    pub attendees: Vec<Participant>,
    /// `RRULE`, as sent.
    pub rrule: Option<String>,
}

/// The events of one calendar object.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Calendar {
    /// The `VEVENT` components in order.
    pub events: Vec<Event>,
}

/// Parses a UTF-8 iCalendar object rooted at `VCALENDAR`; each content line counts as one item, component nesting counts as depth and unknown components and properties are skipped.
///
/// # Errors
/// A broken limit, input that is not UTF-8, a missing root or unbalanced components.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Untrusted<Calendar>, ParseError> {
    let mut budget = Budget::new(limits, bytes.len())?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let source = core::str::from_utf8(bytes).map_err(|_| ParseError::Malformed("not utf-8"))?;
    let mut state = State::default();
    let mut logical = String::new();
    for raw in source.split('\n') {
        let raw = raw.strip_suffix('\r').unwrap_or(raw);
        if let Some(rest) = raw.strip_prefix([' ', '\t']) {
            budget.string_len(logical.len().saturating_add(rest.len()))?;
            logical.push_str(rest);
            continue;
        }
        if !logical.is_empty() {
            state.line(&logical, &mut budget)?;
        }
        budget.string_len(raw.len())?;
        logical.clear();
        logical.push_str(raw);
    }
    if !logical.is_empty() {
        state.line(&logical, &mut budget)?;
    }
    if !state.stack.is_empty() || !state.rooted {
        return Err(ParseError::Malformed("unbalanced components"));
    }
    Ok(Untrusted::external(
        state.calendar,
        ExternalSource::Calendar,
    ))
}

#[derive(Default)]
struct State {
    stack: Vec<String>,
    rooted: bool,
    event: Option<Event>,
    calendar: Calendar,
}

struct ContentLine<'a> {
    name: &'a str,
    params: Vec<(&'a str, &'a str)>,
    value: &'a str,
}

fn content_line(line: &str) -> Option<ContentLine<'_>> {
    let mut quoted = false;
    let mut segments = Vec::new();
    let mut start = 0;
    let mut value_at = None;
    for (i, c) in line.char_indices() {
        match c {
            '"' => quoted = !quoted,
            ';' if !quoted => {
                segments.push(line.get(start..i)?);
                start = i.saturating_add(1);
            }
            ':' if !quoted => {
                segments.push(line.get(start..i)?);
                value_at = Some(i.saturating_add(1));
                break;
            }
            _ => {}
        }
    }
    let value = line.get(value_at?..)?;
    let mut segments = segments.into_iter();
    let name = segments.next()?;
    let params = segments
        .filter_map(|p| p.split_once('='))
        .map(|(k, v)| (k, v.trim_matches('"')))
        .collect();
    Some(ContentLine {
        name,
        params,
        value,
    })
}

fn param<'a>(line: &ContentLine<'a>, name: &str) -> Option<&'a str> {
    line.params
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case(name))
        .map(|(_, v)| *v)
}

fn copy(text: &str, budget: &mut Budget) -> Result<String, ParseError> {
    let mut out = Out::new(budget);
    out.push_str(text)?;
    Ok(out.finish())
}

fn unescape(text: &str, budget: &mut Budget) -> Result<String, ParseError> {
    let mut out = Out::new(budget);
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c)?;
            continue;
        }
        match chars.next() {
            Some('n' | 'N') => out.push('\n')?,
            Some(other) => out.push(other)?,
            None => out.push('\\')?,
        }
    }
    Ok(out.finish())
}

fn participant(line: &ContentLine<'_>, budget: &mut Budget) -> Result<Participant, ParseError> {
    let value = line.value.trim();
    let address = value
        .get(..7)
        .filter(|p| p.eq_ignore_ascii_case("mailto:"))
        .and_then(|_| value.get(7..))
        .unwrap_or(value);
    Ok(Participant {
        address: copy(address, budget)?,
        name: param(line, "CN").map(|n| copy(n, budget)).transpose()?,
    })
}

fn date(line: &ContentLine<'_>, budget: &mut Budget) -> Result<DateText, ParseError> {
    Ok(DateText {
        value: copy(line.value.trim(), budget)?,
        tzid: param(line, "TZID").map(|t| copy(t, budget)).transpose()?,
    })
}

impl State {
    fn line(&mut self, text: &str, budget: &mut Budget) -> Result<(), ParseError> {
        budget.items(1)?;
        let Some(line) = content_line(text) else {
            return Err(ParseError::Malformed("content line"));
        };
        if line.name.eq_ignore_ascii_case("BEGIN") {
            return self.begin(line.value.trim(), budget);
        }
        if line.name.eq_ignore_ascii_case("END") {
            return self.end(line.value.trim());
        }
        let in_event = self
            .stack
            .last()
            .is_some_and(|c| c.eq_ignore_ascii_case("VEVENT"));
        let Some(event) = self.event.as_mut().filter(|_| in_event) else {
            return Ok(());
        };
        let name = line.name.to_ascii_uppercase();
        match name.as_str() {
            "UID" => event.uid = Some(copy(line.value, budget)?),
            "SUMMARY" => event.summary = Some(unescape(line.value, budget)?),
            "DESCRIPTION" => event.description = Some(unescape(line.value, budget)?),
            "LOCATION" => event.location = Some(unescape(line.value, budget)?),
            "DTSTART" => event.start = Some(date(&line, budget)?),
            "DTEND" => event.end = Some(date(&line, budget)?),
            "RRULE" => event.rrule = Some(copy(line.value, budget)?),
            "ORGANIZER" => event.organizer = Some(participant(&line, budget)?),
            "ATTENDEE" => {
                budget.item::<Participant>()?;
                event.attendees.push(participant(&line, budget)?);
            }
            _ => {}
        }
        Ok(())
    }

    fn begin(&mut self, component: &str, budget: &mut Budget) -> Result<(), ParseError> {
        if self.stack.is_empty() {
            if self.rooted || !component.eq_ignore_ascii_case("VCALENDAR") {
                return Err(ParseError::Malformed("root is not VCALENDAR"));
            }
            self.rooted = true;
        }
        budget.depth(self.stack.len().saturating_add(1))?;
        if component.eq_ignore_ascii_case("VEVENT") {
            if self.event.is_some() {
                return Err(ParseError::Malformed("nested VEVENT"));
            }
            budget.item::<Event>()?;
            self.event = Some(Event::default());
        }
        let name = copy(component, budget)?;
        self.stack.push(name);
        Ok(())
    }

    fn end(&mut self, component: &str) -> Result<(), ParseError> {
        let open = self
            .stack
            .pop()
            .ok_or(ParseError::Malformed("END without BEGIN"))?;
        if !open.eq_ignore_ascii_case(component) {
            return Err(ParseError::Malformed("END does not match BEGIN"));
        }
        if open.eq_ignore_ascii_case("VEVENT")
            && let Some(event) = self.event.take()
        {
            self.calendar.events.push(event);
        }
        Ok(())
    }
}
