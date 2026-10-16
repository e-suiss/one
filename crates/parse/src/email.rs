//! A bounded RFC 5322 and MIME parser for the subset One reads: the From, To, Cc, Subject, Date and Message-ID headers, `text/plain` and `text/html` parts as text, and attachment metadata; labelled `external.email`.

use alloc::string::String;
use alloc::vec::Vec;

use one_provenance::{ExternalSource, Untrusted};

use crate::limits::{Budget, Limits, ParseError};
use crate::text::{Charset, Out, base64, decode_charset, html_to_text, quoted_printable};

/// The `Message-ID` header as sent, angle brackets included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageId(String);

impl MessageId {
    /// The header text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// The kind of a text part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BodyKind {
    /// `text/plain`.
    Plain,
    /// `text/html`, reduced to its text.
    Html,
}

/// One text part of the message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TextBody {
    /// The part's media type.
    pub kind: BodyKind,
    /// The decoded text.
    pub text: String,
}

/// The metadata of a part that is not read as text; its content is never decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attachment {
    /// The lower-case media type.
    pub media_type: String,
    /// The declared file name.
    pub filename: Option<String>,
    /// The size of the part as transferred, in bytes.
    pub encoded_size: usize,
}

/// The parts of an e-mail One reads.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Email {
    /// `From`, with encoded words decoded.
    pub from: Option<String>,
    /// `To`, with encoded words decoded.
    pub to: Option<String>,
    /// `Cc`, with encoded words decoded.
    pub cc: Option<String>,
    /// `Subject`, with encoded words decoded.
    pub subject: Option<String>,
    /// `Date`, as sent.
    pub date: Option<String>,
    /// `Message-ID`, as sent.
    pub message_id: Option<MessageId>,
    /// The text parts in message order.
    pub bodies: Vec<TextBody>,
    /// The other parts.
    pub attachments: Vec<Attachment>,
}

/// Parses an RFC 5322 message with MIME parts; each header, part and HTML tag counts as one item and MIME nesting counts as depth.
///
/// # Errors
/// A broken limit or a multipart entity without a boundary.
pub fn parse(bytes: &[u8], limits: &Limits) -> Result<Untrusted<Email>, ParseError> {
    let mut budget = Budget::new(limits, bytes.len())?;
    let mut email = Email::default();
    entity(bytes, 0, &mut budget, &mut email)?;
    Ok(Untrusted::external(email, ExternalSource::Email))
}

struct Line {
    start: usize,
    end: usize,
    next: usize,
}

fn lines(bytes: &[u8]) -> impl Iterator<Item = Line> + '_ {
    let mut pos = 0;
    core::iter::from_fn(move || {
        if pos >= bytes.len() {
            return None;
        }
        let start = pos;
        let rest = bytes.get(start..).unwrap_or_default();
        let (end, next) = match rest.iter().position(|&b| b == b'\n') {
            Some(i) => {
                let lf = start.saturating_add(i);
                let end = if lf > start && bytes.get(lf.saturating_sub(1)) == Some(&b'\r') {
                    lf.saturating_sub(1)
                } else {
                    lf
                };
                (end, lf.saturating_add(1))
            }
            None => (bytes.len(), bytes.len()),
        };
        pos = next;
        Some(Line { start, end, next })
    })
}

struct Header {
    name: Vec<u8>,
    value: Vec<u8>,
}

fn split_head(bytes: &[u8]) -> (Vec<Line>, &[u8]) {
    let mut head = Vec::new();
    for line in lines(bytes) {
        if line.start == line.end {
            return (head, bytes.get(line.next..).unwrap_or_default());
        }
        head.push(line);
    }
    (head, &[])
}

fn headers(bytes: &[u8], head: &[Line], budget: &mut Budget) -> Result<Vec<Header>, ParseError> {
    let mut out: Vec<Header> = Vec::new();
    for line in head {
        let text = bytes.get(line.start..line.end).unwrap_or_default();
        if text.first().is_some_and(|&b| b == b' ' || b == b'\t') {
            if let Some(last) = out.last_mut() {
                let len = last.value.len().saturating_add(text.len());
                budget.string(text.len())?;
                budget.string_len(len)?;
                last.value.extend_from_slice(text);
            }
            continue;
        }
        let Some(colon) = text.iter().position(|&b| b == b':') else {
            continue;
        };
        budget.item::<Header>()?;
        let name = text.get(..colon).unwrap_or_default().trim_ascii();
        let value = text.get(colon.saturating_add(1)..).unwrap_or_default();
        budget.string(name.len())?;
        budget.string(value.len())?;
        out.push(Header {
            name: name.to_vec(),
            value: value.to_vec(),
        });
    }
    Ok(out)
}

fn header<'h>(headers: &'h [Header], name: &str) -> Option<&'h [u8]> {
    headers
        .iter()
        .find(|h| h.name.eq_ignore_ascii_case(name.as_bytes()))
        .map(|h| h.value.trim_ascii())
}

fn encoded_parts(word: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let inner = word.strip_prefix(b"=?")?.strip_suffix(b"?=")?;
    let mut fields = inner.splitn(3, |&b| b == b'?');
    let charset = fields.next()?;
    let encoding = fields.next()?;
    let text = fields.next()?;
    matches!(encoding, b"B" | b"b" | b"Q" | b"q").then_some((charset, encoding, text))
}

fn encoded_word(
    (charset, encoding, text): (&[u8], &[u8], &[u8]),
    out: &mut Out<'_>,
) -> Result<(), ParseError> {
    let label = core::str::from_utf8(charset).unwrap_or_default();
    let label = label.split('*').next().unwrap_or_default();
    let decoded = if matches!(encoding, b"B" | b"b") {
        base64(text, out.budget())?
    } else {
        quoted_printable(text, true, out.budget())?
    };
    decode_charset(
        &decoded,
        Charset::from_label(label).unwrap_or(Charset::Utf8),
        out,
    )
}

fn header_text(value: &[u8], budget: &mut Budget) -> Result<String, ParseError> {
    let mut out = Out::new(budget);
    let mut previous_encoded = false;
    let mut rest = value;
    while !rest.is_empty() {
        let space_len = rest.iter().take_while(|b| b.is_ascii_whitespace()).count();
        let (space, tail) = rest.split_at_checked(space_len).unwrap_or((rest, &[]));
        let word_len = tail.iter().take_while(|b| !b.is_ascii_whitespace()).count();
        let (word, tail) = tail.split_at_checked(word_len).unwrap_or((tail, &[]));
        rest = tail;
        if word.is_empty() {
            continue;
        }
        let encoded = encoded_parts(word);
        let joined = encoded.is_some() && previous_encoded;
        if !space.is_empty() && !out.is_empty() && !joined {
            out.push(' ')?;
        }
        match encoded {
            Some(parts) => encoded_word(parts, &mut out)?,
            None => decode_charset(word, Charset::Utf8, &mut out)?,
        }
        previous_encoded = encoded.is_some();
    }
    Ok(out.finish())
}

struct ContentType {
    media_type: String,
    params: Vec<(String, Vec<u8>)>,
}

impl ContentType {
    fn param(&self, name: &str) -> Option<&[u8]> {
        self.params
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_slice())
    }
}

fn split_params(value: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut quoted = false;
    let mut start = 0;
    for (i, &b) in value.iter().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b';' if !quoted => {
                out.push(value.get(start..i).unwrap_or_default());
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    out.push(value.get(start..).unwrap_or_default());
    out
}

fn unquote(value: &[u8]) -> Vec<u8> {
    let Some(inner) = value
        .strip_prefix(b"\"")
        .and_then(|v| v.strip_suffix(b"\""))
    else {
        return value.to_vec();
    };
    let mut out = Vec::with_capacity(inner.len());
    let mut escape = false;
    for &b in inner {
        if escape || b != b'\\' {
            out.push(b);
            escape = false;
        } else {
            escape = true;
        }
    }
    out
}

fn percent_decode(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len());
    let mut i = 0;
    while let Some(&b) = value.get(i) {
        let hi = value
            .get(i.saturating_add(1))
            .and_then(|&c| char::from(c).to_digit(16));
        let lo = value
            .get(i.saturating_add(2))
            .and_then(|&c| char::from(c).to_digit(16));
        if let (b'%', Some(h), Some(l)) = (b, hi, lo) {
            out.push(u8::try_from(h.saturating_mul(16).saturating_add(l)).unwrap_or(b'?'));
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    out
}

fn content_type(
    value: Option<&[u8]>,
    default: &str,
    budget: &mut Budget,
) -> Result<ContentType, ParseError> {
    let Some(value) = value else {
        return Ok(ContentType {
            media_type: String::from(default),
            params: Vec::new(),
        });
    };
    let mut parts = split_params(value).into_iter();
    let media = parts.next().unwrap_or_default().trim_ascii();
    let mut media_type = String::from_utf8_lossy(media).into_owned();
    media_type.make_ascii_lowercase();
    if media_type.is_empty() {
        media_type = String::from(default);
    }
    let mut params = Vec::new();
    for part in parts {
        let Some(eq) = part.iter().position(|&b| b == b'=') else {
            continue;
        };
        budget.item::<(String, Vec<u8>)>()?;
        let name = part.get(..eq).unwrap_or_default().trim_ascii();
        let raw = part
            .get(eq.saturating_add(1)..)
            .unwrap_or_default()
            .trim_ascii();
        let name = String::from_utf8_lossy(name).into_owned();
        let value = match name.strip_suffix('*') {
            Some(base) => {
                let mut fields = raw.splitn(3, |&b| b == b'\'');
                let decoded = match (fields.next(), fields.next(), fields.next()) {
                    (Some(_), Some(_), Some(text)) => percent_decode(text),
                    _ => percent_decode(raw),
                };
                params.push((String::from(base), decoded));
                continue;
            }
            None => unquote(raw),
        };
        params.push((name, value));
    }
    Ok(ContentType { media_type, params })
}

fn entity(
    bytes: &[u8],
    depth: usize,
    budget: &mut Budget,
    email: &mut Email,
) -> Result<(), ParseError> {
    budget.depth(depth)?;
    let (head, body) = split_head(bytes);
    let headers = headers(bytes, &head, budget)?;
    if depth == 0 {
        let text = |name: &str, budget: &mut Budget| -> Result<Option<String>, ParseError> {
            header(&headers, name)
                .map(|v| header_text(v, budget))
                .transpose()
        };
        email.from = text("From", budget)?;
        email.to = text("To", budget)?;
        email.cc = text("Cc", budget)?;
        email.subject = text("Subject", budget)?;
        email.date = text("Date", budget)?;
        email.message_id = text("Message-ID", budget)?.map(MessageId);
    }
    let ctype = content_type(header(&headers, "Content-Type"), "text/plain", budget)?;
    if ctype.media_type.starts_with("multipart/") {
        let boundary = ctype
            .param("boundary")
            .filter(|b| !b.is_empty())
            .ok_or(ParseError::Malformed("multipart without boundary"))?;
        for part in multipart(body, boundary) {
            budget.item::<Attachment>()?;
            entity(part, depth.saturating_add(1), budget, email)?;
        }
        return Ok(());
    }
    let disposition = content_type(header(&headers, "Content-Disposition"), "inline", budget)?;
    let filename = disposition
        .param("filename")
        .or_else(|| ctype.param("name"));
    let kind = match ctype.media_type.as_str() {
        "text/plain" => Some(BodyKind::Plain),
        "text/html" => Some(BodyKind::Html),
        _ => None,
    };
    let as_text = kind.filter(|_| disposition.media_type != "attachment" && filename.is_none());
    let Some(kind) = as_text else {
        let filename = filename.map(|f| header_text(f, budget)).transpose()?;
        budget.string(ctype.media_type.len())?;
        budget.item::<Attachment>()?;
        email.attachments.push(Attachment {
            media_type: ctype.media_type,
            filename,
            encoded_size: body.len(),
        });
        return Ok(());
    };
    let encoding = header(&headers, "Content-Transfer-Encoding").unwrap_or_default();
    let decoded = if encoding.eq_ignore_ascii_case(b"base64") {
        base64(body, budget)?
    } else if encoding.eq_ignore_ascii_case(b"quoted-printable") {
        quoted_printable(body, false, budget)?
    } else {
        budget.alloc(body.len())?;
        body.to_vec()
    };
    let charset = ctype
        .param("charset")
        .and_then(|c| core::str::from_utf8(c).ok())
        .and_then(Charset::from_label)
        .unwrap_or(Charset::Utf8);
    let mut out = Out::new(budget);
    match kind {
        BodyKind::Plain => {
            let mut raw = Out::new(out.budget());
            decode_charset(&decoded, charset, &mut raw)?;
            let raw = raw.finish();
            crate::document::plain(&raw, &mut out)?;
        }
        BodyKind::Html => {
            let mut raw = Out::new(out.budget());
            decode_charset(&decoded, charset, &mut raw)?;
            let raw = raw.finish();
            html_to_text(&raw, &mut out)?;
        }
    }
    let text = out.finish();
    budget.item::<TextBody>()?;
    email.bodies.push(TextBody { kind, text });
    Ok(())
}

fn multipart<'a>(body: &'a [u8], boundary: &[u8]) -> Vec<&'a [u8]> {
    let mut parts = Vec::new();
    let mut open: Option<usize> = None;
    for line in lines(body) {
        let text = body
            .get(line.start..line.end)
            .unwrap_or_default()
            .trim_ascii_end();
        let Some(rest) = text
            .strip_prefix(b"--")
            .and_then(|t| t.strip_prefix(boundary))
        else {
            continue;
        };
        let closing = rest == b"--";
        if !rest.is_empty() && !closing {
            continue;
        }
        if let Some(start) = open {
            let end = line.start.saturating_sub(eol_before(body, line.start));
            parts.push(body.get(start..end.max(start)).unwrap_or_default());
        }
        if closing {
            return parts;
        }
        open = Some(line.next);
    }
    if let Some(start) = open {
        parts.push(body.get(start..).unwrap_or_default());
    }
    parts
}

fn eol_before(body: &[u8], at: usize) -> usize {
    match (body.get(at.wrapping_sub(2)), body.get(at.wrapping_sub(1))) {
        (Some(b'\r'), Some(b'\n')) => 2,
        (_, Some(b'\n')) => 1,
        _ => 0,
    }
}
