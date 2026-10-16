//! Shared text decoding under a budget: charsets, base64, quoted-printable and HTML to text.

use alloc::string::String;
use alloc::vec::Vec;

use crate::limits::{Budget, ParseError};

/// A charset this crate decodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Charset {
    Utf8,
    Latin1,
    Latin5,
    Windows1252,
    Windows1254,
}

impl Charset {
    pub(crate) fn from_label(label: &str) -> Option<Self> {
        let label = label.trim().trim_matches('"');
        let eq = |names: &[&str]| names.iter().any(|n| n.eq_ignore_ascii_case(label));
        if eq(&["utf-8", "utf8", "us-ascii", "ascii"]) {
            Some(Self::Utf8)
        } else if eq(&["iso-8859-1", "latin1", "iso_8859-1", "l1"]) {
            Some(Self::Latin1)
        } else if eq(&["iso-8859-9", "latin5", "iso_8859-9", "l5"]) {
            Some(Self::Latin5)
        } else if eq(&["windows-1252", "cp1252"]) {
            Some(Self::Windows1252)
        } else if eq(&["windows-1254", "cp1254"]) {
            Some(Self::Windows1254)
        } else {
            None
        }
    }
}

const C1_1252: [char; 32] = [
    '€', '\u{fffd}', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\u{fffd}', 'Ž',
    '\u{fffd}', '\u{fffd}', '‘', '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\u{fffd}',
    'ž', 'Ÿ',
];

fn single_byte(charset: Charset, b: u8) -> char {
    let turkish = matches!(charset, Charset::Latin5 | Charset::Windows1254);
    let windows = matches!(charset, Charset::Windows1252 | Charset::Windows1254);
    match b {
        0x80..=0x9f if windows => {
            let c = C1_1252
                .get(usize::from(b.saturating_sub(0x80)))
                .copied()
                .unwrap_or('\u{fffd}');
            if turkish && matches!(c, 'Ž' | 'ž') {
                '\u{fffd}'
            } else {
                c
            }
        }
        0xd0 if turkish => 'Ğ',
        0xdd if turkish => 'İ',
        0xde if turkish => 'Ş',
        0xf0 if turkish => 'ğ',
        0xfd if turkish => 'ı',
        0xfe if turkish => 'ş',
        _ => char::from(b),
    }
}

/// Bounded text output: every byte written is charged to the string and allocation limits.
pub(crate) struct Out<'b> {
    text: String,
    budget: &'b mut Budget,
}

impl<'b> Out<'b> {
    pub(crate) const fn new(budget: &'b mut Budget) -> Self {
        Self {
            text: String::new(),
            budget,
        }
    }

    pub(crate) fn push(&mut self, c: char) -> Result<(), ParseError> {
        let len = self.text.len().saturating_add(c.len_utf8());
        self.budget.string_len(len)?;
        self.budget.alloc(c.len_utf8())?;
        self.text.push(c);
        Ok(())
    }

    pub(crate) fn push_str(&mut self, s: &str) -> Result<(), ParseError> {
        s.chars().try_for_each(|c| self.push(c))
    }

    pub(crate) const fn budget(&mut self) -> &mut Budget {
        &mut *self.budget
    }

    pub(crate) fn item(&mut self) -> Result<(), ParseError> {
        self.budget.items(1)
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    pub(crate) fn finish(self) -> String {
        self.text
    }
}

/// Decodes `bytes` in `charset`; invalid UTF-8 becomes U+FFFD.
pub(crate) fn decode_charset(
    bytes: &[u8],
    charset: Charset,
    out: &mut Out<'_>,
) -> Result<(), ParseError> {
    if charset != Charset::Utf8 {
        return bytes
            .iter()
            .try_for_each(|&b| out.push(single_byte(charset, b)));
    }
    for chunk in bytes.utf8_chunks() {
        out.push_str(chunk.valid())?;
        if !chunk.invalid().is_empty() {
            out.push('\u{fffd}')?;
        }
    }
    Ok(())
}

fn base64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c.saturating_sub(b'A')),
        b'a'..=b'z' => Some(c.saturating_sub(b'a').saturating_add(26)),
        b'0'..=b'9' => Some(c.saturating_sub(b'0').saturating_add(52)),
        b'+' | b'-' => Some(62),
        b'/' | b'_' => Some(63),
        _ => None,
    }
}

/// Decodes base64, skipping whitespace and stopping at padding; the output is never longer than the input.
pub(crate) fn base64(input: &[u8], budget: &mut Budget) -> Result<Vec<u8>, ParseError> {
    let capacity = input.len().saturating_mul(3) / 4;
    budget.alloc(capacity)?;
    let mut out = Vec::with_capacity(capacity);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in input {
        if c == b'=' {
            break;
        }
        if c.is_ascii_whitespace() {
            continue;
        }
        let v = base64_value(c).ok_or(ParseError::Malformed("base64"))?;
        acc = (acc << 6 | u32::from(v)) & 0x00ff_ffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    Ok(out)
}

fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c.saturating_sub(b'0')),
        b'A'..=b'F' => Some(c.saturating_sub(b'A').saturating_add(10)),
        b'a'..=b'f' => Some(c.saturating_sub(b'a').saturating_add(10)),
        _ => None,
    }
}

/// Decodes quoted-printable; `underscore_space` is the RFC 2047 `Q` form.
pub(crate) fn quoted_printable(
    input: &[u8],
    underscore_space: bool,
    budget: &mut Budget,
) -> Result<Vec<u8>, ParseError> {
    budget.alloc(input.len())?;
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while let Some(&c) = input.get(i) {
        i = i.saturating_add(1);
        match c {
            b'=' => match (
                input.get(i).copied(),
                input.get(i.saturating_add(1)).copied(),
            ) {
                (Some(b'\r'), Some(b'\n')) => i = i.saturating_add(2),
                (Some(b'\n'), _) => i = i.saturating_add(1),
                (Some(h), Some(l)) => match (hex(h), hex(l)) {
                    (Some(h), Some(l)) => {
                        out.push(h.saturating_mul(16).saturating_add(l));
                        i = i.saturating_add(2);
                    }
                    _ => out.push(b'='),
                },
                _ => out.push(b'='),
            },
            b'_' if underscore_space => out.push(b' '),
            _ => out.push(c),
        }
    }
    Ok(out)
}

const SKIPPED: &[&str] = &["script", "style", "template", "noscript", "head"];
const BLOCKS: &[&str] = &[
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
    "title",
];

const ENTITIES: &[(&str, char)] = &[
    ("amp", '&'),
    ("lt", '<'),
    ("gt", '>'),
    ("quot", '"'),
    ("apos", '\''),
    ("nbsp", ' '),
    ("shy", '\u{ad}'),
    ("copy", '©'),
    ("reg", '®'),
    ("euro", '€'),
    ("ndash", '–'),
    ("mdash", '—'),
    ("hellip", '…'),
    ("laquo", '«'),
    ("raquo", '»'),
    ("lsquo", '‘'),
    ("rsquo", '’'),
    ("ldquo", '“'),
    ("rdquo", '”'),
];

fn entity(name: &str) -> Option<char> {
    if let Some(num) = name.strip_prefix('#') {
        let code = match num.strip_prefix(['x', 'X']) {
            Some(h) => u32::from_str_radix(h, 16).ok()?,
            None => num.parse::<u32>().ok()?,
        };
        return Some(char::from_u32(code).unwrap_or('\u{fffd}'));
    }
    ENTITIES.iter().find(|(n, _)| *n == name).map(|(_, c)| *c)
}

fn tag_name(tag: &str) -> &str {
    let tag = tag.trim_start_matches('/');
    let end = tag
        .find(|c: char| c.is_ascii_whitespace() || c == '/' || c == '>')
        .unwrap_or(tag.len());
    tag.get(..end).unwrap_or("")
}

fn find_from(haystack: &str, from: usize, needle: &str) -> Option<usize> {
    haystack
        .get(from..)
        .and_then(|rest| rest.find(needle))
        .map(|i| i.saturating_add(from))
}

fn find_close(html: &str, from: usize, name: &str) -> Option<usize> {
    let lower_rest = html.get(from..)?;
    let bytes = lower_rest.as_bytes();
    let mut i = 0;
    while let Some(off) = lower_rest.get(i..).and_then(|r| r.find("</")) {
        let start = i.saturating_add(off);
        let name_start = start.saturating_add(2);
        let candidate = bytes.get(name_start..name_start.saturating_add(name.len()));
        if candidate.is_some_and(|c| c.eq_ignore_ascii_case(name.as_bytes())) {
            return Some(from.saturating_add(start));
        }
        i = name_start;
    }
    None
}

fn separate(out: &mut Out<'_>, line: &mut bool, space: &mut bool) -> Result<(), ParseError> {
    if *line {
        out.push('\n')?;
    } else if *space {
        out.push(' ')?;
    }
    *line = false;
    *space = false;
    Ok(())
}

/// Converts HTML to visible-structure text: tags, comments, scripts and styles are dropped, block tags break lines, entities are decoded and whitespace collapses; each tag is charged as one item.
pub(crate) fn html_to_text(html: &str, out: &mut Out<'_>) -> Result<(), ParseError> {
    let mut i = 0;
    let mut space = false;
    let mut line = false;
    while let Some(c) = html.get(i..).and_then(|r| r.chars().next()) {
        match c {
            '<' if html
                .get(i.saturating_add(1)..)
                .and_then(|r| r.chars().next())
                .is_some_and(|n| n.is_ascii_alphabetic() || matches!(n, '/' | '!' | '?')) =>
            {
                out.item()?;
                if html.get(i..).is_some_and(|r| r.starts_with("<!--")) {
                    i = find_from(html, i.saturating_add(4), "-->")
                        .map_or(html.len(), |e| e.saturating_add(3));
                    continue;
                }
                let end = find_from(html, i, ">").map_or(html.len(), |e| e.saturating_add(1));
                let tag = html
                    .get(i.saturating_add(1)..end.saturating_sub(1))
                    .unwrap_or("");
                let name = tag_name(tag);
                let closing = tag.starts_with('/');
                i = end;
                if !closing && SKIPPED.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                    i = find_close(html, i, name).map_or(html.len(), |e| {
                        find_from(html, e, ">").map_or(html.len(), |g| g.saturating_add(1))
                    });
                    continue;
                }
                if BLOCKS.iter().any(|b| b.eq_ignore_ascii_case(name)) {
                    line = !out.is_empty();
                }
            }
            '&' => {
                let rest = html.get(i.saturating_add(1)..).unwrap_or("");
                let decoded = rest
                    .find(';')
                    .filter(|&e| e <= 32)
                    .and_then(|e| rest.get(..e).and_then(entity).map(|ch| (ch, e)));
                separate(out, &mut line, &mut space)?;
                if let Some((ch, e)) = decoded {
                    out.push(ch)?;
                    i = i.saturating_add(e).saturating_add(2);
                } else {
                    out.push('&')?;
                    i = i.saturating_add(1);
                }
            }
            c if c.is_whitespace() => {
                space = !out.is_empty();
                i = i.saturating_add(c.len_utf8());
            }
            c => {
                separate(out, &mut line, &mut space)?;
                out.push(c)?;
                i = i.saturating_add(c.len_utf8());
            }
        }
    }
    Ok(())
}
