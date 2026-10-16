//! Documents as text: plain text, Markdown and HTML, labelled `external.document`; PDF and Office formats are not parsed here.

use alloc::string::String;

use one_provenance::{ExternalSource, Untrusted};

use crate::limits::{Budget, Limits, ParseError};
use crate::text::{Out, html_to_text};

/// The input format of a document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// UTF-8 plain text.
    Plain,
    /// UTF-8 Markdown, kept as its source text.
    Markdown,
    /// UTF-8 HTML, reduced to its text.
    Html,
}

/// The text of a document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Document {
    /// The input format.
    pub format: Format,
    /// The text, with line endings normalised to `\n`.
    pub text: String,
}

/// Parses a UTF-8 document; a leading byte-order mark is dropped and each line or tag counts as one item.
///
/// # Errors
/// A broken limit or input that is not UTF-8.
pub fn parse(
    bytes: &[u8],
    limits: &Limits,
    format: Format,
) -> Result<Untrusted<Document>, ParseError> {
    let mut budget = Budget::new(limits, bytes.len())?;
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(bytes);
    let source = core::str::from_utf8(bytes).map_err(|_| ParseError::Malformed("not utf-8"))?;
    let mut out = Out::new(&mut budget);
    match format {
        Format::Html => html_to_text(source, &mut out)?,
        Format::Plain | Format::Markdown => plain(source, &mut out)?,
    }
    let text = out.finish();
    Ok(Untrusted::external(
        Document { format, text },
        ExternalSource::Document,
    ))
}

pub(crate) fn plain(source: &str, out: &mut Out<'_>) -> Result<(), ParseError> {
    for line in source.split_inclusive('\n') {
        out.item()?;
        let body = line.strip_suffix('\n').unwrap_or(line);
        let body = body.strip_suffix('\r').unwrap_or(body);
        out.push_str(body)?;
        if line.ends_with('\n') {
            out.push('\n')?;
        }
    }
    Ok(())
}
