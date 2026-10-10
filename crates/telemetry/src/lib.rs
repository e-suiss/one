//! Content-free logs, traces and metrics: only opaque identifiers, counts, durations and numbers reach telemetry, under a closed field list, and every line passes the leak scanner (T-37 (1), T-40, §18 OP-17, SEC-6).

pub mod fields;
pub mod leak;

use std::cell::Cell;
use std::fmt::{self, Write as _};
use std::io::Write;
use std::sync::Arc;

use tracing_subscriber::fmt::MakeWriter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

pub use fields::Field;

/// An opaque identifier: a 1–16 letter lower-case prefix, `_`, and 1–64 characters of `[0-9a-z]`.
#[derive(Clone, PartialEq, Eq)]
pub struct OpaqueId(String);

impl OpaqueId {
    /// Parses `prefix_suffix`; anything else is rejected.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (prefix, suffix) = s.split_once('_')?;
        let ok_prefix =
            (1..=16).contains(&prefix.len()) && prefix.bytes().all(|b| b.is_ascii_lowercase());
        let ok_suffix = (1..=64).contains(&suffix.len())
            && suffix
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
        (ok_prefix && ok_suffix).then(|| Self(s.to_owned()))
    }
}

impl fmt::Debug for OpaqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// The outcome of an operation; a normative decision is [`Outcome::Decided`], never an error (T-28 (6)).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// The operation completed.
    Ok,
    /// The operation produced a typed, normative decision.
    Decided,
    /// The operation failed.
    Error,
}

impl Outcome {
    /// The stable wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::Decided => "decided",
            Self::Error => "error",
        }
    }
}

/// The only value types telemetry accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    /// An opaque identifier.
    Id(OpaqueId),
    /// A count.
    Count(u64),
    /// A duration in milliseconds.
    Millis(u64),
    /// A signed number such as a status code.
    Number(i64),
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Id(id) => f.write_str(&id.0),
            Self::Count(n) | Self::Millis(n) => write!(f, "{n}"),
            Self::Number(n) => write!(f, "{n}"),
        }
    }
}

/// A field given a value of the wrong kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KindMismatch(pub Field);

/// Renders `fields` as `name=value` pairs after checking each value's kind.
///
/// # Errors
/// Returns the first field whose value has the wrong kind.
pub fn render(fields: &[(Field, Value)]) -> Result<String, KindMismatch> {
    let mut out = String::new();
    for (field, value) in fields {
        if !field.accepts(value) {
            return Err(KindMismatch(*field));
        }
        if !out.is_empty() {
            out.push(' ');
        }
        let _ = write!(out, "{}={value}", field.name());
    }
    Ok(out)
}

/// Emits one structured event with a stable name, an outcome and typed fields (T-40 (4)).
pub fn emit(event: &'static str, outcome: Outcome, fields: &[(Field, Value)]) {
    match render(fields) {
        Ok(rendered) => tracing::info!(event, outcome = outcome.as_str(), fields = %rendered),
        Err(KindMismatch(field)) => tracing::warn!(
            event = "telemetry.kind_mismatch",
            outcome = Outcome::Error.as_str(),
            field = field.name()
        ),
    }
}

/// Receives the kinds of leak found in a dropped log line, never the line itself (SEC-22 (8)).
pub trait LeakSink: Send + Sync {
    /// Called once per dropped line.
    fn leak_blocked(&self, kinds: &[leak::LeakKind]);
}

/// A [`MakeWriter`] that drops lines carrying secret-shaped data (SEC-6).
pub struct Scrubbing<W> {
    inner: W,
    sink: Arc<dyn LeakSink>,
}

impl<W> Scrubbing<W> {
    /// Wraps `inner`; findings go to `sink`.
    pub fn new(inner: W, sink: Arc<dyn LeakSink>) -> Self {
        Self { inner, sink }
    }
}

/// One line writer produced by [`Scrubbing`].
pub struct ScrubbingLine<W: Write> {
    inner: W,
    sink: Arc<dyn LeakSink>,
    buf: Vec<u8>,
}

thread_local! {
    static IN_SINK: Cell<bool> = const { Cell::new(false) };
}

/// The line written in place of a dropped one.
pub const BLOCKED_LINE: &[u8] = b"{\"event\":\"telemetry.leak_blocked\",\"outcome\":\"decided\"}\n";

impl<W: Write> ScrubbingLine<W> {
    fn emit_buffered(&mut self) -> std::io::Result<()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let kinds = leak::scan(&String::from_utf8_lossy(&self.buf));
        if kinds.is_empty() {
            self.inner.write_all(&self.buf)?;
        } else {
            if !IN_SINK.with(Cell::get) {
                IN_SINK.with(|f| f.set(true));
                self.sink.leak_blocked(&kinds);
                IN_SINK.with(|f| f.set(false));
            }
            self.inner.write_all(BLOCKED_LINE)?;
        }
        self.buf.clear();
        Ok(())
    }
}

impl<W: Write> Write for ScrubbingLine<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.buf.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.emit_buffered()?;
        self.inner.flush()
    }
}

impl<W: Write> Drop for ScrubbingLine<W> {
    fn drop(&mut self) {
        let _ = self.flush();
    }
}

impl<'a, W> MakeWriter<'a> for Scrubbing<W>
where
    W: MakeWriter<'a>,
{
    type Writer = ScrubbingLine<W::Writer>;

    fn make_writer(&'a self) -> Self::Writer {
        ScrubbingLine {
            inner: self.inner.make_writer(),
            sink: Arc::clone(&self.sink),
            buf: Vec::new(),
        }
    }
}

/// The global subscriber could not be installed.
#[derive(Debug)]
pub struct InitError(tracing_subscriber::util::TryInitError);

impl fmt::Display for InitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "telemetry init failed: {}", self.0)
    }
}

impl std::error::Error for InitError {}

/// Installs the process-wide JSON log subscriber on stdout behind the leak scanner.
///
/// # Errors
/// Fails if a global subscriber is already installed.
pub fn init(filter: &str, sink: Arc<dyn LeakSink>) -> Result<(), InitError> {
    init_with_writer(filter, Scrubbing::new(std::io::stdout, sink))
}

/// Installs the JSON log subscriber with a custom writer.
///
/// # Errors
/// Fails if a global subscriber is already installed.
pub fn init_with_writer<W>(filter: &str, writer: W) -> Result<(), InitError>
where
    W: for<'a> MakeWriter<'a> + Send + Sync + 'static,
{
    Registry::default()
        .with(EnvFilter::new(filter))
        .with(
            tracing_subscriber::fmt::layer()
                .json()
                .with_current_span(true)
                .with_span_list(false)
                .with_writer(writer),
        )
        .try_init()
        .map_err(InitError)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_37_opaque_id_rejects_content_shaped_strings() {
        assert!(OpaqueId::parse("task_01j9z3k4").is_some());
        for bad in [
            "alice@example.com",
            "task_Hello World",
            "_abc",
            "task_",
            "Task_abc",
            "no-separator",
        ] {
            assert!(OpaqueId::parse(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn t_37_field_with_wrong_kind_is_rejected() {
        assert_eq!(
            render(&[(Field::DurationMs, Value::Millis(12))]),
            Ok("duration_ms=12".to_owned())
        );
        assert_eq!(
            render(&[(Field::DurationMs, Value::Count(1))]),
            Err(KindMismatch(Field::DurationMs))
        );
    }

    #[test]
    fn t_28_decision_is_not_an_error_outcome() {
        assert_ne!(Outcome::Decided.as_str(), Outcome::Error.as_str());
    }
}
