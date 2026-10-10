//! A secret-shaped value logged by mistake never reaches the log output and is reported to the leak sink (SEC-6, T-37).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::io::Write;
use std::sync::{Arc, Mutex, PoisonError};

use one_telemetry::leak::LeakKind;
use one_telemetry::{LeakSink, Scrubbing};
use tracing_subscriber::fmt::MakeWriter;

const CANARY: &str = "4111 1111 1111 1111";

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

#[derive(Default)]
struct Sink(Mutex<Vec<LeakKind>>);

impl LeakSink for Sink {
    fn leak_blocked(&self, kinds: &[LeakKind]) {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .extend_from_slice(kinds);
    }
}

#[test]
fn sec_6_card_number_never_appears_in_logs() {
    let capture = Capture::default();
    let sink = Arc::new(Sink::default());
    let writer = Scrubbing::new(capture.clone(), Arc::clone(&sink) as Arc<dyn LeakSink>);
    one_telemetry::init_with_writer("trace", writer).unwrap();

    tracing::info!(event = "http.request", outcome = "ok", "served");
    tracing::warn!(note = CANARY, "mistake");

    let output = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("http.request"), "capture failed: {output}");
    assert!(output.contains("telemetry.leak_blocked"));
    assert!(!output.contains(CANARY), "leaked: {output}");
    assert_eq!(*sink.0.lock().unwrap(), vec![LeakKind::Card]);
}
