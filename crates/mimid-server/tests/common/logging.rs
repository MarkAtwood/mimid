//! A JSON capture of `tracing` events, through the server's own JSON
//! output, for tests of what the server logs (bead mimid-bfzm).

use std::io::Write;
use std::sync::{Arc, Mutex, Once};

use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Metadata, Subscriber};

struct Writer(Arc<Mutex<Vec<u8>>>);

impl Write for Writer {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// The global subscriber of a test binary that uses [`JsonCapture`]: it
/// records nothing, but answers every callsite "sometimes", so `tracing`
/// asks the current thread's dispatcher about each event. Without it, a
/// callsite first reached on another test's thread, while no capture is
/// registered, can cache "never" and hide its events from a capture
/// started later.
struct Undecided;

impl Subscriber for Undecided {
    fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
        Interest::sometimes()
    }

    fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
        Some(tracing::level_filters::LevelFilter::TRACE)
    }

    fn enabled(&self, _: &Metadata<'_>) -> bool {
        false
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, _: &Event<'_>) {}

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// The JSON lines (`mimid_server::logging`) of every `mimid_server` event
/// at every level emitted on this thread while the capture lives. A
/// `#[tokio::test]` runtime runs every task on its own thread, so this sees
/// the events of spawned tasks and servers too, and nothing from other
/// tests. The first capture in a test binary installs [`Undecided`] as the
/// global subscriber, so a binary using it cannot also use
/// `common::capture_logs`.
pub struct JsonCapture {
    buffer: Arc<Mutex<Vec<u8>>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl JsonCapture {
    pub fn start() -> Self {
        static GLOBAL: Once = Once::new();
        GLOBAL.call_once(|| {
            tracing::subscriber::set_global_default(Undecided)
                .expect("no other global subscriber in this test binary");
        });
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buffer);
        let subscriber = mimid_server::logging::json_subscriber(
            tracing_subscriber::EnvFilter::new("mimid_server=trace"),
            move || Writer(Arc::clone(&writer)),
        );
        Self {
            buffer,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// Every line captured so far, parsed.
    pub fn lines(&self) -> Vec<serde_json::Value> {
        let text = String::from_utf8(self.buffer.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    /// The captured lines at INFO, WARN or ERROR.
    pub fn above_debug(&self) -> Vec<serde_json::Value> {
        self.lines()
            .into_iter()
            .filter(|line| !matches!(line["level"].as_str(), Some("DEBUG" | "TRACE")))
            .collect()
    }
}

/// The fields of the span named `name` that `line`'s event ran in.
pub fn span_fields<'a>(line: &'a serde_json::Value, name: &str) -> &'a serde_json::Value {
    line["spans"]
        .as_array()
        .and_then(|spans| spans.iter().find(|span| span["name"] == name))
        .map(|span| &span["fields"])
        .unwrap_or_else(|| panic!("no {name} span in {line}"))
}
