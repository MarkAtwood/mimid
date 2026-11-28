//! Captures of what the server reports to `tracing`: [`JsonCapture`] for
//! its events, through the server's own JSON output (bead mimid-bfzm), and
//! [`SpanCapture`] for the spans it opens, which are what an OpenTelemetry
//! collector receives as traces (bead mimid-1wgh.46.20.1.1).

use std::collections::{BTreeMap, HashMap};
use std::fmt;
use std::io::Write;
use std::sync::{Arc, Mutex, Once, PoisonError};

use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

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

/// Installs [`Undecided`] as the test binary's global subscriber, once.
fn undecided_global() {
    static GLOBAL: Once = Once::new();
    GLOBAL.call_once(|| {
        tracing::subscriber::set_global_default(Undecided)
            .expect("no other global subscriber in this test binary");
    });
}

impl JsonCapture {
    pub fn start() -> Self {
        undecided_global();
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let writer = Arc::clone(&buffer);
        let subscriber = mimid_telemetry::logging::json_subscriber(
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

/// One span opened while a [`SpanCapture`] lived: what a trace exporter
/// would send, as a name, a level and the fields set at creation or
/// recorded later.
#[derive(Debug, Clone)]
pub struct CapturedSpan {
    pub name: &'static str,
    pub level: Level,
    pub fields: BTreeMap<String, String>,
}

impl CapturedSpan {
    /// The value of `field`, or `None` if it was never set. A field
    /// declared `Empty` and never recorded reads as absent.
    pub fn field(&self, field: &str) -> Option<&str> {
        self.fields.get(field).map(String::as_str)
    }
}

/// Collects each field into a map, with `Display` and `Debug` values as
/// the text they print.
struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Default)]
struct Opened {
    spans: Vec<CapturedSpan>,
    /// Span id to its index in `spans`. An id is reused after its span
    /// closes, so the last span with an id is the one a later `record`
    /// belongs to; a test reads `spans`, which keeps them all.
    index: HashMap<u64, usize>,
}

/// The `tracing-subscriber` layer behind [`SpanCapture`].
struct Opener(Arc<Mutex<Opened>>);

impl<S> tracing_subscriber::Layer<S> for Opener
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, _: Context<'_, S>) {
        let mut fields = BTreeMap::new();
        attributes.record(&mut Fields(&mut fields));
        let mut opened = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let at = opened.spans.len();
        opened.spans.push(CapturedSpan {
            name: attributes.metadata().name(),
            level: *attributes.metadata().level(),
            fields,
        });
        opened.index.insert(id.into_u64(), at);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _: Context<'_, S>) {
        let mut opened = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(at) = opened.index.get(&id.into_u64()).copied() else {
            return;
        };
        let mut fields = std::mem::take(&mut opened.spans[at].fields);
        values.record(&mut Fields(&mut fields));
        opened.spans[at].fields = fields;
    }
}

/// Every span opened on this thread while the capture lives, under an
/// `EnvFilter` the caller gives: a capture with `"info"` sees what a
/// collector sees from a server started with no `RUST_LOG`, which is the
/// question bead mimid-1wgh.46.20.1.1 is about.
///
/// It shares [`JsonCapture`]'s global [`Undecided`] subscriber, for the
/// same reason, so a binary using either cannot also use
/// `common::capture_logs`.
pub struct SpanCapture {
    opened: Arc<Mutex<Opened>>,
    _guard: tracing::subscriber::DefaultGuard,
}

impl SpanCapture {
    pub fn start(filter: &str) -> Self {
        undecided_global();
        let opened = Arc::new(Mutex::new(Opened::default()));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(filter))
            .with(Opener(Arc::clone(&opened)));
        Self {
            opened,
            _guard: tracing::subscriber::set_default(subscriber),
        }
    }

    /// The spans named `name`, in the order they were opened.
    pub fn named(&self, name: &str) -> Vec<CapturedSpan> {
        self.opened
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spans
            .iter()
            .filter(|span| span.name == name)
            .cloned()
            .collect()
    }

    /// The one span named `name`, or a panic saying what was opened
    /// instead.
    pub fn only(&self, name: &str) -> CapturedSpan {
        let mut found = self.named(name);
        assert_eq!(
            found.len(),
            1,
            "expected one {name} span, got {found:?}; opened: {:?}",
            self.opened
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .spans
                .iter()
                .map(|span| span.name)
                .collect::<Vec<_>>()
        );
        found.remove(0)
    }
}
