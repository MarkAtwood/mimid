//! The `tracing` subscriber that `mimid` installs, and its JSON output
//! (bead mimid-bfzm).
//!
//! `RUST_LOG` filters events and spans; `mimid` defaults it to `info`.
//! [`LOG_FORMAT_VAR`] (`MIMID_LOG_FORMAT`) selects the output on standard
//! output:
//!
//! - unset, empty or `text`: tracing-subscriber's human-readable format;
//! - `json`: one JSON object per line, for `jq` and other tools.
//!
//! A JSON line has this shape (keys absent when there is nothing to put
//! in them):
//!
//! ```json
//! {"timestamp": "2026-11-13T10:00:00.000000Z", "level": "ERROR",
//!  "target": "mimid_server::http", "event": "peer_provider_failed",
//!  "message": "peer provider failed",
//!  "fields": {"error": "peer provider request failed",
//!             "error.sources": ["peer answered 400"], "status": 400},
//!  "spans": [{"name": "protocol_request",
//!             "fields": {"endpoint": "keyMaterial", "peer": "b.example"}}]}
//! ```
//!
//! `event` is the event's stable name. Every INFO, WARN and ERROR event of
//! this crate has one (`name: "..."` at the call site, lower snake case);
//! DEBUG and TRACE events have none. An error field holds the error's
//! message, and `<field>.sources` the messages of its source chain, as the
//! text format shows them.
//!
//! # Limitations
//!
//! - The text format does not show event names; select `json` to see
//!   them.
//! - An event's name is told apart from `tracing`'s default name only by
//!   the absence of a space: the default is `event <file>:<line>`, and a
//!   record from the `log` crate is named `log event`.

use std::ffi::OsString;
use std::fmt;

use serde_json::{Map, Value};
use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::EnvFilter;
use tracing_subscriber::fmt::format::{JsonFields, Writer};
use tracing_subscriber::fmt::time::{FormatTime, SystemTime};
use tracing_subscriber::fmt::{FmtContext, FormatEvent, FormattedFields, MakeWriter};
use tracing_subscriber::registry::LookupSpan;

/// The environment variable that selects the log output format.
pub const LOG_FORMAT_VAR: &str = "MIMID_LOG_FORMAT";

/// A log output format, chosen by [`LOG_FORMAT_VAR`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum LogFormat {
    /// tracing-subscriber's human-readable format: the default.
    #[default]
    Text,
    /// One JSON object per line (see the module documentation).
    Json,
}

impl LogFormat {
    /// The format [`LOG_FORMAT_VAR`] selects: [`LogFormat::Text`] if it is
    /// unset, empty or `text`, and [`LogFormat::Json`] if it is `json`.
    ///
    /// # Errors
    ///
    /// Returns [`LogFormatError`] for any other value.
    pub fn from_env() -> Result<Self, LogFormatError> {
        match std::env::var_os(LOG_FORMAT_VAR) {
            None => Ok(Self::Text),
            Some(value) => Self::parse(&value),
        }
    }

    /// The format named `value`, as [`LogFormat::from_env`] reads it.
    fn parse(value: &OsString) -> Result<Self, LogFormatError> {
        match value.to_str() {
            Some("" | "text") => Ok(Self::Text),
            Some("json") => Ok(Self::Json),
            _ => Err(LogFormatError {
                value: value.clone(),
            }),
        }
    }
}

/// [`LOG_FORMAT_VAR`] names no log format.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{LOG_FORMAT_VAR} must be \"text\" or \"json\", not {value:?}")]
pub struct LogFormatError {
    value: OsString,
}

/// A subscriber that writes JSON lines (see the module documentation) to
/// `writer`, keeping the events and spans `filter` enables.
pub fn json_subscriber<W>(filter: EnvFilter, writer: W) -> impl Subscriber + Send + Sync + 'static
where
    W: for<'w> MakeWriter<'w> + Send + Sync + 'static,
{
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .fmt_fields(JsonFields::new())
        .event_format(JsonEvents)
        .finish()
}

/// Formats each event as one JSON line (see the module documentation).
/// Span fields come from [`JsonFields`], so the subscriber must use it.
#[derive(Debug, Clone, Copy, Default)]
pub struct JsonEvents;

impl<S> FormatEvent<S, JsonFields> for JsonEvents
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, JsonFields>,
        mut writer: Writer<'_>,
        event: &Event<'_>,
    ) -> fmt::Result {
        let metadata = event.metadata();
        let mut line = Map::new();
        let mut timestamp = String::new();
        if SystemTime
            .format_time(&mut Writer::new(&mut timestamp))
            .is_ok()
        {
            line.insert("timestamp".into(), timestamp.into());
        }
        line.insert("level".into(), metadata.level().as_str().into());
        line.insert("target".into(), metadata.target().into());
        if !metadata.name().contains(' ') {
            line.insert("event".into(), metadata.name().into());
        }
        let mut fields = FieldMap::default();
        event.record(&mut fields);
        if let Some(message) = fields.message {
            line.insert("message".into(), message.into());
        }
        if !fields.fields.is_empty() {
            line.insert("fields".into(), fields.fields.into());
        }
        let spans: Vec<Value> = ctx
            .event_scope()
            .into_iter()
            .flat_map(|scope| scope.from_root())
            .map(|span| {
                let mut entry = Map::new();
                entry.insert("name".into(), span.name().into());
                let extensions = span.extensions();
                // JsonFields stores a span's fields as a JSON object.
                if let Some(Ok(Value::Object(fields))) = extensions
                    .get::<FormattedFields<JsonFields>>()
                    .map(|fields| serde_json::from_str::<Value>(fields))
                    && !fields.is_empty()
                {
                    entry.insert("fields".into(), fields.into());
                }
                entry.into()
            })
            .collect();
        if !spans.is_empty() {
            line.insert("spans".into(), spans.into());
        }
        // Serializing a map of strings, numbers and arrays cannot fail.
        let text = serde_json::to_string(&line).map_err(|_| fmt::Error)?;
        writeln!(writer, "{text}")
    }
}

/// An event's fields as JSON values, with `message` kept apart.
#[derive(Default)]
struct FieldMap {
    message: Option<String>,
    fields: Map<String, Value>,
}

impl FieldMap {
    fn insert(&mut self, field: &Field, value: Value) {
        if field.name() == "message" {
            self.message = Some(match value {
                Value::String(text) => text,
                other => other.to_string(),
            });
        } else {
            self.fields.insert(field.name().into(), value);
        }
    }
}

impl Visit for FieldMap {
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.insert(field, value.into());
    }

    fn record_i64(&mut self, field: &Field, value: i64) {
        self.insert(field, value.into());
    }

    fn record_u64(&mut self, field: &Field, value: u64) {
        self.insert(field, value.into());
    }

    fn record_bool(&mut self, field: &Field, value: bool) {
        self.insert(field, value.into());
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        self.insert(field, value.into());
    }

    fn record_error(&mut self, field: &Field, value: &(dyn std::error::Error + 'static)) {
        self.insert(field, value.to_string().into());
        let sources: Vec<Value> = std::iter::successors(value.source(), |source| source.source())
            .map(|source| source.to_string().into())
            .collect();
        if !sources.is_empty() {
            self.fields
                .insert(format!("{}.sources", field.name()), sources.into());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.insert(field, format!("{value:?}").into());
    }
}

/// A JSON capture of events for this crate's unit tests.
#[cfg(test)]
pub(crate) mod testing {
    use std::io::Write;
    use std::sync::{Arc, Mutex, Once};

    use serde_json::Value;
    use tracing::level_filters::LevelFilter;
    use tracing::span::{Attributes, Id, Record};
    use tracing::subscriber::Interest;
    use tracing::{Event, Metadata, Subscriber};
    use tracing_subscriber::EnvFilter;

    use super::json_subscriber;

    /// The global subscriber of the unit tests: it records nothing, but
    /// answers every callsite "sometimes", so `tracing` asks the current
    /// thread's dispatcher about each event. Without it, a callsite first
    /// reached on another test's thread, while no capture is registered,
    /// can cache "never" and hide its events from a later capture.
    struct Undecided;

    impl Subscriber for Undecided {
        fn register_callsite(&self, _: &'static Metadata<'static>) -> Interest {
            Interest::sometimes()
        }

        fn max_level_hint(&self) -> Option<LevelFilter> {
            Some(LevelFilter::TRACE)
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

    #[derive(Clone, Default)]
    struct Buffer(Arc<Mutex<Vec<u8>>>);

    impl Write for Buffer {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The JSON lines of every event `emit` produces on this thread, at
    /// every level, with each line's timestamp removed after checking
    /// that it is a string.
    pub(crate) fn lines(emit: impl FnOnce()) -> Vec<Value> {
        static GLOBAL: Once = Once::new();
        GLOBAL.call_once(|| {
            tracing::subscriber::set_global_default(Undecided)
                .expect("no other global subscriber in the unit tests");
        });
        let buffer = Buffer::default();
        let writer = buffer.clone();
        let subscriber = json_subscriber(EnvFilter::new("trace"), move || writer.clone());
        tracing::subscriber::with_default(subscriber, emit);
        let text = String::from_utf8(buffer.0.lock().unwrap().clone()).unwrap();
        text.lines()
            .map(|line| {
                let mut value: Value = serde_json::from_str(line).unwrap();
                let removed = value.as_object_mut().unwrap().remove("timestamp");
                assert!(matches!(removed, Some(Value::String(_))), "{line}");
                value
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::testing::lines;
    use super::*;

    #[derive(Debug, thiserror::Error)]
    #[error("outer failed")]
    struct Outer(#[source] Inner);

    #[derive(Debug, thiserror::Error)]
    #[error("inner failed")]
    struct Inner;

    /// A named event inside a span becomes one line with its name, its
    /// message, its fields (an error with its source chain, a string with
    /// a newline kept as data, a number, an absent `Option` left out) and
    /// the span with its fields.
    #[test]
    fn json_line_carries_name_fields_error_chain_and_spans() {
        let got = lines(|| {
            let span = tracing::info_span!("protocol_request", endpoint = "update", peer = 7_u64);
            let _entered = span.enter();
            let error = Outer(Inner);
            let absent: Option<u16> = None;
            tracing::error!(
                name: "sample_failed",
                error = &error as &dyn std::error::Error,
                text = "two\nlines",
                status = 400_u64,
                absent,
                "sample failed"
            );
        });
        assert_eq!(
            got,
            [json!({
                "level": "ERROR",
                "target": "mimid_server::logging::tests",
                "event": "sample_failed",
                "message": "sample failed",
                "fields": {
                    "error": "outer failed",
                    "error.sources": ["inner failed"],
                    "text": "two\nlines",
                    "status": 400,
                },
                "spans": [{
                    "name": "protocol_request",
                    "fields": {"endpoint": "update", "peer": 7},
                }],
            })]
        );
    }

    /// An event without `name:` has no `event` key, and an event outside
    /// any span has no `spans` key.
    #[test]
    fn json_line_of_unnamed_event_has_no_event_key() {
        let got = lines(|| tracing::debug!(count = 3_u64, "counted"));
        assert_eq!(
            got,
            [json!({
                "level": "DEBUG",
                "target": "mimid_server::logging::tests",
                "message": "counted",
                "fields": {"count": 3},
            })]
        );
    }

    #[test]
    fn log_format_values() {
        for (value, format) in [
            ("", LogFormat::Text),
            ("text", LogFormat::Text),
            ("json", LogFormat::Json),
        ] {
            assert_eq!(LogFormat::parse(&value.into()), Ok(format), "{value:?}");
        }
        for value in ["JSON", "Text", " json", "yaml"] {
            assert!(LogFormat::parse(&value.into()).is_err(), "{value:?}");
        }
    }
}
