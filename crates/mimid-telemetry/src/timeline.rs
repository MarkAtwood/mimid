//! Every span a test's process opened, with when it opened and closed:
//! the timeline a trace exporter would have sent, read back in process
//! (bead mimid-604m).
//!
//! What this answers that a log cannot: a span appears in the log only
//! when an event is written inside it, so a hop that logs nothing is
//! invisible there however long it took. A span is also the only place
//! the duration of a hop is recorded at all.
//!
//! The subscriber is global, not a thread's default
//! ([`tracing::subscriber::set_default`]), because the work being timed
//! runs on a runtime's worker threads and a thread-local capture would
//! see none of it.
//!
//! # Limitations
//!
//! - [`Timeline::install`] sets the process's one global subscriber, so
//!   a test binary that calls it installs nothing else and the timeline
//!   covers every test in that binary. [`Timeline::local`] is this
//!   thread's default instead, and sees only the spans opened on it: no
//!   use for a daemon's work, which runs on a runtime's workers.
//! - Times are [`Instant`]s taken when the span opened and closed, not
//!   the clock of the event's own timestamp. A span whose future is
//!   parked between `enter` and `exit` is counted while parked, which is
//!   the point: that is the stall.
//! - A span that never closes has no end: the process ended first, or
//!   the future was dropped.
//! - Fields are the text they print, as a collector's attributes would
//!   be, so a number reads as its digits.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use tracing::Subscriber;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing_subscriber::layer::{Context, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;

/// One span, as a collector would have received it.
#[derive(Debug, Clone)]
pub struct TimedSpan {
    /// The span's id while it was open. Ids are reused once a span
    /// closes, so this identifies a span only among those open with it.
    pub id: u64,
    /// The span this one was opened inside, if any.
    pub parent: Option<u64>,
    /// The span's name, as the macro gave it.
    pub name: &'static str,
    /// The fields set when it opened or recorded later.
    pub fields: BTreeMap<String, String>,
    /// When it opened, from the timeline's start.
    pub opened: Duration,
    /// When it closed, or `None` if it had not when this was read.
    pub closed: Option<Duration>,
}

impl TimedSpan {
    /// The value of `field`, or `None` if it was never set. A field
    /// declared `Empty` and never recorded reads as absent.
    #[must_use]
    pub fn field(&self, field: &str) -> Option<&str> {
        self.fields.get(field).map(String::as_str)
    }

    /// How long it was open, or `None` if it had not closed.
    #[must_use]
    pub fn took(&self) -> Option<Duration> {
        self.closed.map(|closed| closed.saturating_sub(self.opened))
    }
}

/// Collects each field as the text it prints.
struct Fields<'a>(&'a mut BTreeMap<String, String>);

impl Visit for Fields<'_> {
    fn record_str(&mut self, field: &Field, value: &str) {
        self.0.insert(field.name().to_owned(), value.to_owned());
    }

    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.0.insert(field.name().to_owned(), format!("{value:?}"));
    }
}

#[derive(Debug)]
struct Recorded {
    started: Instant,
    spans: Vec<TimedSpan>,
    /// Span id to the index in `spans` of the span open under it now.
    open: BTreeMap<u64, usize>,
}

/// The layer behind [`Timeline`].
struct Recorder(Arc<Mutex<Recorded>>);

impl<S> tracing_subscriber::Layer<S> for Recorder
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(&self, attributes: &Attributes<'_>, id: &Id, ctx: Context<'_, S>) {
        let mut fields = BTreeMap::new();
        attributes.record(&mut Fields(&mut fields));
        // The explicit parent when the call site gave one, and otherwise
        // the span this one was opened inside.
        let parent = attributes
            .parent()
            .map(Id::into_u64)
            .or_else(|| ctx.current_span().id().map(Id::into_u64))
            .filter(|_| !attributes.is_root());
        let mut recorded = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let opened = recorded.started.elapsed();
        let at = recorded.spans.len();
        recorded.spans.push(TimedSpan {
            id: id.into_u64(),
            parent,
            name: attributes.metadata().name(),
            fields,
            opened,
            closed: None,
        });
        recorded.open.insert(id.into_u64(), at);
    }

    fn on_record(&self, id: &Id, values: &Record<'_>, _: Context<'_, S>) {
        let mut recorded = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let Some(at) = recorded.open.get(&id.into_u64()).copied() else {
            return;
        };
        let mut fields = std::mem::take(&mut recorded.spans[at].fields);
        values.record(&mut Fields(&mut fields));
        recorded.spans[at].fields = fields;
    }

    fn on_close(&self, id: Id, _: Context<'_, S>) {
        let mut recorded = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let closed = recorded.started.elapsed();
        if let Some(at) = recorded.open.remove(&id.into_u64()) {
            recorded.spans[at].closed = Some(closed);
        }
    }
}

/// Every span this process opens, from the moment it is installed.
///
/// `filter` is in `RUST_LOG` syntax and decides which spans are
/// recorded, as `[telemetry] span_level` decides which a collector gets.
pub struct Timeline {
    recorded: Arc<Mutex<Recorded>>,
    /// Held by [`Timeline::local`], which is this thread's default
    /// subscriber only; `None` for [`Timeline::install`], which is the
    /// process's.
    _local: Option<tracing::subscriber::DefaultGuard>,
}

impl Timeline {
    /// Installs the global subscriber and starts the clock: every thread
    /// of this process, which is what a daemon's work needs.
    ///
    /// # Panics
    ///
    /// If a global subscriber is already installed. One test binary can
    /// hold one, so a binary that calls this installs nothing else.
    #[must_use]
    pub fn install(filter: &str) -> Self {
        let (recorded, subscriber) = Self::recorder(filter);
        tracing::subscriber::set_global_default(subscriber)
            .expect("nothing has set this process's subscriber yet");
        Self {
            recorded,
            _local: None,
        }
    }

    /// A timeline for this thread only, which a test sharing its binary
    /// with others can take: it records the spans opened on the thread
    /// that holds it and ends when it is dropped, so it neither needs
    /// the process's one subscriber nor takes it from another test.
    #[must_use]
    pub fn local(filter: &str) -> Self {
        let (recorded, subscriber) = Self::recorder(filter);
        let guard = tracing::subscriber::set_default(subscriber);
        Self {
            recorded,
            _local: Some(guard),
        }
    }

    /// The recorder and the subscriber around it.
    fn recorder(
        filter: &str,
    ) -> (
        Arc<Mutex<Recorded>>,
        impl Subscriber + Send + Sync + 'static,
    ) {
        let recorded = Arc::new(Mutex::new(Recorded {
            started: Instant::now(),
            spans: Vec::new(),
            open: BTreeMap::new(),
        }));
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(filter))
            .with(Recorder(Arc::clone(&recorded)));
        (recorded, subscriber)
    }

    /// Every span opened so far, in the order they opened.
    #[must_use]
    pub fn spans(&self) -> Vec<TimedSpan> {
        self.recorded
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .spans
            .clone()
    }

    /// The spans named `name`, in the order they opened.
    #[must_use]
    pub fn named(&self, name: &str) -> Vec<TimedSpan> {
        self.spans()
            .into_iter()
            .filter(|span| span.name == name)
            .collect()
    }

    /// The nearest span named `name` that `span` was opened inside, if
    /// any: its parent, or its parent's parent, and so on.
    ///
    /// A span id is reused once its span closes, so a parent is the span
    /// with that id whose own window covers the child's opening.
    #[must_use]
    pub fn enclosing(&self, span: &TimedSpan, name: &str) -> Option<TimedSpan> {
        let spans = self.spans();
        let mut child = span.clone();
        while let Some(parent) = child.parent {
            let found = spans.iter().find(|span| {
                span.id == parent
                    && span.opened <= child.opened
                    && span.closed.is_none_or(|closed| closed >= child.opened)
            })?;
            if found.name == name {
                return Some(found.clone());
            }
            child = found.clone();
        }
        None
    }

    /// The spans under `parent`, directly or deeper, in the order they
    /// opened.
    #[must_use]
    pub fn under(&self, parent: &TimedSpan) -> Vec<TimedSpan> {
        let spans = self.spans();
        let mut family = vec![parent.id];
        let mut found = Vec::new();
        for span in spans {
            if span.parent.is_some_and(|parent| family.contains(&parent)) {
                family.push(span.id);
                found.push(span);
            }
        }
        found
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A nested pair of spans is recorded with its fields, its parent and
    /// a duration that covers the inner one.
    ///
    /// One test only: the subscriber is global, so a second would race
    /// this one for it.
    #[test]
    fn nested_spans_are_timed_with_their_fields_and_parents() {
        // `local`, not `install`: this binary's other tests share the
        // process's one subscriber slot, and everything here runs on
        // this thread.
        let timeline = Timeline::local("debug");
        {
            let outer = tracing::debug_span!("outer", room = "r", msgid = tracing::field::Empty);
            let _outer = outer.enter();
            outer.record("msgid", "abc");
            let _inner = tracing::debug_span!("inner", n = 3).entered();
        }
        let outer = timeline.named("outer");
        let [outer] = &outer[..] else {
            panic!("one outer span, got {:?}", timeline.spans());
        };
        assert_eq!(outer.field("room"), Some("r"));
        assert_eq!(outer.field("msgid"), Some("abc"));
        let inner = timeline.under(outer);
        let [inner] = &inner[..] else {
            panic!("one span under outer, got {inner:?}");
        };
        assert_eq!(inner.name, "inner");
        assert_eq!(inner.field("n"), Some("3"));
        assert_eq!(inner.parent, Some(outer.id));
        // The inner span opened and closed inside the outer one.
        assert!(inner.opened >= outer.opened, "{inner:?} {outer:?}");
        assert!(
            inner.closed.unwrap() <= outer.closed.unwrap(),
            "{inner:?} {outer:?}"
        );
        assert_eq!(
            timeline.enclosing(inner, "outer").map(|s| s.id),
            Some(outer.id)
        );
        assert!(timeline.enclosing(outer, "outer").is_none());
        // A span that never closed reads as still open.
        let open = tracing::debug_span!("left_open");
        let _entered = open.enter();
        assert_eq!(timeline.named("left_open")[0].closed, None);
    }
}
