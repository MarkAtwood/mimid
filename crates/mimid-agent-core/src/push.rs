//! The server's push channel: RFC 8620 §7.3 EventSource at the Session's
//! `eventSourceUrl`, which draft-atwood-jmap-chat-00 §Push Notifications
//! requires every JMAP Chat server to serve.
//!
//! A [`PushSource`] ([`crate::Agent::push_source`]) owns what a connection
//! needs and nothing of the agent's state, so a caller can follow the
//! stream while the agent is busy: it only learns that something changed.
//! Reading what changed stays the job of the agent's own calls
//! (`Message/changes` in [`crate::Agent::receive`]), so the push channel
//! adds no second path into the MLS state.
//!
//! [`PushSource::open`] fills the template with `types`, `closeafter=no`
//! and `ping` ([`PING_SECS`]), sends `Last-Event-ID` when the caller has
//! one, and checks the answer is a `text/event-stream`.
//! [`PushStream::next`] parses the stream (the WHATWG HTML "server-sent
//! events" interpretation, which RFC 8620 §7.3 points to) and returns the
//! `state` events, as the type names this account's StateChange names
//! (RFC 8620 §7.1), and the `ping` events; it skips other events (a JMAP
//! Chat server's `typing` and `presence`).
//!
//! # Limitations
//!
//! - The `retry` field is ignored: the caller picks its own reconnection
//!   delay.
//! - The read timeout ([`READ_TIMEOUT`]) assumes the server pings at most
//!   every [`PING_SECS`]. A server that raises the interval (RFC 8620 §7.3
//!   lets it) sees its streams dropped and reopened after each
//!   [`READ_TIMEOUT`] of quiet.

use std::collections::BTreeSet;
use std::time::Duration;

use serde_json::Value;

use crate::AgentError;

/// The data types whose changes [`crate::Agent`] reads when it syncs:
/// `Message` ([`crate::Agent::receive`]), `Chat`
/// ([`crate::Agent::join_own_rooms`]), `Consent`
/// ([`crate::Agent::consents`]) and `KeyPackage`
/// ([`crate::Agent::refresh_key_packages`], which the daemon runs after
/// each sync to top its KeyPackages up; findings log F9, F17). A
/// StateChange naming any of them is worth a sync.
pub const SYNC_TYPES: [&str; 4] = ["Message", "Chat", "Consent", "KeyPackage"];

/// The `ping` interval asked for, in seconds. INVENTED, NOT FROM SPEC:
/// long enough to cost nothing, short enough that a dead connection is
/// noticed within [`READ_TIMEOUT`].
pub const PING_SECS: u64 = 30;

/// How long the stream may stay silent before it is taken as dead: two
/// pings and some slack. INVENTED, NOT FROM SPEC.
pub const READ_TIMEOUT: Duration = Duration::from_secs(2 * PING_SECS + 15);

/// How long connecting may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// The longest event accepted, in octets of its lines: a StateChange for
/// a few types is a few hundred. INVENTED, NOT FROM SPEC.
pub const MAX_EVENT_LEN: usize = 64 * 1024;

/// The start of an error body kept in [`AgentError::Status`].
const MAX_ERROR_BODY: usize = 512;

/// What [`PushSource::open`] needs: the template, the account and the
/// bearer token, with a client of its own (no overall timeout, a read
/// timeout instead).
#[derive(Clone)]
pub struct PushSource {
    http: reqwest::Client,
    template: String,
    account_id: String,
    token: String,
}

impl std::fmt::Debug for PushSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PushSource")
            .field("template", &self.template)
            .field("account_id", &self.account_id)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// One event of a [`PushStream`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PushEvent {
    /// A `state` event: the type names its StateChange lists for this
    /// account (none if it lists other accounts only).
    State(BTreeSet<String>),
    /// A `ping` event.
    Ping,
}

impl PushSource {
    /// A source for the Session's `eventSourceUrl` `template` of
    /// `account_id`, authenticated with `token`.
    pub(crate) fn new(template: &str, account_id: &str, token: &str) -> Result<Self, AgentError> {
        let http = reqwest::Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .read_timeout(READ_TIMEOUT)
            .build()
            .map_err(|source| AgentError::Http {
                what: "building the EventSource client".to_owned(),
                source,
            })?;
        Ok(Self {
            http,
            template: template.to_owned(),
            account_id: account_id.to_owned(),
            token: token.to_owned(),
        })
    }

    /// The URL for `types`: the template's `types`, `closeafter` and
    /// `ping` filled in (RFC 6570 level 1, RFC 8620 §7.3).
    pub fn url(&self, types: &[&str]) -> String {
        self.template
            .replace("{types}", &encode(&types.join(",")))
            .replace("{closeafter}", "no")
            .replace("{ping}", &PING_SECS.to_string())
    }

    /// Opens the stream for `types`, resuming after `last_event_id` if
    /// given.
    ///
    /// # Errors
    ///
    /// [`AgentError::Http`] if the server cannot be reached,
    /// [`AgentError::Status`] if it answers other than 200, and
    /// [`AgentError::Malformed`] if the answer is not a
    /// `text/event-stream`.
    pub async fn open(
        &self,
        types: &[&str],
        last_event_id: Option<&str>,
    ) -> Result<PushStream, AgentError> {
        const WHAT: &str = "GET eventSourceUrl";
        let mut request = self
            .http
            .get(self.url(types))
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "text/event-stream");
        if let Some(id) = last_event_id {
            request = request.header("Last-Event-ID", id);
        }
        let response = request.send().await.map_err(|source| AgentError::Http {
            what: WHAT.to_owned(),
            source,
        })?;
        let status = response.status();
        if status != reqwest::StatusCode::OK {
            let mut body = response.text().await.unwrap_or_default();
            if body.len() > MAX_ERROR_BODY {
                let cut = (0..=MAX_ERROR_BODY)
                    .rev()
                    .find(|&i| body.is_char_boundary(i))
                    .unwrap_or(0);
                body.truncate(cut);
            }
            return Err(AgentError::Status {
                what: WHAT.to_owned(),
                status: status.as_u16(),
                body,
            });
        }
        let content_type = response
            .headers()
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let essence = content_type
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if essence != "text/event-stream" {
            return Err(AgentError::malformed(
                WHAT,
                format!("Content-Type {content_type:?} is not text/event-stream"),
            ));
        }
        Ok(PushStream {
            response,
            parser: Parser::default(),
            account_id: self.account_id.clone(),
            last_event_id: last_event_id.map(str::to_owned),
        })
    }
}

/// An open EventSource stream ([`PushSource::open`]).
#[derive(Debug)]
pub struct PushStream {
    response: reqwest::Response,
    parser: Parser,
    account_id: String,
    last_event_id: Option<String>,
}

impl PushStream {
    /// The next `state` or `ping` event; `None` when the server ends the
    /// stream.
    ///
    /// # Errors
    ///
    /// [`AgentError::Http`] if the connection fails or stays silent for
    /// [`READ_TIMEOUT`], and [`AgentError::Malformed`] for an event longer
    /// than [`MAX_EVENT_LEN`] or a `state` event that is not a
    /// StateChange. The stream is of no further use after an error.
    pub async fn next(&mut self) -> Result<Option<PushEvent>, AgentError> {
        loop {
            while let Some(raw) = self.parser.event()? {
                if let Some(id) = raw.id.clone() {
                    self.last_event_id = (!id.is_empty()).then_some(id);
                }
                if let Some(event) = interpret(&raw, &self.account_id)? {
                    return Ok(Some(event));
                }
            }
            let chunk = self
                .response
                .chunk()
                .await
                .map_err(|source| AgentError::Http {
                    what: "reading the EventSource stream".to_owned(),
                    source,
                })?;
            match chunk {
                Some(bytes) => self.parser.feed(&bytes),
                None => return Ok(None),
            }
        }
    }

    /// The last event ID the server set, to resume with.
    pub fn last_event_id(&self) -> Option<&str> {
        self.last_event_id.as_deref()
    }
}

/// `state` and `ping` events as [`PushEvent`]s; `None` for other events.
fn interpret(raw: &RawEvent, account_id: &str) -> Result<Option<PushEvent>, AgentError> {
    const WHAT: &str = "EventSource state event";
    match raw.event.as_str() {
        "state" => {
            let change: Value = serde_json::from_str(&raw.data)
                .map_err(|e| AgentError::malformed(WHAT, format!("not JSON: {e}")))?;
            if change["@type"] != "StateChange" {
                return Err(AgentError::malformed(WHAT, "not a StateChange"));
            }
            let changed = change["changed"]
                .as_object()
                .ok_or_else(|| AgentError::malformed(WHAT, "no changed object"))?;
            let types = match changed.get(account_id) {
                None => BTreeSet::new(),
                Some(types) => types
                    .as_object()
                    .ok_or_else(|| AgentError::malformed(WHAT, "the account's entry is no map"))?
                    .keys()
                    .cloned()
                    .collect(),
            };
            Ok(Some(PushEvent::State(types)))
        }
        "ping" => Ok(Some(PushEvent::Ping)),
        _ => Ok(None),
    }
}

/// One dispatched event, before interpretation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct RawEvent {
    /// The event type; `message` when none was given.
    event: String,
    /// The `data` lines joined with LF.
    data: String,
    /// The `id` field, if the event set one.
    id: Option<String>,
}

/// The event-stream parser of the WHATWG HTML standard, "Interpreting an
/// event stream": lines end in CRLF, LF or CR; an empty line dispatches;
/// `:` starts a comment; one space after the colon is dropped. Text is
/// UTF-8, invalid sequences replaced.
#[derive(Debug, Default)]
struct Parser {
    /// Octets not yet ending a line.
    pending: Vec<u8>,
    /// The last line ended with CR, so a leading LF is that line's end.
    after_cr: bool,
    /// Whether the start (and a byte order mark there) has been seen.
    started: bool,
    /// The event being read.
    event: Option<String>,
    data: Option<String>,
    id: Option<String>,
    /// Octets of the lines of the event being read.
    len: usize,
    /// Complete events not yet taken.
    ready: std::collections::VecDeque<RawEvent>,
    /// An event went over [`MAX_EVENT_LEN`].
    too_long: bool,
}

impl Parser {
    /// Takes `bytes` from the stream.
    fn feed(&mut self, mut bytes: &[u8]) {
        if self.too_long {
            return;
        }
        if self.after_cr && bytes.first() == Some(&b'\n') {
            bytes = &bytes[1..];
        }
        self.after_cr = false;
        let mut start = 0;
        let mut i = 0;
        while i < bytes.len() {
            match bytes[i] {
                b'\n' | b'\r' => {
                    let cr = bytes[i] == b'\r';
                    self.pending.extend_from_slice(&bytes[start..i]);
                    let line = std::mem::take(&mut self.pending);
                    self.line(&line);
                    if self.too_long {
                        return;
                    }
                    i += 1;
                    if cr {
                        if i == bytes.len() {
                            self.after_cr = true;
                        } else if bytes[i] == b'\n' {
                            i += 1;
                        }
                    }
                    start = i;
                }
                _ => i += 1,
            }
        }
        self.pending.extend_from_slice(&bytes[start..]);
        if self.len + self.pending.len() > MAX_EVENT_LEN {
            self.too_long = true;
        }
    }

    /// The next complete event.
    fn event(&mut self) -> Result<Option<RawEvent>, AgentError> {
        if let Some(event) = self.ready.pop_front() {
            return Ok(Some(event));
        }
        if self.too_long {
            return Err(AgentError::malformed(
                "EventSource stream",
                format!("an event is longer than {MAX_EVENT_LEN} octets"),
            ));
        }
        Ok(None)
    }

    /// One line, without its end.
    fn line(&mut self, line: &[u8]) {
        let mut line = line;
        if !self.started {
            self.started = true;
            line = line.strip_prefix("\u{feff}".as_bytes()).unwrap_or(line);
        }
        if line.is_empty() {
            self.dispatch();
            return;
        }
        self.len += line.len() + 1;
        if self.len > MAX_EVENT_LEN {
            self.too_long = true;
            return;
        }
        if line.first() == Some(&b':') {
            return;
        }
        let text = String::from_utf8_lossy(line);
        let (field, value) = match text.split_once(':') {
            Some((field, value)) => (field, value.strip_prefix(' ').unwrap_or(value)),
            None => (&*text, ""),
        };
        match field {
            "event" => self.event = Some(value.to_owned()),
            "data" => match &mut self.data {
                Some(data) => {
                    data.push('\n');
                    data.push_str(value);
                }
                None => self.data = Some(value.to_owned()),
            },
            "id" if !value.contains('\0') => self.id = Some(value.to_owned()),
            _ => {}
        }
    }

    /// Ends the event being read; one with no `data` is dropped, but its
    /// `id` still counts.
    fn dispatch(&mut self) {
        self.len = 0;
        let event = self.event.take();
        let id = self.id.take();
        match self.data.take() {
            Some(data) => self.ready.push_back(RawEvent {
                event: event
                    .filter(|e| !e.is_empty())
                    .unwrap_or_else(|| "message".to_owned()),
                data,
                id,
            }),
            None if id.is_some() => self.ready.push_back(RawEvent {
                event: String::new(),
                data: String::new(),
                id,
            }),
            None => {}
        }
    }
}

/// `text` percent-encoded for a level 1 template expression (RFC 6570
/// §3.2.2): everything but the unreserved characters.
fn encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(chunks: &[&[u8]]) -> Vec<RawEvent> {
        let mut parser = Parser::default();
        let mut out = Vec::new();
        for chunk in chunks {
            parser.feed(chunk);
            while let Some(event) = parser.event().unwrap() {
                out.push(event);
            }
        }
        out
    }

    fn raw(event: &str, data: &str) -> RawEvent {
        RawEvent {
            event: event.to_owned(),
            data: data.to_owned(),
            id: None,
        }
    }

    #[test]
    fn events_split_on_every_line_end_and_across_chunks() {
        let want = vec![raw("state", "{\"a\":1}\nmore"), raw("ping", "{}")];
        for chunks in [
            vec![&b"event: state\ndata: {\"a\":1}\ndata:more\n\nevent:ping\ndata: {}\n\n"[..]],
            vec![&b"event: state\r\ndata: {\"a\":1}\r\ndata:more\r\n\r\nevent:ping\r\ndata: {}\r\n\r\n"[..]],
            vec![&b"event: state\rdata: {\"a\":1}\rdata:more\r\revent:ping\rdata: {}\r\r"[..]],
            // CRLF split between chunks, and a comment line.
            vec![
                &b": hello\r\nevent: state\r"[..],
                &b"\ndata: {\"a\":1}\r\ndata:more\r"[..],
                &b"\n\r"[..],
                &b"\nevent:ping\ndata: {}\n"[..],
                &b"\n"[..],
            ],
        ] {
            assert_eq!(events(&chunks), want, "{chunks:?}");
        }
    }

    #[test]
    fn a_byte_order_mark_and_an_unterminated_event_are_handled() {
        assert_eq!(
            events(&["\u{feff}data: x\n\ndata: never ends\n".as_bytes()]),
            vec![raw("message", "x")]
        );
    }

    #[test]
    fn the_id_is_kept_unless_it_holds_nul() {
        let got = events(&[b"id: 7\nevent: ping\ndata: {}\n\nid: a\0b\ndata: y\n\nid: 9\n\n"]);
        assert_eq!(got[0].id.as_deref(), Some("7"));
        assert_eq!(got[1].id, None);
        assert_eq!(got[2].id.as_deref(), Some("9"));
        assert_eq!(got.len(), 3);
    }

    #[test]
    fn an_event_past_the_limit_is_refused() {
        let mut parser = Parser::default();
        parser.feed(b"data: ");
        parser.feed(&vec![b'x'; MAX_EVENT_LEN]);
        assert!(matches!(parser.event(), Err(AgentError::Malformed { .. })));
        // Many short lines count too.
        let mut parser = Parser::default();
        for _ in 0..=MAX_EVENT_LEN / 8 {
            parser.feed(b"data: x\n");
        }
        assert!(matches!(parser.event(), Err(AgentError::Malformed { .. })));
        // At the limit is fine.
        let mut line = b"data:".to_vec();
        line.resize(MAX_EVENT_LEN - 1, b'x');
        line.extend_from_slice(b"\n\n");
        assert_eq!(events(&[&line]).len(), 1);
    }

    #[test]
    fn state_events_name_this_accounts_types() {
        let state = |data: &str| {
            interpret(
                &RawEvent {
                    event: "state".to_owned(),
                    data: data.to_owned(),
                    id: None,
                },
                "A1",
            )
        };
        assert_eq!(
            state(r#"{"@type":"StateChange","changed":{"A1":{"Message":"s1","Chat":"c"},"B2":{"Consent":"x"}}}"#)
                .unwrap(),
            Some(PushEvent::State(BTreeSet::from([
                "Chat".to_owned(),
                "Message".to_owned()
            ])))
        );
        assert_eq!(
            state(r#"{"@type":"StateChange","changed":{"B2":{"Message":"s"}}}"#).unwrap(),
            Some(PushEvent::State(BTreeSet::new()))
        );
        for bad in [
            "not json",
            r#"{"@type":"Other","changed":{}}"#,
            r#"{"@type":"StateChange"}"#,
            r#"{"@type":"StateChange","changed":{"A1":["Message"]}}"#,
        ] {
            assert!(
                matches!(state(bad), Err(AgentError::Malformed { .. })),
                "{bad}"
            );
        }
        for other in ["typing", "presence", "message"] {
            assert_eq!(interpret(&raw(other, "{}"), "A1").unwrap(), None, "{other}");
        }
        assert_eq!(
            interpret(&raw("ping", "{\"interval\":30}"), "A1").unwrap(),
            Some(PushEvent::Ping)
        );
    }

    #[test]
    fn the_url_fills_the_template() {
        let source = PushSource::new(
            "https://s.example/es?types={types}&closeafter={closeafter}&ping={ping}",
            "A1",
            "secret",
        )
        .unwrap();
        assert_eq!(
            source.url(&SYNC_TYPES),
            "https://s.example/es?types=Message%2CChat%2CConsent%2CKeyPackage&closeafter=no&ping=30"
        );
        assert!(!format!("{source:?}").contains("secret"));
    }
}
