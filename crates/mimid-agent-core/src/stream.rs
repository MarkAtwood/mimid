//! The live stream binding to the user's mimid server
//! (docs/design/binary-live-stream.md; epic mimid-e64f): the same
//! operations as [`crate::client::Jmap`], as CBOR messages over one
//! WebSocket at `<server_url>/mimid/live` (crate `mimid_live`). JMAP is
//! the default; [`crate::Binding::Stream`] picks this one.
//!
//! - One connection at a time, opened at [`Stream::open`] and again on
//!   the next call after it failed. Requests share it; each waits for
//!   its `Ack` or `Error` (decision mimid-1wgh.74).
//! - Receiving: [`Stream::messages_since`] subscribes from the agent's
//!   saved Message state (decision mimid-1wgh.75). The `Deliver`s that
//!   arrive are kept until the next `Position` (or the `Subscribe` `Ack`);
//!   each call returns those up to the last position and that position,
//!   so the agent's bookkeeping is the same as on JMAP. A call from a
//!   state other than where the kept ones start, as after a crash before
//!   the state was saved, subscribes again on a new connection.
//! - Each `Deliver`, `Position` and `Changed`, and the loss of the
//!   connection, notifies [`Stream::wake`], so a caller can sync at once.
//!
//! # Limitations
//!
//! - The reader task runs on the caller's Tokio runtime
//!   (`tokio::spawn`).
//! - Requests outstanding when the connection fails get an error; they
//!   are not sent again, as on JMAP.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use mimid_live::{
    AckResult, ClientHello, ClientMessage, ErrorMessage, MAX_MESSAGE_BYTES, Op, OpKind,
    ProviderHello, ProviderMessage, Request, VERSION, code,
};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;

use crate::AgentError;

/// How long one request, or the hello, may take: as one JMAP request.
const TIMEOUT: Duration = Duration::from_secs(30);

/// Frames queued for the writer.
const OUT_BUFFER: usize = 64;

/// One item of the receive feed.
#[derive(Debug)]
enum Item {
    Deliver { id: String, fanout: Vec<u8> },
    Position(String),
}

/// What the connection received for the agent.
#[derive(Debug, Default)]
struct Feed {
    /// Whether a `Subscribe` was sent on this connection.
    subscribed: bool,
    /// The state the kept items start after; `None` before the first
    /// position of a subscription from the start.
    cursor: Option<String>,
    items: VecDeque<Item>,
}

type Answer = Result<AckResult, ErrorMessage>;

/// The state one connection's reader shares.
struct Shared {
    pending: Mutex<HashMap<u64, (OpKind, oneshot::Sender<Answer>)>>,
    feed: Mutex<Feed>,
    alive: AtomicBool,
}

/// One open connection.
struct Connection {
    shared: Arc<Shared>,
    out: mpsc::Sender<Vec<u8>>,
    next_id: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

fn stream_error(what: &str, detail: impl Into<String>) -> AgentError {
    AgentError::Stream {
        what: what.to_owned(),
        detail: detail.into(),
    }
}

/// An `Error` answer as the error JMAP gives for the same refusal: the
/// method named as on JMAP, the code as the JMAP error type (decision
/// mimid-1wgh.79).
pub(crate) fn method_error(method: &str, error: &ErrorMessage) -> AgentError {
    AgentError::Method {
        method: method.to_owned(),
        kind: error.code.clone(),
        description: error.detail.clone().unwrap_or_default(),
    }
}

impl Connection {
    async fn open(
        url: &str,
        token: &str,
        wake: &Arc<Notify>,
    ) -> Result<(Self, ProviderHello), AgentError> {
        const WHAT: &str = "live stream hello";
        let mut config = WebSocketConfig::default();
        config.max_message_size = Some(MAX_MESSAGE_BYTES);
        config.max_frame_size = Some(MAX_MESSAGE_BYTES);
        let (socket, _) = tokio::time::timeout(
            TIMEOUT,
            tokio_tungstenite::connect_async_with_config(url, Some(config), false),
        )
        .await
        .map_err(|_| stream_error(WHAT, "timed out"))?
        .map_err(|e| stream_error(WHAT, e.to_string()))?;
        let (mut sink, mut source) = socket.split();
        let hello = ClientMessage::Hello(ClientHello {
            versions: vec![VERSION],
            token: token.to_owned(),
            extra: Vec::new(),
        });
        sink.send(Message::Binary(hello.encode().into()))
            .await
            .map_err(|e| stream_error(WHAT, e.to_string()))?;
        let answer = tokio::time::timeout(TIMEOUT, async {
            loop {
                match source.next().await {
                    Some(Ok(Message::Binary(bytes))) => return Ok(bytes),
                    Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                    Some(Ok(_)) | None => return Err("the server closed".to_owned()),
                    Some(Err(e)) => return Err(e.to_string()),
                }
            }
        })
        .await
        .map_err(|_| stream_error(WHAT, "timed out"))?
        .map_err(|detail| stream_error(WHAT, detail))?;
        let hello = match ProviderMessage::decode(&answer, |_| None) {
            Ok(ProviderMessage::Hello(hello)) if hello.version == VERSION => hello,
            Ok(ProviderMessage::Error(error)) => {
                return Err(method_error("live stream hello", &error));
            }
            Ok(other) => {
                return Err(stream_error(
                    WHAT,
                    format!("not a ProviderHello: {other:?}"),
                ));
            }
            Err(e) => return Err(stream_error(WHAT, e.error.to_string())),
        };
        let shared = Arc::new(Shared {
            pending: Mutex::default(),
            feed: Mutex::default(),
            alive: AtomicBool::new(true),
        });
        let (out, mut queue) = mpsc::channel::<Vec<u8>>(OUT_BUFFER);
        let writer_shared = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Some(frame) = queue.recv().await {
                if sink.send(Message::Binary(frame.into())).await.is_err() {
                    break;
                }
            }
            writer_shared.alive.store(false, Ordering::SeqCst);
            let _ = sink.close().await;
        });
        let reader_shared = Arc::clone(&shared);
        let wake = Arc::clone(wake);
        tokio::spawn(async move {
            while let Some(frame) = source.next().await {
                let Ok(Message::Binary(bytes)) = frame else {
                    match frame {
                        Ok(Message::Ping(_) | Message::Pong(_)) => continue,
                        _ => break,
                    }
                };
                if !read(&reader_shared, &bytes, &wake) {
                    break;
                }
            }
            reader_shared.alive.store(false, Ordering::SeqCst);
            // Fail what is outstanding.
            lock(&reader_shared.pending).clear();
            wake.notify_one();
        });
        Ok((
            Self {
                shared,
                out,
                next_id: AtomicU64::new(1),
            },
            hello,
        ))
    }

    fn alive(&self) -> bool {
        self.shared.alive.load(Ordering::SeqCst)
    }

    /// Sends `op` and waits for its answer.
    async fn call(&self, what: &str, op: Op) -> Result<Answer, AgentError> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (answer, waiting) = oneshot::channel();
        lock(&self.shared.pending).insert(id, (op.kind(), answer));
        let frame = ClientMessage::Request(Request {
            v: VERSION,
            id,
            op,
            extra: Vec::new(),
        })
        .encode();
        if self.out.send(frame).await.is_err() {
            lock(&self.shared.pending).remove(&id);
            return Err(stream_error(what, "the connection is closed"));
        }
        match tokio::time::timeout(TIMEOUT, waiting).await {
            Ok(Ok(answer)) => Ok(answer),
            Ok(Err(_)) => Err(stream_error(what, "the connection closed")),
            Err(_) => {
                lock(&self.shared.pending).remove(&id);
                Err(stream_error(what, "timed out"))
            }
        }
    }
}

/// Handles one frame from the server; `false` if the connection ends.
fn read(shared: &Shared, bytes: &[u8], wake: &Notify) -> bool {
    let decoded = ProviderMessage::decode(bytes, |id| {
        lock(&shared.pending).get(&id).map(|(kind, _)| *kind)
    });
    let message = match decoded {
        Ok(message) => message,
        Err(error) => {
            tracing::warn!(
                name: "live_stream_frame_refused",
                error = &error as &dyn std::error::Error,
                "the server sent a frame that does not decode"
            );
            // An unknown message type from a later version is ignored
            // (note §3); anything else ends the connection.
            return matches!(error.error, mimid_live::DecodeError::UnknownType(_));
        }
    };
    match message {
        ProviderMessage::Ack(ack) => {
            let Some((kind, answer)) = lock(&shared.pending).remove(&ack.id) else {
                return true;
            };
            if kind == OpKind::Subscribe
                && let AckResult::Subscribe { state } = &ack.result
            {
                lock(&shared.feed)
                    .items
                    .push_back(Item::Position(state.clone()));
                wake.notify_one();
            }
            let _ = answer.send(Ok(ack.result));
            true
        }
        ProviderMessage::Error(error) => match error.id {
            Some(id) => {
                if let Some((_, answer)) = lock(&shared.pending).remove(&id) {
                    let _ = answer.send(Err(error));
                }
                true
            }
            None => {
                tracing::debug!(code = error.code, "the live stream connection was refused");
                false
            }
        },
        ProviderMessage::Deliver(deliver) => {
            lock(&shared.feed).items.push_back(Item::Deliver {
                id: deliver.message_id,
                fanout: deliver.fanout,
            });
            wake.notify_one();
            true
        }
        ProviderMessage::Position(position) => {
            lock(&shared.feed)
                .items
                .push_back(Item::Position(position.state));
            wake.notify_one();
            true
        }
        ProviderMessage::Changed(_) => {
            wake.notify_one();
            true
        }
        // A second hello, or a message type added later.
        _ => true,
    }
}

/// The live stream binding of one account.
pub(crate) struct Stream {
    url: String,
    token: String,
    /// What the server said in its hello.
    pub hello: ProviderHello,
    connection: tokio::sync::Mutex<Arc<Connection>>,
    wake: Arc<Notify>,
}

impl Stream {
    /// Connects to `<server_url>/mimid/live` and says hello.
    pub async fn open(server_url: &str, token: &str) -> Result<Self, AgentError> {
        let base = server_url.trim_end_matches('/');
        let url = match base.split_once("://") {
            Some(("https", rest)) => format!("wss://{rest}{}", mimid_live::PATH),
            Some(("http", rest)) => format!("ws://{rest}{}", mimid_live::PATH),
            _ => {
                return Err(AgentError::Invalid(format!(
                    "{server_url} is not an http or https URL"
                )));
            }
        };
        let wake = Arc::new(Notify::new());
        let (connection, hello) = Connection::open(&url, token, &wake).await?;
        Ok(Self {
            url,
            token: token.to_owned(),
            hello,
            connection: tokio::sync::Mutex::new(Arc::new(connection)),
            wake,
        })
    }

    /// Notified on each `Deliver`, `Position` and `Changed`, and when the
    /// connection is lost.
    pub fn wake(&self) -> Arc<Notify> {
        Arc::clone(&self.wake)
    }

    /// The current connection, opened again if it failed.
    async fn connection(&self) -> Result<Arc<Connection>, AgentError> {
        let mut current = self.connection.lock().await;
        if !current.alive() {
            let (connection, _) = Connection::open(&self.url, &self.token, &self.wake).await?;
            *current = Arc::new(connection);
        }
        Ok(Arc::clone(&current))
    }

    /// A new connection, replacing the current one.
    async fn reconnect(&self) -> Result<Arc<Connection>, AgentError> {
        let mut current = self.connection.lock().await;
        let (connection, _) = Connection::open(&self.url, &self.token, &self.wake).await?;
        *current = Arc::new(connection);
        Ok(Arc::clone(&current))
    }

    /// `op`, answered: the `Ack`'s result, or the `Error` as the JMAP
    /// error of `method`.
    pub async fn call(
        &self,
        method: &str,
        op: Op,
    ) -> Result<Result<AckResult, ErrorMessage>, AgentError> {
        self.connection().await?.call(method, op).await
    }

    /// `op`, whose `Error` is an error.
    pub async fn ok(&self, method: &str, op: Op) -> Result<AckResult, AgentError> {
        self.call(method, op)
            .await?
            .map_err(|error| method_error(method, &error))
    }

    /// The Messages stored since `since` (every Message when `None`, or
    /// when the server cannot resume), as (id, body), and the new Message
    /// state, as [`crate::client::Jmap::messages_since`] gives them.
    pub async fn messages_since(
        &self,
        since: Option<&str>,
    ) -> Result<(String, Vec<(String, Vec<u8>)>), AgentError> {
        const WHAT: &str = "Subscribe";
        let mut connection = self.connection().await?;
        let current = {
            let feed = lock(&connection.shared.feed);
            feed.subscribed && feed.cursor.as_deref() == since
        };
        if !current {
            if lock(&connection.shared.feed).subscribed {
                connection = self.reconnect().await?;
            }
            match subscribe(&connection, since).await? {
                Ok(()) => {}
                Err(error) if error.code == code::CANNOT_RESUME && since.is_some() => {
                    connection = self.reconnect().await?;
                    subscribe(&connection, None)
                        .await?
                        .map_err(|error| method_error(WHAT, &error))?;
                }
                Err(error) => return Err(method_error(WHAT, &error)),
            }
        }
        let mut feed = lock(&connection.shared.feed);
        let Some(last) = feed
            .items
            .iter()
            .rposition(|item| matches!(item, Item::Position(_)))
        else {
            return Ok((feed.cursor.clone().unwrap_or_default(), Vec::new()));
        };
        let mut messages = Vec::new();
        let mut state = String::new();
        for item in feed.items.drain(..=last) {
            match item {
                Item::Deliver { id, fanout } => messages.push((id, fanout)),
                Item::Position(position) => state = position,
            }
        }
        feed.cursor = Some(state.clone());
        Ok((state, messages))
    }
}

/// Sends `Subscribe` from `since` on `connection` and waits for its `Ack`,
/// after which the replay is in the feed.
async fn subscribe(
    connection: &Connection,
    since: Option<&str>,
) -> Result<Result<(), ErrorMessage>, AgentError> {
    {
        let mut feed = lock(&connection.shared.feed);
        feed.subscribed = true;
        feed.cursor = since.map(str::to_owned);
        feed.items.clear();
    }
    let answer = connection
        .call(
            "Subscribe",
            Op::Subscribe {
                since: since.map(str::to_owned),
            },
        )
        .await?;
    if answer.is_err() {
        // The server keeps no subscription after an Error; the next call
        // subscribes again.
        lock(&connection.shared.feed).subscribed = false;
    }
    Ok(answer.map(drop))
}
