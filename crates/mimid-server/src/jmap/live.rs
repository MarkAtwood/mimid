//! The live stream: `GET /mimid/live`, a WebSocket carrying the messages
//! of crate `mimid_live` (docs/design/binary-live-stream.md; epic
//! mimid-e64f). It is mimid's second binding of the client-provider
//! operations of draft-atwood-jmap-chat-mimi-00, served only with
//! [`JmapOptions::live_stream`](super::JmapOptions::live_stream). It is
//! not JMAP, but it lives beside the JMAP routes because it shares their
//! state and calls the same core functions as the JMAP methods (note
//! §5.10), so the two bindings differ in shape only.
//!
//! A connection:
//!
//! 1. The client sends `ClientHello` within [`HELLO_TIMEOUT`]. Its token
//!    is checked by [`Authenticator::authenticate_token`], the code of the
//!    JMAP `Account` extractor (decision mimid-1wgh.73). The provider
//!    answers `ProviderHello`, or `Error` (`unsupportedVersion`,
//!    `unauthorized`) and closes.
//! 2. Each request runs in its own task, so a slow hub holds up nothing
//!    else; its `Ack` or `Error` goes out when it ends (decision
//!    mimid-1wgh.74). At most [`MAX_OUTSTANDING`] run at once.
//! 3. `Subscribe` is handled in the connection's own loop: `Deliver`s of
//!    what `Message/changes` and `Message/get` give from `since`, then the
//!    `Ack`; afterwards, on each change-bus event, the `Deliver`s of the
//!    new Messages and a `Position` (decision mimid-1wgh.75), and a
//!    `Changed` when the Chat, KeyPackage or Consent state moved.
//! 4. The token is checked again before each request and each run of
//!    `Deliver`s; once it fails the provider sends `Error` `unauthorized`
//!    without `id` and closes.
//!
//! A text frame, a frame over the limits ([`MAX_MESSAGE_BYTES`],
//! [`MAX_REQUEST_BYTES`]), a frame that does not decode before the hello
//! ends, or a second hello, ends the connection after an `Error`. A
//! request that does not decode gets `Error` `badMessage` with its `id`
//! when it has one.
//!
//! # Limitations
//!
//! - Every change on the bus, for any account, makes every subscribed
//!   connection recompute its Message changes, as the EventSource does.
//! - A frame up to a little over [`MAX_MESSAGE_BYTES`] is read whole
//!   before its size is checked.
//! - A request's task is not cancelled when the connection closes; its
//!   answer is dropped.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use axum::extract::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::response::Response;
use futures_util::{SinkExt, StreamExt};
use jmap_server::JmapError;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{GroupInfoCode, KeyMaterialResponse, SubmitResult, UpdateResult};
use mimid_live::{
    AckResult, ChatEntry, ClientMessage, ConsentEntry, Deliver, ErrorMessage, KeyPackageEntry,
    MAX_MESSAGE_BYTES, MAX_OUTSTANDING, MAX_REQUEST_BYTES, Op, Position, ProviderHello,
    ProviderMessage, VERSION, code,
};
use serde_json::{Map, Value, json};
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::mpsc;

use super::JmapState;
use super::auth::{Account, AuthRejection};
use super::eventsource::{self, Params};
use super::methods::{
    chat_set, consent, group_info, key_material, key_package, room_create, room_report_abuse,
    room_send, room_unbind, room_update,
};
use super::session::{ASSET_URL_TEMPLATE, CIPHER_SUITES};
use crate::store::ConsentDecision;

/// How long the client has to send its `ClientHello`. INVENTED, NOT FROM
/// SPEC (decision mimid-1wgh.73).
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(10);

/// How far past [`MAX_MESSAGE_BYTES`] the WebSocket layer reads a frame,
/// so that one just over the limit is answered `tooLarge` rather than
/// cut off.
const READ_SLACK: usize = 1024;

/// Frames queued for a slow client before senders wait.
const OUT_BUFFER: usize = 64;

/// The `privateMetadata` namespace of the accepted record (decision
/// mimid-1wgh.63), which `SetChatAccepted` and `ListChats` restate.
/// INVENTED, NOT FROM SPEC; the agent writes the same one over JMAP.
const ACCEPTED_NAMESPACE: &str = "mimid.reviewcommit.com";

/// `GET /mimid/live`.
pub(super) async fn get_live(
    State(state): State<JmapState>,
    upgrade: WebSocketUpgrade,
) -> Response {
    upgrade
        .max_message_size(MAX_MESSAGE_BYTES + READ_SLACK)
        .max_frame_size(MAX_MESSAGE_BYTES + READ_SLACK)
        .on_upgrade(move |socket| connection(state, socket))
}

/// What the writer task sends.
enum Out {
    Frame(Vec<u8>),
    Close,
}

/// The sending side of a connection, shared with the request tasks.
#[derive(Clone)]
struct Sender(mpsc::Sender<Out>);

impl Sender {
    /// Sends `message`; `false` once the client is gone.
    async fn send(&self, message: &ProviderMessage) -> bool {
        self.0.send(Out::Frame(message.encode())).await.is_ok()
    }

    async fn error(&self, error: ErrorMessage) -> bool {
        self.send(&ProviderMessage::Error(error)).await
    }

    /// Sends a connection-level `Error` with `code`, then closes.
    async fn fail(&self, code: &str) {
        self.error(ErrorMessage::new(None, code)).await;
        let _ = self.0.send(Out::Close).await;
    }
}

async fn connection(state: JmapState, socket: WebSocket) {
    let (mut sink, mut source) = socket.split();
    let (out, mut queue) = mpsc::channel::<Out>(OUT_BUFFER);
    let writer = tokio::spawn(async move {
        while let Some(out) = queue.recv().await {
            match out {
                Out::Frame(bytes) => {
                    if sink.send(Message::Binary(bytes.into())).await.is_err() {
                        break;
                    }
                }
                Out::Close => {
                    let _ = sink.send(Message::Close(None)).await;
                    break;
                }
            }
        }
        let _ = sink.close().await;
    });
    let sender = Sender(out);
    if let Some((account, token)) = hello(&state, &sender, &mut source).await {
        Connection {
            state,
            sender: sender.clone(),
            account,
            token,
            outstanding: Arc::new(AtomicUsize::new(0)),
        }
        .run(&mut source)
        .await;
    }
    let _ = sender.0.send(Out::Close).await;
    drop(sender);
    let _ = writer.await;
}

type Source = futures_util::stream::SplitStream<WebSocket>;

/// The next binary frame, or `None` when the connection should end (the
/// client closed, sent a text frame, or the socket failed).
async fn next_frame(source: &mut Source, sender: &Sender) -> Option<Vec<u8>> {
    loop {
        match source.next().await? {
            Ok(Message::Binary(bytes)) => return Some(bytes.to_vec()),
            Ok(Message::Ping(_) | Message::Pong(_)) => {}
            Ok(Message::Text(_)) => {
                tracing::debug!("live stream: text frame, closing");
                sender.fail(code::BAD_MESSAGE).await;
                return None;
            }
            Ok(Message::Close(_)) => return None,
            Err(error) => {
                tracing::debug!(
                    error = &error as &dyn std::error::Error,
                    "live stream: read failed"
                );
                // Most likely a frame past the WebSocket layer's limit.
                sender.fail(code::TOO_LARGE).await;
                return None;
            }
        }
    }
}

/// The hello exchange: the authenticated account and its token, or
/// `None` after the refusal was sent.
async fn hello(
    state: &JmapState,
    sender: &Sender,
    source: &mut Source,
) -> Option<(Account, String)> {
    let Ok(frame) = tokio::time::timeout(HELLO_TIMEOUT, next_frame(source, sender)).await else {
        tracing::debug!("live stream: no ClientHello in time");
        sender.fail(code::BAD_MESSAGE).await;
        return None;
    };
    let frame = frame?;
    if frame.len() > MAX_REQUEST_BYTES {
        sender.fail(code::TOO_LARGE).await;
        return None;
    }
    let hello = match ClientMessage::decode(&frame) {
        Ok(ClientMessage::Hello(hello)) => hello,
        Ok(ClientMessage::Request(_)) | Err(_) => {
            tracing::debug!("live stream: the first frame is not a ClientHello");
            sender.fail(code::BAD_MESSAGE).await;
            return None;
        }
    };
    if !hello.versions.contains(&VERSION) {
        sender.fail(code::UNSUPPORTED_VERSION).await;
        return None;
    }
    let account = match state.0.authenticator.authenticate_token(&hello.token).await {
        Ok(account) => account,
        Err(rejection) => {
            sender.fail(rejection_code(rejection)).await;
            return None;
        }
    };
    let welcome = ProviderMessage::Hello(ProviderHello {
        version: VERSION,
        user_uri: account.user().as_str().to_owned(),
        room_id_prefix: format!("mimi://{}/r/", state.0.hub.domain()),
        hub_sender: state.0.hub_sender.clone(),
        cipher_suites: CIPHER_SUITES.iter().map(|s| u64::from(*s)).collect(),
        max_key_packages: state.0.max_key_packages,
        max_message_bytes: MAX_MESSAGE_BYTES as u64,
        max_request_bytes: MAX_REQUEST_BYTES as u64,
        max_mls_object_size: Some(super::MAX_MLS_OBJECT_SIZE as u64),
        stores_assets: true,
        asset_lifetime: state.0.asset_lifetime,
        message_retention: state.0.message_retention,
        fetches_assets: true,
        accepted_rooms: true,
        extra: Vec::new(),
    });
    if !sender.send(&welcome).await {
        return None;
    }
    tracing::debug!(account_id = account.account_id(), "live stream opened");
    Some((account, hello.token))
}

fn rejection_code(rejection: AuthRejection) -> &'static str {
    match rejection {
        AuthRejection::Unauthorized => code::UNAUTHORIZED,
        _ => code::SERVER_FAIL,
    }
}

struct Connection {
    state: JmapState,
    sender: Sender,
    account: Account,
    token: String,
    outstanding: Arc<AtomicUsize>,
}

/// The subscription of a connection: the last Message state sent and the
/// last notice states.
struct Subscription {
    position: String,
    notices: BTreeMap<&'static str, String>,
}

impl Connection {
    async fn run(self, source: &mut Source) {
        // Subscribed before any Subscribe, so no change falls between a
        // replay and the first wake-up.
        let mut changes = self.state.0.bus.subscribe();
        let mut subscription: Option<Subscription> = None;
        let mut stop = self.state.0.stop.clone();
        loop {
            let stopping = async {
                match stop.as_mut() {
                    Some(stop) => {
                        if stop.wait_for(|stopping| *stopping).await.is_err() {
                            std::future::pending::<()>().await;
                        }
                    }
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                () = stopping => return,
                frame = next_frame(source, &self.sender) => {
                    let Some(frame) = frame else { return };
                    if !self.frame(&frame, &mut subscription).await {
                        return;
                    }
                }
                received = changes.recv(), if subscription.is_some() => {
                    if matches!(received, Err(RecvError::Closed)) {
                        return;
                    }
                    while matches!(changes.try_recv(), Ok(_) | Err(TryRecvError::Lagged(_))) {}
                    if let Some(subscription) = subscription.as_mut()
                        && !self.follow(subscription).await
                    {
                        return;
                    }
                }
            }
        }
    }

    /// Checks the token again; `false` (after the refusal) if it fails.
    async fn still_authorized(&self) -> bool {
        match self
            .state
            .0
            .authenticator
            .authenticate_token(&self.token)
            .await
        {
            Ok(account) if account == self.account => true,
            Ok(_) => {
                self.sender.fail(code::UNAUTHORIZED).await;
                false
            }
            Err(rejection) => {
                tracing::debug!("live stream: the token no longer authenticates");
                self.sender.fail(rejection_code(rejection)).await;
                false
            }
        }
    }

    /// Handles one frame; `false` if the connection should end.
    async fn frame(&self, frame: &[u8], subscription: &mut Option<Subscription>) -> bool {
        if frame.len() > MAX_MESSAGE_BYTES {
            self.sender.fail(code::TOO_LARGE).await;
            return false;
        }
        let request = match ClientMessage::decode(frame) {
            Ok(ClientMessage::Request(request)) => request,
            Ok(ClientMessage::Hello(_)) => {
                self.sender.fail(code::BAD_MESSAGE).await;
                return false;
            }
            Err(error) => {
                tracing::debug!(
                    error = &error.error as &dyn std::error::Error,
                    "live stream: a frame does not decode"
                );
                let mut answer = ErrorMessage::new(error.id, code::BAD_MESSAGE);
                answer.detail = Some(error.error.to_string());
                return self.sender.error(answer).await;
            }
        };
        if !request.op.kind().is_upload() && frame.len() > MAX_REQUEST_BYTES {
            self.sender.fail(code::TOO_LARGE).await;
            return false;
        }
        if !self.still_authorized().await {
            return false;
        }
        let id = request.id;
        if let Op::Subscribe { since, after } = request.op {
            if subscription.is_some() || (since.is_some() && after.is_some()) {
                let mut answer = ErrorMessage::new(Some(id), code::BAD_MESSAGE);
                answer.detail = Some(
                    if subscription.is_some() {
                        "one Subscribe per connection"
                    } else {
                        "since and after together"
                    }
                    .to_owned(),
                );
                return self.sender.error(answer).await;
            }
            return match self.subscribe(id, since.as_deref(), after.as_ref()).await {
                Ok(Some(started)) => {
                    *subscription = Some(started);
                    true
                }
                Ok(None) => true,
                Err(()) => false,
            };
        }
        if self.outstanding.fetch_add(1, Ordering::SeqCst) >= MAX_OUTSTANDING {
            self.outstanding.fetch_sub(1, Ordering::SeqCst);
            return self
                .sender
                .error(ErrorMessage::new(Some(id), code::RATE_LIMITED))
                .await;
        }
        let (state, account, sender, outstanding) = (
            self.state.clone(),
            self.account.clone(),
            self.sender.clone(),
            Arc::clone(&self.outstanding),
        );
        tokio::spawn(async move {
            let answer = match run(&state, &account, request.op).await {
                Ok(result) => ProviderMessage::Ack(mimid_live::Ack {
                    v: VERSION,
                    id,
                    result,
                    extra: Vec::new(),
                }),
                Err(mut error) => {
                    error.id = Some(id);
                    ProviderMessage::Error(error)
                }
            };
            outstanding.fetch_sub(1, Ordering::SeqCst);
            sender.send(&answer).await;
        });
        true
    }

    /// The replay of a `Subscribe` and its answer: the subscription, or
    /// `Ok(None)` after an `Error` answer, or `Err(())` if the client is
    /// gone. Without `since`, every Message, except in a Chat named in
    /// `after` the Messages up to the id given for it (findings log F12:
    /// ids sort in the order the Messages were stored, F2).
    async fn subscribe(
        &self,
        id: u64,
        since: Option<&str>,
        after: Option<&BTreeMap<String, String>>,
    ) -> Result<Option<Subscription>, ()> {
        let projection = &self.state.0.projection;
        let fail = |e: &(dyn std::error::Error + 'static)| {
            tracing::error!(
                name: "live_stream_replay_failed",
                error = e,
                "live stream: the replay could not be read"
            );
            ErrorMessage::new(Some(id), code::SERVER_FAIL)
        };
        let replay = match since {
            None => projection
                .messages(&self.account, None)
                .await
                .map(|(state, mut rows)| {
                    if let Some(after) = after {
                        rows.retain(|row| {
                            after
                                .get(&row.chat_id)
                                .is_none_or(|last| row.message_id > *last)
                        });
                    }
                    (state, rows)
                }),
            Some(since) => match projection
                .message_changes_since(&self.account, since, None, false)
                .await
            {
                Ok(Some(changes)) => projection
                    .messages(&self.account, Some(&changes.created))
                    .await
                    .map(|(_, rows)| (changes.new_state, rows)),
                Ok(None) => {
                    return if self
                        .sender
                        .error(ErrorMessage::new(Some(id), code::CANNOT_RESUME))
                        .await
                    {
                        Ok(None)
                    } else {
                        Err(())
                    };
                }
                Err(error) => Err(error),
            },
        };
        let (position, rows) = match replay {
            Ok(replay) => replay,
            Err(error) => {
                let sent = self.sender.error(fail(&error)).await;
                return if sent { Ok(None) } else { Err(()) };
            }
        };
        for row in rows {
            if !self.sender.send(&deliver(row)).await {
                return Err(());
            }
        }
        let notices = self.notices().await.unwrap_or_default();
        let ack = ProviderMessage::Ack(mimid_live::Ack {
            v: VERSION,
            id,
            result: AckResult::Subscribe {
                state: position.clone(),
            },
            extra: Vec::new(),
        });
        if !self.sender.send(&ack).await {
            return Err(());
        }
        Ok(Some(Subscription { position, notices }))
    }

    /// The states the `Changed` notice watches.
    async fn notices(&self) -> Option<BTreeMap<&'static str, String>> {
        match eventsource::states(
            &self.state.0.projection,
            self.state.0.key_packages.as_deref(),
            &self.state.0.store,
            &self.account,
            &Params::live_notices(),
        )
        .await
        {
            Ok(states) => Some(states),
            Err(error) => {
                tracing::error!(
                    name: "live_stream_state_failed",
                    error = &error as &dyn std::error::Error,
                    "live stream: the account's states could not be read"
                );
                None
            }
        }
    }

    /// Sends what moved since `subscription`; `false` if the connection
    /// should end.
    async fn follow(&self, subscription: &mut Subscription) -> bool {
        if !self.still_authorized().await {
            return false;
        }
        let projection = &self.state.0.projection;
        let changes = match projection
            .message_changes_since(&self.account, &subscription.position, None, true)
            .await
        {
            Ok(Some(changes)) => changes,
            Ok(None) => {
                // A state this provider gave cannot be ahead of the
                // account's, and deletions since it are passed over (the
                // client has every Message up to it); the store went back.
                self.sender.fail(code::CANNOT_RESUME).await;
                return false;
            }
            Err(error) => {
                tracing::error!(
                    name: "live_stream_changes_failed",
                    error = &error as &dyn std::error::Error,
                    "live stream: the Message changes could not be read"
                );
                self.sender.fail(code::SERVER_FAIL).await;
                return false;
            }
        };
        if !changes.created.is_empty() {
            let rows = match projection
                .messages(&self.account, Some(&changes.created))
                .await
            {
                Ok((_, rows)) => rows,
                Err(error) => {
                    tracing::error!(
                        name: "live_stream_changes_failed",
                        error = &error as &dyn std::error::Error,
                        "live stream: the new Messages could not be read"
                    );
                    self.sender.fail(code::SERVER_FAIL).await;
                    return false;
                }
            };
            for row in rows {
                if !self.sender.send(&deliver(row)).await {
                    return false;
                }
            }
        }
        if changes.new_state != subscription.position {
            let position = ProviderMessage::Position(Position {
                v: VERSION,
                state: changes.new_state.clone(),
                extra: Vec::new(),
            });
            if !self.sender.send(&position).await {
                return false;
            }
            subscription.position = changes.new_state;
        }
        if let Some(now) = self.notices().await {
            let types: Vec<String> = now
                .iter()
                .filter(|(kind, state)| subscription.notices.get(*kind) != Some(*state))
                .map(|(kind, _)| (*kind).to_owned())
                .collect();
            if !types.is_empty() {
                let changed = ProviderMessage::Changed(mimid_live::Changed {
                    v: VERSION,
                    types,
                    extra: Vec::new(),
                });
                if !self.sender.send(&changed).await {
                    return false;
                }
            }
            subscription.notices = now;
        }
        true
    }
}

fn deliver(row: crate::store::MessageRow) -> ProviderMessage {
    ProviderMessage::Deliver(Deliver {
        v: VERSION,
        message_id: row.message_id,
        chat_id: row.chat_id,
        fanout: row.bytes,
        extra: Vec::new(),
    })
}

/// A method error as an `Error`: its type becomes the code (decision
/// mimid-1wgh.79).
fn method_error(error: &JmapError) -> ErrorMessage {
    let code = serde_json::to_value(&error.error_type)
        .ok()
        .and_then(|v| v.as_str().map(str::to_owned))
        .unwrap_or_else(|| code::SERVER_FAIL.to_owned());
    ErrorMessage {
        detail: error.description.clone(),
        // rateLimited (jmap-chat-spec 43ee02c; bead mimid-e64f.21).
        retry_after: error
            .extra
            .get("retryAfter")
            .and_then(serde_json::Value::as_u64),
        ..ErrorMessage::new(None, &code)
    }
}

/// A SetError (`{"type", "properties", "existingId", "description"}`) as
/// an `Error`.
fn set_error(error: &Value) -> ErrorMessage {
    let mut answer = ErrorMessage::new(None, error["type"].as_str().unwrap_or(code::SERVER_FAIL));
    answer.detail = error["description"].as_str().map(str::to_owned);
    answer.properties = error["properties"].as_array().map(|p| {
        p.iter()
            .filter_map(|p| p.as_str().map(str::to_owned))
            .collect()
    });
    answer.existing_id = error["existingId"].as_str().map(str::to_owned);
    answer
}

fn server_fail(error: &(dyn std::error::Error + 'static)) -> ErrorMessage {
    tracing::error!(
        name: "live_stream_request_failed",
        error,
        "live stream request failed"
    );
    ErrorMessage::new(None, code::SERVER_FAIL)
}

fn decision_name(decision: Option<ConsentDecision>) -> Option<String> {
    match decision {
        Some(ConsentDecision::Grant) => Some("grant".to_owned()),
        Some(ConsentDecision::Revoke) => Some("revoke".to_owned()),
        _ => None,
    }
}

fn consent_entry(record: &crate::store::ConsentRecord) -> ConsentEntry {
    ConsentEntry {
        consent_id: record.id.clone(),
        requester_uri: record.requester_uri.clone(),
        target_uri: record.target_uri.clone(),
        room: record.room_id.clone(),
        requested: record.requested,
        decision: decision_name(record.decision),
        updated: record.updated_ms,
        extra: Vec::new(),
    }
}

/// Runs one request through the core function its JMAP method calls.
#[allow(
    clippy::result_large_err,
    reason = "one per refused request, encoded at once"
)]
async fn run(state: &JmapState, account: &Account, op: Op) -> Result<AckResult, ErrorMessage> {
    let inner = &state.0;
    let (store, follower) = (&inner.store, &*inner.follower);
    let jmap = |e: JmapError| method_error(&e);
    Ok(match op {
        Op::Send {
            room,
            message,
            silent,
        } => {
            let sent = room_send::send_core(
                follower,
                store,
                account,
                &room,
                &message,
                silent.unwrap_or(false),
            )
            .await
            .map_err(jmap)?;
            match sent.result {
                SubmitResult::Accepted {
                    accepted_timestamp,
                    frank,
                } => AckResult::Send {
                    accepted_at: accepted_timestamp,
                    frank: frank
                        .map(|f| f.tls_serialize_detached())
                        .transpose()
                        .map_err(|e| server_fail(&e))?,
                    message_ids: Some(sent.message_ids),
                },
                SubmitResult::NotAllowed => return Err(ErrorMessage::new(None, code::NOT_ALLOWED)),
                SubmitResult::EpochTooOld { current_epoch } => {
                    return Err(ErrorMessage {
                        current_epoch: Some(current_epoch),
                        ..ErrorMessage::new(None, code::EPOCH_TOO_OLD)
                    });
                }
            }
        }
        Op::Update { room, request } => {
            let (response, message_ids) =
                room_update::update_core(follower, store, account, &room, &request)
                    .await
                    .map_err(jmap)?;
            let description = response.error_description.as_str().to_owned();
            let refused = |code: &str| ErrorMessage {
                error_description: Some(description.clone()).filter(|d| !d.is_empty()),
                ..ErrorMessage::new(None, code)
            };
            match response.result {
                UpdateResult::Success { accepted_timestamp } => AckResult::Update {
                    accepted_at: accepted_timestamp,
                    error_description: Some(description.clone()).filter(|d| !d.is_empty()),
                    message_ids: Some(message_ids),
                },
                UpdateResult::WrongEpoch { current_epoch } => {
                    return Err(ErrorMessage {
                        current_epoch: Some(current_epoch),
                        ..refused(code::WRONG_EPOCH)
                    });
                }
                UpdateResult::NotAllowed => return Err(refused(code::NOT_ALLOWED)),
                UpdateResult::InvalidProposal { invalid_proposals } => {
                    let refs = invalid_proposals
                        .iter()
                        .map(Serialize::tls_serialize_detached)
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(|e| server_fail(&e))?;
                    return Err(ErrorMessage {
                        invalid_proposals: Some(refs),
                        ..refused(code::INVALID_PROPOSAL)
                    });
                }
            }
        }
        Op::CreateRoom {
            room,
            group_info,
            ratchet_tree,
        } => AckResult::CreateRoom {
            chat_id: room_create::create_core(
                &inner.hub,
                store,
                &inner.bus,
                account,
                room,
                &group_info,
                &ratchet_tree,
            )
            .await
            .map_err(jmap)?,
        },
        Op::Unbind { room } => {
            room_unbind::unbind_core(follower, store, account, &room)
                .await
                .map_err(jmap)?;
            AckResult::Done
        }
        Op::ReportAbuse { room, report } => {
            use room_report_abuse::Refusal;
            match room_report_abuse::report_core(follower, store, account, &room, &report)
                .await
                .map_err(jmap)?
            {
                None => AckResult::Done,
                Some(Refusal::NotAllowed) => {
                    return Err(ErrorMessage::new(None, code::NOT_ALLOWED));
                }
                Some(Refusal::Unverified) => {
                    return Err(ErrorMessage::new(None, code::UNVERIFIED_MESSAGE));
                }
                Some(Refusal::Other(status)) => {
                    return Err(ErrorMessage {
                        status: Some(u64::from(status)),
                        ..ErrorMessage::new(None, code::REFUSED)
                    });
                }
            }
        }
        Op::FetchGroupInfo { room, request } => {
            let (status, response) = group_info::fetch_core(follower, account, &room, &request)
                .await
                .map_err(jmap)?;
            AckResult::FetchGroupInfo {
                status: match status {
                    GroupInfoCode::Success => "success",
                    GroupInfoCode::NotAuthorized => "notAuthorized",
                    GroupInfoCode::NoSuchRoom => "noSuchRoom",
                }
                .to_owned(),
                response,
            }
        }
        Op::FetchKeyMaterial { room, request } => {
            let response = key_material::fetch_core(
                follower,
                store,
                inner.key_material_limiter.as_ref(),
                account,
                &room,
                &request,
            )
            .await
            .map_err(jmap)?;
            // As the JMAP method: a response that does not decode is the
            // server's failure.
            KeyMaterialResponse::tls_deserialize_exact(&response[..])
                .map_err(|e| server_fail(&e))?;
            AckResult::FetchKeyMaterial { response }
        }
        Op::PublishKeyPackage {
            key_package,
            last_resort,
        } => {
            let key_packages = key_packages(state)?;
            match key_package::create_one(
                key_packages,
                account,
                &key_package,
                last_resort,
                inner.max_key_packages,
            )
            .await
            .map_err(jmap)?
            {
                Ok(entry) => AckResult::PublishKeyPackage {
                    key_package_ref: entry.reference,
                    last_resort: entry.last_resort,
                },
                Err(error) => return Err(set_error(&error)),
            }
        }
        Op::ListKeyPackages => {
            let (state_text, entries) = key_package::list(key_packages(state)?, store, account)
                .await
                .map_err(jmap)?;
            AckResult::ListKeyPackages {
                state: state_text,
                key_packages: entries
                    .into_iter()
                    .map(|(entry, bytes)| KeyPackageEntry {
                        key_package_ref: entry.reference,
                        key_package: bytes,
                        last_resort: entry.last_resort,
                        extra: Vec::new(),
                    })
                    .collect(),
            }
        }
        Op::DestroyKeyPackage { key_package_ref } => {
            if key_package::destroy_one(key_packages(state)?, account, &key_package_ref)
                .await
                .map_err(jmap)?
            {
                AckResult::Done
            } else {
                return Err(ErrorMessage::new(None, code::NOT_FOUND));
            }
        }
        Op::ListConsent => {
            let consents = consent::Cx::new(store, follower, account);
            AckResult::ListConsent {
                state: consents.state().await.map_err(jmap)?,
                records: consents
                    .records()
                    .await
                    .map_err(jmap)?
                    .iter()
                    .map(consent_entry)
                    .collect(),
            }
        }
        Op::CreateConsent {
            requester_uri,
            target_uri,
            room,
            requested,
            decision,
        } => {
            let consents = consent::Cx::new(store, follower, account);
            let mut create = Map::new();
            create.insert("requesterUri".into(), json!(requester_uri));
            create.insert("targetUri".into(), json!(target_uri));
            if let Some(room) = room {
                create.insert("roomId".into(), json!(room));
            }
            if let Some(requested) = requested {
                create.insert("requested".into(), json!(requested));
            }
            if let Some(decision) = decision {
                create.insert("decision".into(), json!(decision));
            }
            let created = match consents
                .create_one(&Value::Object(create))
                .await
                .map_err(jmap)?
            {
                Ok(created) => created,
                Err(error) => return Err(set_error(&error)),
            };
            let id = created["id"].as_str().unwrap_or_default();
            let record = consents
                .records()
                .await
                .map_err(jmap)?
                .into_iter()
                .find(|r| r.id == id)
                .ok_or_else(|| ErrorMessage::new(None, code::SERVER_FAIL))?;
            AckResult::CreateConsent {
                record: consent_entry(&record),
            }
        }
        Op::UpdateConsent {
            consent_id,
            requested,
            decision,
        } => {
            let consents = consent::Cx::new(store, follower, account);
            let mut patch = Map::new();
            if let Some(requested) = requested {
                patch.insert("requested".into(), json!(requested));
            }
            if let Some(decision) = decision {
                patch.insert("decision".into(), json!(decision));
            }
            match consents
                .update_one(&consent_id, &Value::Object(patch))
                .await
                .map_err(jmap)?
            {
                Ok(_) => AckResult::Done,
                Err(error) => return Err(set_error(&error)),
            }
        }
        Op::DestroyConsent { consent_id } => {
            let consents = consent::Cx::new(store, follower, account);
            match consents.destroy_one(&consent_id).await.map_err(jmap)? {
                Ok(()) => AckResult::Done,
                Err(error) => return Err(set_error(&error)),
            }
        }
        Op::ListChats => {
            let (state_text, chats) = inner
                .projection
                .chat_entries(account)
                .await
                .map_err(|e| server_fail(&e))?;
            AckResult::ListChats {
                state: state_text,
                chats: chats
                    .into_iter()
                    .map(|chat| ChatEntry {
                        accepted: chat.private.get(ACCEPTED_NAMESPACE).is_some_and(|record| {
                            record.get("accepted") == Some(&Value::Bool(true))
                        }),
                        chat_id: chat.chat_id,
                        room: chat.room_id,
                        bound: chat.bound,
                        extra: Vec::new(),
                    })
                    .collect(),
            }
        }
        Op::SetChatAccepted { chat_id, accepted } => {
            let mut patch = Map::new();
            patch.insert(
                format!("privateMetadata/{ACCEPTED_NAMESPACE}"),
                if accepted {
                    json!({"accepted": true})
                } else {
                    Value::Null
                },
            );
            // The stream always speaks for the metadata extension.
            let account = account.clone().with_metadata(true);
            match chat_set::update_private_metadata(
                &inner.projection,
                store,
                &inner.bus,
                &account,
                &chat_id,
                &patch,
            )
            .await
            .map_err(jmap)?
            {
                Ok(()) => AckResult::Done,
                Err(error) => return Err(set_error(&error)),
            }
        }
        Op::Upload { data, media_type } => {
            let Some(_admitted) = inner.uploads.admit(account.account_id()) else {
                return Err(ErrorMessage::new(None, code::RATE_LIMITED));
            };
            let media_type = media_type.unwrap_or_else(|| "application/octet-stream".to_owned());
            let size = data.len() as u64;
            match super::blobs::upload_core(state, account, &media_type, &data).await {
                Ok(blob_id) => AckResult::Upload {
                    url: format!(
                        "{}{}",
                        inner.base_url,
                        ASSET_URL_TEMPLATE.replace("{blobId}", &blob_id)
                    ),
                    blob_id,
                    size,
                },
                Err(refused) => return Err(ErrorMessage::new(None, refused.code)),
            }
        }
        Op::FetchAsset { room, url } => {
            match super::blobs::fetch_asset_core(state, account, &room, &url).await {
                Ok(data) => AckResult::FetchAsset { data },
                Err(refused) => return Err(ErrorMessage::new(None, refused.code)),
            }
        }
        Op::Subscribe { .. } => {
            return Err(ErrorMessage::new(None, code::BAD_MESSAGE));
        }
        _ => return Err(ErrorMessage::new(None, code::BAD_MESSAGE)),
    })
}

/// The KeyPackage store, which a server without one (no follower
/// KeyPackages) lacks: then the KeyPackage requests are `serverFail`, as
/// the JMAP methods are not registered.
#[allow(
    clippy::result_large_err,
    reason = "one per refused request, encoded at once"
)]
fn key_packages(
    state: &JmapState,
) -> Result<&crate::follower::key_packages::KeyPackages, ErrorMessage> {
    state
        .0
        .key_packages
        .as_deref()
        .ok_or_else(|| ErrorMessage::new(None, code::SERVER_FAIL))
}
