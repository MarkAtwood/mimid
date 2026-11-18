//! Abuse reports from a JMAP Chat client (bead mimid-oon0; decision
//! mimid-1wgh.59). INVENTED, NOT FROM SPEC: neither draft-atwood-jmap-chat-00
//! nor draft-atwood-jmap-chat-mimi-00 defines a report method.
//!
//! When [`AgentChat::sync`] stores a received franked message, it keeps the
//! message's protocol-07 §5.9 `AbusiveMessage` (its `application_data` as
//! received, the hub's frank and the acceptance time) with the room, keyed
//! by the Message id. The plaintext store saves them beside
//! the Messages, so a report works after a restart; a frank is dropped when
//! its Message is destroyed. Received messages without a frank (from a room
//! without franking) and the user's own messages keep none.
//!
//! `Message/reportAbuse` takes:
//!
//! - `accountId`;
//! - `messageIds`: 1 to [`MAX_REPORTED_MESSAGES`] ids of received Messages
//!   of one Chat, sent by one user;
//! - `reasonCode` (optional, default 0): the §5.9 `AbuseType`, 0 to 255
//!   (the draft defines no codes yet, decision mimid-1wgh.5.32);
//! - `note` (optional, default empty): at most [`MAX_NOTE_LEN`] octets.
//!
//! A Message with no kept frank (not found, the user's own, unfranked) is
//! `invalidArguments` naming it, and nothing is sent. Otherwise the agent
//! sends the report through the user's server to the room's hub
//! ([`Agent::report_abuse`](mimid_agent_core::Agent::report_abuse)) and the
//! answer is `{accountId, responseCode}` with `responseCode` `accepted`,
//! `notAllowed` (the hub's room policy refused this user), `unverifiedMessage`
//! (a frank did not verify at the hub), or `refused` with the hub's `status`.
//! A server or hub that cannot be reached is `serverUnavailable`.
//!
//! # Limitations
//!
//! - A message from a room without franking cannot be reported: an
//!   `AbusiveMessage` needs a frank. Neither can a report without messages
//!   or an anonymous one be sent.
//! - Franks of messages stored before this version were not kept; those
//!   messages cannot be reported.
//! - The method is served under the JMAP Chat capability, which does not
//!   define it.

use std::sync::{Arc, PoisonError};

use jmap_chat_types::Message;
use jmap_server::{
    CallContext, Dispatcher, HandlerFuture, HandlerOutput, Id, JmapError, JmapHandler,
};
use mimid_agent_core::frank::{decode_abusive_message, encode_abusive_message};
use mimid_agent_core::{
    AbuseType, AgentError, MAX_NOTE_LEN, MAX_REPORTED_MESSAGES, ReceivedMessage, ReportOutcome,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::backend::AgentChat;
use crate::sync::SyncReport;

/// The method's name.
pub const METHOD: &str = "Message/reportAbuse";

/// What a received franked Message keeps for a report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct KeptFrank {
    /// The room URI.
    room: String,
    /// The hex of the TLS-encoded `AbusiveMessage`.
    message: String,
}

/// Registers [`METHOD`] on `dispatcher`, served by `chat`.
pub(crate) fn register(chat: &Arc<AgentChat>, dispatcher: &mut Dispatcher<()>) {
    dispatcher.register(METHOD, Arc::new(Handler(Arc::clone(chat))));
}

struct Handler(Arc<AgentChat>);

impl JmapHandler<()> for Handler {
    fn call(&self, cx: CallContext<()>) -> HandlerFuture {
        let chat = Arc::clone(&self.0);
        Box::pin(async move { chat.report_abuse(cx.args).await.map(HandlerOutput::new) })
    }
}

fn invalid(why: impl Into<String>) -> JmapError {
    let why = why.into();
    tracing::debug!(method = METHOD, why, "abuse report refused");
    JmapError::invalid_arguments(why)
}

impl AgentChat {
    /// Keeps `received`'s frank for Message `id`, if it has one.
    pub(crate) fn keep_frank(&self, id: &Id, received: &ReceivedMessage, report: &mut SyncReport) {
        let Some(message) = received.abusive_message() else {
            return;
        };
        match encode_abusive_message(&message) {
            Ok(bytes) => {
                self.franks
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(
                        id.as_ref().to_owned(),
                        KeptFrank {
                            room: received.room.clone(),
                            message: hex::encode(bytes),
                        },
                    );
            }
            // Not for a message that was decoded; kept as a problem, not
            // an error, since the Message itself is stored.
            Err(e) => report.problems.push(format!(
                "{}: a message's frank was not kept, so it cannot be reported: {e}",
                received.room
            )),
        }
    }

    async fn report_abuse(&self, args: Value) -> Result<Value, JmapError> {
        let Value::Object(args) = args else {
            return Err(invalid("arguments must be an object"));
        };
        match args.get("accountId") {
            Some(Value::String(id)) if id == self.account.as_ref() => {}
            Some(Value::String(_)) => return Err(JmapError::account_not_found()),
            _ => return Err(invalid("accountId is required")),
        }
        let ids = message_ids(&args)?;
        let reason = match args.get("reasonCode") {
            None | Some(Value::Null) => AbuseType::RESERVED,
            Some(value) => value
                .as_u64()
                .and_then(|code| u8::try_from(code).ok())
                .map(AbuseType)
                .ok_or_else(|| invalid("reasonCode is an integer from 0 to 255"))?,
        };
        let note = match args.get("note") {
            None | Some(Value::Null) => "",
            Some(Value::String(note)) if note.len() <= MAX_NOTE_LEN => note.as_str(),
            Some(Value::String(_)) => {
                return Err(invalid(format!("note is over {MAX_NOTE_LEN} octets")));
            }
            Some(_) => return Err(invalid("note is a string")),
        };
        let (room, messages) = self.kept(&ids).await?;
        let agent = self.agent.lock().await;
        let outcome = agent
            .report_abuse(&room, &messages, reason, note)
            .await
            .map_err(agent_error)?;
        let code = match outcome {
            ReportOutcome::Accepted => "accepted",
            ReportOutcome::NotAllowed => "notAllowed",
            ReportOutcome::UnverifiedMessage => "unverifiedMessage",
            ReportOutcome::Refused { status } => {
                return Ok(json!({
                    "accountId": self.account,
                    "responseCode": "refused",
                    "status": status,
                }));
            }
            // ReportOutcome is #[non_exhaustive].
            _ => "refused",
        };
        tracing::info!(
            name: "abuse_report_sent",
            room,
            messages = messages.len(),
            outcome = code,
            "abuse report sent"
        );
        Ok(json!({ "accountId": self.account, "responseCode": code }))
    }

    /// The room and the kept AbusiveMessages of the Messages `ids`, which
    /// must still exist, each with a kept frank, all in one room.
    async fn kept(
        &self,
        ids: &[Id],
    ) -> Result<(String, Vec<mimid_agent_core::AbusiveMessage>), JmapError> {
        let mut room: Option<String> = None;
        let mut messages = Vec::with_capacity(ids.len());
        for id in ids {
            let exists = self
                .stored::<Message>(id)
                .await
                .map_err(|e| {
                    tracing::error!(
                        name: "agent_chat_store_read_failed",
                        method = METHOD,
                        error = &e as &dyn std::error::Error,
                        "reading a Message failed"
                    );
                    JmapError::server_fail("internal error")
                })?
                .is_some();
            let kept = exists
                .then(|| {
                    self.franks
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner)
                        .get(id.as_ref())
                        .cloned()
                })
                .flatten()
                .ok_or_else(|| {
                    invalid(format!(
                        "Message {id} has no frank to report: it is not a received \
                         message from a franked room"
                    ))
                })?;
            match &room {
                None => room = Some(kept.room.clone()),
                Some(first) if *first == kept.room => {}
                Some(_) => return Err(invalid("messageIds are not all in one Chat")),
            }
            let message = hex::decode(&kept.message)
                .map_err(|_| AgentError::Invalid("not hex".to_owned()))
                .and_then(|bytes| decode_abusive_message(&bytes))
                .map_err(|e| {
                    tracing::error!(
                        name: "kept_frank_unreadable",
                        method = METHOD,
                        error = &e as &dyn std::error::Error,
                        "a kept frank does not decode"
                    );
                    JmapError::server_fail("internal error")
                })?;
            messages.push(message);
        }
        // message_ids gave at least one.
        let room = room.ok_or_else(|| invalid("messageIds is empty"))?;
        Ok((room, messages))
    }
}

/// `messageIds`: 1 to [`MAX_REPORTED_MESSAGES`] distinct ids.
fn message_ids(args: &Map<String, Value>) -> Result<Vec<Id>, JmapError> {
    let Some(Value::Array(values)) = args.get("messageIds") else {
        return Err(invalid("messageIds is required"));
    };
    if values.is_empty() || values.len() > MAX_REPORTED_MESSAGES {
        return Err(invalid(format!(
            "messageIds has 1 to {MAX_REPORTED_MESSAGES} ids"
        )));
    }
    let mut ids: Vec<Id> = Vec::with_capacity(values.len());
    for value in values {
        let id = value
            .as_str()
            .map(|id| Id::from(id.to_owned()))
            .ok_or_else(|| invalid("messageIds holds strings"))?;
        if ids.contains(&id) {
            return Err(invalid(format!("Message {id} is named twice")));
        }
        ids.push(id);
    }
    Ok(ids)
}

/// An agent failure as a JMAP error: the server or hub out of reach is
/// `serverUnavailable`, a report the agent will not assemble is
/// `invalidArguments`, anything else `serverFail`.
fn agent_error(error: AgentError) -> JmapError {
    match error {
        AgentError::Invalid(why) => invalid(why),
        AgentError::NoSuchRoom(_) => invalid("the Chat's room is not known to the agent"),
        AgentError::Http { .. } => JmapError::server_unavailable(),
        AgentError::Status { status, .. } if status >= 500 => JmapError::server_unavailable(),
        AgentError::Method { ref kind, .. } if kind == "serverUnavailable" => {
            JmapError::server_unavailable()
        }
        error => {
            tracing::error!(
                name: "abuse_report_failed",
                method = METHOD,
                error = &error as &dyn std::error::Error,
                "abuse report failed"
            );
            JmapError::server_fail("internal error")
        }
    }
}
