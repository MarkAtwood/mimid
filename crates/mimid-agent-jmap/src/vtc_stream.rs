//! The call signals a client receives, over the agent's JMAP WebSocket
//! (bead mimid-1wgh.114.8; decided on bead mimid-1wgh.100).
//!
//! A signal cannot arrive any other way. The agent's EventSource carries
//! RFC 8620 §7.3 `StateChange` objects -- "these types changed, go
//! look" -- and a signal is not stored, so there is nothing to look at
//! (decision mimid-1wgh.117: signalling is not content). So the socket
//! carries it as an RFC 8887 extension message, which is what
//! draft-atwood-jmap-vtc-wss-00's `VTCCallSignal` is.
//!
//! [`CallSignals`] is the socket's end of the store's change feed: it
//! holds the client's `VTCStreamEnable` subscription, follows
//! [`Change::CallSignal`](mimid_agent_store::Change::CallSignal), and
//! sends each one the subscription covers.
//!
//! # Limitations
//!
//! - A signal is sent to the sockets open when it arrives and to nobody
//!   else: it is not kept and not replayed, as the draft requires of an
//!   ephemeral event. A client that reconnects mid-negotiation has lost
//!   that negotiation and starts another.
//! - A signal may be sent twice, because the agent's journal is replayed
//!   after a crash. The client ignores a second copy of an offer it
//!   applied; the draft says so.
//! - The subscription is this connection's alone. Two clients of one
//!   account each get their own, and both see every signal their filter
//!   covers, because the agent cannot tell which of a user's clients a
//!   call is being held on.

use std::sync::Arc;

use jmap_types::JmapError;
use jmap_vtc_server::VtcEphemeralSubscription;
use jmap_vtc_types::{CallSignalKind, VtcCallSignal, VtcEventType, VtcStreamEnable};
use jmap_websocket::server::{ExtensionHandler, ExtensionMessage, ExtensionSender};
use mimid_agent_store::Change;

use crate::backend::AgentChat;

/// The RFC 8887 extension message types this handler takes: the
/// subscribe and unsubscribe controls of
/// draft-atwood-jmap-vtc-wss-00.
const MESSAGE_TYPES: &[&str] = &[ENABLE, DISABLE];

/// draft-atwood-jmap-vtc-wss-00 §`VTCStreamEnable`.
const ENABLE: &str = "VTCStreamEnable";

/// draft-atwood-jmap-vtc-wss-00 §`VTCStreamDisable`.
const DISABLE: &str = "VTCStreamDisable";

/// The `@type` of what this handler sends.
const CALL_SIGNAL: &str = "VTCCallSignal";

/// The socket's end of the call-signal feed.
pub(crate) struct CallSignals {
    chat: Arc<AgentChat>,
    /// The client's subscription, empty until it enables the stream.
    /// draft-atwood-jmap-vtc-wss-00: a client receives nothing until it
    /// asks, so an unasked socket carries no call traffic at all.
    subscription: Option<VtcEphemeralSubscription>,
    /// The task following the store's changes, while there is one.
    pump: Option<tokio::task::JoinHandle<()>>,
    sender: Option<ExtensionSender>,
}

/// The call-signal stream of `chat`, to hand
/// [`jmap_websocket::server::Connection::with_extension`].
///
/// One per connection: the subscription it holds is that client's, and
/// two clients of one account each get their own.
#[must_use]
pub fn call_signal_stream(chat: Arc<AgentChat>) -> impl jmap_websocket::server::ExtensionHandler {
    CallSignals::new(chat)
}

impl CallSignals {
    fn new(chat: Arc<AgentChat>) -> Self {
        Self {
            chat,
            subscription: None,
            pump: None,
            sender: None,
        }
    }

    /// Starts following the store's changes, replacing any task already
    /// running: a second `VTCStreamEnable` replaces the first
    /// subscription, so it replaces the task reading for it.
    fn follow(&mut self) {
        if let Some(old) = self.pump.take() {
            old.abort();
        }
        let (Some(sender), Some(subscription)) = (self.sender.clone(), self.subscription.clone())
        else {
            return;
        };
        let chat = Arc::clone(&self.chat);
        self.pump = Some(tokio::spawn(async move {
            let store = chat.store();
            let mut from = store.last_seq();
            let mut wake = store.subscribe();
            loop {
                // A lagged receiver has missed changes. A missed signal
                // is a negotiation that will not complete, and there is
                // nothing to re-read, so the socket says nothing and
                // the call fails rather than half-connecting.
                if wake.recv().await.is_err() {
                    return;
                }
                let Ok(batch) = store.changes_since(from) else {
                    from = store.last_seq();
                    continue;
                };
                for (seq, change) in batch {
                    from = seq;
                    let Change::CallSignal {
                        room,
                        sender: who,
                        kind,
                        sdp,
                    } = change
                    else {
                        continue;
                    };
                    // Resolved here rather than in signal_of, because
                    // the lookup reads the object store and this is the
                    // only async context the pump has.
                    let Some(call) = chat.call_of_room(&room) else {
                        continue;
                    };
                    let Some(signal) = signal_of(&chat, &subscription, &call, &who, kind, &sdp)
                    else {
                        continue;
                    };
                    if sender.try_send(&signal).is_err() {
                        // Closed or full: a full queue means the client
                        // is not reading, and a signal it has not read
                        // is as lost as one never sent.
                        return;
                    }
                }
            }
        }));
    }
}

/// The event for one signal, or `None` when this subscription does not
/// cover it: a call the client did not ask for, or an event type it
/// filtered out. The caller has already resolved the room to its call.
fn signal_of(
    chat: &AgentChat,
    subscription: &VtcEphemeralSubscription,
    call: &jmap_types::Id,
    sender: &str,
    kind: mimid_agent_core::SignalKind,
    sdp: &str,
) -> Option<VtcCallSignal> {
    let filter = subscription.filter()?;
    if !filter.includes(VtcEventType::CallSignal.as_str()) {
        return None;
    }
    if !matches!(filter.call_ids(), jmap_vtc_server::CallScope::All)
        && !matches!(
            filter.call_ids(),
            jmap_vtc_server::CallScope::Only(ids) if ids.iter().any(|id| id == call)
        )
    {
        return None;
    }
    let kind = match kind {
        mimid_agent_core::SignalKind::Offer => CallSignalKind::Offer,
        mimid_agent_core::SignalKind::Answer => CallSignalKind::Answer,
        mimid_agent_core::SignalKind::Candidate => CallSignalKind::Candidate,
        _ => return None,
    };
    // An offer or answer carries the whole description in `sdp`; a
    // candidate carries the object a client passes to WebRTC, parsed
    // back out of the fragment the wire carried it in.
    let (sdp, candidate) = if kind == CallSignalKind::Candidate {
        (serde_json::Value::Null, candidate_of(sdp)?)
    } else {
        (
            serde_json::Value::String(sdp.to_owned()),
            serde_json::Value::Null,
        )
    };
    // The sender is the authenticated MLS sender the store recorded, not
    // anything the sender asserted (draft-atwood-jmap-vtc-00
    // §VTCCallSignal), so a participant cannot signal as another. It is
    // carried as the Id a client already has for that person, because
    // `participantId` is a JMAP Id: a user URI is not one (RFC 8620 §1.2
    // allows no `:` or `/`), so putting the URI there made every event
    // fail to build.
    let participant = participant_id(chat, sender)?;
    let event = serde_json::json!({
        "@type": CALL_SIGNAL,
        "accountId": chat.account_id().as_ref(),
        "callId": call.as_ref(),
        "participantId": participant.as_ref(),
        "signal": kind.as_str(),
        "sdp": sdp,
        "candidate": candidate,
        "timestamp": serde_json::to_value(jmap_server::now_utc_string()).ok()?,
    });
    match serde_json::from_value(event) {
        Ok(signal) => Some(signal),
        // Never silently: an event that will not build is a call that
        // does not connect, and the client has nothing to go on.
        Err(error) => {
            tracing::error!(
                name: "agent_call_signal_undeliverable",
                error = &error as &dyn std::error::Error,
                "a call signal could not be built into a VTCCallSignal"
            );
            None
        }
    }
}

/// The Id a client already has for `user` in this account: the account's
/// own id for this user, else the person's store key, which is what
/// `ChatMember.id` carries (`crate::render::Render::known_id`).
///
/// `None` for a sender this agent has no person record for, which is a
/// signal from someone it has never seen in a room.
fn participant_id(chat: &AgentChat, user: &str) -> Option<jmap_types::Id> {
    if user == chat.store().user() {
        return Some(chat.account_id().clone());
    }
    chat.store()
        .state()
        .person_of_user(user)
        .map(|key| jmap_types::Id::from(key.as_str()))
}

/// The `RTCIceCandidateInit` a client needs, read out of the SDP
/// fragment the room carried (RFC 8840): the `a=candidate:` line, and
/// the `a=mid:` line when the sender gave one.
///
/// The inverse of the agent's own encoder
/// (`crate::vtc_backend`'s `candidate_fragment`). `None` for a fragment
/// with no candidate line, which is not a candidate however it was
/// labelled.
fn candidate_of(fragment: &str) -> Option<serde_json::Value> {
    let line = |prefix: &str| {
        fragment
            .lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix(prefix))
            .map(str::to_owned)
    };
    // WebRTC takes the candidate with or without the "candidate:"
    // prefix; it is given back as the SDP attribute spells it.
    let candidate = line("a=candidate:").map(|rest| format!("candidate:{rest}"))?;
    let mut object = serde_json::Map::new();
    object.insert("candidate".to_owned(), serde_json::Value::String(candidate));
    object.insert(
        "sdpMid".to_owned(),
        line("a=mid:").map_or(serde_json::Value::Null, serde_json::Value::String),
    );
    // sdpMLineIndex is not carried: the mid names the same media
    // description and WebRTC takes either (crate::vtc).
    object.insert("sdpMLineIndex".to_owned(), serde_json::Value::Null);
    Some(serde_json::Value::Object(object))
}

impl ExtensionHandler for CallSignals {
    fn message_types(&self) -> &[&str] {
        MESSAGE_TYPES
    }

    fn start(&mut self, sender: ExtensionSender) {
        self.sender = Some(sender);
    }

    async fn handle(&mut self, message: ExtensionMessage) -> Result<(), JmapError> {
        // `ExtensionMessage::body` is "every member of the message except
        // `@type`", and `VtcStreamMessage` is tagged on `@type`, so
        // deserializing the enum from the body can never succeed: it
        // always fails with "missing field `@type`" and the client gets a
        // `RequestError` for a frame that was correct. The type name is
        // what the transport already dispatched on, so it is what this
        // dispatches on too, deserializing the one frame type.
        match message.message_type.as_str() {
            ENABLE => {
                let enable = message.deserialize::<VtcStreamEnable>()?;
                let mut subscription = self.subscription.take().unwrap_or_default();
                subscription.replace_with(&enable)?;
                self.subscription = Some(subscription);
                self.follow();
            }
            DISABLE => {
                self.subscription = None;
                if let Some(pump) = self.pump.take() {
                    pump.abort();
                }
            }
            // A control message this version does not know is ignored,
            // as the draft requires of an unrecognized value. The
            // transport only routes `message_types()` here, so this is
            // unreachable until that list grows.
            _ => {}
        }
        Ok(())
    }

    async fn close(&mut self) {
        if let Some(pump) = self.pump.take() {
            pump.abort();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The candidate a client gets back is the one the sender sent: the
    /// agent encodes it as an SDP fragment for the wire
    /// (`crate::vtc_backend`) and reads it back here, and a round trip
    /// that loses the candidate line is a call that finds no route.
    #[test]
    fn a_candidate_survives_the_fragment_round_trip() {
        const LINE: &str = "candidate:1 1 UDP 2130706431 192.0.2.1 50000 typ host";
        // As vtc_backend::candidate_fragment writes it.
        let fragment = format!("a=mid:0\r\na={LINE}\r\n");
        let back = candidate_of(&fragment).expect("a candidate");
        assert_eq!(back["candidate"], serde_json::json!(LINE));
        assert_eq!(back["sdpMid"], serde_json::json!("0"));
        assert!(back["sdpMLineIndex"].is_null(), "the mid names it instead");
    }

    /// A sender that gave no mid is carried without one rather than
    /// with an invented one.
    #[test]
    fn a_candidate_without_a_mid_keeps_none() {
        let back =
            candidate_of("a=candidate:1 1 UDP 1 192.0.2.1 5000 typ host\r\n").expect("a candidate");
        assert!(back["sdpMid"].is_null());
        assert!(
            back["candidate"]
                .as_str()
                .is_some_and(|c| c.starts_with("candidate:"))
        );
    }

    /// A fragment with no candidate line is not a candidate, however it
    /// was labelled, so nothing is sent for it.
    #[test]
    fn a_fragment_with_no_candidate_is_refused() {
        assert!(candidate_of("a=mid:0\r\n").is_none());
        assert!(candidate_of("").is_none());
        assert!(candidate_of("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n").is_none());
    }
}
