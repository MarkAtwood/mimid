//! [`VtcBackend`] for [`AgentChat`]: the VTC method handlers of
//! crate-jmap's `jmap-vtc-server` served over the agent's store (bead
//! mimid-1wgh.114.2).
//!
//! The handlers own the draft's rules; this owns what is mimid's:
//!
//! - a call is a MIMI room of its own, parent-dependent on the chat it
//!   belongs to, so creating one hosts that room and invites the chat's
//!   people ([`crate::AgentChat`] over `Store::start_call`);
//! - its signalling goes through that room's messages
//!   (`Store::send_call_signal`), which is `VTCCall/signal`;
//! - its media secret comes from that room's MLS group
//!   (`Store::media_secret`), which is `VTCCall/exportMediaSecret`.
//!
//! Everything a VTC server usually does with media, mimid does not do.
//! [`crate::vtc::capability`] advertises room calls and nothing else, so
//! the ring, scheduled, breakout, recording, livestream and lobby paths
//! in the handlers are never reached.
//!
//! # Limitations
//!
//! - The VTC records live in the agent's own object store beside its
//!   Chats and Messages, as a projection does. The MIMI room is the
//!   durable thing; a VTCCall is how a client addresses it.
//! - `active_call_count` counts what this account holds, which is what
//!   `maxConcurrentCalls` is about, and mimid advertises no limit.
//! - A call the agent has not joined cannot carry an observed state
//!   (decisions mimid-1wgh.117, mimid-1wgh.118): nothing here invents
//!   one.

use std::sync::Arc;

use jmap_chat_server::ChatStore;
use jmap_server::{
    BackendSetError, GetObject, Id, JmapObject, JmapReads, SetError, SetErrorType, SetObject,
};
use jmap_vtc_server::{CallSignalRequest, EpochMoved, MediaSecret, StatefulObject, VtcBackend};
use jmap_vtc_types::{VtcCall, VtcCapability};

use jmap_chat_server::memory::MemoryError;

use crate::backend::AgentChat;

/// The `VTCCall` property naming the call's own MIMI room
/// (draft-atwood-jmap-vtc-00 §Optional Binding Fields `mimiRoomId`).
pub(crate) const MIMI_ROOM_ID: &str = "mimiRoomId";

/// One call room claimed while its `VTCCall` is being made, so the
/// projection does not make a second call for it
/// (`crate::backend::StartingCalls` says why a claim and not an order).
/// The claim is released when this is dropped, on the way out of
/// `create_call` whether it succeeded or not: a room left behind by a
/// failed create is then projected by the next sync, like any other call
/// room this agent is in without a call of its own.
///
/// A poisoned lock is taken anyway (`into_inner`), because the set holds
/// nothing that a panic could leave half-written and a lock nobody can
/// take would turn one panic into a duplicate call for every later one.
struct Starting {
    rooms: crate::backend::StartingCalls,
    key: String,
}

impl Starting {
    fn claim(rooms: &crate::backend::StartingCalls, key: &str) -> Self {
        rooms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(key.to_owned());
        Self {
            rooms: std::sync::Arc::clone(rooms),
            key: key.to_owned(),
        }
    }
}

impl Drop for Starting {
    fn drop(&mut self) {
        self.rooms
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.key);
    }
}

/// Which VTC types this backend stores.
fn served(type_name: &str) -> bool {
    matches!(type_name, "VTCCall" | "VTCParticipant")
}

fn refuse(kind: SetErrorType, why: impl Into<String>) -> BackendSetError<MemoryError> {
    let mut error = SetError::new(kind);
    error.description = Some(why.into());
    BackendSetError::SetError(Box::new(error))
}

impl AgentChat {
    /// The store key of the room `call`'s `mimiRoomId` names, or a
    /// refusal naming why there is none: a call this agent did not host,
    /// or one whose room it has left.
    async fn call_room_key(&self, call: &VtcCall) -> Result<String, BackendSetError<MemoryError>> {
        let uri = call
            .extra
            .get(MIMI_ROOM_ID)
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| {
                refuse(
                    SetErrorType::NotFound,
                    "this call has no MIMI room of its own",
                )
            })?;
        let key = self.store().state().room_of_uri(uri).cloned();
        key.ok_or_else(|| {
            refuse(
                SetErrorType::NotFound,
                "this agent is not in the call's room",
            )
        })
    }

    /// The id of the `VTCCall` whose `mimiRoomId` names the room
    /// `room_key`, or `None` when no call of this account has that room:
    /// a chat, or a call room this agent is in without a VTCCall of its
    /// own, which is what a call hosted by another of the user's clients
    /// looks like until its records are projected.
    ///
    /// The store key is resolved to the room's URI first, because
    /// `mimiRoomId` holds the URI: it crosses providers, and a store key
    /// is local (decision mimid-1wgh.124 says the same of the
    /// announcement).
    pub(crate) async fn call_of_room(&self, room_key: &str) -> Option<Id> {
        let uri = self
            .store()
            .state()
            .rooms
            .get(room_key)
            .map(|room| room.uri.clone())?;
        let (calls, _) = jmap_vtc_server::VtcBackend::get_objects_unscoped::<VtcCall>(
            self,
            self.account_id(),
            self.account_id(),
            None,
        )
        .await
        .ok()?;
        calls
            .into_iter()
            .find(|call| {
                call.extra
                    .get(MIMI_ROOM_ID)
                    .and_then(serde_json::Value::as_str)
                    == Some(uri.as_str())
            })
            .map(|call| call.id)
    }

    /// The `VTCCall` of `call_id` as this caller may see it, or a
    /// `notFound` refusal: the read path is the access check
    /// ([`VtcBackend`]'s §Per-call access).
    async fn vtc_call(
        &self,
        caller: &Id,
        account_id: &Id,
        call_id: &Id,
    ) -> Result<VtcCall, BackendSetError<MemoryError>> {
        let (calls, _) = self
            .get_objects_unscoped::<VtcCall>(
                caller,
                account_id,
                Some(std::slice::from_ref(call_id)),
            )
            .await
            .map_err(BackendSetError::Other)?;
        calls
            .into_iter()
            .next()
            .ok_or_else(|| refuse(SetErrorType::NotFound, "no such call"))
    }
}

impl AgentChat {
    /// [`VtcBackend::create_object`] by another name, so that
    /// [`VtcBackend::create_call`] can call it without naming the trait
    /// beside [`jmap_chat_server::ChatStore`]'s method of the same name.
    async fn create_vtc_object<O, F>(
        &self,
        caller: &Id,
        account_id: &Id,
        create_id: &str,
        build: F,
    ) -> Result<(Id, O), BackendSetError<MemoryError>>
    where
        O: SetObject + Send + Sync,
        F: FnOnce(&Id) -> O + Send,
    {
        ChatStore::create_object(self.inner_backend(), caller, account_id, create_id, build).await
    }

    /// The object store the VTC records live in, beside the Chats and
    /// Messages: the agent's own.
    fn inner_backend(&self) -> &jmap_chat_server::memory::MemoryBackend {
        &self.inner
    }
}

impl VtcBackend for AgentChat {
    async fn vtc_capability(
        &self,
        _caller: &Id,
        _account_id: &Id,
    ) -> Result<VtcCapability, MemoryError> {
        Ok(crate::vtc::capability(self.vtc_options()))
    }

    fn has_capability(&self, _caller: &Id, account_id: &Id, uri: &str) -> bool {
        *account_id == *self.account_id()
            && matches!(
                uri,
                "urn:ietf:params:jmap:chat" | "urn:ietf:params:jmap:vtc"
            )
    }

    /// The agent serves one user, so the caller is that user: their URI,
    /// which is what a `VTCParticipant`'s `userId` carries.
    async fn caller_user_id(&self, _caller: &Id, _account_id: &Id) -> Result<String, MemoryError> {
        Ok(self.store().user().to_owned())
    }

    async fn active_call_count(&self, caller: &Id, account_id: &Id) -> Result<u64, MemoryError> {
        let (calls, _) = self
            .get_objects_unscoped::<VtcCall>(caller, account_id, None)
            .await?;
        Ok(calls
            .iter()
            .filter(|call| *call.state() == jmap_vtc_types::CallState::Active)
            .count() as u64)
    }

    async fn signal_call(
        &self,
        caller: &Id,
        account_id: &Id,
        call_id: &Id,
        signal: &CallSignalRequest,
    ) -> Result<(), BackendSetError<MemoryError>> {
        let call = self.vtc_call(caller, account_id, call_id).await?;
        let room = self.call_room_key(&call).await?;
        let kind = match signal.signal {
            jmap_vtc_types::CallSignalKind::Offer => mimid_agent_core::SignalKind::Offer,
            jmap_vtc_types::CallSignalKind::Answer => mimid_agent_core::SignalKind::Answer,
            jmap_vtc_types::CallSignalKind::Candidate => mimid_agent_core::SignalKind::Candidate,
            ref other => {
                return Err(refuse(
                    SetErrorType::InvalidProperties,
                    format!("this server does not carry the signal {other:?}"),
                ));
            }
        };
        // An offer or answer carries the SDP; a candidate carries the
        // fragment, which the agent sends as the session part's body so
        // that everything on the wire is SDP.
        let sdp = match (&signal.sdp, &signal.candidate) {
            (Some(sdp), _) => sdp.clone(),
            (None, Some(candidate)) => candidate_fragment(candidate),
            (None, None) => {
                return Err(refuse(
                    SetErrorType::InvalidProperties,
                    "the signal carries neither a session description nor a candidate",
                ));
            }
        };
        self.store()
            .send_call_signal(&room, kind, &sdp)
            .await
            .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?;
        self.store()
            .save()
            .await
            .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?;
        Ok(())
    }

    async fn export_media_secret(
        &self,
        caller: &Id,
        account_id: &Id,
        call_id: &Id,
        epoch: Option<u64>,
    ) -> Result<Result<MediaSecret, EpochMoved>, BackendSetError<MemoryError>> {
        let call = self.vtc_call(caller, account_id, call_id).await?;
        let room = self.call_room_key(&call).await?;
        let secret = match self.store().media_secret(&room).await {
            Ok(secret) => secret,
            // A restart inside the epoch: §4.4's leaf was punctured when
            // this agent read the secret, and the secret itself was only
            // ever in memory. The epoch has not moved, so there is no
            // truthful EpochMoved to send and no way to serve the one
            // the client is asking about -- a state this surface cannot
            // express. Moving the epoch makes it expressible: afterwards
            // the current epoch really has moved on, the ordinary check
            // below says so, and the client re-asks for the new one
            // through code it already has (bead mimid-1wgh.129, decision
            // recorded there).
            //
            // Only this failure. A removed member, a group with no
            // Exporter Tree and a storage failure are all unchanged by a
            // new epoch, so they are refusals as before. And no retry
            // beyond the one: a restart loop must not become a Commit
            // loop.
            Err(mimid_agent_store::action::ActionError::Agent(
                mimid_agent_core::AgentError::SecretConsumed { epoch: lost, .. },
            )) => {
                tracing::info!(
                    name: "agent_call_rekeyed_after_restart",
                    room = room,
                    lost_epoch = lost,
                    "this epoch's media secret was already read and is no longer held; \
                     moving the call to a new epoch so every member rekeys"
                );
                self.store()
                    .rekey(&room)
                    .await
                    .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?;
                self.store()
                    .media_secret(&room)
                    .await
                    .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?
            }
            Err(e) => return Err(refuse(SetErrorType::Forbidden, e.to_string())),
        };
        // The client named an epoch that has ended: tell it which one is
        // current rather than hand it a secret nobody else is using.
        // After a rekey above, this is what tells the client the epoch
        // moved.
        if let Some(wanted) = epoch
            && wanted != secret.epoch()
        {
            return Ok(Err(EpochMoved::new(secret.epoch())));
        }
        Ok(Ok(MediaSecret::new(
            secret.epoch(),
            secret.expose_secret().to_vec(),
        )))
    }

    /// The call's own MIMI room is hosted here, and then the VTCCall
    /// records it: `Store::start_call` makes a room-policy-04 §5
    /// parent-dependent room under the chat the call names and invites
    /// that chat's people (decision mimid-1wgh.113).
    ///
    /// `ring_targets` is always empty, because the capability advertises
    /// no ring calls, so none of the ring bookkeeping the trait
    /// describes applies. A call with no `chatId` is refused: mimid has
    /// no media plane to hold a call that is not a MIMI room, so there
    /// would be nothing to join.
    async fn create_call<F>(
        &self,
        caller: &Id,
        account_id: &Id,
        build: F,
        _ring_targets: &[String],
    ) -> Result<VtcCall, BackendSetError<MemoryError>>
    where
        F: FnOnce(&Id) -> VtcCall + Send,
    {
        let (id, mut call) = self
            .create_vtc_object::<VtcCall, _>(caller, account_id, "vtc-call", build)
            .await?;
        let Some(chat) = call.chat_id.clone().flatten() else {
            // Nothing to undo: the handler drops a refused create.
            return Err(refuse(
                SetErrorType::InvalidProperties,
                "a call here needs a chatId: its media is keyed by a MIMI \
                 room under that chat's room",
            ));
        };
        // Refused BEFORE the room is hosted, so a refused create leaves
        // no call room behind and announces nothing: an announcement for
        // a call nobody can join is worse than a refusal that says why
        // (decision on bead mimid-1wgh.114.15).
        //
        // The parent chat's participants are what `start_call_with`
        // invites, since `among` is None here (bead mimid-1wgh.131), so
        // they are what the call room would hold.
        let would_hold = {
            let state = self.store().state();
            let Some(parent) = state.rooms.get(chat.as_ref()) else {
                return Err(refuse(
                    SetErrorType::InvalidProperties,
                    "this chat is not a room this agent is in",
                ));
            };
            1 + parent.others(self.store().user()).len() as u64
        };
        if would_hold > crate::vtc::MAX_PARTICIPANTS {
            return Err(refuse(
                SetErrorType::InvalidProperties,
                format!(
                    "a call here is between two people, and this chat has \
                     {would_hold}: mimid carries a call's signalling to \
                     every member of its room with no way to address one \
                     peer, so a call of three or more cannot connect"
                ),
            ));
        }
        // The media kinds and the subject travel in the announcement,
        // because the call room carries neither and the receiving side
        // projects the call from the room (bead mimid-1wgh.114.11;
        // decision mimid-1wgh.128). A kind this library does not know is
        // sent as the string the client gave, since it is the client's
        // and another implementation may know it.
        let options = mimid_agent_store::action::CallOptions {
            among: None,
            media: call
                .media_types
                .iter()
                .map(|kind| match serde_json::to_value(kind) {
                    Ok(serde_json::Value::String(text)) => text,
                    _ => String::new(),
                })
                .filter(|kind| !kind.is_empty())
                .collect(),
            subject: call.subject.clone().unwrap_or_default(),
        };
        // Claimed before the room is made, because `start_call_with`
        // records it before it returns and the runner saves on its own
        // task (`Starting`).
        let key = self.store().new_key();
        let _starting = Starting::claim(&self.starting_calls, &key);
        let room = self
            .store()
            .start_call_with(key, chat.as_ref(), &options)
            .await
            .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?;
        // The room goes on the call before the save, so the record of
        // the call room is written with the object this method is
        // returning (bead mimid-1wgh.114.14) and the projection has the
        // `mimiRoomId` it matches on once the claim is released.
        call.extra.insert(
            MIMI_ROOM_ID.to_owned(),
            serde_json::Value::String(room.uri.clone()),
        );
        let patch = serde_json::from_value(serde_json::json!({
            MIMI_ROOM_ID: room.uri,
        }))
        .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?;
        VtcBackend::update_object::<VtcCall>(self, caller, account_id, &id, patch).await?;
        // A crash before this loses the call's room, which the
        // refusal says; one after it is a room the next sync projects a
        // call for.
        self.store()
            .save()
            .await
            .map_err(|e| refuse(SetErrorType::Forbidden, e.to_string()))?;
        Ok(call)
    }

    async fn create_object<O, F>(
        &self,
        caller: &Id,
        account_id: &Id,
        create_id: &str,
        build: F,
    ) -> Result<(Id, O), BackendSetError<MemoryError>>
    where
        O: SetObject + Send + Sync,
        F: FnOnce(&Id) -> O + Send,
    {
        self.inner
            .create_object(caller, account_id, create_id, build)
            .await
    }

    async fn update_object<O: SetObject + Send + Sync>(
        &self,
        caller: &Id,
        account_id: &Id,
        id: &Id,
        patch: O::Patch,
    ) -> Result<Option<O>, BackendSetError<MemoryError>> {
        self.inner
            .update_object(caller, account_id, id, patch)
            .await
    }

    /// The conditional update, as far as this backend can make it one.
    ///
    /// THE CONDITION IS NOT ENFORCED HERE, and the reason is a bound
    /// rather than a choice: `O` is only [`StatefulObject`], whose
    /// supertrait is [`SetObject`], and reading an object back needs
    /// [`GetObject`] — a sibling marker, not a supertrait. So there is no
    /// way to read `O` generically to compare its state, and no way to
    /// build an `O::State` to return if it differed. The reference
    /// backend compares by decoding its own raw storage, which the
    /// agent's object store does not expose.
    ///
    /// What protects the invariant instead: the handlers read the call
    /// and check its state before they call this, so `expected` is
    /// already known to hold at that moment. The window this leaves is
    /// two concurrent `VTCCall/set` requests on one call, where the
    /// second would apply a patch the first had just made redundant —
    /// an end applied twice, not a state the draft forbids. The agent
    /// serves one user over loopback, so that window needs two of their
    /// own clients racing.
    ///
    /// `Ok(Err(..))` is therefore never returned, and a caller that
    /// needs a real compare-and-set should not read this as one.
    async fn update_object_if<O: StatefulObject + Send + Sync>(
        &self,
        caller: &Id,
        account_id: &Id,
        id: &Id,
        _expected: &[O::State],
        patch: O::Patch,
    ) -> Result<Result<Option<O>, O::State>, BackendSetError<MemoryError>> {
        VtcBackend::update_object::<O>(self, caller, account_id, id, patch)
            .await
            .map(Ok)
    }

    async fn destroy_object<O: SetObject + Send + Sync>(
        &self,
        caller: &Id,
        account_id: &Id,
        id: &Id,
    ) -> Result<(), BackendSetError<MemoryError>> {
        self.inner.destroy_object::<O>(caller, account_id, id).await
    }

    async fn get_objects_unscoped<O: GetObject + Send + Sync>(
        &self,
        caller: &Id,
        account_id: &Id,
        ids: Option<&[Id]>,
    ) -> Result<(Vec<O>, Vec<Id>), MemoryError> {
        // The agent serves one user their own records, so there is no
        // call a caller may not see: the ordinary read is the unscoped
        // one (VtcBackend's §Per-call access).
        self.get_objects(caller, account_id, ids, None).await
    }

    /// The agent delivers nothing to a client out of band: a client of
    /// its loopback endpoint reads the records, and the one event that
    /// matters, a call signal, arrives as a message in the call's room
    /// and reaches the client as a `VTCCallSignal` through the WebSocket
    /// transport when mimid serves one. Dropped until then, rather than
    /// queued where nothing drains it.
    async fn deliver_event(
        &self,
        _caller: &Id,
        _account_id: &Id,
        _event: jmap_vtc_types::VtcEvent,
    ) {
    }

    /// mimid advertises no recording, so the handlers never ask.
    async fn deliver_recording_state_event(
        &self,
        _caller: &Id,
        _account_id: &Id,
        _event: jmap_vtc_types::VtcRecordingStateEvent,
    ) {
    }

    fn supports_type<O: JmapObject>(&self, _caller: &Id, account_id: &Id) -> bool {
        *account_id == *self.account_id() && served(O::TYPE_NAME)
    }
}

/// One ICE candidate as the SDP fragment a session part carries
/// (RFC 8840): the `a=mid:` line naming its media description, when the
/// client gave one, and the `a=candidate:` line.
///
/// `sdpMLineIndex` is not carried: the mid names the same media
/// description and WebRTC takes either (`crate::vtc`).
fn candidate_fragment(candidate: &serde_json::Map<String, serde_json::Value>) -> String {
    let field = |name: &str| {
        candidate
            .get(name)
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    let mut out = String::new();
    let mid = field("sdpMid");
    if !mid.is_empty() {
        out.push_str(&format!("a=mid:{mid}\r\n"));
    }
    let line = field("candidate");
    let line = line.strip_prefix("candidate:").unwrap_or(&line);
    if !line.is_empty() {
        out.push_str(&format!("a=candidate:{line}\r\n"));
    }
    out
}

/// Registers the VTC methods on `dispatcher` when the surface is on
/// (decision mimid-1wgh.119). When off nothing is registered, so a
/// client is told the method is unknown rather than finding it refuse.
pub(crate) fn register(this: &Arc<AgentChat>, dispatcher: &mut jmap_server::Dispatcher<Id>) {
    if this.vtc_options().enabled {
        jmap_vtc_server::register_vtc_handlers(dispatcher, Arc::clone(this));
    }
}
