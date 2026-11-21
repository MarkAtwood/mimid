//! The agent's provider client: one interface over the two bindings of
//! draft-atwood-jmap-chat-mimi-00's operations (docs/design/binary-live-stream.md
//! §5.2; decision mimid-1wgh.80), JMAP ([`crate::client::Jmap`], the
//! default) and the live stream ([`crate::stream::Stream`]), chosen by
//! [`Binding`] in the agent's configuration. The agent calls only this,
//! so the same agent code runs over either, and the side-by-side tests
//! compare what it reports.

use std::sync::{Arc, Mutex, PoisonError};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::ProposalRef;
use mimi_protocol::{
    FanoutEvent, FanoutMessage, KeyMaterialResponse, UpdateRequest, UpdateResult,
    UpdateRoomResponse, Utf8String,
};
use mimid_live::{AckResult, Op, code};
use serde_json::json;

use crate::AgentError;
use crate::agent::ReportOutcome;
use crate::client::{
    Accepted, ConsentRecord, Fetched, HubSender, Jmap, MAX_ASSET_LEN, MAX_SENT, OwnChat, digest,
};
use crate::stream::{Stream, method_error};

/// Which binding the agent speaks to its provider (decision
/// mimid-1wgh.80).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum Binding {
    /// JMAP (draft-atwood-jmap-chat-mimi-00): the standard, and the
    /// default.
    #[default]
    Jmap,
    /// mimid's live stream: CBOR over a WebSocket at `/mimid/live`
    /// (INVENTED, NOT FROM SPEC). The server must have it switched on.
    Stream,
}

/// The digests of the MLSMessages this agent sent, as [`Jmap`] keeps
/// them, for the stream binding.
#[derive(Default)]
struct Sent(Mutex<Vec<u64>>);

impl Sent {
    fn remember(&self, message: &impl Serialize) {
        if let Ok(bytes) = message.tls_serialize_detached() {
            let mut sent = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            sent.push(digest(&bytes));
            let excess = sent.len().saturating_sub(MAX_SENT);
            sent.drain(..excess);
        }
    }

    fn digests(&self) -> Vec<u64> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    fn restore(&self, digests: &[u64]) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = digests.to_vec();
    }

    fn is_own(&self, body: &[u8]) -> bool {
        let Ok(fanouts) = FanoutMessage::decode_all(body) else {
            return false;
        };
        let sent = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        fanouts.iter().any(|fanout| {
            let message = match &fanout.event {
                FanoutEvent::Application { message, .. }
                | FanoutEvent::Commit { message, .. }
                | FanoutEvent::Proposal { message, .. } => message,
                FanoutEvent::Welcome { .. } => return false,
            };
            message
                .tls_serialize_detached()
                .is_ok_and(|bytes| sent.contains(&digest(&bytes)))
        })
    }
}

/// The stream binding and what it keeps beside the connection.
pub(crate) struct StreamProvider {
    stream: Stream,
    sent: Sent,
    hub_sender: HubSender,
}

/// The provider client.
pub(crate) enum Provider {
    Jmap(Box<Jmap>),
    Stream(Box<StreamProvider>),
}

/// A malformed answer of `what`.
fn malformed(what: &str, detail: impl Into<String>) -> AgentError {
    AgentError::malformed(what, detail)
}

fn unexpected(what: &str, result: &AckResult) -> AgentError {
    malformed(what, format!("an Ack of another shape: {result:?}"))
}

impl Provider {
    /// Opens `binding` to the server at `server_url` with `token`.
    pub async fn open(binding: Binding, server_url: &str, token: &str) -> Result<Self, AgentError> {
        Ok(match binding {
            Binding::Jmap => Self::Jmap(Box::new(Jmap::open(server_url, token).await?)),
            Binding::Stream => {
                let stream = Stream::open(server_url, token).await?;
                let hub_sender = crate::client::parse_hub_sender_bytes(&stream.hello.hub_sender)
                    .map_err(|detail| malformed("ProviderHello", detail))?;
                Self::Stream(Box::new(StreamProvider {
                    stream,
                    sent: Sent::default(),
                    hub_sender,
                }))
            }
        })
    }

    /// The binding's wake-up: notified when the stream has something for
    /// the agent. `None` on JMAP, which is polled.
    pub fn wake(&self) -> Option<Arc<tokio::sync::Notify>> {
        match self {
            Self::Jmap(_) => None,
            Self::Stream(s) => Some(s.stream.wake()),
        }
    }

    /// The server's EventSource, on JMAP; `None` on the stream, which
    /// pushes by itself ([`Provider::wake`]).
    pub fn push_source(&self) -> Result<Option<crate::push::PushSource>, AgentError> {
        match self {
            Self::Jmap(j) => j.push_source(),
            Self::Stream(_) => Ok(None),
        }
    }

    /// The hub's ExternalSender.
    pub fn hub_sender(&self) -> &HubSender {
        match self {
            Self::Jmap(j) => &j.hub_sender,
            Self::Stream(s) => &s.hub_sender,
        }
    }

    /// `roomIdPrefix`.
    pub fn room_id_prefix(&self) -> &str {
        match self {
            Self::Jmap(j) => &j.room_id_prefix,
            Self::Stream(s) => &s.stream.hello.room_id_prefix,
        }
    }

    /// `assetLifetime`.
    pub fn asset_lifetime(&self) -> Option<u64> {
        match self {
            Self::Jmap(j) => j.asset_lifetime,
            Self::Stream(s) => s.stream.hello.asset_lifetime,
        }
    }

    /// Whether the account can record accepted rooms.
    pub fn chat_metadata(&self) -> bool {
        match self {
            Self::Jmap(j) => j.chat_metadata,
            Self::Stream(s) => s.stream.hello.accepted_rooms,
        }
    }

    /// See [`Jmap::sent_digests`].
    pub fn sent_digests(&self) -> Vec<u64> {
        match self {
            Self::Jmap(j) => j.sent_digests(),
            Self::Stream(s) => s.sent.digests(),
        }
    }

    /// See [`Jmap::restore_sent`].
    pub fn restore_sent(&self, digests: &[u64]) {
        match self {
            Self::Jmap(j) => j.restore_sent(digests),
            Self::Stream(s) => s.sent.restore(digests),
        }
    }

    /// See [`Jmap::remember_sent`].
    pub fn remember_sent(&self, message: &impl Serialize) {
        match self {
            Self::Jmap(j) => j.remember_sent(message),
            Self::Stream(s) => s.sent.remember(message),
        }
    }

    /// See [`Jmap::is_own`].
    pub fn is_own(&self, body: &[u8]) -> bool {
        match self {
            Self::Jmap(j) => j.is_own(body),
            Self::Stream(s) => s.sent.is_own(body),
        }
    }

    /// See [`Jmap::upload`].
    pub async fn upload(&self, bytes: Vec<u8>) -> Result<String, AgentError> {
        match self {
            Self::Jmap(j) => j.upload(bytes).await,
            Self::Stream(s) => {
                if !s.stream.hello.stores_assets {
                    return Err(AgentError::Invalid(
                        "the server does not store attachments".to_owned(),
                    ));
                }
                let op = Op::Upload {
                    data: bytes,
                    media_type: Some("application/octet-stream".to_owned()),
                };
                match s.stream.ok("upload", op).await? {
                    AckResult::Upload { url, .. } => Ok(url),
                    other => Err(unexpected("upload", &other)),
                }
            }
        }
    }

    /// See [`Jmap::fetch_asset`].
    pub async fn fetch_asset(&self, room: &str, url: &str) -> Result<Vec<u8>, AgentError> {
        match self {
            Self::Jmap(j) => j.fetch_asset(room, url).await,
            Self::Stream(s) => {
                const WHAT: &str = "GET assetDownloadUrl";
                if !s.stream.hello.fetches_assets {
                    return Err(AgentError::Invalid(
                        "the server does not fetch attachments".to_owned(),
                    ));
                }
                let op = Op::FetchAsset {
                    room: room.to_owned(),
                    url: url.to_owned(),
                };
                match s.stream.ok(WHAT, op).await? {
                    AckResult::FetchAsset { data } if data.len() > MAX_ASSET_LEN => {
                        Err(malformed(WHAT, "the attachment is too large"))
                    }
                    AckResult::FetchAsset { data } => Ok(data),
                    other => Err(unexpected(WHAT, &other)),
                }
            }
        }
    }

    /// The account's Consent records.
    pub async fn consents(&self) -> Result<Vec<ConsentRecord>, AgentError> {
        match self {
            Self::Jmap(j) => j.consents().await,
            Self::Stream(s) => match s.stream.ok("Consent/get", Op::ListConsent).await? {
                AckResult::ListConsent { records, .. } => Ok(records
                    .into_iter()
                    .map(|r| ConsentRecord {
                        id: r.consent_id,
                        requester: r.requester_uri,
                        target: r.target_uri,
                        room: r.room,
                        decision: r.decision,
                        requested: r.requested,
                    })
                    .collect()),
                other => Err(unexpected("Consent/get", &other)),
            },
        }
    }

    /// Creates the any-room Consent record from `requester` to `target`,
    /// with `decision` when the user is the target (Consent/set create).
    pub async fn create_consent(
        &self,
        requester: &str,
        target: &str,
        decision: Option<&str>,
    ) -> Result<(), AgentError> {
        match self {
            Self::Jmap(j) => {
                let mut record = json!({"requesterUri": requester, "targetUri": target});
                if let Some(decision) = decision {
                    record["decision"] = json!(decision);
                }
                j.consent_set(json!({"create": {"c": record}})).await
            }
            Self::Stream(s) => {
                let op = Op::CreateConsent {
                    requester_uri: requester.to_owned(),
                    target_uri: target.to_owned(),
                    room: None,
                    requested: None,
                    decision: decision.map(str::to_owned),
                };
                s.stream.ok("Consent/set", op).await.map(drop)
            }
        }
    }

    /// Changes `requested` or `decision` of the Consent record `id`
    /// (Consent/set update).
    pub async fn update_consent(
        &self,
        id: &str,
        requested: Option<bool>,
        decision: Option<&str>,
    ) -> Result<(), AgentError> {
        match self {
            Self::Jmap(j) => {
                let mut patch = json!({});
                if let Some(requested) = requested {
                    patch["requested"] = json!(requested);
                }
                if let Some(decision) = decision {
                    patch["decision"] = json!(decision);
                }
                j.consent_set(json!({"update": {id: patch}})).await
            }
            Self::Stream(s) => {
                let op = Op::UpdateConsent {
                    consent_id: id.to_owned(),
                    requested,
                    decision: decision.map(|d| Some(d.to_owned())),
                };
                s.stream.ok("Consent/set", op).await.map(drop)
            }
        }
    }

    /// See [`Jmap::publish_key_package`]: the KeyPackage's id, the
    /// unpadded base64url of its KeyPackageRef.
    pub async fn publish_key_package(&self, key_package: &[u8]) -> Result<String, AgentError> {
        match self {
            Self::Jmap(j) => j.publish_key_package(key_package).await,
            Self::Stream(s) => {
                let op = Op::PublishKeyPackage {
                    key_package: key_package.to_vec(),
                    last_resort: None,
                };
                match s.stream.ok("KeyPackage/set", op).await? {
                    AckResult::PublishKeyPackage {
                        key_package_ref, ..
                    } => Ok(URL_SAFE_NO_PAD.encode(key_package_ref)),
                    other => Err(unexpected("KeyPackage/set", &other)),
                }
            }
        }
    }

    /// See [`Jmap::key_package_changes`]. The stream has no
    /// `KeyPackage/changes`: its `Changed` `KeyPackage` is followed by
    /// `ListKeyPackages` ([`Provider::key_package_ids`]), so this is
    /// `None` there.
    pub async fn key_package_changes(
        &self,
        since: &str,
    ) -> Result<Option<(Vec<String>, String)>, AgentError> {
        match self {
            Self::Jmap(j) => j.key_package_changes(since).await,
            Self::Stream(_) => Ok(None),
        }
    }

    /// See [`Jmap::clients`].
    pub async fn clients(&self) -> Result<Vec<(String, Vec<u8>)>, AgentError> {
        const WHAT: &str = "Client/get";
        match self {
            Self::Jmap(j) => j.clients().await,
            Self::Stream(s) => match s.stream.ok(WHAT, Op::ListClients).await? {
                AckResult::ListClients { clients, .. } => clients
                    .into_iter()
                    .map(|c| {
                        Ok((
                            c.client_id,
                            crate::client::signature_key_octets(WHAT, &c.signature_key)?,
                        ))
                    })
                    .collect(),
                other => Err(unexpected(WHAT, &other)),
            },
        }
    }

    /// See [`Jmap::destroy_client`].
    pub async fn destroy_client(&self, id: &str) -> Result<(), AgentError> {
        match self {
            Self::Jmap(j) => j.destroy_client(id).await,
            Self::Stream(s) => {
                let op = Op::DestroyClient {
                    client_id: id.to_owned(),
                };
                s.stream.ok("Client/set", op).await.map(drop)
            }
        }
    }

    /// See [`Jmap::key_package_ids`].
    pub async fn key_package_ids(&self) -> Result<(String, Vec<String>), AgentError> {
        match self {
            Self::Jmap(j) => j.key_package_ids().await,
            Self::Stream(s) => match s.stream.ok("KeyPackage/get", Op::ListKeyPackages).await? {
                AckResult::ListKeyPackages {
                    state,
                    key_packages,
                } => Ok((
                    state,
                    key_packages
                        .iter()
                        .map(|k| URL_SAFE_NO_PAD.encode(&k.key_package_ref))
                        .collect(),
                )),
                other => Err(unexpected("KeyPackage/get", &other)),
            },
        }
    }

    /// See [`Jmap::create_room`].
    pub async fn create_room(
        &self,
        room_id: &str,
        group_info: &[u8],
        tree: &[u8],
    ) -> Result<String, AgentError> {
        match self {
            Self::Jmap(j) => j.create_room(room_id, group_info, tree).await,
            Self::Stream(s) => {
                let op = Op::CreateRoom {
                    room: room_id.to_owned(),
                    group_info: group_info.to_vec(),
                    ratchet_tree: tree.to_vec(),
                };
                s.stream.ok("Room/create", op).await?;
                Ok(room_id.to_owned())
            }
        }
    }

    /// [`Provider::chats`], one per room, by room: of a room's Chats, one
    /// whose room is recorded as accepted if there is one.
    pub async fn own_chats(&self) -> Result<Vec<OwnChat>, AgentError> {
        let mut chats = self.chats().await?;
        chats.sort_by(|a, b| a.room.cmp(&b.room).then(b.accepted.cmp(&a.accepted)));
        chats.dedup_by(|later, first| later.room == first.room);
        Ok(chats)
    }

    /// See [`Jmap::chats`].
    pub async fn chats(&self) -> Result<Vec<OwnChat>, AgentError> {
        match self {
            Self::Jmap(j) => j.chats().await,
            Self::Stream(s) => match s.stream.ok("Chat/get", Op::ListChats).await? {
                AckResult::ListChats { chats, .. } => Ok(chats
                    .into_iter()
                    .map(|chat| OwnChat {
                        id: chat.chat_id,
                        room: chat.room,
                        accepted: chat.accepted,
                    })
                    .collect()),
                other => Err(unexpected("Chat/get", &other)),
            },
        }
    }

    /// See [`Jmap::set_accepted`].
    pub async fn set_accepted(&self, chat_id: &str, accepted: bool) -> Result<(), AgentError> {
        match self {
            Self::Jmap(j) => j.set_accepted(chat_id, accepted).await,
            Self::Stream(s) => {
                let op = Op::SetChatAccepted {
                    chat_id: chat_id.to_owned(),
                    accepted,
                };
                s.stream.ok("Chat/set", op).await.map(drop)
            }
        }
    }

    /// See [`Jmap::group_info`].
    pub async fn group_info(&self, room: &str, request: &[u8]) -> Result<Vec<u8>, AgentError> {
        match self {
            Self::Jmap(j) => j.group_info(room, request).await,
            Self::Stream(s) => {
                let op = Op::FetchGroupInfo {
                    room: room.to_owned(),
                    request: request.to_vec(),
                };
                match s.stream.ok("GroupInfo/fetch", op).await? {
                    AckResult::FetchGroupInfo { response, .. } => Ok(response),
                    other => Err(unexpected("GroupInfo/fetch", &other)),
                }
            }
        }
    }

    /// See [`Jmap::key_material`].
    pub async fn key_material(&self, request: &[u8]) -> Result<KeyMaterialResponse, AgentError> {
        match self {
            Self::Jmap(j) => j.key_material(request).await,
            Self::Stream(s) => {
                const WHAT: &str = "KeyMaterial/fetch";
                let decoded = mimi_protocol::KeyMaterialRequest::tls_deserialize_exact(request)
                    .map_err(|e| AgentError::tls("own KeyMaterialRequest", e))?;
                let op = Op::FetchKeyMaterial {
                    room: decoded.tbs().room_id.as_str().to_owned(),
                    request: request.to_vec(),
                };
                match s.stream.ok(WHAT, op).await? {
                    // The response as the hub sent it (findings log F5).
                    AckResult::FetchKeyMaterial { response } => {
                        KeyMaterialResponse::tls_deserialize_exact(&response[..])
                            .map_err(|e| malformed(WHAT, format!("{e:?}")))
                    }
                    other => Err(unexpected(WHAT, &other)),
                }
            }
        }
    }

    /// See [`Jmap::messages_since`].
    pub async fn messages_since(
        &self,
        since: Option<&str>,
        after: &std::collections::BTreeMap<String, String>,
    ) -> Result<(String, Vec<Fetched>), AgentError> {
        match self {
            Self::Jmap(j) => j.messages_since(since, after).await,
            Self::Stream(s) => s.stream.messages_since(since, after).await,
        }
    }

    /// See [`Jmap::update`].
    pub async fn update(
        &self,
        room: &str,
        request: &UpdateRequest,
    ) -> Result<(UpdateRoomResponse, Vec<String>), AgentError> {
        let s = match self {
            Self::Jmap(j) => return j.update(room, request).await,
            Self::Stream(s) => s,
        };
        const WHAT: &str = "Room/update";
        let bytes = request
            .tls_serialize_detached()
            .map_err(|e| AgentError::tls("own UpdateRequest", e))?;
        let op = Op::Update {
            room: room.to_owned(),
            request: bytes,
        };
        let description = |text: Option<String>| {
            Utf8String::new(text.unwrap_or_default())
                .map_err(|e| malformed(WHAT, format!("errorDescription: {e:?}")))
        };
        let mut ids = Vec::new();
        let (result, text) = match s.stream.call(WHAT, op).await? {
            Ok(AckResult::Update {
                accepted_at,
                error_description,
                message_ids,
            }) => {
                ids = message_ids.unwrap_or_default();
                (
                    UpdateResult::Success {
                        accepted_timestamp: accepted_at,
                    },
                    error_description,
                )
            }
            Ok(other) => return Err(unexpected(WHAT, &other)),
            Err(error) => {
                let result = match error.code.as_str() {
                    code::WRONG_EPOCH => UpdateResult::WrongEpoch {
                        current_epoch: error.current_epoch.unwrap_or(0),
                    },
                    code::NOT_ALLOWED => UpdateResult::NotAllowed,
                    code::INVALID_PROPOSAL => UpdateResult::InvalidProposal {
                        invalid_proposals: error
                            .invalid_proposals
                            .iter()
                            .flatten()
                            .filter_map(|b| ProposalRef::tls_deserialize_exact(&b[..]).ok())
                            .collect(),
                    },
                    _ => return Err(method_error(WHAT, &error)),
                };
                (result, error.error_description)
            }
        };
        Ok((
            UpdateRoomResponse {
                error_description: description(text)?,
                result,
            },
            ids,
        ))
    }

    /// See [`Jmap::report_abuse`].
    pub async fn report_abuse(
        &self,
        room: &str,
        report: &[u8],
    ) -> Result<ReportOutcome, AgentError> {
        let s = match self {
            Self::Jmap(j) => return j.report_abuse(room, report).await,
            Self::Stream(s) => s,
        };
        const WHAT: &str = "Room/reportAbuse";
        let op = Op::ReportAbuse {
            room: room.to_owned(),
            report: report.to_vec(),
        };
        match s.stream.call(WHAT, op).await? {
            Ok(_) => Ok(ReportOutcome::Accepted),
            Err(error) => match error.code.as_str() {
                code::NOT_ALLOWED => Ok(ReportOutcome::NotAllowed),
                code::UNVERIFIED_MESSAGE => Ok(ReportOutcome::UnverifiedMessage),
                // findings log F8: `status` is optional.
                code::REFUSED => Ok(ReportOutcome::Refused {
                    status: error.status.and_then(|status| u16::try_from(status).ok()),
                }),
                _ => Err(method_error(WHAT, &error)),
            },
        }
    }

    /// See [`Jmap::send`].
    pub async fn send(
        &self,
        room: &str,
        message: &mimi_mls::wire::MLSMessage,
        silent: bool,
    ) -> Result<Accepted, AgentError> {
        let s = match self {
            Self::Jmap(j) => return j.send(room, message, silent).await,
            Self::Stream(s) => s,
        };
        const WHAT: &str = "Room/send";
        let bytes = message
            .tls_serialize_detached()
            .map_err(|e| AgentError::tls("own message", e))?;
        let op = Op::Send {
            room: room.to_owned(),
            message: bytes,
            silent: silent.then_some(true),
        };
        match s.stream.call(WHAT, op).await? {
            Ok(AckResult::Send {
                accepted_at,
                message_ids,
                ..
            }) => Ok(Accepted {
                accepted_at,
                message_ids: message_ids.unwrap_or_default(),
            }),
            Ok(other) => Err(unexpected(WHAT, &other)),
            // As Jmap::send: the hub's refusal is Refused, named by its
            // responseCode.
            Err(error) if error.code == code::NOT_ALLOWED || error.code == code::EPOCH_TOO_OLD => {
                Err(AgentError::Refused {
                    what: WHAT.to_owned(),
                    reason: error.code,
                })
            }
            Err(error) => Err(method_error(WHAT, &error)),
        }
    }
}
