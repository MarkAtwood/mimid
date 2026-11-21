//! The messages of version 1 (docs/design/binary-live-stream.md §5.11,
//! whose CDDL each type mirrors; decision mimid-1wgh.77).

use std::collections::BTreeMap;

use crate::cbor::{self, Value};
use crate::fields::{Extra, Fields, Writer, as_bytes, as_text, as_uint};
use crate::{DecodeError, FrameError, VERSION};

/// A message from the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClientMessage {
    /// The first message of a connection.
    Hello(ClientHello),
    /// Any later one.
    Request(Request),
}

/// `ClientHello`.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientHello {
    /// The stream versions the client supports.
    pub versions: Vec<u64>,
    /// The bearer token (decision mimid-1wgh.73).
    pub token: String,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

impl std::fmt::Debug for ClientHello {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientHello")
            .field("versions", &self.versions)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

/// A client request: `id` and one operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// `v`.
    pub v: u64,
    /// `id`, unique among the client's outstanding requests.
    pub id: u64,
    /// What is asked.
    pub op: Op,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// The operation of a [`Request`], one per message type.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Op {
    /// `Subscribe`: Message/changes and Message/get from `since`, then live.
    Subscribe {
        /// A Message state; `None` for every stored Message.
        since: Option<String>,
        /// Without `since`: per Chat id, the id of the last Message the
        /// client handled in that Chat, so that only the Messages after
        /// it are replayed for that Chat (findings log F12, the stream's
        /// `Message/query` sorted by `id` with an `anchor`). A Chat not
        /// named is replayed whole.
        after: Option<BTreeMap<String, String>>,
    },
    /// `Send`: Room/send.
    Send {
        /// The room ID.
        room: String,
        /// The MLSMessage.
        message: Vec<u8>,
        /// `silent`: the provider may skip push notifications for the
        /// Messages it stores for it (draft-atwood-jmap-chat-mimi-00
        /// §Room/send); `None` is `false`.
        silent: Option<bool>,
    },
    /// `Update`: Room/update.
    Update {
        /// The room ID.
        room: String,
        /// The UpdateRequest.
        request: Vec<u8>,
    },
    /// `CreateRoom`: Room/create.
    CreateRoom {
        /// The room ID.
        room: String,
        /// The MLSMessage carrying the GroupInfo.
        group_info: Vec<u8>,
        /// The ratchet tree.
        ratchet_tree: Vec<u8>,
    },
    /// `Unbind`: Room/unbind.
    Unbind {
        /// The room ID.
        room: String,
    },
    /// `ReportAbuse`: Room/reportAbuse.
    ReportAbuse {
        /// The room ID.
        room: String,
        /// The AbuseReport.
        report: Vec<u8>,
    },
    /// `FetchGroupInfo`: GroupInfo/fetch.
    FetchGroupInfo {
        /// The room ID.
        room: String,
        /// The GroupInfoRequest.
        request: Vec<u8>,
    },
    /// `FetchKeyMaterial`: KeyMaterial/fetch.
    FetchKeyMaterial {
        /// The room ID.
        room: String,
        /// The KeyMaterialRequest.
        request: Vec<u8>,
    },
    /// `PublishKeyPackage`: KeyPackage/set create.
    PublishKeyPackage {
        /// The KeyPackage.
        key_package: Vec<u8>,
        /// `lastResort`, if the client states it.
        last_resort: Option<bool>,
    },
    /// `ListKeyPackages`: KeyPackage/get.
    ListKeyPackages,
    /// `DestroyKeyPackage`: KeyPackage/set destroy.
    DestroyKeyPackage {
        /// The KeyPackageRef, as its TLS encoding.
        key_package_ref: Vec<u8>,
    },
    /// `ListConsent`: Consent/get.
    ListConsent,
    /// `CreateConsent`: Consent/set create.
    CreateConsent {
        /// `requesterUri`.
        requester_uri: String,
        /// `targetUri`.
        target_uri: String,
        /// The room the scope is limited to.
        room: Option<String>,
        /// `requested`, if given.
        requested: Option<bool>,
        /// `decision`, if given: `grant` or `revoke`.
        decision: Option<String>,
    },
    /// `UpdateConsent`: Consent/set update.
    UpdateConsent {
        /// The record.
        consent_id: String,
        /// A new `requested`.
        requested: Option<bool>,
        /// A new `decision`: `Some(None)` is `null`.
        decision: Option<Option<String>>,
    },
    /// `DestroyConsent`: Consent/set destroy.
    DestroyConsent {
        /// The record.
        consent_id: String,
    },
    /// `ListChats`: Chat/get of `roomId` and the accepted record.
    ListChats,
    /// `SetChatAccepted`: Chat/set of the accepted record (decision
    /// mimid-1wgh.63).
    SetChatAccepted {
        /// The Chat.
        chat_id: String,
        /// Whether the user accepted the room.
        accepted: bool,
    },
    /// `Upload`: a blob upload (RFC 8620 §6.1).
    Upload {
        /// The blob.
        data: Vec<u8>,
        /// Its media type, if given.
        media_type: Option<String>,
    },
    /// `FetchAsset`: a fetch at `assetDownloadUrl`.
    FetchAsset {
        /// The room the message came from.
        room: String,
        /// The attachment's URL.
        url: String,
    },
}

/// The kind of an [`Op`], which decides the shape of its [`Ack`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[allow(missing_docs, reason = "each is the Op of the same name")]
pub enum OpKind {
    Subscribe,
    Send,
    Update,
    CreateRoom,
    Unbind,
    ReportAbuse,
    FetchGroupInfo,
    FetchKeyMaterial,
    PublishKeyPackage,
    ListKeyPackages,
    DestroyKeyPackage,
    ListConsent,
    CreateConsent,
    UpdateConsent,
    DestroyConsent,
    ListChats,
    SetChatAccepted,
    Upload,
    FetchAsset,
}

impl OpKind {
    const ALL: [Self; 19] = [
        Self::Subscribe,
        Self::Send,
        Self::Update,
        Self::CreateRoom,
        Self::Unbind,
        Self::ReportAbuse,
        Self::FetchGroupInfo,
        Self::FetchKeyMaterial,
        Self::PublishKeyPackage,
        Self::ListKeyPackages,
        Self::DestroyKeyPackage,
        Self::ListConsent,
        Self::CreateConsent,
        Self::UpdateConsent,
        Self::DestroyConsent,
        Self::ListChats,
        Self::SetChatAccepted,
        Self::Upload,
        Self::FetchAsset,
    ];

    /// The message's `t`.
    pub fn name(self) -> &'static str {
        match self {
            Self::Subscribe => "Subscribe",
            Self::Send => "Send",
            Self::Update => "Update",
            Self::CreateRoom => "CreateRoom",
            Self::Unbind => "Unbind",
            Self::ReportAbuse => "ReportAbuse",
            Self::FetchGroupInfo => "FetchGroupInfo",
            Self::FetchKeyMaterial => "FetchKeyMaterial",
            Self::PublishKeyPackage => "PublishKeyPackage",
            Self::ListKeyPackages => "ListKeyPackages",
            Self::DestroyKeyPackage => "DestroyKeyPackage",
            Self::ListConsent => "ListConsent",
            Self::CreateConsent => "CreateConsent",
            Self::UpdateConsent => "UpdateConsent",
            Self::DestroyConsent => "DestroyConsent",
            Self::ListChats => "ListChats",
            Self::SetChatAccepted => "SetChatAccepted",
            Self::Upload => "Upload",
            Self::FetchAsset => "FetchAsset",
        }
    }

    fn of(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|kind| kind.name() == name)
    }

    /// Whether requests of this kind may be up to
    /// [`MAX_MESSAGE_BYTES`](crate::MAX_MESSAGE_BYTES) rather than
    /// [`MAX_REQUEST_BYTES`](crate::MAX_REQUEST_BYTES).
    pub fn is_upload(self) -> bool {
        self == Self::Upload
    }
}

impl Op {
    /// This operation's kind.
    pub fn kind(&self) -> OpKind {
        match self {
            Self::Subscribe { .. } => OpKind::Subscribe,
            Self::Send { .. } => OpKind::Send,
            Self::Update { .. } => OpKind::Update,
            Self::CreateRoom { .. } => OpKind::CreateRoom,
            Self::Unbind { .. } => OpKind::Unbind,
            Self::ReportAbuse { .. } => OpKind::ReportAbuse,
            Self::FetchGroupInfo { .. } => OpKind::FetchGroupInfo,
            Self::FetchKeyMaterial { .. } => OpKind::FetchKeyMaterial,
            Self::PublishKeyPackage { .. } => OpKind::PublishKeyPackage,
            Self::ListKeyPackages => OpKind::ListKeyPackages,
            Self::DestroyKeyPackage { .. } => OpKind::DestroyKeyPackage,
            Self::ListConsent => OpKind::ListConsent,
            Self::CreateConsent { .. } => OpKind::CreateConsent,
            Self::UpdateConsent { .. } => OpKind::UpdateConsent,
            Self::DestroyConsent { .. } => OpKind::DestroyConsent,
            Self::ListChats => OpKind::ListChats,
            Self::SetChatAccepted { .. } => OpKind::SetChatAccepted,
            Self::Upload { .. } => OpKind::Upload,
            Self::FetchAsset { .. } => OpKind::FetchAsset,
        }
    }

    fn read(kind: OpKind, f: &mut Fields) -> Result<Self, DecodeError> {
        Ok(match kind {
            OpKind::Subscribe => Self::Subscribe {
                since: f.opt_text("since")?,
                after: f.opt_value("after").map(text_map).transpose()?,
            },
            OpKind::Send => Self::Send {
                room: f.text("room")?,
                message: f.bytes("message")?,
                silent: f.opt_bool("silent")?,
            },
            OpKind::Update => Self::Update {
                room: f.text("room")?,
                request: f.bytes("request")?,
            },
            OpKind::CreateRoom => Self::CreateRoom {
                room: f.text("room")?,
                group_info: f.bytes("groupInfo")?,
                ratchet_tree: f.bytes("ratchetTree")?,
            },
            OpKind::Unbind => Self::Unbind {
                room: f.text("room")?,
            },
            OpKind::ReportAbuse => Self::ReportAbuse {
                room: f.text("room")?,
                report: f.bytes("report")?,
            },
            OpKind::FetchGroupInfo => Self::FetchGroupInfo {
                room: f.text("room")?,
                request: f.bytes("request")?,
            },
            OpKind::FetchKeyMaterial => Self::FetchKeyMaterial {
                room: f.text("room")?,
                request: f.bytes("request")?,
            },
            OpKind::PublishKeyPackage => Self::PublishKeyPackage {
                key_package: f.bytes("keyPackage")?,
                last_resort: f.opt_bool("lastResort")?,
            },
            OpKind::ListKeyPackages => Self::ListKeyPackages,
            OpKind::DestroyKeyPackage => Self::DestroyKeyPackage {
                key_package_ref: f.bytes("keyPackageRef")?,
            },
            OpKind::ListConsent => Self::ListConsent,
            OpKind::CreateConsent => Self::CreateConsent {
                requester_uri: f.text("requesterUri")?,
                target_uri: f.text("targetUri")?,
                room: f.opt_text("room")?,
                requested: f.opt_bool("requested")?,
                decision: f.opt_text("decision")?,
            },
            OpKind::UpdateConsent => Self::UpdateConsent {
                consent_id: f.text("consentId")?,
                requested: f.opt_bool("requested")?,
                decision: f.opt_text_or_null("decision")?,
            },
            OpKind::DestroyConsent => Self::DestroyConsent {
                consent_id: f.text("consentId")?,
            },
            OpKind::ListChats => Self::ListChats,
            OpKind::SetChatAccepted => Self::SetChatAccepted {
                chat_id: f.text("chatId")?,
                accepted: f.bool("accepted")?,
            },
            OpKind::Upload => Self::Upload {
                data: f.bytes("data")?,
                media_type: f.opt_text("type")?,
            },
            OpKind::FetchAsset => Self::FetchAsset {
                room: f.text("room")?,
                url: f.text("url")?,
            },
        })
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Self::Subscribe { since, after } => {
                w.opt_text("since", since.as_deref());
                if let Some(after) = after {
                    w.put(
                        "after",
                        Value::Map(
                            after
                                .iter()
                                .map(|(k, v)| (Value::Text(k.clone()), Value::Text(v.clone())))
                                .collect(),
                        ),
                    );
                }
            }
            Self::Send {
                room,
                message,
                silent,
            } => {
                w.text("room", room)
                    .bytes("message", message)
                    .opt_bool("silent", *silent);
            }
            Self::Update { room, request }
            | Self::FetchGroupInfo { room, request }
            | Self::FetchKeyMaterial { room, request } => {
                w.text("room", room).bytes("request", request);
            }
            Self::CreateRoom {
                room,
                group_info,
                ratchet_tree,
            } => {
                w.text("room", room)
                    .bytes("groupInfo", group_info)
                    .bytes("ratchetTree", ratchet_tree);
            }
            Self::Unbind { room } => {
                w.text("room", room);
            }
            Self::ReportAbuse { room, report } => {
                w.text("room", room).bytes("report", report);
            }
            Self::PublishKeyPackage {
                key_package,
                last_resort,
            } => {
                w.bytes("keyPackage", key_package)
                    .opt_bool("lastResort", *last_resort);
            }
            Self::ListKeyPackages | Self::ListConsent | Self::ListChats => {}
            Self::DestroyKeyPackage { key_package_ref } => {
                w.bytes("keyPackageRef", key_package_ref);
            }
            Self::CreateConsent {
                requester_uri,
                target_uri,
                room,
                requested,
                decision,
            } => {
                w.text("requesterUri", requester_uri)
                    .text("targetUri", target_uri)
                    .opt_text("room", room.as_deref())
                    .opt_bool("requested", *requested)
                    .opt_text("decision", decision.as_deref());
            }
            Self::UpdateConsent {
                consent_id,
                requested,
                decision,
            } => {
                w.text("consentId", consent_id)
                    .opt_bool("requested", *requested);
                if let Some(decision) = decision {
                    w.text_or_null("decision", decision.as_deref());
                }
            }
            Self::DestroyConsent { consent_id } => {
                w.text("consentId", consent_id);
            }
            Self::SetChatAccepted { chat_id, accepted } => {
                w.text("chatId", chat_id).bool("accepted", *accepted);
            }
            Self::Upload { data, media_type } => {
                w.bytes("data", data)
                    .opt_text("type", media_type.as_deref());
            }
            Self::FetchAsset { room, url } => {
                w.text("room", room).text("url", url);
            }
        }
    }
}

/// Reads `v` and `t` of a message map, checking `v`.
fn envelope(f: &mut Fields) -> Result<(u64, String), DecodeError> {
    let v = f.uint("v")?;
    let t = f.text("t")?;
    Ok((v, t))
}

/// The hello messages keep their v1 form in every version (Agora §11.6).
fn check_hello_version(v: u64) -> Result<(), DecodeError> {
    if v == 1 {
        Ok(())
    } else {
        Err(DecodeError::UnknownVersion(v))
    }
}

fn check_version(v: u64) -> Result<(), DecodeError> {
    if v == VERSION {
        Ok(())
    } else {
        Err(DecodeError::UnknownVersion(v))
    }
}

fn frame(bytes: &[u8]) -> Result<Fields, FrameError> {
    let value = cbor::decode(bytes).map_err(|e| FrameError::new(None, DecodeError::Cbor(e)))?;
    Fields::of(value).map_err(|e| FrameError::new(None, e))
}

fn head(w: &mut Writer, v: u64, t: &str) {
    w.uint("v", v).text("t", t);
}

impl ClientMessage {
    /// Decodes one client frame.
    ///
    /// # Errors
    ///
    /// A [`FrameError`], with the request's `id` once it is known.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let mut f = frame(bytes)?;
        let (v, t) = envelope(&mut f).map_err(|e| FrameError::new(None, e))?;
        if t == "ClientHello" {
            let hello = (|| {
                check_hello_version(v)?;
                let versions = f
                    .array("versions")?
                    .into_iter()
                    .map(|v| as_uint("versions", v))
                    .collect::<Result<Vec<_>, _>>()?;
                if versions.is_empty() {
                    return Err(DecodeError::Invalid("versions is empty"));
                }
                Ok(ClientHello {
                    versions,
                    token: f.text("token")?,
                    extra: Vec::new(),
                })
            })()
            .map_err(|e| FrameError::new(None, e))?;
            return Ok(Self::Hello(ClientHello {
                extra: f.rest(),
                ..hello
            }));
        }
        check_version(v).map_err(|e| FrameError::new(None, e))?;
        let id = f.uint("id").map_err(|e| FrameError::new(None, e))?;
        let fail = |e| FrameError::new(Some(id), e);
        let kind = OpKind::of(&t).ok_or_else(|| fail(DecodeError::UnknownType(t.clone())))?;
        let op = Op::read(kind, &mut f).map_err(fail)?;
        Ok(Self::Request(Request {
            v,
            id,
            op,
            extra: f.rest(),
        }))
    }

    /// The frame's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        let value = match self {
            Self::Hello(hello) => {
                head(&mut w, 1, "ClientHello");
                w.put(
                    "versions",
                    Value::Array(hello.versions.iter().map(|v| Value::Uint(*v)).collect()),
                )
                .text("token", &hello.token);
                w.finish(&hello.extra)
            }
            Self::Request(request) => {
                head(&mut w, request.v, request.op.kind().name());
                w.uint("id", request.id);
                request.op.write(&mut w);
                w.finish(&request.extra)
            }
        };
        cbor::encode(&value)
    }
}

/// A message from the provider.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderMessage {
    /// `ProviderHello`.
    Hello(ProviderHello),
    /// `Ack`.
    Ack(Ack),
    /// `Error`.
    Error(ErrorMessage),
    /// `Deliver`.
    Deliver(Deliver),
    /// `Position`.
    Position(Position),
    /// `Changed`.
    Changed(Changed),
}

/// `ProviderHello`: what the mimi capability of the JMAP Session says
/// (draft-atwood-jmap-chat-mimi-00 §capability), and the limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderHello {
    /// The negotiated version.
    pub version: u64,
    /// `userUri`.
    pub user_uri: String,
    /// `roomIdPrefix`.
    pub room_id_prefix: String,
    /// `hubSender`, the ExternalSender as its TLS encoding.
    pub hub_sender: Vec<u8>,
    /// `cipherSuites`.
    pub cipher_suites: Vec<u64>,
    /// `maxKeyPackages`.
    pub max_key_packages: u64,
    /// The largest frame either side sends.
    pub max_message_bytes: u64,
    /// The largest request but `Upload`.
    pub max_request_bytes: u64,
    /// `maxMlsObjectSize`: the largest MLS or MIMI structure any request
    /// carries (findings log F10), the account capability's.
    pub max_mls_object_size: Option<u64>,
    /// Whether `Upload` stores blobs at an unauthenticated URL (`assetUrl`).
    pub stores_assets: bool,
    /// `assetLifetime`, seconds.
    pub asset_lifetime: Option<u64>,
    /// `messageRetention`, seconds: how long the provider keeps a stored
    /// Message; `None` if it states no limit
    /// (draft-atwood-jmap-chat-mimi-00 §capability; decision
    /// mimid-1wgh.82).
    pub message_retention: Option<u64>,
    /// Whether `FetchAsset` works (`assetDownloadUrl`).
    pub fetches_assets: bool,
    /// Whether `SetChatAccepted` works (decision mimid-1wgh.63).
    pub accepted_rooms: bool,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// `Ack`: the request `id` was done.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ack {
    /// `v`.
    pub v: u64,
    /// The request's `id`.
    pub id: u64,
    /// What it returned.
    pub result: AckResult,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// What a request returned, by its [`OpKind`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AckResult {
    /// `Subscribe`: the state after the replay.
    Subscribe {
        /// `state`.
        state: String,
    },
    /// `Send`.
    Send {
        /// `acceptedAt`, ms.
        accepted_at: u64,
        /// The hub's Frank, TLS-encoded.
        frank: Option<Vec<u8>>,
        /// `messageIds`: the Messages stored for it in the account
        /// (findings log F18).
        message_ids: Option<Vec<String>>,
    },
    /// `Update`.
    Update {
        /// `acceptedAt`, ms.
        accepted_at: u64,
        /// The hub's `errorDescription`, when not empty.
        error_description: Option<String>,
        /// `messageIds`: the Messages stored for the handshake in the
        /// account (findings log F18).
        message_ids: Option<Vec<String>>,
    },
    /// `CreateRoom`.
    CreateRoom {
        /// The new Chat.
        chat_id: String,
    },
    /// `Unbind`, `ReportAbuse`, `DestroyKeyPackage`, `UpdateConsent`,
    /// `DestroyConsent`, `SetChatAccepted`: nothing.
    Done,
    /// `FetchGroupInfo`.
    FetchGroupInfo {
        /// The GroupInfoResponse status name.
        status: String,
        /// The whole GroupInfoResponse.
        response: Vec<u8>,
    },
    /// `FetchKeyMaterial`.
    FetchKeyMaterial {
        /// The whole KeyMaterialResponse.
        response: Vec<u8>,
    },
    /// `PublishKeyPackage`.
    PublishKeyPackage {
        /// The KeyPackageRef, TLS-encoded.
        key_package_ref: Vec<u8>,
        /// `lastResort` as the provider derived it.
        last_resort: bool,
    },
    /// `ListKeyPackages`.
    ListKeyPackages {
        /// The KeyPackage state.
        state: String,
        /// The records.
        key_packages: Vec<KeyPackageEntry>,
    },
    /// `ListConsent`.
    ListConsent {
        /// The Consent state.
        state: String,
        /// The records.
        records: Vec<ConsentEntry>,
    },
    /// `CreateConsent`.
    CreateConsent {
        /// The new record.
        record: ConsentEntry,
    },
    /// `ListChats`.
    ListChats {
        /// The Chat state.
        state: String,
        /// The Chats with a room.
        chats: Vec<ChatEntry>,
    },
    /// `Upload`.
    Upload {
        /// The blob's id.
        blob_id: String,
        /// Where other providers' clients fetch it (`assetUrl` filled in).
        url: String,
        /// Its size.
        size: u64,
    },
    /// `FetchAsset`.
    FetchAsset {
        /// The attachment as stored.
        data: Vec<u8>,
    },
}

/// One KeyPackage record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPackageEntry {
    /// `keyPackageRef`.
    pub key_package_ref: Vec<u8>,
    /// `keyPackage`.
    pub key_package: Vec<u8>,
    /// `lastResort`.
    pub last_resort: bool,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// One Consent record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentEntry {
    /// `consentId`.
    pub consent_id: String,
    /// `requesterUri`.
    pub requester_uri: String,
    /// `targetUri`.
    pub target_uri: String,
    /// `room`, or `None` for any room.
    pub room: Option<String>,
    /// `requested`.
    pub requested: bool,
    /// `decision`.
    pub decision: Option<String>,
    /// `updated`, ms.
    pub updated: u64,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// One Chat with a room.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChatEntry {
    /// `chatId`.
    pub chat_id: String,
    /// `room`.
    pub room: String,
    /// `bound` (findings log F4).
    pub bound: bool,
    /// `accepted` (decision mimid-1wgh.63).
    pub accepted: bool,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// `Error`: a request, or the connection, failed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ErrorMessage {
    /// `v`.
    pub v: u64,
    /// The request's `id`; `None` for the connection.
    pub id: Option<u64>,
    /// The code ([`crate::code`]).
    pub code: String,
    /// Diagnostic text, not for display.
    pub detail: Option<String>,
    /// The hub's current epoch, for `epochTooOld` and `wrongEpoch`.
    pub current_epoch: Option<u64>,
    /// The invalid ProposalRefs, TLS-encoded, for `invalidProposal`.
    pub invalid_proposals: Option<Vec<Vec<u8>>>,
    /// The hub's `errorDescription`, for a refused `Update`.
    pub error_description: Option<String>,
    /// The HTTP status of another provider's refusal, for `refused`.
    pub status: Option<u64>,
    /// The properties named, for `invalidProperties`.
    pub properties: Option<Vec<String>>,
    /// The existing record, for `alreadyExists`.
    pub existing_id: Option<String>,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

impl ErrorMessage {
    /// An error with `code` and nothing else.
    pub fn new(id: Option<u64>, code: &str) -> Self {
        Self {
            v: VERSION,
            id,
            code: code.to_owned(),
            ..Self::default()
        }
    }
}

/// `Deliver`: one stored Message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deliver {
    /// `v`.
    pub v: u64,
    /// The JMAP Message id.
    pub message_id: String,
    /// The Chat it is in.
    pub chat_id: String,
    /// The FanoutMessage as stored.
    pub fanout: Vec<u8>,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// `Position`: the Message state after the `Deliver`s before it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Position {
    /// `v`.
    pub v: u64,
    /// `state`.
    pub state: String,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

/// `Changed`: data types whose state moved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Changed {
    /// `v`.
    pub v: u64,
    /// `Chat`, `KeyPackage`, `Consent`.
    pub types: Vec<String>,
    /// Members the CDDL does not name.
    pub extra: Extra,
}

fn texts(key: &'static str, items: Vec<Value>) -> Result<Vec<String>, DecodeError> {
    items.into_iter().map(|v| as_text(key, v)).collect()
}

/// A map of text to text (`{ * tstr => tstr }`).
fn text_map(value: Value) -> Result<BTreeMap<String, String>, DecodeError> {
    let Value::Map(pairs) = value else {
        return Err(DecodeError::WrongType("after"));
    };
    pairs
        .into_iter()
        .map(|(k, v)| Ok((as_text("after", k)?, as_text("after", v)?)))
        .collect()
}

fn opt_texts(f: &mut Fields, key: &'static str) -> Result<Option<Vec<String>>, DecodeError> {
    f.opt_array(key)?.map(|items| texts(key, items)).transpose()
}

fn text_array(items: &[String]) -> Value {
    Value::Array(items.iter().map(|t| Value::Text(t.clone())).collect())
}

fn records<T>(
    key: &'static str,
    items: Vec<Value>,
    read: impl Fn(&mut Fields) -> Result<T, DecodeError>,
) -> Result<Vec<T>, DecodeError> {
    items
        .into_iter()
        .map(|item| {
            let mut f = Fields::of(item).map_err(|_| DecodeError::WrongType(key))?;
            read(&mut f)
        })
        .collect()
}

impl KeyPackageEntry {
    fn read(f: &mut Fields) -> Result<Self, DecodeError> {
        Ok(Self {
            key_package_ref: f.bytes("keyPackageRef")?,
            key_package: f.bytes("keyPackage")?,
            last_resort: f.bool("lastResort")?,
            extra: Vec::new(),
        })
    }

    fn value(&self) -> Value {
        Writer::default()
            .bytes("keyPackageRef", &self.key_package_ref)
            .bytes("keyPackage", &self.key_package)
            .bool("lastResort", self.last_resort)
            .finish(&self.extra)
    }
}

impl ConsentEntry {
    fn read(f: &mut Fields) -> Result<Self, DecodeError> {
        Ok(Self {
            consent_id: f.text("consentId")?,
            requester_uri: f.text("requesterUri")?,
            target_uri: f.text("targetUri")?,
            room: f.text_or_null("room")?,
            requested: f.bool("requested")?,
            decision: f.text_or_null("decision")?,
            updated: f.uint("updated")?,
            extra: Vec::new(),
        })
    }

    fn value(&self) -> Value {
        Writer::default()
            .text("consentId", &self.consent_id)
            .text("requesterUri", &self.requester_uri)
            .text("targetUri", &self.target_uri)
            .text_or_null("room", self.room.as_deref())
            .bool("requested", self.requested)
            .text_or_null("decision", self.decision.as_deref())
            .uint("updated", self.updated)
            .finish(&self.extra)
    }
}

impl ChatEntry {
    fn read(f: &mut Fields) -> Result<Self, DecodeError> {
        Ok(Self {
            chat_id: f.text("chatId")?,
            room: f.text("room")?,
            bound: f.bool("bound")?,
            accepted: f.bool("accepted")?,
            extra: Vec::new(),
        })
    }

    fn value(&self) -> Value {
        Writer::default()
            .text("chatId", &self.chat_id)
            .text("room", &self.room)
            .bool("bound", self.bound)
            .bool("accepted", self.accepted)
            .finish(&self.extra)
    }
}

/// Reads one nested record and keeps its unknown members.
fn with_rest<T>(
    read: impl Fn(&mut Fields) -> Result<T, DecodeError>,
    set: impl Fn(&mut T, Extra),
) -> impl Fn(&mut Fields) -> Result<T, DecodeError> {
    move |f| {
        let mut value = read(f)?;
        set(&mut value, f.take_rest());
        Ok(value)
    }
}

impl AckResult {
    fn read(kind: OpKind, f: &mut Fields) -> Result<Self, DecodeError> {
        let kp = with_rest(KeyPackageEntry::read, |r, e| r.extra = e);
        let consent = with_rest(ConsentEntry::read, |r, e| r.extra = e);
        let chat = with_rest(ChatEntry::read, |r, e| r.extra = e);
        Ok(match kind {
            OpKind::Subscribe => Self::Subscribe {
                state: f.text("state")?,
            },
            OpKind::Send => Self::Send {
                accepted_at: f.uint("acceptedAt")?,
                frank: f.opt_bytes("frank")?,
                message_ids: opt_texts(f, "messageIds")?,
            },
            OpKind::Update => Self::Update {
                accepted_at: f.uint("acceptedAt")?,
                error_description: f.opt_text("errorDescription")?,
                message_ids: opt_texts(f, "messageIds")?,
            },
            OpKind::CreateRoom => Self::CreateRoom {
                chat_id: f.text("chatId")?,
            },
            OpKind::Unbind
            | OpKind::ReportAbuse
            | OpKind::DestroyKeyPackage
            | OpKind::UpdateConsent
            | OpKind::DestroyConsent
            | OpKind::SetChatAccepted => Self::Done,
            OpKind::FetchGroupInfo => Self::FetchGroupInfo {
                status: f.text("status")?,
                response: f.bytes("response")?,
            },
            OpKind::FetchKeyMaterial => Self::FetchKeyMaterial {
                response: f.bytes("response")?,
            },
            OpKind::PublishKeyPackage => Self::PublishKeyPackage {
                key_package_ref: f.bytes("keyPackageRef")?,
                last_resort: f.bool("lastResort")?,
            },
            OpKind::ListKeyPackages => Self::ListKeyPackages {
                state: f.text("state")?,
                key_packages: records("keyPackages", f.array("keyPackages")?, kp)?,
            },
            OpKind::ListConsent => Self::ListConsent {
                state: f.text("state")?,
                records: records("records", f.array("records")?, consent)?,
            },
            OpKind::CreateConsent => {
                let mut record = records("record", vec![f.take_value("record")?], consent)?;
                Self::CreateConsent {
                    record: record.remove(0),
                }
            }
            OpKind::ListChats => Self::ListChats {
                state: f.text("state")?,
                chats: records("chats", f.array("chats")?, chat)?,
            },
            OpKind::Upload => Self::Upload {
                blob_id: f.text("blobId")?,
                url: f.text("url")?,
                size: f.uint("size")?,
            },
            OpKind::FetchAsset => Self::FetchAsset {
                data: f.bytes("data")?,
            },
        })
    }

    fn write(&self, w: &mut Writer) {
        match self {
            Self::Subscribe { state } => {
                w.text("state", state);
            }
            Self::Send {
                accepted_at,
                frank,
                message_ids,
            } => {
                w.uint("acceptedAt", *accepted_at)
                    .opt_bytes("frank", frank.as_deref());
                if let Some(ids) = message_ids {
                    w.put("messageIds", text_array(ids));
                }
            }
            Self::Update {
                accepted_at,
                error_description,
                message_ids,
            } => {
                w.uint("acceptedAt", *accepted_at)
                    .opt_text("errorDescription", error_description.as_deref());
                if let Some(ids) = message_ids {
                    w.put("messageIds", text_array(ids));
                }
            }
            Self::CreateRoom { chat_id } => {
                w.text("chatId", chat_id);
            }
            Self::Done => {}
            Self::FetchGroupInfo { status, response } => {
                w.text("status", status).bytes("response", response);
            }
            Self::FetchKeyMaterial { response } => {
                w.bytes("response", response);
            }
            Self::PublishKeyPackage {
                key_package_ref,
                last_resort,
            } => {
                w.bytes("keyPackageRef", key_package_ref)
                    .bool("lastResort", *last_resort);
            }
            Self::ListKeyPackages {
                state,
                key_packages,
            } => {
                w.text("state", state).put(
                    "keyPackages",
                    Value::Array(key_packages.iter().map(KeyPackageEntry::value).collect()),
                );
            }
            Self::ListConsent { state, records } => {
                w.text("state", state).put(
                    "records",
                    Value::Array(records.iter().map(ConsentEntry::value).collect()),
                );
            }
            Self::CreateConsent { record } => {
                w.put("record", record.value());
            }
            Self::ListChats { state, chats } => {
                w.text("state", state).put(
                    "chats",
                    Value::Array(chats.iter().map(ChatEntry::value).collect()),
                );
            }
            Self::Upload { blob_id, url, size } => {
                w.text("blobId", blob_id)
                    .text("url", url)
                    .uint("size", *size);
            }
            Self::FetchAsset { data } => {
                w.bytes("data", data);
            }
        }
    }
}

impl ProviderMessage {
    /// Decodes one provider frame. `kind_of` gives the kind of the
    /// outstanding request with an `id`, which decides an `Ack`'s shape.
    ///
    /// # Errors
    ///
    /// A [`FrameError`]; [`DecodeError::UnknownRequest`] for an `Ack` of
    /// no outstanding request.
    pub fn decode(
        bytes: &[u8],
        kind_of: impl Fn(u64) -> Option<OpKind>,
    ) -> Result<Self, FrameError> {
        let mut f = frame(bytes)?;
        let none = |e| FrameError::new(None, e);
        let (v, t) = envelope(&mut f).map_err(none)?;
        if t == "ProviderHello" {
            let mut hello = (|| {
                check_hello_version(v)?;
                Ok(ProviderHello {
                    version: f.uint("version")?,
                    user_uri: f.text("userUri")?,
                    room_id_prefix: f.text("roomIdPrefix")?,
                    hub_sender: f.bytes("hubSender")?,
                    cipher_suites: f
                        .array("cipherSuites")?
                        .into_iter()
                        .map(|v| as_uint("cipherSuites", v))
                        .collect::<Result<_, _>>()?,
                    max_key_packages: f.uint("maxKeyPackages")?,
                    max_message_bytes: f.uint("maxMessageBytes")?,
                    max_request_bytes: f.uint("maxRequestBytes")?,
                    max_mls_object_size: f.opt_uint("maxMlsObjectSize")?,
                    stores_assets: f.bool("storesAssets")?,
                    asset_lifetime: f.opt_uint("assetLifetime")?,
                    message_retention: f.opt_uint("messageRetention")?,
                    fetches_assets: f.bool("fetchesAssets")?,
                    accepted_rooms: f.bool("acceptedRooms")?,
                    extra: Vec::new(),
                })
            })()
            .map_err(none)?;
            hello.extra = f.rest();
            return Ok(Self::Hello(hello));
        }
        check_version(v).map_err(none)?;
        let message = match t.as_str() {
            "Ack" => {
                let id = f.uint("id").map_err(none)?;
                let fail = |e| FrameError::new(Some(id), e);
                let kind = kind_of(id).ok_or_else(|| fail(DecodeError::UnknownRequest(id)))?;
                let result = AckResult::read(kind, &mut f).map_err(fail)?;
                Self::Ack(Ack {
                    v,
                    id,
                    result,
                    extra: Vec::new(),
                })
            }
            "Error" => {
                let id = f.opt_uint("id").map_err(none)?;
                let fail = |e| FrameError::new(id, e);
                Self::Error(
                    (|| {
                        Ok(ErrorMessage {
                            v,
                            id,
                            code: f.text("code")?,
                            detail: f.opt_text("detail")?,
                            current_epoch: f.opt_uint("currentEpoch")?,
                            invalid_proposals: f
                                .opt_array("invalidProposals")?
                                .map(|items| {
                                    items
                                        .into_iter()
                                        .map(|v| as_bytes("invalidProposals", v))
                                        .collect::<Result<Vec<_>, _>>()
                                })
                                .transpose()?,
                            error_description: f.opt_text("errorDescription")?,
                            status: f.opt_uint("status")?,
                            properties: f
                                .opt_array("properties")?
                                .map(|items| texts("properties", items))
                                .transpose()?,
                            existing_id: f.opt_text("existingId")?,
                            extra: Vec::new(),
                        })
                    })()
                    .map_err(fail)?,
                )
            }
            "Deliver" => Self::Deliver(
                (|| {
                    Ok(Deliver {
                        v,
                        message_id: f.text("messageId")?,
                        chat_id: f.text("chatId")?,
                        fanout: f.bytes("fanout")?,
                        extra: Vec::new(),
                    })
                })()
                .map_err(none)?,
            ),
            "Position" => Self::Position(Position {
                v,
                state: f.text("state").map_err(none)?,
                extra: Vec::new(),
            }),
            "Changed" => Self::Changed(Changed {
                v,
                types: f
                    .array("types")
                    .and_then(|items| texts("types", items))
                    .map_err(none)?,
                extra: Vec::new(),
            }),
            _ => return Err(none(DecodeError::UnknownType(t))),
        };
        let extra = f.rest();
        Ok(match message {
            Self::Ack(m) => Self::Ack(Ack { extra, ..m }),
            Self::Error(m) => Self::Error(ErrorMessage { extra, ..m }),
            Self::Deliver(m) => Self::Deliver(Deliver { extra, ..m }),
            Self::Position(m) => Self::Position(Position { extra, ..m }),
            Self::Changed(m) => Self::Changed(Changed { extra, ..m }),
            Self::Hello(m) => Self::Hello(m),
        })
    }

    /// The frame's bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::default();
        let value = match self {
            Self::Hello(h) => {
                head(&mut w, 1, "ProviderHello");
                w.uint("version", h.version)
                    .text("userUri", &h.user_uri)
                    .text("roomIdPrefix", &h.room_id_prefix)
                    .bytes("hubSender", &h.hub_sender)
                    .put(
                        "cipherSuites",
                        Value::Array(h.cipher_suites.iter().map(|s| Value::Uint(*s)).collect()),
                    )
                    .uint("maxKeyPackages", h.max_key_packages)
                    .uint("maxMessageBytes", h.max_message_bytes)
                    .uint("maxRequestBytes", h.max_request_bytes)
                    .opt_uint("maxMlsObjectSize", h.max_mls_object_size)
                    .bool("storesAssets", h.stores_assets)
                    .opt_uint("assetLifetime", h.asset_lifetime)
                    .opt_uint("messageRetention", h.message_retention)
                    .bool("fetchesAssets", h.fetches_assets)
                    .bool("acceptedRooms", h.accepted_rooms);
                w.finish(&h.extra)
            }
            Self::Ack(a) => {
                head(&mut w, a.v, "Ack");
                w.uint("id", a.id);
                a.result.write(&mut w);
                w.finish(&a.extra)
            }
            Self::Error(e) => {
                head(&mut w, e.v, "Error");
                w.opt_uint("id", e.id)
                    .text("code", &e.code)
                    .opt_text("detail", e.detail.as_deref())
                    .opt_uint("currentEpoch", e.current_epoch);
                if let Some(refs) = &e.invalid_proposals {
                    w.put(
                        "invalidProposals",
                        Value::Array(refs.iter().map(|r| Value::Bytes(r.clone())).collect()),
                    );
                }
                w.opt_text("errorDescription", e.error_description.as_deref())
                    .opt_uint("status", e.status);
                if let Some(properties) = &e.properties {
                    w.put("properties", text_array(properties));
                }
                w.opt_text("existingId", e.existing_id.as_deref());
                w.finish(&e.extra)
            }
            Self::Deliver(d) => {
                head(&mut w, d.v, "Deliver");
                w.text("messageId", &d.message_id)
                    .text("chatId", &d.chat_id)
                    .bytes("fanout", &d.fanout);
                w.finish(&d.extra)
            }
            Self::Position(p) => {
                head(&mut w, p.v, "Position");
                w.text("state", &p.state);
                w.finish(&p.extra)
            }
            Self::Changed(c) => {
                head(&mut w, c.v, "Changed");
                w.put("types", text_array(&c.types));
                w.finish(&c.extra)
            }
        };
        cbor::encode(&value)
    }
}
