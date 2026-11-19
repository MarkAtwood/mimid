//! The JMAP transport to the user's mimid server
//! (draft-atwood-jmap-chat-mimi-00), reached with a bearer token.
//!
//! The account comes from the Session; the hub's external-sender identity
//! and the room ID prefix from its `urn:ietf:params:jmap:chat:mimi`
//! account capability. KeyMaterial/fetch is turned back into the
//! protocol-07 KeyMaterialResponse and Room/update into an
//! UpdateRoomResponse, so the engine reasons in protocol-07 terms.
//!
//! Receiving: [`Jmap::messages_since`] reads the Messages the server
//! stored, every one the first time and then by `Message/changes`. Each
//! body is a FanoutMessage (draft §application/mimi-fanout). The server also
//! stores this user's own handshakes and messages; [`Jmap::is_own`]
//! recognises those this agent sent, so they are skipped.

use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{Capabilities, KeyPackage, ProposalRef};
use mimi_protocol::{
    ClientKeyMaterial, FanoutEvent, FanoutMessage, HandshakeBundle, IdentifierUri,
    KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode, Protocol, UpdateRequest,
    UpdateResult, UpdateRoomResponse, Utf8String,
};
use serde_json::{Value, json};

use crate::AgentError;
use crate::agent::ReportOutcome;

const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];
const MIMI: &str = "urn:ietf:params:jmap:chat:mimi";

/// draft-ietf-jmap-metadata-05 §1.2.1.
const METADATA: &str = "urn:ietf:params:jmap:metadata";

/// The `privateMetadata` namespace in which a device records that the
/// user accepted a room (decision mimid-1wgh.63 item 5). INVENTED, NOT
/// FROM SPEC.
pub const ACCEPTED_NAMESPACE: &str = "mimid.reviewcommit.com";

/// How many sent-message digests are kept.
pub(crate) const MAX_SENT: usize = 1024;

/// The largest attachment fetched, in stored octets. INVENTED, NOT FROM
/// SPEC; mimid-server stores blobs up to 16 MiB.
pub const MAX_ASSET_LEN: usize = 16 * 1024 * 1024;

/// How long one JMAP request may take.
const TIMEOUT: Duration = Duration::from_secs(30);

/// The start of an error body kept in [`AgentError::Status`].
const MAX_ERROR_BODY: usize = 512;

/// A deterministic 64-bit digest of an MLSMessage's bytes: SipHash with
/// fixed keys, the same in every run. Enough to recognise one's own
/// messages among a room's.
fn digest(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    #[allow(deprecated, reason = "SipHasher's fixed keys are what is wanted")]
    let mut hasher = std::hash::SipHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

/// The hub's ExternalSender (RFC 9420 §12.1.8.1): an Ed25519 key and a
/// BasicCredential identity, the provider URI.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HubSender {
    pub signature_key: [u8; 32],
    pub identity: String,
}

/// One Chat of the account with a `roomId` (draft-atwood-jmap-chat-mimi-00
/// §Chat.roomId), and whether a device of the user recorded the room as
/// accepted (decision mimid-1wgh.63).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnChat {
    /// The Chat's id.
    pub id: String,
    /// The room.
    pub room: String,
    /// `{"accepted": true}` in [`ACCEPTED_NAMESPACE`].
    pub accepted: bool,
}

/// One JMAP Consent record (draft-atwood-jmap-chat-mimi-00 §Consent).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentRecord {
    /// The record's id.
    pub id: String,
    /// The user asking to fetch KeyPackages.
    pub requester: String,
    /// The user whose KeyPackages they are.
    pub target: String,
    /// The room the consent is for, or `None` for any room.
    pub room: Option<String>,
    /// `grant`, `revoke`, or `None` before a decision.
    pub decision: Option<String>,
    /// Whether a request is pending.
    pub requested: bool,
}

pub(crate) struct Jmap {
    /// Digests ([`digest`]) of the MLSMessages this agent sent.
    sent: Mutex<Vec<u64>>,
    api_url: String,
    token: String,
    account_id: String,
    pub hub_sender: HubSender,
    pub room_id_prefix: String,
    /// The Session's `uploadUrl`.
    upload_url: String,
    /// The mimi capability's `assetUrl` template, if the server stores
    /// attachments.
    asset_url: Option<String>,
    /// The mimi capability's `assetLifetime`: the seconds an upload stays
    /// at `assetUrl` (draft-atwood-jmap-chat-mimi-00 §Account-Level
    /// Capability Object, jmap-chat-spec 120db2c), or `None` if the server
    /// states no limit.
    pub asset_lifetime: Option<u64>,
    /// The mimi capability's `assetDownloadUrl` template, if the server
    /// fetches attachments.
    asset_download_url: Option<String>,
    /// Whether the account keeps Chat `privateMetadata` in vendor
    /// namespaces (draft-ietf-jmap-metadata-05 §1.2.1), where accepted
    /// rooms are recorded (decision mimid-1wgh.63).
    pub chat_metadata: bool,
    http: reqwest::Client,
}

impl Jmap {
    /// Reads the Session at `<base>/.well-known/jmap`.
    pub async fn open(base: &str, token: &str) -> Result<Self, AgentError> {
        let what = "GET /.well-known/jmap";
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .map_err(|source| AgentError::Http {
                what: "building the HTTP client".to_owned(),
                source,
            })?;
        let base = base.trim_end_matches('/');
        let response = http
            .get(format!("{base}/.well-known/jmap"))
            .bearer_auth(token)
            .send()
            .await
            .map_err(|source| AgentError::Http {
                what: what.to_owned(),
                source,
            })?;
        let session = read_json(what, response).await?;
        let account_id = session["primaryAccounts"][MIMI]
            .as_str()
            .ok_or_else(|| AgentError::malformed(what, format!("no {MIMI} account")))?
            .to_owned();
        let mimi = &session["accounts"][&account_id]["accountCapabilities"][MIMI];
        let hub_sender = parse_hub_sender(
            mimi["hubSender"]
                .as_str()
                .ok_or_else(|| AgentError::malformed(what, "no hubSender"))?,
        )
        .map_err(|detail| AgentError::malformed(what, detail))?;
        let room_id_prefix = mimi["roomIdPrefix"]
            .as_str()
            .ok_or_else(|| AgentError::malformed(what, "no roomIdPrefix"))?
            .to_owned();
        let api_url = session["apiUrl"]
            .as_str()
            .map_or_else(|| format!("{base}/jmap/api"), str::to_owned);
        let upload_url = session["uploadUrl"]
            .as_str()
            .map_or_else(
                || format!("{base}/jmap/upload/{{accountId}}/"),
                str::to_owned,
            )
            .replace("{accountId}", &account_id);
        let asset_url = mimi["assetUrl"].as_str().map(str::to_owned);
        let asset_lifetime =
            parse_asset_lifetime(mimi).map_err(|detail| AgentError::malformed(what, detail))?;
        let asset_download_url = mimi["assetDownloadUrl"].as_str().map(str::to_owned);
        let chat_info =
            &session["accounts"][&account_id]["accountCapabilities"][METADATA]["dataTypes"]["Chat"];
        let chat_metadata = session["capabilities"].get(METADATA).is_some()
            && chat_info["supportsPrivate"] == true
            && chat_info["supportsVendorNamespaces"] == true;
        Ok(Self {
            sent: Mutex::default(),
            api_url,
            token: token.to_owned(),
            account_id,
            hub_sender,
            room_id_prefix,
            upload_url,
            asset_url,
            asset_lifetime,
            asset_download_url,
            chat_metadata,
            http,
        })
    }

    /// One method call; its response arguments, or the method error.
    async fn call(&self, method: &str, mut args: Value) -> Result<Value, AgentError> {
        args["accountId"] = json!(self.account_id);
        let mut using = USING.to_vec();
        if self.chat_metadata {
            using.push(METADATA);
        }
        let body = json!({"using": using, "methodCalls": [[method, args, "c"]]});
        let response = self
            .http
            .post(&self.api_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .map_err(|source| AgentError::Http {
                what: method.to_owned(),
                source,
            })?;
        let value = read_json(method, response).await?;
        let call = &value["methodResponses"][0];
        if call[0] == "error" {
            return Err(AgentError::Method {
                method: method.to_owned(),
                kind: call[1]["type"].as_str().unwrap_or("error").to_owned(),
                description: call[1]["description"].as_str().unwrap_or("").to_owned(),
            });
        }
        Ok(call[1].clone())
    }

    /// A /set call; the first SetError is an error.
    async fn set(&self, method: &str, args: Value) -> Result<Value, AgentError> {
        let answer = self.call(method, args).await?;
        for key in ["notCreated", "notUpdated", "notDestroyed"] {
            if let Some(error) = answer[key].as_object().and_then(|e| e.values().next()) {
                let properties = error["properties"]
                    .as_array()
                    .map(|p| format!(" {p:?}"))
                    .unwrap_or_default();
                return Err(AgentError::Method {
                    method: method.to_owned(),
                    kind: error["type"].as_str().unwrap_or("error").to_owned(),
                    description: format!(
                        "{}{properties}",
                        error["description"].as_str().unwrap_or("")
                    ),
                });
            }
        }
        Ok(answer)
    }

    /// Uploads `bytes` (RFC 8620 §6.1) and returns the URL other
    /// providers fetch them from: the mimi capability's `assetUrl`
    /// expanded with the blob's id (draft-atwood-jmap-chat-mimi-00
    /// §Account-Level Capability Object).
    pub async fn upload(&self, bytes: Vec<u8>) -> Result<String, AgentError> {
        let what = "upload";
        let template = self.asset_url.as_deref().ok_or_else(|| {
            AgentError::Invalid("the server does not store attachments".to_owned())
        })?;
        let response = self
            .http
            .post(&self.upload_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/octet-stream")
            .body(bytes)
            .send()
            .await
            .map_err(|source| AgentError::Http {
                what: what.to_owned(),
                source,
            })?;
        let answer = read_json(what, response).await?;
        let blob_id = answer["blobId"]
            .as_str()
            .ok_or_else(|| AgentError::malformed(what, "no blobId"))?;
        expand_template(template, &[("blobId", blob_id)])
            .map_err(|detail| AgentError::malformed("assetUrl", detail))
    }

    /// Fetches the attachment at `url` for `room` through this user's
    /// server, at the mimi capability's `assetDownloadUrl` expanded with
    /// `roomId` and `url` (draft-atwood-jmap-chat-mimi-00 §Account-Level
    /// Capability Object); the server reads its own assets and asks the
    /// room's hub for others (protocol-07 §5.10.2). At most
    /// [`MAX_ASSET_LEN`] octets.
    pub async fn fetch_asset(&self, room: &str, url: &str) -> Result<Vec<u8>, AgentError> {
        let what = "GET assetDownloadUrl";
        let template = self.asset_download_url.as_deref().ok_or_else(|| {
            AgentError::Invalid("the server does not fetch attachments".to_owned())
        })?;
        let endpoint = expand_template(template, &[("roomId", room), ("url", url)])
            .map_err(|detail| AgentError::malformed("assetDownloadUrl", detail))?;
        let endpoint = reqwest::Url::parse(&endpoint)
            .map_err(|e| AgentError::malformed("assetDownloadUrl", e.to_string()))?;
        let mut response = self
            .http
            .get(endpoint)
            .bearer_auth(&self.token)
            .send()
            .await
            .map_err(|source| AgentError::Http {
                what: what.to_owned(),
                source,
            })?;
        if !response.status().is_success() {
            return Err(read_json(what, response)
                .await
                .err()
                .unwrap_or_else(|| AgentError::malformed(what, "an error status")));
        }
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|source| AgentError::Http {
            what: what.to_owned(),
            source,
        })? {
            if body.len() + chunk.len() > MAX_ASSET_LEN {
                return Err(AgentError::malformed(what, "the attachment is too large"));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// The account's Consent records.
    pub async fn consents(&self) -> Result<Vec<ConsentRecord>, AgentError> {
        let answer = self.call("Consent/get", json!({"ids": null})).await?;
        Ok(answer["list"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| ConsentRecord {
                id: r["id"].as_str().unwrap_or_default().to_owned(),
                requester: r["requesterUri"].as_str().unwrap_or_default().to_owned(),
                target: r["targetUri"].as_str().unwrap_or_default().to_owned(),
                room: r["roomId"].as_str().map(str::to_owned),
                decision: r["decision"].as_str().map(str::to_owned),
                requested: r["requested"] == true,
            })
            .collect())
    }

    /// Consent/set with `args`.
    pub async fn consent_set(&self, args: Value) -> Result<(), AgentError> {
        self.set("Consent/set", args).await.map(drop)
    }

    /// KeyPackage/set create.
    pub async fn publish_key_package(&self, key_package: &[u8]) -> Result<(), AgentError> {
        let answer = self
            .set(
                "KeyPackage/set",
                json!({"create": {"k": {"keyPackage": URL_SAFE_NO_PAD.encode(key_package)}}}),
            )
            .await?;
        if answer["created"]["k"].is_object() {
            Ok(())
        } else {
            Err(AgentError::malformed("KeyPackage/set", "nothing created"))
        }
    }

    /// Room/create for the room `room_id`; returns the room ID.
    pub async fn create_room(
        &self,
        room_id: &str,
        group_info: &[u8],
        tree: &[u8],
    ) -> Result<String, AgentError> {
        let answer = self
            .call(
                "Room/create",
                json!({
                    "roomId": room_id,
                    "groupInfo": URL_SAFE_NO_PAD.encode(group_info),
                    "ratchetTree": URL_SAFE_NO_PAD.encode(tree),
                }),
            )
            .await?;
        answer["roomId"]
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| AgentError::malformed("Room/create", "no roomId"))
    }

    /// Every Chat of the account that has a `roomId`
    /// (draft-atwood-jmap-chat-mimi-00 §Chat.roomId), bound or not: the
    /// rooms the user is or was in, whichever client joined them, with
    /// whether a device recorded the room as accepted (always `false`
    /// without [`Jmap::chat_metadata`]). By room.
    pub async fn own_chats(&self) -> Result<Vec<OwnChat>, AgentError> {
        const WHAT: &str = "Chat/get";
        let selector = format!("privateMetadata/{ACCEPTED_NAMESPACE}");
        let properties = if self.chat_metadata {
            json!(["roomId", selector])
        } else {
            json!(["roomId"])
        };
        let answer = self
            .call(WHAT, json!({"ids": null, "properties": properties}))
            .await?;
        let mut chats: Vec<OwnChat> = answer["list"]
            .as_array()
            .ok_or_else(|| AgentError::malformed(WHAT, "no list"))?
            .iter()
            .filter_map(|chat| {
                Some(OwnChat {
                    id: chat["id"].as_str()?.to_owned(),
                    room: chat["roomId"].as_str()?.to_owned(),
                    accepted: chat["privateMetadata"][ACCEPTED_NAMESPACE]["accepted"] == true,
                })
            })
            .collect();
        chats.sort_by(|a, b| a.room.cmp(&b.room).then(b.accepted.cmp(&a.accepted)));
        chats.dedup_by(|later, first| later.room == first.room);
        Ok(chats)
    }

    /// Records in Chat `chat_id`'s `privateMetadata` that the user accepted
    /// its room, or (`accepted` false) removes the record (decision
    /// mimid-1wgh.63; draft-ietf-jmap-metadata-05 §3.2).
    pub async fn set_accepted(&self, chat_id: &str, accepted: bool) -> Result<(), AgentError> {
        let value = if accepted {
            json!({"accepted": true})
        } else {
            Value::Null
        };
        let mut patch = serde_json::Map::new();
        patch.insert(format!("privateMetadata/{ACCEPTED_NAMESPACE}"), value);
        let mut update = serde_json::Map::new();
        update.insert(chat_id.to_owned(), Value::Object(patch));
        self.set("Chat/set", json!({"update": update}))
            .await
            .map(drop)
    }

    /// GroupInfo/fetch of `room` with the TLS-encoded GroupInfoRequest
    /// `request` (draft-atwood-jmap-chat-mimi-00 §GroupInfo/fetch): the
    /// whole GroupInfoResponse, unchanged.
    pub async fn group_info(&self, room: &str, request: &[u8]) -> Result<Vec<u8>, AgentError> {
        const WHAT: &str = "GroupInfo/fetch";
        let answer = self
            .call(
                WHAT,
                json!({"roomId": room, "request": URL_SAFE_NO_PAD.encode(request)}),
            )
            .await?;
        let response = answer["response"]
            .as_str()
            .ok_or_else(|| AgentError::malformed(WHAT, "no response"))?;
        URL_SAFE_NO_PAD
            .decode(response)
            .map_err(|e| AgentError::malformed(WHAT, format!("response is not base64url: {e}")))
    }

    /// KeyMaterial/fetch for the KeyMaterialRequest `request`, answered as
    /// the KeyMaterialResponse it describes.
    pub async fn key_material(&self, request: &[u8]) -> Result<KeyMaterialResponse, AgentError> {
        const WHAT: &str = "KeyMaterial/fetch";
        let decoded = KeyMaterialRequest::tls_deserialize_exact(request)
            .map_err(|e| AgentError::tls("own KeyMaterialRequest", e))?;
        let room_id = decoded.tbs().room_id.as_str().to_owned();
        let answer = self
            .call(
                WHAT,
                json!({"roomId": room_id, "request": URL_SAFE_NO_PAD.encode(request)}),
            )
            .await?;
        let user_status = match answer["userStatus"].as_str() {
            Some("success") => KeyMaterialUserCode::Success,
            Some("partialSuccess") => KeyMaterialUserCode::PartialSuccess,
            Some("incompatibleProtocol") => KeyMaterialUserCode::IncompatibleProtocol,
            Some("noCompatibleMaterial") => KeyMaterialUserCode::NoCompatibleMaterial,
            Some("userUnknown") => KeyMaterialUserCode::UserUnknown,
            Some("noConsent") => KeyMaterialUserCode::NoConsent,
            Some("noConsentForThisRoom") => KeyMaterialUserCode::NoConsentForThisRoom,
            Some("userDeleted") => KeyMaterialUserCode::UserDeleted,
            other => {
                return Err(AgentError::malformed(
                    WHAT,
                    format!("unknown userStatus {other:?}"),
                ));
            }
        };
        let uri = |text: &Value, field: &str| {
            IdentifierUri::new(text.as_str().unwrap_or_default())
                .map_err(|e| AgentError::malformed(WHAT, format!("{field}: {e:?}")))
        };
        let user_uri = uri(&answer["userUri"], "userUri")?;
        let mut clients = Vec::new();
        for client in answer["clients"].as_array().into_iter().flatten() {
            let client_uri = uri(&client["clientUri"], "clientUri")?;
            let bytes = |key: &str| -> Result<Option<Vec<u8>>, AgentError> {
                client[key]
                    .as_str()
                    .map(|text| {
                        URL_SAFE_NO_PAD.decode(text).map_err(|_| {
                            AgentError::malformed(WHAT, format!("{key}: not base64url"))
                        })
                    })
                    .transpose()
            };
            clients.push(match client["clientStatus"].as_str() {
                Some("success") => {
                    let key_package = bytes("keyPackage")?.ok_or_else(|| {
                        AgentError::malformed(WHAT, "a success has no keyPackage")
                    })?;
                    ClientKeyMaterial::Success {
                        client_uri,
                        key_package: KeyPackage::tls_deserialize_exact(&key_package[..]).map_err(
                            |e| AgentError::malformed(WHAT, format!("keyPackage: {e:?}")),
                        )?,
                    }
                }
                Some("keyMaterialExhausted") => {
                    ClientKeyMaterial::KeyMaterialExhausted { client_uri }
                }
                Some("nothingCompatible") => ClientKeyMaterial::NothingCompatible {
                    client_uri,
                    client_capabilities: bytes("clientCapabilities")?
                        .map(|b| {
                            Capabilities::tls_deserialize_exact(&b[..]).map_err(|e| {
                                AgentError::malformed(WHAT, format!("clientCapabilities: {e:?}"))
                            })
                        })
                        .transpose()?,
                },
                other => {
                    return Err(AgentError::malformed(
                        WHAT,
                        format!("unknown clientStatus {other:?}"),
                    ));
                }
            });
        }
        Ok(KeyMaterialResponse {
            protocol: Protocol::Mls10,
            user_status,
            user_uri,
            clients,
        })
    }

    fn remember_sent(&self, message: &impl Serialize) {
        if let Ok(bytes) = message.tls_serialize_detached() {
            let mut sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
            sent.push(digest(&bytes));
            let excess = sent.len().saturating_sub(MAX_SENT);
            sent.drain(..excess);
        }
    }

    /// The digests of the messages sent, oldest first, for the state.
    pub fn sent_digests(&self) -> Vec<u64> {
        self.sent
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }

    /// Restores the digests of messages sent in earlier runs.
    pub fn restore_sent(&self, digests: &[u64]) {
        *self.sent.lock().unwrap_or_else(PoisonError::into_inner) = digests.to_vec();
    }

    /// Whether the FanoutMessage `body` carries an MLSMessage this agent
    /// sent.
    pub fn is_own(&self, body: &[u8]) -> bool {
        let Ok(fanouts) = FanoutMessage::decode_all(body) else {
            return false;
        };
        let sent = self.sent.lock().unwrap_or_else(PoisonError::into_inner);
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

    /// The Messages stored since `since` (every Message when `None`, or
    /// when the server cannot calculate the changes), as (id, body), and
    /// the new Message state.
    pub async fn messages_since(
        &self,
        since: Option<&str>,
    ) -> Result<(String, Vec<(String, Vec<u8>)>), AgentError> {
        let (state, ids) = match since {
            None => (None, Value::Null),
            Some(since) => {
                let mut ids = Vec::new();
                let mut state = since.to_owned();
                loop {
                    let changes = match self
                        .call("Message/changes", json!({"sinceState": state}))
                        .await
                    {
                        Ok(changes) => changes,
                        Err(AgentError::Method { kind, .. })
                            if kind == "cannotCalculateChanges" =>
                        {
                            return Box::pin(self.messages_since(None)).await;
                        }
                        Err(e) => return Err(e),
                    };
                    ids.extend(changes["created"].as_array().into_iter().flatten().cloned());
                    state = changes["newState"]
                        .as_str()
                        .ok_or_else(|| AgentError::malformed("Message/changes", "no newState"))?
                        .to_owned();
                    if changes["hasMoreChanges"] != true {
                        break;
                    }
                }
                if ids.is_empty() {
                    return Ok((state, Vec::new()));
                }
                (Some(state), Value::Array(ids))
            }
        };
        let answer = self
            .call("Message/get", json!({"ids": ids, "properties": ["body"]}))
            .await?;
        let state = match state {
            Some(state) => state,
            None => answer["state"]
                .as_str()
                .ok_or_else(|| AgentError::malformed("Message/get", "no state"))?
                .to_owned(),
        };
        let mut messages = Vec::new();
        for message in answer["list"].as_array().into_iter().flatten() {
            let id = message["id"].as_str().unwrap_or_default().to_owned();
            let body = message["body"]
                .as_str()
                .and_then(|b| URL_SAFE_NO_PAD.decode(b).ok())
                .ok_or_else(|| {
                    AgentError::malformed("Message/get", format!("Message {id} has no body"))
                })?;
            messages.push((id, body));
        }
        Ok((state, messages))
    }

    /// Room/update, answered as the UpdateRoomResponse it describes.
    pub async fn update(
        &self,
        room: &str,
        request: &UpdateRequest,
    ) -> Result<UpdateRoomResponse, AgentError> {
        const WHAT: &str = "Room/update";
        match &request.bundle {
            HandshakeBundle::Commit {
                proposal_or_commit, ..
            } => self.remember_sent(proposal_or_commit),
            HandshakeBundle::Proposal {
                proposal_or_commit,
                more_proposals,
            } => {
                self.remember_sent(proposal_or_commit);
                for proposal in more_proposals {
                    self.remember_sent(proposal);
                }
            }
        }
        let bytes = request
            .tls_serialize_detached()
            .map_err(|e| AgentError::tls("own UpdateRequest", e))?;
        let answer = self
            .call(
                WHAT,
                json!({"roomId": room, "request": URL_SAFE_NO_PAD.encode(bytes)}),
            )
            .await?;
        let result = match answer["responseCode"].as_str() {
            Some("success") => UpdateResult::Success {
                accepted_timestamp: utc_date_ms(answer["acceptedAt"].as_str().unwrap_or(""))
                    .map_err(|detail| AgentError::malformed(WHAT, detail))?,
            },
            Some("wrongEpoch") => UpdateResult::WrongEpoch {
                current_epoch: answer["currentEpoch"].as_u64().unwrap_or(0),
            },
            Some("notAllowed") => UpdateResult::NotAllowed,
            Some("invalidProposal") => UpdateResult::InvalidProposal {
                invalid_proposals: answer["invalidProposals"]
                    .as_array()
                    .into_iter()
                    .flatten()
                    .filter_map(|r| r.as_str())
                    .filter_map(|r| URL_SAFE_NO_PAD.decode(r).ok())
                    .filter_map(|b| ProposalRef::tls_deserialize_exact(&b[..]).ok())
                    .collect(),
            },
            other => {
                return Err(AgentError::malformed(
                    WHAT,
                    format!("unknown responseCode {other:?}"),
                ));
            }
        };
        Ok(UpdateRoomResponse {
            error_description: Utf8String::new(
                answer["errorDescription"].as_str().unwrap_or("").to_owned(),
            )
            .map_err(|e| AgentError::malformed(WHAT, format!("errorDescription: {e:?}")))?,
            result,
        })
    }

    /// Room/reportAbuse (INVENTED, NOT FROM SPEC; decision mimid-1wgh.58)
    /// of the TLS-encoded AbuseReport `report` about `room`: the hub's
    /// answer as the server relays it.
    pub async fn report_abuse(
        &self,
        room: &str,
        report: &[u8],
    ) -> Result<ReportOutcome, AgentError> {
        const WHAT: &str = "Room/reportAbuse";
        let answer = self
            .call(
                WHAT,
                json!({"roomId": room, "report": URL_SAFE_NO_PAD.encode(report)}),
            )
            .await?;
        match answer["responseCode"].as_str() {
            Some("accepted") => Ok(ReportOutcome::Accepted),
            Some("notAllowed") => Ok(ReportOutcome::NotAllowed),
            Some("unverifiedMessage") => Ok(ReportOutcome::UnverifiedMessage),
            Some("refused") => Ok(ReportOutcome::Refused {
                status: answer["status"]
                    .as_u64()
                    .and_then(|status| u16::try_from(status).ok())
                    .ok_or_else(|| AgentError::malformed(WHAT, "refused without a status"))?,
            }),
            other => Err(AgentError::malformed(
                WHAT,
                format!("unknown responseCode {other:?}"),
            )),
        }
    }

    /// Room/send of the MLSMessage `message`; the hub's accepted time in
    /// milliseconds, or the refusal as an error.
    pub async fn send(
        &self,
        room: &str,
        message: &mimi_mls::wire::MLSMessage,
    ) -> Result<u64, AgentError> {
        const WHAT: &str = "Room/send";
        let bytes = message
            .tls_serialize_detached()
            .map_err(|e| AgentError::tls("own message", e))?;
        self.remember_sent(message);
        let answer = self
            .call(
                WHAT,
                json!({"roomId": room, "message": URL_SAFE_NO_PAD.encode(bytes)}),
            )
            .await?;
        match answer["responseCode"].as_str() {
            Some("accepted") => utc_date_ms(answer["acceptedAt"].as_str().unwrap_or(""))
                .map_err(|detail| AgentError::malformed(WHAT, detail)),
            code => Err(AgentError::Refused {
                what: WHAT.to_owned(),
                reason: format!(
                    "{} {}",
                    code.unwrap_or("no responseCode"),
                    answer["errorDescription"].as_str().unwrap_or("")
                )
                .trim()
                .to_owned(),
            }),
        }
    }
}

/// The JSON body of `response`, or its status as an error.
async fn read_json(what: &str, response: reqwest::Response) -> Result<Value, AgentError> {
    let status = response.status();
    let text = response.text().await.map_err(|source| AgentError::Http {
        what: what.to_owned(),
        source,
    })?;
    if !status.is_success() {
        let mut body = text;
        if body.len() > MAX_ERROR_BODY {
            let cut = (0..=MAX_ERROR_BODY)
                .rev()
                .find(|&i| body.is_char_boundary(i))
                .unwrap_or(0);
            body.truncate(cut);
        }
        return Err(AgentError::Status {
            what: what.to_owned(),
            status: status.as_u16(),
            body,
        });
    }
    serde_json::from_str(&text).map_err(|e| AgentError::malformed(what, format!("not JSON: {e}")))
}

/// The hub's ExternalSender from its base64url: `SignaturePublicKey` then
/// a BasicCredential.
/// The mimi capability's `assetLifetime`, `None` if absent or null.
/// Anything but an UnsignedInt (RFC 8620 §1.3) is refused rather than read
/// as "no limit", which would state a false "never" in every ExternalPart.
fn parse_asset_lifetime(mimi: &Value) -> Result<Option<u64>, String> {
    match mimi.get("assetLifetime") {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|&n| n <= MAX_UNSIGNED_INT)
            .map(Some)
            .ok_or_else(|| format!("assetLifetime {value} is not an UnsignedInt")),
    }
}

/// The largest JMAP UnsignedInt, 2^53 - 1 (RFC 8620 §1.3).
const MAX_UNSIGNED_INT: u64 = (1 << 53) - 1;

fn parse_hub_sender(text: &str) -> Result<HubSender, String> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| "hubSender is not base64url".to_owned())?;
    let mut reader = &bytes[..];
    let key = VLBytes::tls_deserialize(&mut reader)
        .map_err(|e| format!("hubSender signature key: {e:?}"))?;
    let signature_key = <[u8; 32]>::try_from(key.as_slice())
        .map_err(|_| "hubSender signature key is not 32 octets".to_owned())?;
    let mut reader = reader
        .strip_prefix(&[0x00, 0x01][..])
        .ok_or_else(|| "hubSender credential is not a BasicCredential".to_owned())?;
    let identity =
        VLBytes::tls_deserialize(&mut reader).map_err(|e| format!("hubSender identity: {e:?}"))?;
    Ok(HubSender {
        signature_key,
        identity: String::from_utf8(identity.as_slice().to_vec())
            .map_err(|_| "hubSender identity is not UTF-8".to_owned())?,
    })
}

/// Milliseconds since the UNIX epoch of an RFC 3339 UTCDate
/// (`YYYY-MM-DDTHH:MM:SS[.fff]Z`, RFC 8620 §1.4).
pub(crate) fn utc_date_ms(text: &str) -> Result<u64, String> {
    let bad = || format!("not a UTCDate: {text:?}");
    let (date, time) = text.split_once('T').ok_or_else(bad)?;
    let time = time.strip_suffix('Z').ok_or_else(bad)?;
    let mut d = date.split('-').map(str::parse::<u64>);
    let (Some(Ok(year)), Some(Ok(month)), Some(Ok(day)), None) =
        (d.next(), d.next(), d.next(), d.next())
    else {
        return Err(bad());
    };
    let (hms, fraction) = time.split_once('.').unwrap_or((time, ""));
    let mut t = hms.split(':').map(str::parse::<u64>);
    let (Some(Ok(hour)), Some(Ok(minute)), Some(Ok(second)), None) =
        (t.next(), t.next(), t.next(), t.next())
    else {
        return Err(bad());
    };
    if year < 1970 || !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return Err(bad());
    }
    let millis = match fraction.len() {
        0 => 0,
        _ => format!("{fraction:0<3}")[..3]
            .parse::<u64>()
            .map_err(|_| bad())?,
    };
    // Days from civil (Howard Hinnant's algorithm), year >= 1970.
    let (y, m) = if month <= 2 {
        (year - 1, month + 9)
    } else {
        (year, month - 3)
    };
    let era = y / 400;
    let yoe = y - era * 400;
    let doy = (153 * m + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Ok(((days * 24 + hour) * 60 + minute) * 60_000 + second * 1000 + millis)
}

/// `template` expanded with `vars` as an RFC 6570 level 1 URI Template
/// (§1.2, §3.2.2 simple string expansion): each `{name}` becomes the
/// variable's value with every octet outside the unreserved set
/// (ALPHA, DIGIT, `-`, `.`, `_`, `~`) percent-encoded, and an undefined
/// variable expands to nothing (§2.3). Literals are copied unchanged.
///
/// # Errors
///
/// An expression of a higher level (an operator, a variable list or a
/// modifier) or an unclosed brace, as text.
pub(crate) fn expand_template(template: &str, vars: &[(&str, &str)]) -> Result<String, String> {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let after = &rest[open + 1..];
        let close = after
            .find('}')
            .ok_or_else(|| "an unclosed expression".to_owned())?;
        let name = &after[..close];
        let level1 = !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'%'));
        if !level1 {
            return Err(format!("{{{name}}} is not a level 1 expression"));
        }
        if let Some((_, value)) = vars.iter().find(|(n, _)| *n == name) {
            for b in value.bytes() {
                if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
                    out.push(char::from(b));
                } else {
                    out.push_str(&format!("%{b:02X}"));
                }
            }
        }
        rest = &after[close + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

#[cfg(test)]
mod tests {

    /// RFC 8620 §1.3: an UnsignedInt is an integer in 0..=2^53-1.
    #[test]
    fn asset_lifetime_is_an_unsigned_int_or_absent() {
        use super::parse_asset_lifetime as parse;
        use serde_json::json;
        assert_eq!(parse(&json!({})), Ok(None));
        assert_eq!(parse(&json!({"assetLifetime": null})), Ok(None));
        assert_eq!(parse(&json!({"assetLifetime": 0})), Ok(Some(0)));
        assert_eq!(
            parse(&json!({"assetLifetime": 2_592_000})),
            Ok(Some(2_592_000))
        );
        assert_eq!(
            parse(&json!({"assetLifetime": 9_007_199_254_740_991_u64})),
            Ok(Some(9_007_199_254_740_991))
        );
        for bad in [
            json!(9_007_199_254_740_992_u64),
            json!(-1),
            json!(1.5),
            json!("3600"),
            json!(true),
            json!([3600]),
        ] {
            assert!(parse(&json!({"assetLifetime": bad})).is_err(), "{bad}");
        }
    }

    // RFC 6570 §1.2 (level 1) and §3.2.2 examples, with var := "value",
    // hello := "Hello World!", half := "50%", empty := "" and undef
    // undefined.
    #[test]
    fn level_1_templates_expand_as_rfc_6570_shows() {
        let vars = [
            ("var", "value"),
            ("hello", "Hello World!"),
            ("half", "50%"),
            ("empty", ""),
        ];
        for (template, expanded) in [
            ("{var}", "value"),
            ("{hello}", "Hello%20World%21"),
            ("{half}", "50%25"),
            ("O{empty}X", "OX"),
            ("O{undef}X", "OX"),
        ] {
            assert_eq!(
                super::expand_template(template, &vars).as_deref(),
                Ok(expanded),
                "{template}"
            );
        }
    }

    #[test]
    fn the_asset_download_template_escapes_room_and_url() {
        assert_eq!(
            super::expand_template(
                "https://p.example/jmap/asset/A1?room={roomId}&url={url}",
                &[
                    ("roomId", "mimi://a.example/r/one"),
                    ("url", "https://b.example/a/1?x=1&y=é"),
                ],
            )
            .as_deref(),
            Ok(
                "https://p.example/jmap/asset/A1?room=mimi%3A%2F%2Fa.example%2Fr%2Fone\
                &url=https%3A%2F%2Fb.example%2Fa%2F1%3Fx%3D1%26y%3D%C3%A9"
            )
        );
    }

    #[test]
    fn higher_level_and_unclosed_expressions_are_refused() {
        for template in [
            "{+var}", "{#var}", "{x,y}", "{var:3}", "{list*}", "{}", "a{var",
        ] {
            assert!(
                super::expand_template(template, &[("var", "v")]).is_err(),
                "{template}"
            );
        }
    }
    use super::*;

    #[test]
    fn utc_dates_parse_to_milliseconds() {
        assert_eq!(utc_date_ms("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(
            utc_date_ms("2023-11-14T22:15:00.123Z").unwrap(),
            1_700_000_100_123
        );
        assert_eq!(
            utc_date_ms("2000-03-01T00:00:01.5Z").unwrap(),
            951_868_801_500
        );
        assert!(utc_date_ms("2023-11-14 22:15:00Z").is_err());
        assert!(utc_date_ms("1969-12-31T23:59:59Z").is_err());
    }

    #[test]
    fn the_hub_sender_parses() {
        let mut bytes = vec![0x20];
        bytes.extend([7u8; 32]);
        bytes.extend([0x00, 0x01, 0x10]);
        bytes.extend(b"mimi://a.example");
        let sender = parse_hub_sender(&URL_SAFE_NO_PAD.encode(&bytes)).unwrap();
        assert_eq!(sender.signature_key, [7; 32]);
        assert_eq!(sender.identity, "mimi://a.example");
        assert!(parse_hub_sender("!!").is_err());
    }
}
