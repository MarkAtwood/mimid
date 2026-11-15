//! The JMAP transport to a mimid server (draft-atwood-jmap-chat-mimi-00;
//! bead mimid-1wgh.12.41): the client's own provider, reached with a
//! bearer token, instead of the protocol-07 wire lane and mimi-hubd's JSON
//! lane. The account comes from the Session; the hub's external-sender
//! identity and the room ID prefix from its `urn:ietf:params:jmap:chat:mimi`
//! account capability.
//!
//! Each call answers what the wire call it replaces answers, so the rest of
//! the client is unchanged: KeyMaterial/fetch is turned back into a
//! KeyMaterialResponse, Room/update into an UpdateRoomResponse.
//!
//! Receiving: [`Jmap::messages_since`] reads the Messages the server stored,
//! every one the first time and then by `Message/changes`. Each body is a
//! FanoutMessage, handled as one from the hub. The server also stores the
//! client's own handshakes and messages; [`Jmap::is_own`] recognises those
//! this process sent, so they are skipped.

use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mimi_mls::tls_codec::{Deserialize, Serialize, VLBytes};
use mimi_mls::wire::{Capabilities, KeyPackage, ProposalRef};
use mimi_protocol::{
    ClientKeyMaterial, FanoutEvent, FanoutMessage, HandshakeBundle, IdentifierUri,
    KeyMaterialRequest, KeyMaterialResponse, KeyMaterialUserCode, Protocol, SubmitMessageRequest,
    UpdateRequest, UpdateResult, UpdateRoomResponse, Utf8String,
};
use serde_json::{Value, json};

use crate::hub::HubSender;

const USING: [&str; 3] = [
    "urn:ietf:params:jmap:core",
    "urn:ietf:params:jmap:chat",
    "urn:ietf:params:jmap:chat:mimi",
];
const MIMI: &str = "urn:ietf:params:jmap:chat:mimi";

/// How many sent-message digests are kept.
const MAX_SENT: usize = 1024;

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

/// How long one JMAP request may take.
const TIMEOUT: Duration = Duration::from_secs(30);

pub struct Jmap {
    /// Digests ([`digest`]) of the MLSMessages this client sent, which the
    /// server also stores as Messages (draft §Room/update, §Room/send), so
    /// polling skips them. Kept in the state across runs.
    sent: std::sync::Mutex<Vec<u64>>,
    api_url: String,
    token: String,
    account_id: String,
    pub hub_sender: HubSender,
    pub room_id_prefix: String,
    http: reqwest::Client,
}

impl Jmap {
    /// Reads the Session at `<base>/.well-known/jmap`.
    pub async fn open(base: &str, token: &str) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(TIMEOUT)
            .build()
            .context("building the JMAP client")?;
        let base = base.trim_end_matches('/');
        let response = http
            .get(format!("{base}/.well-known/jmap"))
            .bearer_auth(token)
            .send()
            .await
            .context("GET /.well-known/jmap")?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("GET /.well-known/jmap: {status} {text}");
        }
        let session: Value = serde_json::from_str(&text).context("the Session is not JSON")?;
        let account_id = session["primaryAccounts"][MIMI]
            .as_str()
            .ok_or_else(|| anyhow!("the Session has no {MIMI} account"))?
            .to_owned();
        let mimi = &session["accounts"][&account_id]["accountCapabilities"][MIMI];
        let hub_sender = parse_hub_sender(
            mimi["hubSender"]
                .as_str()
                .ok_or_else(|| anyhow!("the {MIMI} capability has no hubSender"))?,
        )?;
        let room_id_prefix = mimi["roomIdPrefix"]
            .as_str()
            .ok_or_else(|| anyhow!("the {MIMI} capability has no roomIdPrefix"))?
            .to_owned();
        let api_url = session["apiUrl"]
            .as_str()
            .map_or_else(|| format!("{base}/jmap/api"), str::to_owned);
        Ok(Self {
            sent: std::sync::Mutex::default(),
            api_url,
            token: token.to_owned(),
            account_id,
            hub_sender,
            room_id_prefix,
            http,
        })
    }

    /// One method call; its response arguments, or the method error as an
    /// error.
    async fn call(&self, method: &str, mut args: Value) -> anyhow::Result<Value> {
        args["accountId"] = json!(self.account_id);
        let body = json!({"using": USING, "methodCalls": [[method, args, "c"]]});
        let response = self
            .http
            .post(&self.api_url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .with_context(|| format!("JMAP {method}"))?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if !status.is_success() {
            bail!("JMAP {method}: {status} {text}");
        }
        let value: Value = serde_json::from_str(&text).context("the JMAP answer is not JSON")?;
        let call = &value["methodResponses"][0];
        if call[0] == "error" {
            bail!(
                "JMAP {method}: {} {}",
                call[1]["type"].as_str().unwrap_or("error"),
                call[1]["description"].as_str().unwrap_or("")
            );
        }
        Ok(call[1].clone())
    }

    /// The account's Consent records (draft-atwood-jmap-chat-mimi-00
    /// §Consent).
    pub async fn consents(&self) -> anyhow::Result<Vec<Value>> {
        let answer = self.call("Consent/get", json!({"ids": null})).await?;
        Ok(answer["list"].as_array().cloned().unwrap_or_default())
    }

    /// Consent/set with `args`; a SetError is an error.
    pub async fn consent_set(&self, args: Value) -> anyhow::Result<Value> {
        let answer = self.call("Consent/set", args).await?;
        for key in ["notCreated", "notUpdated", "notDestroyed"] {
            if let Some(errors) = answer[key].as_object()
                && let Some(error) = errors.values().next()
            {
                bail!(
                    "Consent/set: {} {}{}",
                    error["type"].as_str().unwrap_or("error"),
                    error["properties"]
                        .as_array()
                        .map(|p| format!("{p:?} "))
                        .unwrap_or_default(),
                    error["description"].as_str().unwrap_or("")
                );
            }
        }
        Ok(answer)
    }

    /// KeyPackage/set create.
    pub async fn publish_key_package(&self, key_package: &[u8]) -> anyhow::Result<()> {
        let answer = self
            .call(
                "KeyPackage/set",
                json!({"create": {"k": {"keyPackage": URL_SAFE_NO_PAD.encode(key_package)}}}),
            )
            .await?;
        if answer["created"]["k"].is_object() {
            Ok(())
        } else {
            bail!("KeyPackage/set refused it: {}", answer["notCreated"]["k"])
        }
    }

    /// Room/create for the room `room_id`; returns the room ID.
    pub async fn create_room(
        &self,
        room_id: &str,
        group_info: &[u8],
        tree: &[u8],
    ) -> anyhow::Result<String> {
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
            .ok_or_else(|| anyhow!("Room/create answered no roomId"))
    }

    /// KeyMaterial/fetch for the KeyMaterialRequest `request`, answered as
    /// the KeyMaterialResponse it decodes.
    pub async fn key_material(&self, request: &[u8]) -> anyhow::Result<Vec<u8>> {
        let decoded = KeyMaterialRequest::tls_deserialize_exact(request)
            .map_err(|e| anyhow!("own KeyMaterialRequest: {e:?}"))?;
        let room_id = decoded.tbs().room_id.as_str().to_owned();
        let answer = self
            .call(
                "KeyMaterial/fetch",
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
            other => bail!("KeyMaterial/fetch: unknown userStatus {other:?}"),
        };
        let user_uri = IdentifierUri::new(answer["userUri"].as_str().unwrap_or_default())
            .map_err(|e| anyhow!("KeyMaterial/fetch userUri: {e:?}"))?;
        let mut clients = Vec::new();
        for client in answer["clients"].as_array().into_iter().flatten() {
            let client_uri = IdentifierUri::new(client["clientUri"].as_str().unwrap_or_default())
                .map_err(|e| anyhow!("KeyMaterial/fetch clientUri: {e:?}"))?;
            let bytes = |key: &str| -> anyhow::Result<Option<Vec<u8>>> {
                client[key]
                    .as_str()
                    .map(|text| {
                        URL_SAFE_NO_PAD
                            .decode(text)
                            .map_err(|_| anyhow!("KeyMaterial/fetch {key} is not base64url"))
                    })
                    .transpose()
            };
            clients.push(match client["clientStatus"].as_str() {
                Some("success") => {
                    let key_package = bytes("keyPackage")?
                        .ok_or_else(|| anyhow!("a success client has no keyPackage"))?;
                    ClientKeyMaterial::Success {
                        client_uri,
                        key_package: KeyPackage::tls_deserialize_exact(&key_package[..])
                            .map_err(|e| anyhow!("KeyMaterial/fetch keyPackage: {e:?}"))?,
                    }
                }
                Some("keyMaterialExhausted") => {
                    ClientKeyMaterial::KeyMaterialExhausted { client_uri }
                }
                Some("nothingCompatible") => ClientKeyMaterial::NothingCompatible {
                    client_uri,
                    client_capabilities: bytes("clientCapabilities")?
                        .map(|b| {
                            Capabilities::tls_deserialize_exact(&b[..])
                                .map_err(|e| anyhow!("clientCapabilities: {e:?}"))
                        })
                        .transpose()?,
                },
                other => bail!("KeyMaterial/fetch: unknown clientStatus {other:?}"),
            });
        }
        KeyMaterialResponse {
            protocol: Protocol::Mls10,
            user_status,
            user_uri,
            clients,
        }
        .tls_serialize_detached()
        .map_err(|e| anyhow!("re-encoding the KeyMaterialResponse: {e:?}"))
    }

    fn remember_sent(&self, message: &impl Serialize) {
        if let Ok(bytes) = message.tls_serialize_detached() {
            let mut sent = self
                .sent
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            sent.push(digest(&bytes));
            let excess = sent.len().saturating_sub(MAX_SENT);
            sent.drain(..excess);
        }
    }

    /// The digests of the messages sent, oldest first, for the state.
    pub fn sent_digests(&self) -> Vec<u64> {
        self.sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }

    /// Restores the digests of messages sent in earlier runs.
    pub fn restore_sent(&self, digests: &[u64]) {
        *self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = digests.to_vec();
    }

    /// Whether the FanoutMessage `body` carries an MLSMessage this client
    /// sent.
    pub fn is_own(&self, body: &[u8]) -> bool {
        let Ok(fanouts) = FanoutMessage::decode_all(body) else {
            return false;
        };
        let sent = self
            .sent
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
    /// the new Message state. Each body is one FanoutMessage
    /// (draft §application/mimi-fanout).
    pub async fn messages_since(
        &self,
        since: Option<&str>,
    ) -> anyhow::Result<(String, Vec<(String, Vec<u8>)>)> {
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
                        Err(e) if format!("{e}").contains("cannotCalculateChanges") => {
                            return Box::pin(self.messages_since(None)).await;
                        }
                        Err(e) => return Err(e),
                    };
                    ids.extend(changes["created"].as_array().into_iter().flatten().cloned());
                    state = changes["newState"]
                        .as_str()
                        .ok_or_else(|| anyhow!("Message/changes has no newState"))?
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
                .ok_or_else(|| anyhow!("Message/get has no state"))?
                .to_owned(),
        };
        let mut messages = Vec::new();
        for message in answer["list"].as_array().into_iter().flatten() {
            let id = message["id"].as_str().unwrap_or_default().to_owned();
            let body = message["body"]
                .as_str()
                .and_then(|b| URL_SAFE_NO_PAD.decode(b).ok())
                .ok_or_else(|| anyhow!("Message {id} has no base64url body"))?;
            messages.push((id, body));
        }
        Ok((state, messages))
    }

    /// Room/update, answered as the UpdateRoomResponse it decodes.
    pub async fn update(&self, room: &str, request: Vec<u8>) -> anyhow::Result<UpdateRoomResponse> {
        if let Ok(decoded) = UpdateRequest::tls_deserialize_exact(&request[..]) {
            match &decoded.bundle {
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
        }
        let answer = self
            .call(
                "Room/update",
                json!({"roomId": room, "request": URL_SAFE_NO_PAD.encode(request)}),
            )
            .await?;
        let result = match answer["responseCode"].as_str() {
            Some("success") => UpdateResult::Success {
                accepted_timestamp: utc_date_ms(answer["acceptedAt"].as_str().unwrap_or(""))?,
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
            other => bail!("Room/update: unknown responseCode {other:?}"),
        };
        Ok(UpdateRoomResponse {
            error_description: Utf8String::new(
                answer["errorDescription"].as_str().unwrap_or("").to_owned(),
            )
            .map_err(|e| anyhow!("errorDescription: {e:?}"))?,
            result,
        })
    }

    /// Room/send of the SubmitMessageRequest `request`'s message; returns
    /// the hub's accepted timestamp, or the refusal as an error.
    pub async fn submit(&self, room: &str, request: &[u8]) -> anyhow::Result<u64> {
        let request = SubmitMessageRequest::tls_deserialize_exact(request)
            .map_err(|e| anyhow!("own SubmitMessageRequest: {e:?}"))?;
        let message = request
            .app_message
            .tls_serialize_detached()
            .map_err(|e| anyhow!("own message: {e:?}"))?;
        self.remember_sent(&request.app_message);
        let answer = self
            .call(
                "Room/send",
                json!({"roomId": room, "message": URL_SAFE_NO_PAD.encode(message)}),
            )
            .await?;
        match answer["responseCode"].as_str() {
            Some("accepted") => utc_date_ms(answer["acceptedAt"].as_str().unwrap_or("")),
            _ => bail!("the hub refused the message: {answer}"),
        }
    }
}

/// The hub's ExternalSender (RFC 9420 §12.1.8.1) from its base64url:
/// `SignaturePublicKey` then a BasicCredential.
fn parse_hub_sender(text: &str) -> anyhow::Result<HubSender> {
    let bytes = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| anyhow!("hubSender is not base64url"))?;
    let mut reader = &bytes[..];
    let key = VLBytes::tls_deserialize(&mut reader)
        .map_err(|e| anyhow!("hubSender signature key: {e:?}"))?;
    let signature_key = <[u8; 32]>::try_from(key.as_slice())
        .map_err(|_| anyhow!("hubSender signature key is not 32 octets"))?;
    let mut reader = reader
        .strip_prefix(&[0x00, 0x01][..])
        .ok_or_else(|| anyhow!("hubSender credential is not a BasicCredential"))?;
    let identity =
        VLBytes::tls_deserialize(&mut reader).map_err(|e| anyhow!("hubSender identity: {e:?}"))?;
    Ok(HubSender {
        signature_key,
        identity: String::from_utf8(identity.as_slice().to_vec())
            .map_err(|_| anyhow!("hubSender identity is not UTF-8"))?,
    })
}

/// Milliseconds since the UNIX epoch of an RFC 3339 UTCDate
/// (`YYYY-MM-DDTHH:MM:SS[.fff]Z`, RFC 8620 §1.4).
fn utc_date_ms(text: &str) -> anyhow::Result<u64> {
    let bad = || anyhow!("not a UTCDate: {text:?}");
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

#[cfg(test)]
mod tests {
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
    }
}
