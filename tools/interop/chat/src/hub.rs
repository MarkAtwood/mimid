//! Requests to the hub: the protocol-07 wire lane through mimid's
//! `PeerClient`, and the few things only mimi-hubd's JSON lane offers
//! (`/mimi/v1/*`, mimi-hubd/README.md "Endpoints"): registering a room's
//! first participant, publishing KeyPackages, relaying Welcomes, and the
//! per-user deliver-once queues a client pulls from, since the hub never
//! dials out.

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_protocol::{SubmitMessageResponse, SubmitResult, UpdateResult, UpdateRoomResponse};
use mimid_server::config::{BaseUrl, Domain};
use mimid_server::peer::PeerClient;
use reqwest::StatusCode;
use url::Url;

/// The largest queue item accepted from the JSON lane. mimi-hubd caps
/// items at 64 KiB (store.rs `MAX_ITEM_BYTES`); this leaves room.
const MAX_ITEM_LEN: usize = 256 * 1024;

/// How long one JSON-lane request may take.
const LANE_TIMEOUT: Duration = Duration::from_secs(20);

pub struct Hub {
    pub domain: Domain,
    peer: PeerClient,
    /// mimi-hubd's JSON lane, or none for a hub without one (a mimid hub):
    /// lane writes are then skipped and pulls find nothing.
    lane: Option<Url>,
    /// mimid's local control listener ([`mimid_server::local`]), for /host.
    local: Option<Url>,
    http: reqwest::Client,
}

/// The hub's external-sender identity, from mimid's local control listener.
pub struct HubSender {
    pub signature_key: [u8; 32],
    pub identity: String,
}

impl Hub {
    /// `base_url` is where the directory is fetched (`PeerClient`);
    /// `lane_url` is the base of the JSON lane.
    pub fn new(
        own: &str,
        hub: &str,
        base_url: &str,
        lane_url: Option<&str>,
        local_url: Option<&str>,
    ) -> anyhow::Result<Self> {
        let domain = Domain::try_from(hub.to_owned()).map_err(|e| anyhow!("--hub {hub:?}: {e}"))?;
        let own =
            Domain::try_from(own.to_owned()).map_err(|e| anyhow!("--own-domain {own:?}: {e}"))?;
        let base = BaseUrl::try_from(base_url.to_owned())
            .map_err(|e| anyhow!("--hub-url {base_url:?}: {e}"))?;
        let peer = PeerClient::new(&own, BTreeMap::from([(domain.clone(), base)]))
            .context("building the protocol client")?;
        let lane = lane_url
            .map(|url| Url::parse(url).with_context(|| format!("--lane-url {url:?}")))
            .transpose()?;
        let local = local_url
            .map(|url| Url::parse(url).with_context(|| format!("--local-url {url:?}")))
            .transpose()?;
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(LANE_TIMEOUT)
            .build()
            .context("building the JSON-lane client")?;
        Ok(Self {
            domain,
            local,
            peer,
            lane,
            http,
        })
    }

    // ---- protocol-07 wire lane ----

    /// §5.2 keyMaterial; returns the KeyMaterialResponse body.
    pub async fn key_material(&self, target: &str, body: Vec<u8>) -> anyhow::Result<Vec<u8>> {
        self.peer
            .key_material(&self.domain, target, body)
            .await
            .map_err(chain)
    }

    /// §5.3 update.
    pub async fn update(&self, room: &str, body: Vec<u8>) -> anyhow::Result<UpdateRoomResponse> {
        let body = self
            .peer
            .update(&self.domain, room, body)
            .await
            .map_err(chain)?;
        UpdateRoomResponse::tls_deserialize_exact(&body[..])
            .map_err(|e| anyhow!("the hub's UpdateRoomResponse does not decode: {e:?}"))
    }

    /// §5.3 update, requiring `success`.
    pub async fn update_ok(&self, room: &str, body: Vec<u8>) -> anyhow::Result<()> {
        let response = self.update(room, body).await?;
        match response.result {
            UpdateResult::Success { .. } => Ok(()),
            other => bail!(
                "the hub refused the update: {other:?} ({:?})",
                crate::chat::clean(response.error_description.as_str())
            ),
        }
    }

    /// §5.4 submitMessage; returns the hub's accepted timestamp.
    pub async fn submit(&self, room: &str, body: Vec<u8>) -> anyhow::Result<u64> {
        let body = self
            .peer
            .submit_message(&self.domain, room, body)
            .await
            .map_err(chain)?;
        let response = SubmitMessageResponse::tls_deserialize_exact(&body[..])
            .map_err(|e| anyhow!("the hub's SubmitMessageResponse does not decode: {e:?}"))?;
        match response.result {
            SubmitResult::Accepted {
                accepted_timestamp, ..
            } => Ok(accepted_timestamp),
            other => bail!("the hub refused the message: {other:?}"),
        }
    }

    /// §5.7 requestConsent (request or cancel), to the hub as the target's
    /// provider.
    pub async fn request_consent(&self, body: Vec<u8>) -> anyhow::Result<()> {
        self.peer
            .request_consent(&self.domain, body)
            .await
            .map_err(chain)
    }

    /// §5.7 updateConsent (grant or revoke).
    pub async fn update_consent(&self, body: Vec<u8>) -> anyhow::Result<()> {
        self.peer
            .update_consent(&self.domain, body)
            .await
            .map_err(chain)
    }

    // ---- mimi-hubd JSON lane ----

    fn lane_url(&self, path: &str, query: &[(&str, &str)]) -> anyhow::Result<Url> {
        let lane = self
            .lane
            .as_ref()
            .ok_or_else(|| anyhow!("no JSON lane (--no-lane)"))?;
        let mut url = lane.join(path).context("building a JSON-lane URL")?;
        {
            let mut pairs = url.query_pairs_mut();
            for (key, value) in query {
                pairs.append_pair(key, value);
            }
        }
        Ok(url)
    }

    async fn lane_post(
        &self,
        path: &str,
        query: &[(&str, &str)],
        body: Vec<u8>,
    ) -> anyhow::Result<()> {
        if self.lane.is_none() {
            return Ok(());
        }
        let url = self.lane_url(path, query)?;
        let response = self
            .http
            .post(url)
            .body(body)
            .send()
            .await
            .with_context(|| format!("POST {path}"))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        bail!(
            "POST {path}: {status} {}",
            text.chars().take(200).collect::<String>()
        )
    }

    /// `POST /mimi/v1/addParticipant?room=&member=`: registers a room
    /// participant, which creates the room (b4.sh does the same).
    pub async fn add_participant(&self, room: &str, member: &str) -> anyhow::Result<()> {
        self.lane_post(
            "/mimi/v1/addParticipant",
            &[("room", room), ("member", member)],
            Vec::new(),
        )
        .await
    }

    /// `POST /mimi/v1/keyMaterial/ingest?user=`: publishes a KeyPackage the
    /// wire keyMaterial route then serves.
    pub async fn publish_key_package(
        &self,
        user: &str,
        key_package: Vec<u8>,
    ) -> anyhow::Result<()> {
        self.lane_post(
            "/mimi/v1/keyMaterial/ingest",
            &[("user", user)],
            key_package,
        )
        .await
    }

    /// `POST /mimi/v1/welcome/ingest?recipient=`: queues a Welcome
    /// (an MLSMessage) for `recipient`, after the hub's suite gate.
    pub async fn relay_welcome(&self, recipient: &str, welcome: Vec<u8>) -> anyhow::Result<()> {
        self.lane_post(
            "/mimi/v1/welcome/ingest",
            &[("recipient", recipient)],
            welcome,
        )
        .await
    }

    /// `POST /mimi/v1/submitMessage?recipient=`: queues opaque bytes for
    /// `recipient`.
    pub async fn deposit(&self, recipient: &str, item: Vec<u8>) -> anyhow::Result<()> {
        self.lane_post("/mimi/v1/submitMessage", &[("recipient", recipient)], item)
            .await
    }

    async fn lane_pull(&self, path: &str, user: &str) -> anyhow::Result<Option<Vec<u8>>> {
        if self.lane.is_none() {
            return Ok(None);
        }
        let url = self.lane_url(path, &[("user", user)])?;
        let response = self
            .http
            .get(url)
            .send()
            .await
            .with_context(|| format!("GET {path}"))?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::NOT_FOUND => return Ok(None),
            status => bail!("GET {path}: {status}"),
        }
        if response
            .content_length()
            .is_some_and(|len| len > MAX_ITEM_LEN as u64)
        {
            bail!("GET {path}: item too large");
        }
        let body = response
            .bytes()
            .await
            .with_context(|| format!("GET {path}"))?;
        if body.len() > MAX_ITEM_LEN {
            bail!("GET {path}: item too large");
        }
        Ok(Some(body.to_vec()))
    }

    /// `GET /mimi/v1/message?user=`: the next queued item for `user`
    /// (deliver-once).
    pub async fn pull_message(&self, user: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.lane_pull("/mimi/v1/message", user).await
    }

    /// `GET /mimi/v1/welcome?user=`: the next queued Welcome for `user`
    /// (deliver-once).
    pub async fn pull_welcome(&self, user: &str) -> anyhow::Result<Option<Vec<u8>>> {
        self.lane_pull("/mimi/v1/welcome", user).await
    }
}

impl Hub {
    // ---- mimid's local control listener ----

    fn local_url(&self, path: &str) -> anyhow::Result<Url> {
        self.local
            .as_ref()
            .ok_or_else(|| anyhow!("no local control listener (--local-url)"))?
            .join(path)
            .context("building a local URL")
    }

    /// `GET /local/v1/hub-sender`.
    pub async fn hub_sender(&self) -> anyhow::Result<HubSender> {
        let response = self
            .http
            .get(self.local_url("/local/v1/hub-sender")?)
            .send()
            .await
            .context("GET /local/v1/hub-sender")?;
        let status = response.status();
        let text = response.text().await.unwrap_or_default();
        if status != StatusCode::OK {
            bail!("GET /local/v1/hub-sender: {status} {text}");
        }
        let value: serde_json::Value =
            serde_json::from_str(&text).context("the hub-sender answer is not JSON")?;
        let key = value["signatureKey"]
            .as_str()
            .and_then(|key| URL_SAFE_NO_PAD.decode(key).ok())
            .and_then(|key| <[u8; 32]>::try_from(key).ok())
            .ok_or_else(|| anyhow!("the hub-sender answer has no 32-byte signatureKey"))?;
        let identity = value["identity"]
            .as_str()
            .ok_or_else(|| anyhow!("the hub-sender answer has no identity"))?
            .to_owned();
        Ok(HubSender {
            signature_key: key,
            identity,
        })
    }

    /// `POST /local/v1/rooms`: has the hub host the group.
    pub async fn create_room(
        &self,
        room: &str,
        creator: &str,
        group_info: &[u8],
        ratchet_tree: &[u8],
    ) -> anyhow::Result<()> {
        let body = serde_json::json!({
            "roomId": room,
            "creator": creator,
            "groupInfo": URL_SAFE_NO_PAD.encode(group_info),
            "ratchetTree": URL_SAFE_NO_PAD.encode(ratchet_tree),
        });
        let response = self
            .http
            .post(self.local_url("/local/v1/rooms")?)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .body(body.to_string())
            .send()
            .await
            .context("POST /local/v1/rooms")?;
        let status = response.status();
        if status == StatusCode::CREATED {
            return Ok(());
        }
        let text = response.text().await.unwrap_or_default();
        bail!("POST /local/v1/rooms: {status} {text}")
    }
}

/// A PeerError with its causes, as one line.
fn chain(error: mimid_server::peer::PeerError) -> anyhow::Error {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    anyhow!(text)
}

/// The TLS encoding of `value`.
pub fn encode<T: Serialize>(value: &T) -> anyhow::Result<Vec<u8>> {
    value
        .tls_serialize_detached()
        .map_err(|e| anyhow!("TLS encoding failed: {e:?}"))
}
