//! The provider's JMAP Chat endpoint (mimid-1wgh.11; plan of
//! mimid-1wgh.12).
//!
//! [`router`] serves it on the protocol listener (decision
//! mimid-1wgh.12.28):
//!
//! - `GET /.well-known/jmap`: the Session ([`session`]; RFC 8620 §2.2);
//! - `POST /jmap/api`: the API ([`api`]; RFC 8620 §3);
//! - `GET /jmap/eventsource`: EventSource push (RFC 8620 §7.3);
//! - `POST /jmap/upload/{accountId}/` and
//!   `GET /jmap/download/{accountId}/{blobId}/{name}`: blobs (RFC 8620 §6;
//!   [`blobs`]);
//! - `GET /assets/{blobId}`: the asset server, unauthenticated, at the
//!   `assetUrl` template ([`blobs`]);
//! - `GET /jmap/asset/{accountId}?room=&url=`: a user's fetch of an
//!   attachment from any provider, at the `assetDownloadUrl` template
//!   ([`blobs`]);
//! - `GET /mimid/live`, only with [`JmapOptions::live_stream`]: the live
//!   stream, mimid's second binding of the same operations over CBOR on
//!   a WebSocket (module `live`; docs/design/binary-live-stream.md).
//!
//! The upload route's body limit is [`blobs::MAX_BLOB_LEN`];
//! every other JMAP route has a body limit of [`api::MAX_SIZE_REQUEST`]
//! (decision mimid-1wgh.12.36). [`auth`] authenticates bearer tokens and is
//! the endpoint's only authorization point (AGENTS.md, security
//! invariants); the live stream's hello goes through the same check.
//! [`bus`] carries the changes that move JMAP state.
//!
//! # Limitations
//!
//! - A blob is deleted a fixed lifetime after upload, whether or not a
//!   message still names it: the server cannot read messages
//!   ([`blobs::BlobSweeper`]; decision mimid-1wgh.67).
//! - Push is EventSource only: there is no PushSubscription (decision
//!   mimid-1wgh.12.30).
//! - Besides `Core/echo`, the read projection ([`projection`]),
//!   `Chat/set` of `privateMetadata` only ([`metadata`]; decision
//!   mimid-1wgh.63), the refusing `Message/set`, `KeyPackage/get`,
//!   `KeyPackage/set`, `KeyMaterial/fetch`, `Room/create`, `Room/update`,
//!   `Room/send`, `Room/unbind`, `GroupInfo/fetch` and the blobext-03
//!   `Blob/get`, `Blob/set`, `Blob/lookup` and `Blob/convert` (decision
//!   mimid-1wgh.69) are implemented; every other method answers
//!   `unknownMethod` until its bead lands.

pub mod api;
pub mod auth;
pub mod blobs;
pub mod bus;
mod eventsource;
pub mod language;
mod live;
pub mod metadata;
mod methods;
pub mod projection;
pub mod rate;
pub mod session;

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRef};
use axum::routing::{get, post};
use jmap_server::Dispatcher;

use crate::config::BaseUrl;
use crate::follower::Follower;
use crate::hub::{Clock, Hub, HubError, SystemClock};
use crate::store::{BlobQuota, Store};
use api::{InFlight, Methods};
use auth::{Account, Authenticator};
use bus::ChangeBus;
use methods::Services;
use session::{DEFAULT_MAX_KEY_PACKAGES, SessionTemplate};

/// `error` and each of its sources, joined by `": "`: the `description`
/// or `errorDescription` of a refusal, saying which check failed
/// (draft-atwood-jmap-chat-mimi-00 §capability; clean-room finding C5).
/// Only for errors that carry no secret and no store detail.
pub(crate) fn error_chain(error: &(dyn std::error::Error + 'static)) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        let cause_text = cause.to_string();
        // Some errors repeat their source's text in their own.
        if !text.ends_with(&cause_text) {
            text.push_str(": ");
            text.push_str(&cause_text);
        }
        source = cause.source();
    }
    text
}

/// The part of a protocol body ([`crate::http::MAX_BODY_LEN`]) kept for
/// the envelope around an MLS object on its way to and from the hub, so
/// that an object of [`MAX_MLS_OBJECT_SIZE`] still fits once wrapped
/// (bead mimid-e64f.18). INVENTED, NOT FROM SPEC.
///
/// The envelopes, in protocol-07 octets beyond the object:
///
/// - `SubmitMessageRequest` (Room/send): 1 (`protocol`) + up to 4
///   (length of `sendingUri`) + the user URI.
/// - `UpdateRequest` (Room/update): 0; the argument is the whole request.
/// - `FanoutMessage`: 8 (`timestamp`) + 1 (an empty `external_proposals`)
///   for a Commit; 8 for a Proposal and its `more_proposals`, all from
///   the request; 8 + 1 + 99 (`Frank`: 32 + 2 + 1 + a 64-octet Ed25519
///   signature, the hub's only scheme) = 108 for an application message.
///
/// The largest, a Room/send's, is 5 octets plus the user URI, so 64 KiB
/// covers any user URI shorter than 65 531 octets.
pub const MLS_OBJECT_ENVELOPE_ALLOWANCE: usize = 64 * 1024;

/// `maxMlsObjectSize` (findings log F10): the largest MLS or MIMI
/// structure, in octets before base64url, that any argument of the mimi
/// methods may carry, on JMAP and on the live stream alike (decision
/// mimid-1wgh.78, as updated for F10). The protocol routes' body cap
/// ([`crate::http::MAX_BODY_LEN`], 4 MiB) less
/// [`MLS_OBJECT_ENVELOPE_ALLOWANCE`] (64 KiB), 4 128 768 octets, so that
/// an object at the limit passes the relay and its fanout passes
/// `/notify` (bead mimid-e64f.18). INVENTED, NOT FROM SPEC: the draft
/// names the property, not its value.
pub const MAX_MLS_OBJECT_SIZE: usize = crate::http::MAX_BODY_LEN - MLS_OBJECT_ENVELOPE_ALLOWANCE;

/// The most MLS or MIMI structures one method call carries: `Room/create`'s
/// `groupInfo` and `ratchetTree`. The request limits of both bindings
/// ([`api::MAX_SIZE_REQUEST`], [`mimid_live::MAX_REQUEST_BYTES`]) fit that
/// many objects of [`MAX_MLS_OBJECT_SIZE`], so the per-object limit is the
/// one a client meets.
pub const MAX_MLS_OBJECTS_PER_CALL: usize = 2;

const _: () =
    assert!(mimid_live::MAX_REQUEST_BYTES >= MAX_MLS_OBJECTS_PER_CALL * MAX_MLS_OBJECT_SIZE);

/// Settings of the JMAP endpoint.
#[derive(Clone)]
#[non_exhaustive]
pub struct JmapOptions {
    /// `maxKeyPackages` (draft-atwood-jmap-chat-mimi-00 L166).
    pub max_key_packages: u64,
    /// Becomes `true` when the server starts shutting down: open
    /// EventSource streams then end, so a graceful shutdown does not wait
    /// on them forever. `None`: they end only when their clients leave.
    pub stop: Option<tokio::sync::watch::Receiver<bool>>,
    /// The clock that stamps uploads with their time (and so their
    /// expiry, [`blobs::BlobSweeper`]). The system clock by default.
    pub clock: Arc<dyn Clock>,
    /// The limits every upload is checked against;
    /// [`BlobQuota::default`] by default.
    pub blob_quota: BlobQuota,
    /// How long, in seconds, a blob stays at `assetUrl` after its upload,
    /// advertised as the mimi capability's `assetLifetime`
    /// (draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object,
    /// jmap-chat-spec 120db2c). It states what a [`blobs::BlobSweeper`]
    /// enforces, so whoever runs the sweeper sets it to the sweeper's
    /// lifetime; the router does not sweep. `None` (the default):
    /// `assetLifetime` is left out, as for a server that deletes nothing.
    pub asset_lifetime: Option<u64>,
    /// How long, in seconds, the server keeps a Message after storing it,
    /// advertised as the mimi capability's `messageRetention` and in the
    /// live stream's `ProviderHello` (draft-atwood-jmap-chat-mimi-00
    /// §Account-Level Capability Object; decision mimid-1wgh.82). It
    /// states what a [`crate::retention::MessageSweeper`] enforces, so
    /// whoever runs the sweeper sets it to the sweeper's retention; the
    /// router does not sweep. `None` (the default): `messageRetention` is
    /// left out, as for a server that keeps Messages forever.
    pub message_retention: Option<u64>,
    /// The per-account limit on `KeyMaterial/fetch`, on both bindings
    /// ([`rate`]; bead mimid-e64f.21), or `None` for none.
    /// [`rate::DEFAULT_KEY_MATERIAL_LIMIT`] by default.
    pub key_material_limit: Option<rate::RateLimit>,
    /// Whether to serve the live stream at [`mimid_live::PATH`]
    /// (module `live`; decision mimid-1wgh.80). `false` by default.
    pub live_stream: bool,
}

impl std::fmt::Debug for JmapOptions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("JmapOptions")
            .field("max_key_packages", &self.max_key_packages)
            .field("stop", &self.stop)
            .field("blob_quota", &self.blob_quota)
            .field("asset_lifetime", &self.asset_lifetime)
            .field("message_retention", &self.message_retention)
            .field("key_material_limit", &self.key_material_limit)
            .field("live_stream", &self.live_stream)
            .finish_non_exhaustive()
    }
}

impl Default for JmapOptions {
    fn default() -> Self {
        Self {
            max_key_packages: DEFAULT_MAX_KEY_PACKAGES,
            stop: None,
            clock: Arc::new(SystemClock),
            blob_quota: BlobQuota::default(),
            asset_lifetime: None,
            message_retention: None,
            key_material_limit: Some(rate::DEFAULT_KEY_MATERIAL_LIMIT),
            live_stream: false,
        }
    }
}

/// The state the JMAP routes share.
#[derive(Clone)]
struct JmapState(Arc<Inner>);

struct Inner {
    authenticator: Authenticator,
    session: SessionTemplate,
    dispatcher: Dispatcher<Account>,
    in_flight: InFlight,
    projection: Arc<projection::Projection>,
    bus: ChangeBus,
    key_packages: Option<Arc<crate::follower::key_packages::KeyPackages>>,
    store: Store,
    stop: Option<tokio::sync::watch::Receiver<bool>>,
    /// This server's base URL, for its own asset URLs.
    base_url: BaseUrl,
    /// The hub, for attachment fetches ([`blobs`]).
    hub: Arc<Hub>,
    /// Uploads in flight per account ([`blobs::MAX_CONCURRENT_UPLOAD`]).
    uploads: InFlight,
    /// Stamps uploads.
    clock: Arc<dyn Clock>,
    /// Limits uploads.
    blob_quota: BlobQuota,
    /// The follower, for the live stream's operations.
    follower: Arc<Follower>,
    /// `maxKeyPackages`.
    max_key_packages: u64,
    /// The hub's ExternalSender, TLS-encoded (`hubSender`).
    hub_sender: Vec<u8>,
    /// `assetLifetime`.
    asset_lifetime: Option<u64>,
    /// `messageRetention`.
    message_retention: Option<u64>,
    /// The `KeyMaterial/fetch` limit both bindings share.
    key_material_limiter: Option<rate::RateLimiter>,
}

impl FromRef<JmapState> for Authenticator {
    fn from_ref(state: &JmapState) -> Self {
        state.0.authenticator.clone()
    }
}

/// Builds the JMAP router for a server reachable at `base_url`, to be
/// merged into the protocol router. It authenticates against `store` for
/// users of the hub's domain, and starts forwarding the follower's stored
/// events to the change bus.
///
/// # Errors
///
/// Returns the error of [`Hub::hub_sender`].
///
/// # Panics
///
/// Panics if called outside a Tokio runtime, since it spawns the
/// forwarding task.
pub fn router(
    base_url: &BaseUrl,
    store: Store,
    hub: Arc<Hub>,
    follower: Arc<Follower>,
    options: JmapOptions,
) -> Result<Router, HubError> {
    let hub_sender = hub.hub_sender()?;
    let session = SessionTemplate::new(
        base_url,
        hub.domain(),
        &hub_sender,
        options.max_key_packages,
        options.asset_lifetime,
        options.message_retention,
        follower
            .key_packages()
            .and_then(|key_packages| key_packages.max_clients()),
        methods::blob::blob_capability(&options.blob_quota),
        options.live_stream,
    );
    let bus = ChangeBus::new();
    bus.forward(follower.subscribe());
    bus.forward_membership(follower.subscribe_membership());
    bus.forward_consent(follower.subscribe_consent());
    let key_packages = follower.key_packages().cloned();
    if let Some(key_packages) = &key_packages {
        bus.forward_key_packages(key_packages.subscribe_changes());
    }
    let authenticator = Authenticator::new(store.clone(), hub.domain().clone());
    let projection = Arc::new(projection::Projection::new(store.clone(), Arc::clone(&hub)));
    let key_material_limiter = options
        .key_material_limit
        .filter(|limit| limit.burst > 0)
        .map(|limit| rate::RateLimiter::new(limit, Arc::clone(&options.clock)));
    let mut methods = Methods::new();
    methods::register_all(
        &mut methods,
        &Services {
            store: store.clone(),
            hub: Arc::clone(&hub),
            follower: Arc::clone(&follower),
            bus: bus.clone(),
            projection: Arc::clone(&projection),
            max_key_packages: options.max_key_packages,
            clock: Arc::clone(&options.clock),
            blob_quota: options.blob_quota,
            asset_lifetime: options.asset_lifetime,
            key_material_limiter: key_material_limiter.clone(),
        },
    );
    let state = JmapState(Arc::new(Inner {
        authenticator,
        session,
        dispatcher: methods.into_dispatcher(),
        in_flight: InFlight::default(),
        projection,
        bus,
        key_packages,
        store,
        stop: options.stop,
        base_url: base_url.clone(),
        hub: Arc::clone(&hub),
        uploads: InFlight::with_limit(blobs::MAX_CONCURRENT_UPLOAD),
        clock: options.clock,
        blob_quota: options.blob_quota,
        follower,
        max_key_packages: options.max_key_packages,
        hub_sender,
        asset_lifetime: options.asset_lifetime,
        message_retention: options.message_retention,
        key_material_limiter,
    }));
    let mut router = Router::new();
    if options.live_stream {
        router = router.route(mimid_live::PATH, get(live::get_live));
    }
    Ok(router
        .route("/.well-known/jmap", get(session::get_session))
        .route("/jmap/api", post(api::post_api))
        .route("/jmap/eventsource", get(eventsource::get_eventsource))
        // The route's own limit replaces the router's for uploads.
        .route(
            "/jmap/upload/{accountId}/",
            post(blobs::upload).layer(DefaultBodyLimit::max(blobs::MAX_BLOB_LEN)),
        )
        .route(
            "/jmap/download/{accountId}/{blobId}/{name}",
            get(blobs::download),
        )
        .route("/jmap/asset/{accountId}", get(blobs::fetch_asset))
        .route("/assets/{blobId}", get(blobs::asset))
        .layer(DefaultBodyLimit::max(api::MAX_SIZE_REQUEST))
        .with_state(state))
}
