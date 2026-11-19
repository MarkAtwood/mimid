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
//!   ([`blobs`]).
//!
//! The upload route's body limit is [`blobs::MAX_BLOB_LEN`];
//! every other JMAP route has a body limit of [`api::MAX_SIZE_REQUEST`]
//! (decision mimid-1wgh.12.36). [`auth`] authenticates bearer tokens and is
//! the endpoint's only authorization point (AGENTS.md, security
//! invariants). [`bus`] carries the changes that move JMAP state.
//!
//! # Limitations
//!
//! - Blobs are never deleted ([`blobs`]).
//! - Push is EventSource only: there is no PushSubscription (decision
//!   mimid-1wgh.12.30).
//! - Besides `Core/echo`, the read projection ([`projection`]),
//!   `Chat/set` of `privateMetadata` only ([`metadata`]; decision
//!   mimid-1wgh.63), the refusing `Message/set`, `KeyPackage/get`,
//!   `KeyPackage/set`, `KeyMaterial/fetch`, `Room/create`, `Room/update`,
//!   `Room/send`, `Room/unbind` and `GroupInfo/fetch` are implemented; every other method answers
//!   `unknownMethod` until its bead lands.

pub mod api;
pub mod auth;
pub mod blobs;
pub mod bus;
mod eventsource;
pub mod language;
pub mod metadata;
mod methods;
pub mod projection;
pub mod session;

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRef};
use axum::routing::{get, post};
use jmap_server::Dispatcher;

use crate::config::BaseUrl;
use crate::follower::Follower;
use crate::hub::{Hub, HubError};
use crate::store::Store;
use api::{InFlight, Methods};
use auth::{Account, Authenticator};
use bus::ChangeBus;
use methods::Services;
use session::{DEFAULT_MAX_KEY_PACKAGES, SessionTemplate};

/// Settings of the JMAP endpoint.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct JmapOptions {
    /// `maxKeyPackages` (draft-atwood-jmap-chat-mimi-00 L166).
    pub max_key_packages: u64,
    /// Becomes `true` when the server starts shutting down: open
    /// EventSource streams then end, so a graceful shutdown does not wait
    /// on them forever. `None`: they end only when their clients leave.
    pub stop: Option<tokio::sync::watch::Receiver<bool>>,
}

impl Default for JmapOptions {
    fn default() -> Self {
        Self {
            max_key_packages: DEFAULT_MAX_KEY_PACKAGES,
            stop: None,
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
    let session = SessionTemplate::new(
        base_url,
        hub.domain(),
        &hub.hub_sender()?,
        options.max_key_packages,
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
    let mut methods = Methods::new();
    methods::register_all(
        &mut methods,
        &Services {
            store: store.clone(),
            hub: Arc::clone(&hub),
            follower,
            bus: bus.clone(),
            projection: Arc::clone(&projection),
            max_key_packages: options.max_key_packages,
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
    }));
    Ok(Router::new()
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
