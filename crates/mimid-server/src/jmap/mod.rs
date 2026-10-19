//! The provider's JMAP Chat endpoint (mimid-1wgh.11; plan of
//! mimid-1wgh.12).
//!
//! [`router`] serves it on the protocol listener (decision
//! mimid-1wgh.12.28):
//!
//! - `GET /.well-known/jmap`: the Session ([`session`]; RFC 8620 §2.2);
//! - `POST /jmap/api`: the API ([`api`]; RFC 8620 §3);
//! - `POST /jmap/upload/{accountId}/` and
//!   `GET /jmap/download/{accountId}/{blobId}/{name}`: always `404`.
//!
//! Every JMAP route has a body limit of [`api::MAX_SIZE_REQUEST`]
//! (decision mimid-1wgh.12.36). [`auth`] authenticates bearer tokens and is
//! the endpoint's only authorization point (AGENTS.md, security
//! invariants). [`bus`] carries the changes that move JMAP state.
//!
//! # Limitations
//!
//! - No blobs: upload and download answer `404`.
//! - No push yet: the Session's `eventSourceUrl` is advertised, since
//!   RFC 8620 §2 requires it, but answers `404` until EventSource
//!   (mimid-1wgh.11.6) lands. There is no PushSubscription (decision
//!   mimid-1wgh.12.30).
//! - Only `Core/echo` is implemented; every other method answers
//!   `unknownMethod` until its bead lands.

pub mod api;
pub mod auth;
pub mod bus;
mod methods;
pub mod session;

use std::sync::Arc;

use axum::Router;
use axum::extract::{DefaultBodyLimit, FromRef};
use axum::http::StatusCode;
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
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct JmapOptions {
    /// `maxKeyPackages` (draft-atwood-jmap-chat-mimi-00 L166).
    pub max_key_packages: u64,
}

impl Default for JmapOptions {
    fn default() -> Self {
        Self {
            max_key_packages: DEFAULT_MAX_KEY_PACKAGES,
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
    let authenticator = Authenticator::new(store.clone(), hub.domain().clone());
    let mut methods = Methods::new();
    methods::register_all(
        &mut methods,
        &Services {
            store,
            hub,
            follower,
            bus,
        },
    );
    let state = JmapState(Arc::new(Inner {
        authenticator,
        session,
        dispatcher: methods.into_dispatcher(),
        in_flight: InFlight::default(),
    }));
    Ok(Router::new()
        .route("/.well-known/jmap", get(session::get_session))
        .route("/jmap/api", post(api::post_api))
        .route("/jmap/upload/{accountId}/", post(no_blobs))
        .route("/jmap/download/{accountId}/{blobId}/{name}", get(no_blobs))
        .layer(DefaultBodyLimit::max(api::MAX_SIZE_REQUEST))
        .with_state(state))
}

/// Upload and download: there are no blobs.
async fn no_blobs() -> StatusCode {
    StatusCode::NOT_FOUND
}
