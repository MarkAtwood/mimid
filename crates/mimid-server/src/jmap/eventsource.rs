//! RFC 8620 §7.3 EventSource push: `GET /jmap/eventsource` (bead
//! mimid-1wgh.11.6). draft-atwood-jmap-chat-00 requires it, and it is the
//! only push mimid offers (decision mimid-1wgh.12.30: no
//! PushSubscription).
//!
//! The query is the Session's `eventSourceUrl` template filled in:
//!
//! - `types`: `*`, or a comma-separated list of type names: `Chat`,
//!   `Message`, `ChatContact`, and `KeyPackage` when the server keeps
//!   KeyPackages (bead mimid-1wgh.12.40), whose state changes when one is
//!   created, destroyed, replaced or handed out to a keyMaterial request,
//!   and `Consent` (bead mimid-1wgh.12.43), whose state changes when one of
//!   the account's Consent records does. Names of types mimid does not serve are ignored: their state never
//!   changes.
//! - `closeafter`: `state` closes the stream after the first `state`
//!   event; `no` (the default) keeps it open.
//! - `ping`: seconds between `ping` events when nothing else is sent; `0`
//!   (the default) sends none. Other values are clamped to
//!   [`MIN_PING_SECS`]..=[`MAX_PING_SECS`] (RFC 8620 §7.3 lets the server
//!   do so), and each ping reports the interval used.
//!
//! Each change on the [`ChangeBus`](super::bus::ChangeBus) makes the stream recompute the
//! account's state strings for the requested types; when any differ from
//! the last ones sent (or, for the first, from those at connection), it
//! sends a `state` event whose data is a StateChange object (RFC 8620
//! §7.1) naming the changed types. Changes that arrive together are sent
//! as one event. No state is sent at connection: the client reads the
//! current states itself.
//!
//! # Limitations
//!
//! - Every change on the bus, for any account, makes every open stream
//!   recompute its states. Fine for a reference server; a busy one would
//!   route changes by account.
//! - Open streams are not counted against `maxConcurrentRequests`.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, Sse};
use axum::response::{IntoResponse, Response};
use serde_json::json;
use tokio::sync::broadcast::error::{RecvError, TryRecvError};
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;

use super::JmapState;
use super::auth::Account;
use super::projection::{Kind, Projection};
use crate::follower::key_packages::KeyPackages;
use crate::http::problem;
use crate::store::Store;

/// The shortest ping interval honoured, in seconds. INVENTED, NOT FROM
/// SPEC.
pub const MIN_PING_SECS: u64 = 10;

/// The longest ping interval honoured, in seconds. INVENTED, NOT FROM
/// SPEC.
pub const MAX_PING_SECS: u64 = 3_600;

/// Events buffered for a slow client before the stream waits for it.
const EVENT_BUFFER: usize = 16;

/// The parsed query of an EventSource request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Params {
    kinds: Vec<Kind>,
    /// Whether `KeyPackage` is among the types (bead mimid-1wgh.12.40).
    key_packages: bool,
    /// Whether `Consent` is among the types (bead mimid-1wgh.12.43).
    consent: bool,
    close_after_state: bool,
    ping: Option<Duration>,
}

impl Params {
    /// The types of the live stream's `Changed` (docs/design/binary-live-stream.md
    /// §5.6): `Chat`, `KeyPackage` and `Consent`. Messages arrive as
    /// `Deliver`s instead.
    pub(super) fn live_notices() -> Self {
        Self {
            kinds: vec![Kind::Chat],
            key_packages: true,
            consent: true,
            close_after_state: false,
            ping: None,
        }
    }

    /// Reads the query, or `None` if a parameter is malformed.
    fn parse(query: &BTreeMap<String, String>) -> Option<Self> {
        let (kinds, key_packages, consent) = match query.get("types").map(String::as_str) {
            None | Some("*") => (Kind::ALL.to_vec(), true, true),
            Some(list) => {
                let names: Vec<&str> = list.split(',').collect();
                if names.iter().any(|name| name.is_empty()) {
                    return None;
                }
                (
                    Kind::ALL
                        .into_iter()
                        .filter(|kind| names.contains(&kind.name()))
                        .collect(),
                    names.contains(&"KeyPackage"),
                    names.contains(&"Consent"),
                )
            }
        };
        let close_after_state = match query.get("closeafter").map(String::as_str) {
            None | Some("no") => false,
            Some("state") => true,
            Some(_) => return None,
        };
        let ping = match query.get("ping") {
            None => 0,
            Some(text) => text.parse::<u64>().ok()?,
        };
        let ping =
            (ping > 0).then(|| Duration::from_secs(ping.clamp(MIN_PING_SECS, MAX_PING_SECS)));
        Some(Self {
            kinds,
            key_packages,
            consent,
            close_after_state,
            ping,
        })
    }
}

/// `GET /jmap/eventsource`.
pub(super) async fn get_eventsource(
    State(state): State<JmapState>,
    account: Account,
    Query(query): Query<BTreeMap<String, String>>,
) -> Response {
    let Some(params) = Params::parse(&query) else {
        tracing::debug!(?query, "eventsource request refused");
        return problem(StatusCode::BAD_REQUEST, "eventsource-query");
    };
    // Subscribe and read the states the first event is measured against
    // before answering, so that a change made after the client has its
    // answer (and reads the current states itself) is always sent.
    let changes = state.0.bus.subscribe();
    let last = match states(
        &state.0.projection,
        state.0.key_packages.as_deref(),
        &state.0.store,
        &account,
        &params,
    )
    .await
    {
        Ok(states) => states,
        Err(error) => {
            tracing::error!(
                name: "jmap_eventsource_state_failed",
                error = &error as &dyn std::error::Error,
                "eventsource could not read the account's states"
            );
            return problem(StatusCode::INTERNAL_SERVER_ERROR, "eventsource-state");
        }
    };
    let (sender, receiver) = mpsc::channel(EVENT_BUFFER);
    tokio::spawn(stream(
        state.clone(),
        account,
        params,
        changes,
        last,
        sender,
    ));
    Sse::new(ReceiverStream::new(receiver)).into_response()
}

/// Why the account's states could not be read.
#[derive(Debug, thiserror::Error)]
pub(super) enum StateError {
    #[error(transparent)]
    Projection(#[from] super::projection::ProjectionError),
    #[error(transparent)]
    Store(#[from] crate::store::StoreError),
}

/// The account's state strings for the requested types. `KeyPackage` is
/// included only when requested and the server keeps KeyPackages.
pub(super) async fn states(
    projection: &Projection,
    key_packages: Option<&KeyPackages>,
    store: &Store,
    account: &Account,
    params: &Params,
) -> Result<BTreeMap<&'static str, String>, StateError> {
    let mut states = BTreeMap::new();
    for kind in &params.kinds {
        states.insert(kind.name(), projection.state(*kind, account).await?);
    }
    if params.key_packages
        && let Some(key_packages) = key_packages
    {
        states.insert(
            "KeyPackage",
            super::methods::key_package::key_package_state(key_packages, account).await?,
        );
    }
    if params.consent {
        states.insert(
            "Consent",
            store
                .consent_state(account.user().as_str())
                .await?
                .to_string(),
        );
    }
    Ok(states)
}

/// Sends events until the client goes away, the bus closes, or, with
/// `closeafter=state`, the first `state` event is sent. `changes` was
/// subscribed before `last` was read, so no change falls between.
async fn stream(
    state: JmapState,
    account: Account,
    params: Params,
    mut changes: tokio::sync::broadcast::Receiver<super::bus::Change>,
    mut last: BTreeMap<&'static str, String>,
    sender: mpsc::Sender<Result<Event, Infallible>>,
) {
    let projection = Arc::clone(&state.0.projection);
    let key_packages = state.0.key_packages.clone();
    let store = state.0.store.clone();
    let mut stop = state.0.stop.clone();
    // The next ping is due one interval after the last event sent.
    let mut ping_due = params
        .ping
        .map(|interval| tokio::time::Instant::now() + interval);
    loop {
        let ping = async {
            match ping_due {
                Some(due) => tokio::time::sleep_until(due).await,
                None => std::future::pending().await,
            }
        };
        let stopping = async {
            match stop.as_mut() {
                // A dropped sender means no shutdown is coming.
                Some(stop) => {
                    if stop.wait_for(|stopping| *stopping).await.is_err() {
                        std::future::pending::<()>().await;
                    }
                }
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            () = sender.closed() => return,
            () = stopping => return,
            () = ping => {
                let interval = params.ping.map_or(0, |p| p.as_secs());
                let event = Event::default().event("ping").data(json!({"interval": interval}).to_string());
                if sender.send(Ok(event)).await.is_err() {
                    return;
                }
                ping_due = params.ping.map(|interval| tokio::time::Instant::now() + interval);
            }
            received = changes.recv() => {
                if matches!(received, Err(RecvError::Closed)) {
                    return;
                }
                // Coalesce what has already arrived; a lag only means the
                // states must be recomputed, which they are.
                while matches!(changes.try_recv(), Ok(_) | Err(TryRecvError::Lagged(_))) {}
                let now = match states(&projection, key_packages.as_deref(), &store, &account, &params).await {
                    Ok(states) => states,
                    Err(error) => {
                        tracing::error!(
                            name: "jmap_eventsource_state_failed",
                            error = &error as &dyn std::error::Error,
                            "eventsource could not read the account's states"
                        );
                        return;
                    }
                };
                let changed: BTreeMap<&str, &String> = now
                    .iter()
                    .filter(|(kind, state)| last.get(*kind) != Some(*state))
                    .map(|(kind, state)| (*kind, state))
                    .collect();
                if changed.is_empty() {
                    continue;
                }
                // RFC 8620 §7.1.
                let data = json!({
                    "@type": "StateChange",
                    "changed": { account.account_id(): changed },
                });
                let event = Event::default().event("state").data(data.to_string());
                if sender.send(Ok(event)).await.is_err() || params.close_after_state {
                    return;
                }
                last = now;
                ping_due = params.ping.map(|interval| tokio::time::Instant::now() + interval);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    #[test]
    fn the_query_follows_rfc_8620_section_7_3() {
        assert_eq!(
            Params::parse(&query(&[
                ("types", "*"),
                ("closeafter", "no"),
                ("ping", "0")
            ])),
            Some(Params {
                kinds: Kind::ALL.to_vec(),
                key_packages: true,
                consent: true,
                close_after_state: false,
                ping: None
            })
        );
        assert_eq!(
            Params::parse(&query(&[
                ("types", "Message,Email,Chat"),
                ("closeafter", "state"),
                ("ping", "300")
            ])),
            Some(Params {
                kinds: vec![Kind::Chat, Kind::Message],
                key_packages: false,
                consent: false,
                close_after_state: true,
                ping: Some(Duration::from_secs(300))
            })
        );
        let clamped = |ping: &str| Params::parse(&query(&[("ping", ping)])).unwrap().ping;
        assert_eq!(clamped("1"), Some(Duration::from_secs(MIN_PING_SECS)));
        assert_eq!(clamped("999999"), Some(Duration::from_secs(MAX_PING_SECS)));
        for bad in [
            query(&[("closeafter", "maybe")]),
            query(&[("ping", "-1")]),
            query(&[("ping", "soon")]),
            query(&[("types", "Chat,,Message")]),
        ] {
            assert_eq!(Params::parse(&bad), None, "{bad:?}");
        }
    }
}
