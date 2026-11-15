//! RFC 8620 §7.3 EventSource push: `GET /jmap/eventsource` (bead
//! mimid-1wgh.11.6). draft-atwood-jmap-chat-00 requires it, and it is the
//! only push mimid offers (decision mimid-1wgh.12.30: no
//! PushSubscription).
//!
//! The query is the Session's `eventSourceUrl` template filled in:
//!
//! - `types`: `*`, or a comma-separated list of type names. Names of types
//!   mimid does not serve are ignored: their state never changes.
//! - `closeafter`: `state` closes the stream after the first `state`
//!   event; `no` (the default) keeps it open.
//! - `ping`: seconds between `ping` events when nothing else is sent; `0`
//!   (the default) sends none. Other values are clamped to
//!   [`MIN_PING_SECS`]..=[`MAX_PING_SECS`] (RFC 8620 §7.3 lets the server
//!   do so), and each ping reports the interval used.
//!
//! Each change on the [`ChangeBus`] makes the stream recompute the
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
use super::bus::ChangeBus;
use super::projection::{Kind, Projection};
use crate::http::problem;

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
struct Params {
    kinds: Vec<Kind>,
    close_after_state: bool,
    ping: Option<Duration>,
}

impl Params {
    /// Reads the query, or `None` if a parameter is malformed.
    fn parse(query: &BTreeMap<String, String>) -> Option<Self> {
        let kinds = match query.get("types").map(String::as_str) {
            None | Some("*") => Kind::ALL.to_vec(),
            Some(list) => {
                let names: Vec<&str> = list.split(',').collect();
                if names.iter().any(|name| name.is_empty()) {
                    return None;
                }
                Kind::ALL
                    .into_iter()
                    .filter(|kind| names.contains(&kind.name()))
                    .collect()
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
    let (sender, receiver) = mpsc::channel(EVENT_BUFFER);
    tokio::spawn(stream(
        Arc::clone(&state.0.projection),
        state.0.bus.clone(),
        account,
        params,
        sender,
    ));
    Sse::new(ReceiverStream::new(receiver)).into_response()
}

/// The account's state strings for `kinds`.
async fn states(
    projection: &Projection,
    account: &Account,
    kinds: &[Kind],
) -> Result<BTreeMap<&'static str, String>, super::projection::ProjectionError> {
    let mut states = BTreeMap::new();
    for kind in kinds {
        states.insert(kind.name(), projection.state(*kind, account).await?);
    }
    Ok(states)
}

/// Sends events until the client goes away, the bus closes, or, with
/// `closeafter=state`, the first `state` event is sent.
async fn stream(
    projection: Arc<Projection>,
    bus: ChangeBus,
    account: Account,
    params: Params,
    sender: mpsc::Sender<Result<Event, Infallible>>,
) {
    // Subscribe before reading the states, so no change falls between.
    let mut changes = bus.subscribe();
    let mut last = match states(&projection, &account, &params.kinds).await {
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
        tokio::select! {
            () = sender.closed() => return,
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
                let now = match states(&projection, &account, &params.kinds).await {
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
