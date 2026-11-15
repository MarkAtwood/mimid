//! Local control routes: a loopback-only listener for operator and test
//! actions that have no client protocol path yet (bead mimid-1wgh.47, the
//! sideband control path). The first route is a narrow room creation
//! (bead mimid-1wgh.12.4, the interim before JMAP `Room/create`), so a
//! room hosted here can be tested against another provider.
//!
//! The listener is off unless the configuration names `local_listen`, and
//! the server refuses to start if that address is not a loopback address.
//! Without `local_token`, nothing authenticates the caller: anyone who can
//! reach the loopback interface of the host can use it. With it, every call
//! must carry `Authorization: Bearer <local_token>`, and any other is a
//! `401` (decision 2 of bead mimid-1wgh.47, for hosts where others have
//! shells).
//!
//! Routes:
//!
//! - `GET /local/v1/hub-sender`: the hub's external-sender identity, as
//!   `{"signatureKey": <base64url>, "identity": "mimi://<domain>"}`. A
//!   client needs it to build a group this hub will host: the group's
//!   `external_senders` and `franking_agent` name the hub (see
//!   [`Hub::create_room`]).
//! - `POST /local/v1/rooms`: `{"roomId", "creator", "groupInfo",
//!   "ratchetTree"}`, the last two base64url without padding. Calls
//!   [`Hub::create_room`] and answers `201` with `{"roomId"}`. A room ID
//!   that is malformed or under another domain is `400`; a room or group
//!   that already exists is `409`; a group that breaks a hub rule is `422`;
//!   any other failure is `500`. Errors are RFC 9457 problem bodies with
//!   only `type` and `status`, as everywhere else in mimid; the reason is
//!   logged.
//! - `GET /local/v1/rooms`: every hosted room, as `{"rooms": [summary,
//!   ...]}` ordered by room ID (bead mimid-1wgh.47.2).
//! - `GET /local/v1/rooms/{roomId}`: one room's summary, the room ID
//!   percent-encoded as one path segment; `404` if it is not hosted here.
//!
//! A room summary is `{"roomId", "groupId", "epoch", "members",
//! "participants", "roles"}`: `groupId` base64url without padding;
//! `members` a list of `{"leaf", "identity"}`; `participants` a list of
//! `{"user", "role"}` from `participant_list`, and `roles` a list of
//! `{"index", "name"}` from `roles_list`, each `null` when the room has no
//! such component or it does not decode. Identities, users and role names
//! are JSON strings when they are UTF-8, else `{"base64url": ...}`; they
//! are opaque in the drafts.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{Path, Request, State};
use axum::http::{StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
use sha2::{Digest, Sha256};

use crate::http::problem;
use crate::hub::{Hub, HubError, RoomSummary};

/// The fewest characters a `local_token` may have. INVENTED, NOT FROM
/// SPEC: 32 characters of a random token are enough that guessing is not a
/// concern.
pub const MIN_LOCAL_TOKEN_LEN: usize = 32;

/// The bearer token the local control listener requires, from the
/// configuration's `local_token`. `Debug` does not print it.
#[derive(Clone, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub struct LocalToken(String);

impl std::fmt::Debug for LocalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalToken(..)")
    }
}

/// Why a `local_token` was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("local_token must be at least {MIN_LOCAL_TOKEN_LEN} visible ASCII characters")]
pub struct InvalidLocalToken;

impl TryFrom<String> for LocalToken {
    type Error = InvalidLocalToken;

    fn try_from(token: String) -> Result<Self, Self::Error> {
        if token.len() >= MIN_LOCAL_TOKEN_LEN && token.bytes().all(|b| b.is_ascii_graphic()) {
            Ok(Self(token))
        } else {
            Err(InvalidLocalToken)
        }
    }
}

impl LocalToken {
    /// Whether `presented` is this token. The digests are compared, so the
    /// comparison's time says nothing about the token.
    fn matches(&self, presented: &str) -> bool {
        Sha256::digest(presented.as_bytes()) == Sha256::digest(self.0.as_bytes())
    }
}

/// The local control router. With `token`, every route requires it.
pub fn router(hub: Arc<Hub>, token: Option<LocalToken>) -> Router {
    let routes = Router::new()
        .route("/local/v1/hub-sender", get(hub_sender))
        .route("/local/v1/rooms", post(create_room).get(list_rooms))
        .route("/local/v1/rooms/{room_id}", get(get_room))
        .with_state(hub);
    match token {
        Some(token) => routes.layer(middleware::from_fn_with_state(
            Arc::new(token),
            require_token,
        )),
        None => routes,
    }
}

/// Refuses a call without `Authorization: Bearer <token>`.
async fn require_token(
    State(token): State<Arc<LocalToken>>,
    request: Request,
    next: Next,
) -> Response {
    let presented = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));
    if presented.is_some_and(|presented| token.matches(presented)) {
        next.run(request).await
    } else {
        // A correct refusal: DEBUG only (the server works as designed).
        tracing::debug!(
            path = request.uri().path(),
            presented = presented.is_some(),
            "local control call refused: no valid local_token"
        );
        problem(StatusCode::UNAUTHORIZED, "unauthorized")
    }
}

async fn hub_sender(State(hub): State<Arc<Hub>>) -> Response {
    Json(serde_json::json!({
        "signatureKey": URL_SAFE_NO_PAD.encode(hub.signature_public_key()),
        "identity": format!("mimi://{}", hub.domain()),
    }))
    .into_response()
}

/// Opaque bytes as JSON: a string when UTF-8, else base64url.
fn opaque(bytes: &[u8]) -> serde_json::Value {
    match std::str::from_utf8(bytes) {
        Ok(text) => text.into(),
        Err(_) => serde_json::json!({ "base64url": URL_SAFE_NO_PAD.encode(bytes) }),
    }
}

fn summary_json(room: &RoomSummary) -> serde_json::Value {
    serde_json::json!({
        "roomId": room.room_id,
        "groupId": URL_SAFE_NO_PAD.encode(&room.group_id),
        "epoch": room.epoch,
        "members": room
            .members
            .iter()
            .map(|(leaf, identity)| serde_json::json!({ "leaf": leaf, "identity": opaque(identity) }))
            .collect::<Vec<_>>(),
        "participants": room.participants.as_ref().map(|list| {
            list.iter()
                .map(|(user, role)| serde_json::json!({ "user": opaque(user), "role": role }))
                .collect::<Vec<_>>()
        }),
        "roles": room.roles.as_ref().map(|roles| {
            roles
                .iter()
                .map(|(index, name)| serde_json::json!({ "index": index, "name": name }))
                .collect::<Vec<_>>()
        }),
    })
}

async fn list_rooms(State(hub): State<Arc<Hub>>) -> Response {
    let rooms = hub.room_summaries(None).await;
    tracing::debug!(rooms = rooms.len(), "local room list read");
    Json(serde_json::json!({ "rooms": rooms.iter().map(summary_json).collect::<Vec<_>>() }))
        .into_response()
}

async fn get_room(State(hub): State<Arc<Hub>>, Path(room_id): Path<String>) -> Response {
    match hub.room_summaries(Some(&room_id)).await.first() {
        Some(room) => Json(summary_json(room)).into_response(),
        None => {
            tracing::debug!(room_id, "local room read: not hosted here");
            problem(StatusCode::NOT_FOUND, "no-such-room")
        }
    }
}

/// The body of `POST /local/v1/rooms`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CreateRoom {
    room_id: String,
    creator: String,
    group_info: String,
    ratchet_tree: String,
}

async fn create_room(State(hub): State<Arc<Hub>>, body: Json<CreateRoom>) -> Response {
    let Json(request) = body;
    let (Ok(group_info), Ok(ratchet_tree)) = (
        URL_SAFE_NO_PAD.decode(&request.group_info),
        URL_SAFE_NO_PAD.decode(&request.ratchet_tree),
    ) else {
        tracing::debug!(
            room_id = request.room_id,
            "local room creation refused: groupInfo or ratchetTree is not base64url"
        );
        return problem(StatusCode::BAD_REQUEST, "undecodable-request");
    };
    match hub
        .create_room(
            &request.room_id,
            request.creator.as_bytes(),
            &group_info,
            &ratchet_tree,
        )
        .await
    {
        Ok(()) => {
            tracing::info!(
                name: "local_room_created",
                room_id = request.room_id,
                creator = request.creator,
                "room created through the local control listener"
            );
            (
                StatusCode::CREATED,
                Json(serde_json::json!({ "roomId": request.room_id })),
            )
                .into_response()
        }
        Err(error) => {
            let (status, kind) = match &error {
                HubError::InvalidRoomId | HubError::ForeignRoom => {
                    (StatusCode::BAD_REQUEST, "invalid-room-id")
                }
                HubError::RoomExists | HubError::GroupExists => {
                    (StatusCode::CONFLICT, "room-exists")
                }
                HubError::GroupInfoHasRatchetTree
                | HubError::InvalidGroupInfo(_)
                | HubError::UnsupportedCipherSuite { .. }
                | HubError::WrongExternalSenders
                | HubError::MissingFrankingAgent
                | HubError::WrongFrankingAgent
                | HubError::FrankAadNotRequired
                | HubError::MissingBaseRoomPolicy
                | HubError::InvalidBaseRoomPolicy(_)
                | HubError::MissingParticipantList
                | HubError::InvalidParticipantList(_)
                | HubError::CreatorNotListed
                | HubError::MemberNotListed { .. }
                | HubError::FieldTooLong(_) => (StatusCode::UNPROCESSABLE_ENTITY, "group-refused"),
                _ => {
                    tracing::error!(
                        name: "local_room_creation_failed",
                        room_id = request.room_id,
                        error = &error as &dyn std::error::Error,
                        "local room creation failed"
                    );
                    return problem(StatusCode::INTERNAL_SERVER_ERROR, "internal-error");
                }
            };
            tracing::debug!(
                room_id = request.room_id,
                error = &error as &dyn std::error::Error,
                "local room creation refused"
            );
            problem(status, kind)
        }
    }
}
