//! Local control routes: a loopback-only listener for operator and test
//! actions that have no client protocol path yet (bead mimid-1wgh.47, the
//! sideband control path). The first route is a narrow room creation
//! (bead mimid-1wgh.12.4, the interim before JMAP `Room/create`), so a
//! room hosted here can be tested against another provider.
//!
//! The listener is off unless the configuration names `local_listen`, and
//! the server refuses to start if that address is not a loopback address.
//! Nothing here authenticates the caller: anyone who can reach the loopback
//! interface of the host can use it.
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
//!   only `type` and `status` ([`crate::http::problem`]); the reason is
//!   logged.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;

use crate::http::problem;
use crate::hub::{Hub, HubError};

/// The local control router.
pub fn router(hub: Arc<Hub>) -> Router {
    Router::new()
        .route("/local/v1/hub-sender", get(hub_sender))
        .route("/local/v1/rooms", post(create_room))
        .with_state(hub)
}

async fn hub_sender(State(hub): State<Arc<Hub>>) -> Response {
    Json(serde_json::json!({
        "signatureKey": URL_SAFE_NO_PAD.encode(hub.signature_public_key()),
        "identity": format!("mimi://{}", hub.domain()),
    }))
    .into_response()
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
                | HubError::MemberNotListed { .. } => {
                    (StatusCode::UNPROCESSABLE_ENTITY, "group-refused")
                }
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
