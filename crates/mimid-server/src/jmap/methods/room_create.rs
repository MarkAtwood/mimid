//! `Room/create` (draft-atwood-jmap-chat-mimi-00 §Room/create; bead
//! mimid-1wgh.12.4).
//!
//! Arguments: `accountId`, `roomId`, `groupInfo` (an MLSMessage of wire
//! format `mls_group_info`) and `ratchetTree`, both unpadded base64url. The
//! client built the MLS group alone; this server becomes its hub.
//!
//! The draft's rules, each `invalidArguments` when broken:
//!
//! 1. the GroupInfo verifies and its suite is offered (the hub checks, in
//!    [`Hub::create_room`]);
//! 2. the tree matches the GroupInfo and has exactly one leaf, whose
//!    credential identity is the account's user and whose signature key is
//!    bound to the account: some KeyPackage the account published used it
//!    (§KeyPackage/set);
//! 3. `external_senders` is exactly the hub (the hub checks);
//! 4. the participant list is exactly the account's user;
//! 5. `roomId` is `roomIdPrefix` followed by the unpadded lowercase base32
//!    of 16 octets, not hosted here yet, and the room metadata, which is
//!    optional, names it as its `room_uri` when present (bead
//!    mimid-1wgh.12.45: a room with metadata requires every member to
//!    support room_metadata under mls-extensions-11 §5);
//! 6. the group ID is 16 octets, not used here yet (the hub checks it is
//!    unused);
//! 7. `franking_agent` names the hub and `base_room_policy` parses: the hub
//!    checks both when present. It requires a `base_room_policy` unless the
//!    operator sets `require_room_policy = false` (bead mimid-jf20), and
//!    franking only with `require_franking` (decision mimid-1wgh.52).
//!
//! On success the room is hosted, the account's Chat is bound to it, and
//! the answer is `{accountId, roomId, chatId}`.
//!
//! # Limitations
//!
//! - The room is hosted and then the Chat bound, in two writes: if the
//!   second fails, the room is hosted without a Chat (logged at ERROR, and
//!   the call is `serverFail`).

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_server::{CallContext, HandlerFuture, HandlerOutput, JmapError, JmapHandler};
use mimi_mls::observer::Observer;
use mimi_protocol::component_id::{PARTICIPANT_LIST, ROOM_METADATA};
use mimi_protocol::{ParticipantListData, RoomMetaData};
use serde_json::{Value, json};

use super::Services;
use crate::follower::key_packages::client_uri;
use mimi_protocol::components;

use crate::hub::{Hub, HubError};
use crate::jmap::api::Methods;
use crate::jmap::auth::Account;
use crate::jmap::bus::{Change, ChangeBus};
use crate::store::Store;

/// Rules 5 and 6: the octets behind a room ID and a group ID.
const ID_OCTETS: usize = 16;

/// Registers `Room/create`.
pub(super) fn register(methods: &mut Methods, services: &Services) {
    methods.add(
        "Room/create",
        Arc::new(Handler {
            hub: Arc::clone(&services.hub),
            store: services.store.clone(),
            bus: services.bus.clone(),
        }),
    );
}

struct Handler {
    hub: Arc<Hub>,
    store: Store,
    bus: ChangeBus,
}

impl JmapHandler<Account> for Handler {
    fn call(&self, cx: CallContext<Account>) -> HandlerFuture {
        let CallContext { args, caller, .. } = cx;
        let (hub, store, bus) = (Arc::clone(&self.hub), self.store.clone(), self.bus.clone());
        Box::pin(async move {
            create(&hub, &store, &bus, &caller, args)
                .await
                .map(HandlerOutput::new)
        })
    }
}

fn invalid(why: &str) -> JmapError {
    tracing::debug!(why, "Room/create refused");
    JmapError::invalid_arguments(why)
}

fn server_fail(error: &(dyn std::error::Error + 'static)) -> JmapError {
    tracing::error!(name: "jmap_room_create_failed", error, "Room/create failed");
    JmapError::server_fail("internal error")
}

/// Whether `text` is the unpadded lowercase RFC 4648 §6 base32 of exactly
/// `octets` octets, with zero trailing bits.
fn is_base32_of(text: &str, octets: usize) -> bool {
    if text.len() != (octets * 8).div_ceil(5) {
        return false;
    }
    let mut bits: u32 = 0;
    let mut count = 0;
    let mut out = 0;
    for byte in text.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return false,
        };
        bits = (bits << 5) | u32::from(value);
        count += 5;
        if count >= 8 {
            count -= 8;
            out += 1;
            bits &= (1 << count) - 1;
        }
    }
    out == octets && bits == 0
}

fn base64(args: &serde_json::Map<String, Value>, key: &str) -> Result<Vec<u8>, JmapError> {
    match args.get(key) {
        Some(Value::String(text)) => URL_SAFE_NO_PAD
            .decode(text)
            .map_err(|_| invalid(&format!("{key} is not unpadded base64url"))),
        _ => Err(invalid(&format!("{key} is required"))),
    }
}

async fn create(
    hub: &Hub,
    store: &Store,
    bus: &ChangeBus,
    caller: &Account,
    args: Value,
) -> Result<Value, JmapError> {
    let Value::Object(args) = args else {
        return Err(invalid("arguments must be an object"));
    };
    let account_id = match args.get("accountId") {
        Some(Value::String(id)) => id.clone(),
        _ => return Err(invalid("accountId is required")),
    };
    caller
        .check_account_id(&account_id)
        .map_err(|_| JmapError::account_not_found())?;
    let requested_room_id = match args.get("roomId") {
        Some(Value::String(id)) => id.clone(),
        _ => return Err(invalid("roomId is required")),
    };
    let group_info = base64(&args, "groupInfo")?;
    let ratchet_tree = base64(&args, "ratchetTree")?;
    let chat_id = create_core(
        hub,
        store,
        bus,
        caller,
        requested_room_id.clone(),
        &group_info,
        &ratchet_tree,
    )
    .await?;
    Ok(json!({ "accountId": account_id, "roomId": requested_room_id, "chatId": chat_id }))
}

/// `Room/create` of `requested_room_id` from `group_info` and
/// `ratchet_tree`, as both bindings call it: every check, the room at the
/// hub, and the creator's Chat, whose id it returns.
///
/// # Errors
///
/// The method's `invalidArguments` and `serverFail`.
pub(crate) async fn create_core(
    hub: &Hub,
    store: &Store,
    bus: &ChangeBus,
    caller: &Account,
    requested_room_id: String,
    group_info: &[u8],
    ratchet_tree: &[u8],
) -> Result<String, JmapError> {
    let (group_info, ratchet_tree) = (group_info.to_vec(), ratchet_tree.to_vec());
    let user = caller.user().as_str();

    // The group as the hub will see it; the hub repeats the MLS checks.
    let room_id = {
        let mls_store = mimi_mls::Store::open_in_memory().map_err(|e| server_fail(&e))?;
        let mut observer = Observer::from_group_info(&mls_store, &group_info, Some(&ratchet_tree))
            .map_err(|_| invalid("groupInfo and ratchetTree are not a valid group"))?
            .observer;
        // A did_webvh creator is known by the user URI its log names
        // (decision mimid-1wgh.4.81.21); the hub checks the rules again.
        observer
            .enforce_did_webvh(hub.did_webvh_code_points())
            .map_err(|_| invalid("the group fails the did_webvh rules"))?;

        // Rule 6 (length; the hub checks it is unused).
        if observer.group_id().len() != ID_OCTETS {
            return Err(invalid("the group ID is not 16 octets"));
        }
        // Rule 2.
        let leaves = observer.member_signature_keys();
        let [(_, signature_key)] = leaves.as_slice() else {
            return Err(invalid("the group has more than one leaf"));
        };
        if observer.members().first().map(|(_, id)| id.as_slice()) != Some(user.as_bytes()) {
            return Err(invalid("the leaf's credential identity is not userUri"));
        }
        let client = client_uri(hub.domain(), signature_key);
        let clients = store
            .clients_of_user(user)
            .await
            .map_err(|e| server_fail(&e))?;
        if !clients.contains(&client) {
            return Err(invalid(
                "the leaf's signature key is not bound to this account",
            ));
        }
        // Rule 4.
        let participants = observer
            .component(PARTICIPANT_LIST)
            .and_then(|data| components::decode::<ParticipantListData>(PARTICIPANT_LIST, data).ok())
            .ok_or_else(|| invalid("the group has no participant list"))?;
        if participants.participants.len() != 1
            || participants.participants[0].user != user.as_bytes()
        {
            return Err(invalid("the participant list is not exactly userUri"));
        }
        // Rule 5.
        if let Some(data) = observer.component(ROOM_METADATA) {
            let metadata = components::decode::<RoomMetaData>(ROOM_METADATA, data)
                .map_err(|_| invalid("the room metadata does not decode"))?;
            if metadata.room_uri.as_str() != requested_room_id {
                return Err(invalid("the room metadata's room_uri is not roomId"));
            }
        }
        let room_id = requested_room_id;
        let prefix = format!("mimi://{}/r/", hub.domain());
        if !room_id
            .strip_prefix(&prefix)
            .is_some_and(|rest| is_base32_of(rest, ID_OCTETS))
        {
            return Err(invalid(
                "room_uri is not roomIdPrefix and base32 of 16 octets",
            ));
        }
        room_id
    };

    match hub
        .create_room(&room_id, user.as_bytes(), &group_info, &ratchet_tree)
        .await
    {
        Ok(()) => {}
        Err(HubError::RoomExists | HubError::GroupExists) => {
            return Err(invalid("the room ID or group ID is already in use"));
        }
        Err(
            error @ (HubError::GroupInfoHasRatchetTree
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
            | HubError::FieldTooLong(_)
            | HubError::InvalidRoomId
            | HubError::ForeignRoom),
        ) => {
            tracing::debug!(
                error = &error as &dyn std::error::Error,
                "Room/create refused by the hub"
            );
            return Err(JmapError::invalid_arguments("the hub refuses this group"));
        }
        Err(error) => return Err(server_fail(&error)),
    }

    // The creator's Chat, bound from now (§Chat.roomId).
    let since = store
        .follower_next_seq()
        .await
        .map_err(|e| server_fail(&e))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX));
    store
        .add_follower_member(&room_id, hub.domain(), user, since, now)
        .await
        .map_err(|e| server_fail(&e))?;
    let (_, chats) = store
        .projection_chats(user)
        .await
        .map_err(|e| server_fail(&e))?;
    let chat_id = chats
        .into_iter()
        .find(|chat| chat.room_id == room_id)
        .map(|chat| chat.chat_id)
        .ok_or_else(|| server_fail(&crate::store::StoreError::Corrupt("no Chat after binding")))?;
    bus.publish(Change::Membership {
        room_id: room_id.clone(),
        user_uri: user.to_owned(),
    });
    tracing::info!(
        name: "jmap_room_created",
        room_id,
        user,
        "room created"
    );
    Ok(chat_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn room_ids_are_base32_of_sixteen_octets() {
        assert!(is_base32_of(&"a".repeat(26), 16));
        // 26 characters carry 130 bits: the last two must be zero.
        assert!(is_base32_of(&format!("{}q", "a".repeat(25)), 16));
        assert!(!is_base32_of(&format!("{}b", "a".repeat(25)), 16));
        assert!(!is_base32_of(&"a".repeat(25), 16));
        assert!(!is_base32_of(&"A".repeat(26), 16));
        assert!(!is_base32_of(&"1".repeat(26), 16));
    }
}
