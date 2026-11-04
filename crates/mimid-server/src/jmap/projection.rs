//! The read projection of the follower log as JMAP Chats, Messages and
//! ChatContacts (bead mimid-1wgh.11.3; plan of mimid-1wgh.12 §3
//! "Projection").
//!
//! - **Chat**: one per room the account's user was ever a member of
//!   (`follower_chat`), with a ULID minted at the first join. `kind` is
//!   `"group"`, `members` is empty and `roomId` is the room
//!   (draft-atwood-jmap-chat-mimi-00 §Chat.roomId). `name` is the hosted
//!   room's current `room_name` while the user is a member, and `""` when
//!   the user is not or the room is followed (decisions mimid-1wgh.12.25,
//!   mimid-1wgh.11.9). `unreadCount` counts every visible Message and
//!   `lastMessageAt` is the latest visible `receivedAt` (decision
//!   mimid-1wgh.12.32). Unbinding is invisible on the Chat.
//! - **Message**: one per visible follower event (decision mimid-1wgh.7.7),
//!   with a stored ULID id (decision mimid-1wgh.12.31), `bodyType`
//!   `application/mimi-fanout` and the base64url FanoutMessage as `body`.
//!   `senderMsgId`, `sentAt` and `senderId` follow mimi-00
//!   §fanout-messages.
//! - **ChatContact**: one per hub of the account's rooms, whose `identity`
//!   and `login` are the hub's provider URI `mimi://<domain>`
//!   (protocol-07 §2.1; mimi-00 §fanout-messages).
//!
//! State strings (plan of mimid-1wgh.12 §3 "State strings"; s is the
//! highest visible seq, m the highest membership id, both decimal):
//!
//! - Message: `s.m`. `/changes` returns the Messages visible above s, plus
//!   every visible Message of a membership above m.
//! - Chat: `s.m.d`, where d is 16 hex digits of SHA-256 over the `name`s
//!   of the account's hosted-room Chats, so it changes whenever one does.
//! - ChatContact: `m`.
//!
//! Messages are never updated or destroyed. `/queryChanges` always answers
//! `cannotCalculateChanges` (decision mimid-1wgh.12.22).
//!
//! # Limitations
//!
//! - Filters are FilterConditions only: a FilterOperator gets
//!   `unsupportedFilter` (RFC 8620 §5.5 lets a server refuse a filter it
//!   cannot process).
//! - `Message/query` needs a `chatId` filter; with `hasMention: true` and no
//!   `chatId` it is `unsupportedFilter` (no cross-chat mention queries).
//!   `text` and `threadRootId` are `unsupportedFilter` (no full-text search,
//!   no threads). Bodies are ciphertext, so `topicId`, `hasAttachment: true`
//!   and `hasMention: true` match nothing.
//! - `/query` enforces no maximum `limit`: crate-jmap's handler cannot
//!   report a clamped one (RFC 8620 §5.5).
//! - `/changes` with `maxChanges` gives intermediate states for Messages
//!   only; Chats and ChatContacts past the limit get
//!   `cannotCalculateChanges`.
//! - The Chat state reads every hosted room's name from the hub, under the
//!   hub's room lock.
//! - `blocked` is always `false`: there is no `ChatContact/set` (decision
//!   mimid-1wgh.12.22).

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use jmap_chat_types::{Chat, ChatContact, Message};
use jmap_server::{
    BackendChangesError, BackendQueryError, ChangesResult, GetObject, HandlerFuture, Id,
    JmapBackend, JmapError, JmapHandler, JmapObject, QueryChangesResult, QueryObject, QueryResult,
    SetError, SetErrorType, State, handle_changes, handle_query, handle_query_changes,
    resolve_query_start, server_fail_from_backend,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use ulid::Ulid;

use super::api::{MAX_OBJECTS_IN_GET, MAX_OBJECTS_IN_SET, Methods};
use super::auth::Account;
use crate::hub::Hub;
use crate::store::{ChatRow, HubRow, MessageRow, ProjectionCursor, Store, StoreError};

/// mimi-00 §mls-messages: every Message of a roomed Chat.
pub const FANOUT_BODY_TYPE: &str = "application/mimi-fanout";

/// The Chat properties a client may name in `properties`: base
/// draft-atwood-jmap-chat-00 §Chat Object Fields, and `roomId` (mimi-00
/// §Chat.roomId). `activeCallId` exists only with the VTC capability,
/// which is not offered.
const CHAT_PROPERTIES: &[&str] = &[
    "id",
    "kind",
    "contactId",
    "name",
    "description",
    "avatarBlobId",
    "members",
    "closedAt",
    "spaceId",
    "categoryId",
    "position",
    "topic",
    "slowModeSeconds",
    "permissionOverrides",
    "createdAt",
    "lastMessageAt",
    "unreadCount",
    "pinnedMessageIds",
    "muted",
    "muteUntil",
    "receiveTypingIndicators",
    "receiptSharing",
    "messageExpirySeconds",
    "roomId",
];

/// Base draft §Message Object Fields.
const MESSAGE_PROPERTIES: &[&str] = &[
    "id",
    "senderMsgId",
    "chatId",
    "senderId",
    "body",
    "bodyType",
    "attachments",
    "mentions",
    "broadcastMentions",
    "actions",
    "reactions",
    "replyTo",
    "threadRootId",
    "replyCount",
    "unreadReplyCount",
    "topicId",
    "subject",
    "sentAt",
    "receivedAt",
    "senderExpiresAt",
    "burnOnRead",
    "expiresAfterReadSeconds",
    "deliveryState",
    "deliveryReceipts",
    "deliveredAt",
    "readAt",
    "readDisposition",
    "editedAt",
    "editHistory",
    "deletedAt",
    "deletedForAll",
];

/// Base draft §ChatContact. `serverUrl` and `directAddress` belong to
/// federation, which is not offered.
const CONTACT_PROPERTIES: &[&str] = &[
    "id",
    "identity",
    "login",
    "displayName",
    "firstSeenAt",
    "lastSeenAt",
    "presence",
    "lastActiveAt",
    "statusText",
    "statusEmoji",
    "endpoints",
    "blocked",
];

/// The three projected data types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Chat,
    Message,
    ChatContact,
}

impl Kind {
    fn of<O: JmapObject>() -> Result<Self, ProjectionError> {
        match O::TYPE_NAME {
            "Chat" => Ok(Self::Chat),
            "Message" => Ok(Self::Message),
            "ChatContact" => Ok(Self::ChatContact),
            _ => Err(ProjectionError::UnknownType),
        }
    }

    fn properties(self) -> &'static [&'static str] {
        match self {
            Self::Chat => CHAT_PROPERTIES,
            Self::Message => MESSAGE_PROPERTIES,
            Self::ChatContact => CONTACT_PROPERTIES,
        }
    }
}

/// A projected object as JSON, possibly cut down to the requested
/// properties. The full object is first built as crate-jmap's typed
/// [`Chat`], [`Message`] or [`ChatContact`], through serde (AGENTS.md).
macro_rules! record {
    ($name:ident, $type_name:literal) => {
        #[doc = concat!("A projected ", $type_name, " as JSON.")]
        #[derive(Debug, Clone, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(Map<String, Value>);

        impl JmapObject for $name {
            const TYPE_NAME: &'static str = $type_name;
            type Property = String;
        }

        impl GetObject for $name {}

        impl QueryObject for $name {
            type Filter = Value;
            type Comparator = Value;
        }
    };
}

record!(ChatRecord, "Chat");
record!(MessageRecord, "Message");
record!(ContactRecord, "ChatContact");

/// An internal failure of the projection. Its text carries no user data.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ProjectionError {
    /// The store failed.
    #[error("store error")]
    Store(#[from] StoreError),
    /// A projected object does not fit crate-jmap's type: a bug.
    #[error("projected object does not serialize")]
    Serde(#[from] serde_json::Error),
    /// A data type other than Chat, Message or ChatContact.
    #[error("not a projected data type")]
    UnknownType,
    /// The request cannot be served, such as `/get` of too many objects.
    #[error("request refused")]
    Request,
}

/// The JMAP read projection over the store and the hub.
#[derive(Debug)]
pub(crate) struct Projection {
    store: Store,
    hub: Arc<Hub>,
}

/// One Chat as projected, with what its state needs.
struct ChatView {
    row: ChatRow,
    name: String,
    hosted: bool,
}

impl Projection {
    pub(crate) fn new(store: Store, hub: Arc<Hub>) -> Self {
        Self { store, hub }
    }

    /// The account's Chats, its cursor and the digest of its hosted rooms'
    /// names.
    async fn chats(
        &self,
        account: &Account,
    ) -> Result<(ProjectionCursor, Vec<ChatView>, String), ProjectionError> {
        let (cursor, rows) = self.store.projection_chats(account.user().as_str()).await?;
        let own = self.hub.domain().as_str();
        // ponytail: every Chat state and Chat/get reads the names of the
        // user's hosted rooms under the hub's single room lock, so it waits
        // behind hub writes. Upgrade path: keep the current room_name in
        // the store when a Commit is accepted and read it here instead.
        let names = self
            .hub
            .room_names(
                rows.iter()
                    .filter(|row| row.hub_domain == own && row.bound)
                    .map(|row| row.room_id.as_str()),
            )
            .await;
        let mut digest = Sha256::new();
        let views: Vec<ChatView> = rows
            .into_iter()
            .map(|row| {
                let hosted = row.hub_domain == own;
                // Decision mimid-1wgh.11.9: "" while the user has no current
                // membership, so the digest moves on leaving and rejoining,
                // and not on a rename the user cannot see.
                let name = if row.bound {
                    names.get(&row.room_id).cloned().unwrap_or_default()
                } else {
                    String::new()
                };
                if hosted {
                    // Rows come by chat id; NUL ends both strings.
                    digest.update(row.chat_id.as_bytes());
                    digest.update([0]);
                    digest.update(name.as_bytes());
                    digest.update([0]);
                }
                ChatView { row, name, hosted }
            })
            .collect();
        Ok((cursor, views, hex(&digest.finalize()[..8])))
    }

    /// The account's current state string for `kind`.
    async fn state(&self, kind: Kind, account: &Account) -> Result<String, ProjectionError> {
        let user = account.user().as_str();
        Ok(match kind {
            Kind::Chat => {
                let (cursor, _, digest) = self.chats(account).await?;
                chat_state(cursor, &digest)
            }
            Kind::Message => message_state(self.store.projection_cursor(user).await?),
            Kind::ChatContact => self.store.projection_hubs(user).await?.0.to_string(),
        })
    }

    /// The state for `kind` and the account's objects of that kind with an
    /// id among `ids` (every one if `None`), as JSON, cut down to
    /// `properties` if given.
    ///
    /// # Errors
    ///
    /// `requestTooLarge` if `ids` is `None` and there are more than
    /// [`MAX_OBJECTS_IN_GET`] objects (RFC 8620 §5.1), and `serverFail` for
    /// an internal failure.
    async fn records(
        &self,
        kind: Kind,
        account: &Account,
        ids: Option<&[String]>,
        properties: Option<&[String]>,
    ) -> Result<(String, Vec<Map<String, Value>>), JmapError> {
        let fail = |error: ProjectionError| server_fail_from_backend(&error);
        let wanted: Option<BTreeSet<&str>> =
            ids.map(|ids| ids.iter().map(String::as_str).collect());
        let keep = |id: &str| wanted.as_ref().is_none_or(|wanted| wanted.contains(id));
        let (state, objects) = match kind {
            Kind::Chat => {
                let (cursor, chats, digest) = self.chats(account).await.map_err(fail)?;
                let objects = chats
                    .iter()
                    .filter(|chat| keep(&chat.row.chat_id))
                    .map(chat_object)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| fail(error.into()))?;
                (chat_state(cursor, &digest), objects)
            }
            Kind::Message => {
                let unique: Option<Vec<String>> = wanted
                    .as_ref()
                    .map(|ids| ids.iter().map(|id| (*id).to_owned()).collect());
                let limit = u32::try_from(MAX_OBJECTS_IN_GET + 1).unwrap_or(u32::MAX);
                let (cursor, rows) = self
                    .store
                    .projection_messages(account.user().as_str(), unique.as_deref(), limit)
                    .await
                    .map_err(|error| fail(error.into()))?;
                if ids.is_none() && rows.len() > MAX_OBJECTS_IN_GET {
                    return Err(JmapError::request_too_large());
                }
                let objects = rows
                    .iter()
                    .map(message_object)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| fail(error.into()))?;
                (message_state(cursor), objects)
            }
            Kind::ChatContact => {
                let (member, hubs) = self
                    .store
                    .projection_hubs(account.user().as_str())
                    .await
                    .map_err(|error| fail(error.into()))?;
                let objects = hubs
                    .iter()
                    .filter(|hub| keep(&contact_id(&hub.hub_domain)))
                    .map(contact_object)
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|error| fail(error.into()))?;
                (member.to_string(), objects)
            }
        };
        if ids.is_none() && objects.len() > MAX_OBJECTS_IN_GET {
            return Err(JmapError::request_too_large());
        }
        let objects = match properties {
            None => objects,
            Some(properties) => objects
                .into_iter()
                .map(|object| {
                    object
                        .into_iter()
                        .filter(|(key, _)| key == "id" || properties.contains(key))
                        .collect()
                })
                .collect(),
        };
        Ok((state, objects))
    }

    /// The ids of the account's objects of `kind`, filtered and sorted as
    /// `/query` asks.
    async fn query_ids(
        &self,
        kind: Kind,
        account: &Account,
        filter: Option<&Value>,
        sort: Option<&[Value]>,
    ) -> Result<(String, Vec<String>), BackendQueryError<ProjectionError>> {
        let condition = condition(filter)?;
        let comparators = comparators(kind, sort)?;
        match kind {
            Kind::Chat => {
                check_filter(&condition, &[("kind", Type::String), ("muted", Type::Bool)])?;
                let (cursor, chats, digest) = self.chats(account).await?;
                let mut chats: Vec<&ChatView> = chats
                    .iter()
                    .filter(|_| {
                        condition.get("kind").is_none_or(|kind| kind == "group")
                            && condition.get("muted").is_none_or(|muted| muted == false)
                    })
                    .collect();
                let comparators = if comparators.is_empty() {
                    vec![("lastMessageAt".to_owned(), false)]
                } else {
                    comparators
                };
                // Base draft §Chat/query: chats without messages sort last.
                chats.sort_by(|a, b| {
                    sort_keys(&comparators, |_| {
                        absent_last(a.row.last_received_at, b.row.last_received_at)
                    })
                    .then_with(|| a.row.chat_id.cmp(&b.row.chat_id))
                });
                let ids = chats.iter().map(|chat| chat.row.chat_id.clone()).collect();
                Ok((chat_state(cursor, &digest), ids))
            }
            Kind::Message => {
                check_filter(
                    &condition,
                    &[
                        ("chatId", Type::String),
                        ("text", Type::String),
                        ("threadRootId", Type::String),
                        ("topicId", Type::String),
                        ("hasAttachment", Type::Bool),
                        ("hasMention", Type::Bool),
                    ],
                )?;
                // Base draft §Message/query: a chatId is needed, and the
                // search filters are unsupported here.
                let unsupported = || BackendQueryError::Method(JmapError::unsupported_filter());
                let Some(Value::String(chat_id)) = condition.get("chatId") else {
                    return Err(unsupported());
                };
                if condition.contains_key("text") || condition.contains_key("threadRootId") {
                    return Err(unsupported());
                }
                let (cursor, mut ids) = self
                    .store
                    .projection_message_ids(account.user().as_str(), chat_id)
                    .await
                    .map_err(ProjectionError::from)?;
                // Ciphertext bodies carry no server-visible topicId,
                // attachments or mentions.
                let matches_none = condition.contains_key("topicId")
                    || condition.get("hasAttachment") == Some(&Value::Bool(true))
                    || condition.get("hasMention") == Some(&Value::Bool(true));
                if matches_none {
                    ids.clear();
                }
                // The store's order is receivedAt ascending, the default.
                if comparators.first().is_some_and(|(_, ascending)| !ascending) {
                    ids.reverse();
                }
                Ok((message_state(cursor), ids))
            }
            Kind::ChatContact => {
                check_filter(
                    &condition,
                    &[
                        ("blocked", Type::Bool),
                        ("presence", Type::String),
                        ("identity", Type::String),
                    ],
                )?;
                let (member, hubs) = self
                    .store
                    .projection_hubs(account.user().as_str())
                    .await
                    .map_err(ProjectionError::from)?;
                let mut hubs: Vec<(String, &HubRow)> = hubs
                    .iter()
                    .filter(|hub| {
                        // No contact has a presence; none is blocked.
                        !condition.contains_key("presence")
                            && condition
                                .get("blocked")
                                .is_none_or(|blocked| blocked == false)
                            && condition
                                .get("identity")
                                .is_none_or(|identity| *identity == provider_uri(&hub.hub_domain))
                    })
                    .map(|hub| (contact_id(&hub.hub_domain), hub))
                    .collect();
                hubs.sort_by(|(a_id, a), (b_id, b)| {
                    sort_keys(&comparators, |property| match property {
                        "lastSeenAt" => Compared::Ordered(a.last_joined_at.cmp(&b.last_joined_at)),
                        "login" => Compared::Ordered(a.hub_domain.cmp(&b.hub_domain)),
                        // Base draft §ChatContact/query: an absent
                        // lastActiveAt sorts last; no contact has one.
                        _ => Compared::Fixed(Ordering::Equal),
                    })
                    .then_with(|| a_id.cmp(b_id))
                });
                let ids = hubs.into_iter().map(|(id, _)| id).collect();
                Ok((member.to_string(), ids))
            }
        }
    }

    async fn chat_changes(
        &self,
        account: &Account,
        since: &str,
        max_changes: Option<u64>,
    ) -> Result<ChangesResult, BackendChangesError<ProjectionError>> {
        let (cursor, chats, digest) = self.chats(account).await?;
        let mut parts = since.splitn(3, '.');
        let (Some(seq), Some(member), Some(since_digest)) = (
            parts.next().and_then(parse_counter),
            parts.next().and_then(parse_counter),
            parts.next(),
        ) else {
            return Err(BackendChangesError::CannotCalculate);
        };
        if seq > cursor.seq || member > cursor.member {
            return Err(BackendChangesError::CannotCalculate);
        }
        let renamed = since_digest != digest;
        let mut created = Vec::new();
        let mut updated = Vec::new();
        for chat in &chats {
            let row = &chat.row;
            if row.first_member > member {
                created.push(Id::from(row.chat_id.as_str()));
            } else if row.last_member > member
                || row.last_seq.is_some_and(|last| last > seq)
                || (renamed && chat.hosted)
            {
                updated.push(Id::from(row.chat_id.as_str()));
            }
        }
        changes(created, updated, chat_state(cursor, &digest), max_changes)
    }

    async fn message_changes(
        &self,
        account: &Account,
        since: &str,
        max_changes: Option<u64>,
    ) -> Result<ChangesResult, BackendChangesError<ProjectionError>> {
        let since = parse_message_state(since).ok_or(BackendChangesError::CannotCalculate)?;
        let changes = self
            .store
            .projection_message_changes(account.user().as_str(), since, max_changes)
            .await
            .map_err(ProjectionError::from)?
            .ok_or(BackendChangesError::CannotCalculate)?;
        Ok(ChangesResult::new(
            changes.created.into_iter().map(Id::from).collect(),
            Vec::new(),
            Vec::new(),
            changes.has_more,
            State::from(message_state(changes.new_cursor)),
        ))
    }

    async fn contact_changes(
        &self,
        account: &Account,
        since: &str,
        max_changes: Option<u64>,
    ) -> Result<ChangesResult, BackendChangesError<ProjectionError>> {
        let (current, hubs) = self
            .store
            .projection_hubs(account.user().as_str())
            .await
            .map_err(ProjectionError::from)?;
        let member = parse_counter(since)
            .filter(|member| *member <= current)
            .ok_or(BackendChangesError::CannotCalculate)?;
        let (created, updated): (Vec<&HubRow>, Vec<&HubRow>) = hubs
            .iter()
            .filter(|hub| hub.last_member > member)
            .partition(|hub| hub.first_member > member);
        let ids = |hubs: Vec<&HubRow>| {
            hubs.into_iter()
                .map(|hub| Id::from(contact_id(&hub.hub_domain)))
                .collect()
        };
        changes(ids(created), ids(updated), current.to_string(), max_changes)
    }
}

/// A complete `/changes` result, or `cannotCalculateChanges` if it exceeds
/// `max_changes`.
///
/// RFC 8620 §5.2 (rfc8620.txt L1761-1769) says the server SHOULD instead
/// return an intermediate state. Chats and ChatContacts skip that SHOULD:
/// the Chat state carries a digest of room names, which cannot be split
/// into intermediate states, and with one Chat per room and one
/// ChatContact per hub the cap is rarely reached.
fn changes(
    created: Vec<Id>,
    updated: Vec<Id>,
    state: String,
    max_changes: Option<u64>,
) -> Result<ChangesResult, BackendChangesError<ProjectionError>> {
    let count = (created.len() + updated.len()) as u64;
    if max_changes.is_some_and(|max| count > max) {
        return Err(BackendChangesError::CannotCalculate);
    }
    Ok(ChangesResult::new(
        created,
        updated,
        Vec::new(),
        false,
        State::from(state),
    ))
}

fn chat_state(cursor: ProjectionCursor, digest: &str) -> String {
    format!("{}.{}.{digest}", cursor.seq, cursor.member)
}

fn message_state(cursor: ProjectionCursor) -> String {
    format!("{}.{}", cursor.seq, cursor.member)
}

fn parse_message_state(state: &str) -> Option<ProjectionCursor> {
    let (seq, member) = state.split_once('.')?;
    Some(ProjectionCursor {
        seq: parse_counter(seq)?,
        member: parse_counter(member)?,
    })
}

/// A state-string counter: decimal digits only, at most `i64::MAX`.
fn parse_counter(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| i64::try_from(*value).is_ok())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// The provider URI of the hub `domain` (protocol-07 §2.1).
fn provider_uri(domain: &str) -> String {
    format!("mimi://{domain}")
}

/// The id of the ChatContact of the hub `domain`: the unpadded base64url
/// of the first 16 octets of SHA-256 of its provider URI, 22 characters.
/// INVENTED, NOT FROM SPEC: base draft §ChatContact leaves the choice to
/// the server, except that it MUST NOT be the accountId, a 26-character
/// ULID.
pub(crate) fn contact_id(domain: &str) -> String {
    URL_SAFE_NO_PAD.encode(&Sha256::digest(provider_uri(domain).as_bytes())[..16])
}

/// An RFC 8620 §1.4 UTCDate for `ms` milliseconds since the UNIX epoch,
/// with the fraction omitted when it is zero.
fn utc_date(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs / 86_400;
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let time = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    );
    if millis == 0 {
        format!("{time}Z")
    } else {
        format!("{time}.{millis:03}Z")
    }
}

/// The proleptic Gregorian date `days` after 1970-01-01 (H. Hinnant,
/// "chrono-Compatible Low-Level Date Algorithms", `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

/// The base draft `senderMsgId` of a FanoutMessage: the ULID of its
/// `timestamp` and the first 10 octets of its SHA-256 (mimi-00
/// §fanout-messages).
fn sender_msg_id(hub_timestamp: u64, hash: &[u8; 32]) -> String {
    let mut random = [0u8; 16];
    random[6..].copy_from_slice(&hash[..10]);
    Ulid::from_parts(hub_timestamp, u128::from_be_bytes(random)).to_string()
}

fn into_map(value: Value) -> Result<Map<String, Value>, serde_json::Error> {
    match value {
        Value::Object(map) => Ok(map),
        _ => Err(serde::de::Error::custom("not an object")),
    }
}

fn chat_object(chat: &ChatView) -> Result<Map<String, Value>, serde_json::Error> {
    let row = &chat.row;
    let mut object = json!({
        "id": row.chat_id,
        "kind": "group",
        "name": chat.name,
        "members": [],
        "createdAt": utc_date(row.created_at),
        "unreadCount": row.message_count,
        "pinnedMessageIds": [],
        "muted": false,
        "receiveTypingIndicators": true,
        "roomId": row.room_id,
    });
    if let Some(last) = row.last_received_at {
        object["lastMessageAt"] = json!(utc_date(last));
    }
    into_map(serde_json::to_value(serde_json::from_value::<Chat>(
        object,
    )?)?)
}

fn message_object(row: &MessageRow) -> Result<Map<String, Value>, serde_json::Error> {
    let object = json!({
        "id": row.message_id,
        "senderMsgId": sender_msg_id(row.hub_timestamp, &row.hash),
        "chatId": row.chat_id,
        "senderId": contact_id(&row.hub_domain),
        "body": URL_SAFE_NO_PAD.encode(&row.bytes),
        "bodyType": FANOUT_BODY_TYPE,
        "attachments": [],
        "mentions": [],
        "broadcastMentions": [],
        "actions": [],
        "reactions": {},
        "sentAt": utc_date(row.hub_timestamp),
        "receivedAt": utc_date(row.received_at),
        // The message reached this mailbox (base draft §Message L665-668
        // covers only sent messages; decision mimid-1wgh.11.7).
        "deliveryState": "delivered",
    });
    into_map(serde_json::to_value(serde_json::from_value::<Message>(
        object,
    )?)?)
}

fn contact_object(hub: &HubRow) -> Result<Map<String, Value>, serde_json::Error> {
    let identity = provider_uri(&hub.hub_domain);
    let object = json!({
        "id": contact_id(&hub.hub_domain),
        "identity": identity,
        "login": identity,
        "firstSeenAt": utc_date(hub.first_joined_at),
        // INVENTED, NOT FROM SPEC: the latest joining of one of the hub's
        // rooms stands for the "most recent interaction".
        "lastSeenAt": utc_date(hub.last_joined_at),
        "blocked": false,
    });
    into_map(serde_json::to_value(
        serde_json::from_value::<ChatContact>(object)?,
    )?)
}

/// The JSON type a filter property takes.
#[derive(Debug, Clone, Copy)]
enum Type {
    String,
    Bool,
}

/// The FilterCondition of a `/query`, or an empty one for no filter.
fn condition(
    filter: Option<&Value>,
) -> Result<Map<String, Value>, BackendQueryError<ProjectionError>> {
    match filter {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(condition)) if !condition.contains_key("operator") => {
            Ok(condition.clone())
        }
        Some(Value::Object(_)) => Err(BackendQueryError::Method(JmapError::unsupported_filter())),
        Some(_) => Err(BackendQueryError::Method(JmapError::invalid_arguments(
            "filter must be an object",
        ))),
    }
}

/// Every property of `condition` must be in `known` with its type.
fn check_filter(
    condition: &Map<String, Value>,
    known: &[(&str, Type)],
) -> Result<(), BackendQueryError<ProjectionError>> {
    for (property, value) in condition {
        let Some((_, kind)) = known.iter().find(|(name, _)| name == property) else {
            return Err(BackendQueryError::Method(JmapError::unsupported_filter()));
        };
        let fits = match kind {
            Type::String => value.is_string(),
            Type::Bool => value.is_boolean(),
        };
        if !fits {
            return Err(BackendQueryError::Method(JmapError::invalid_arguments(
                format!("filter property {property} has the wrong type"),
            )));
        }
    }
    Ok(())
}

/// The `/query` sort as (property, isAscending) pairs. Each property must
/// be one the type sorts by; no collation is supported.
fn comparators(
    kind: Kind,
    sort: Option<&[Value]>,
) -> Result<Vec<(String, bool)>, BackendQueryError<ProjectionError>> {
    let supported: &[&str] = match kind {
        // Base draft §Chat/query and §Message/query name only a default
        // sort, on these properties.
        Kind::Chat => &["lastMessageAt"],
        Kind::Message => &["receivedAt"],
        Kind::ChatContact => &["lastSeenAt", "login", "lastActiveAt"],
    };
    let invalid = |text: &str| BackendQueryError::Method(JmapError::invalid_arguments(text));
    sort.unwrap_or_default()
        .iter()
        .map(|comparator| {
            let comparator = comparator
                .as_object()
                .ok_or_else(|| invalid("sort entries must be objects"))?;
            let property = comparator
                .get("property")
                .and_then(Value::as_str)
                .ok_or_else(|| invalid("a comparator needs a property"))?;
            let ascending = match comparator.get("isAscending") {
                None | Some(Value::Null) => true,
                Some(Value::Bool(ascending)) => *ascending,
                Some(_) => return Err(invalid("isAscending must be a boolean")),
            };
            if !supported.contains(&property) || comparator.contains_key("collation") {
                return Err(BackendQueryError::Method(JmapError::unsupported_sort()));
            }
            Ok((property.to_owned(), ascending))
        })
        .collect()
}

/// How two objects compare on one sort property.
#[derive(Debug, Clone, Copy)]
enum Compared {
    /// The ascending order of their values; a descending sort reverses it.
    Ordered(Ordering),
    /// An order that holds in either direction: an absent value sorts
    /// last.
    Fixed(Ordering),
}

/// Compares two objects by `comparators` in turn.
fn sort_keys(comparators: &[(String, bool)], compare: impl Fn(&str) -> Compared) -> Ordering {
    comparators
        .iter()
        .map(|(property, ascending)| match compare(property) {
            Compared::Ordered(order) if *ascending => order,
            Compared::Ordered(order) => order.reverse(),
            Compared::Fixed(order) => order,
        })
        .find(|order| order.is_ne())
        .unwrap_or(Ordering::Equal)
}

/// How two optional values compare, an absent one sorting last.
fn absent_last(a: Option<u64>, b: Option<u64>) -> Compared {
    match (a, b) {
        (Some(a), Some(b)) => Compared::Ordered(a.cmp(&b)),
        (Some(_), None) => Compared::Fixed(Ordering::Less),
        (None, Some(_)) => Compared::Fixed(Ordering::Greater),
        (None, None) => Compared::Fixed(Ordering::Equal),
    }
}

impl JmapBackend for Projection {
    type Error = ProjectionError;
    type CallerCtx = Account;

    async fn account_exists(&self, caller: &Account, account_id: &Id) -> Result<bool, Self::Error> {
        Ok(caller.check_account_id(account_id.as_ref()).is_ok())
    }

    /// Unused by this module's handlers, which read the state with the
    /// objects (see [`get`]); errors here can only be `serverFail`.
    async fn get_objects<O: GetObject + Send + Sync>(
        &self,
        caller: &Account,
        _account_id: &Id,
        ids: Option<&[Id]>,
        properties: Option<&[String]>,
    ) -> Result<(Vec<O>, Vec<Id>), Self::Error> {
        let kind = Kind::of::<O>()?;
        let ids: Option<Vec<String>> =
            ids.map(|ids| ids.iter().map(|id| id.as_ref().to_owned()).collect());
        let (_, objects) = self
            .records(kind, caller, ids.as_deref(), properties)
            .await
            .map_err(|_| ProjectionError::Request)?;
        let found: BTreeSet<String> = objects
            .iter()
            .filter_map(|object| object.get("id")?.as_str().map(str::to_owned))
            .collect();
        let not_found = ids
            .unwrap_or_default()
            .into_iter()
            .filter(|id| !found.contains(id))
            .collect::<BTreeSet<_>>()
            .into_iter()
            .map(Id::from)
            .collect();
        let objects = objects
            .into_iter()
            .map(|object| serde_json::from_value(Value::Object(object)))
            .collect::<Result<_, _>>()?;
        Ok((objects, not_found))
    }

    async fn get_state<O: JmapObject + Send + Sync>(
        &self,
        caller: &Account,
        _account_id: &Id,
    ) -> Result<State, Self::Error> {
        Ok(State::from(self.state(Kind::of::<O>()?, caller).await?))
    }

    async fn get_changes<O: JmapObject + Send + Sync>(
        &self,
        caller: &Account,
        _account_id: &Id,
        since_state: &State,
        max_changes: Option<u64>,
    ) -> Result<ChangesResult, BackendChangesError<Self::Error>> {
        let since = since_state.as_ref();
        match Kind::of::<O>()? {
            Kind::Chat => self.chat_changes(caller, since, max_changes).await,
            Kind::Message => self.message_changes(caller, since, max_changes).await,
            Kind::ChatContact => self.contact_changes(caller, since, max_changes).await,
        }
    }

    async fn query_objects<O: QueryObject + Send + Sync>(
        &self,
        caller: &Account,
        _account_id: &Id,
        filter: Option<&O::Filter>,
        sort: Option<&[O::Comparator]>,
        limit: Option<u64>,
        position: i64,
        anchor: Option<&Id>,
        anchor_offset: i64,
    ) -> Result<QueryResult, BackendQueryError<Self::Error>> {
        let kind = Kind::of::<O>()?;
        let filter = filter
            .map(serde_json::to_value)
            .transpose()
            .map_err(ProjectionError::from)?;
        let sort = sort
            .map(|sort| sort.iter().map(serde_json::to_value).collect())
            .transpose()
            .map_err(ProjectionError::from)?;
        let sort: Option<Vec<Value>> = sort;
        let (state, ids) = self
            .query_ids(kind, caller, filter.as_ref(), sort.as_deref())
            .await?;
        let ids: Vec<Id> = ids.into_iter().map(Id::from).collect();
        let start = resolve_query_start(&ids, position, anchor, anchor_offset)
            .map_err(BackendQueryError::Method)?;
        let total = ids.len() as u64;
        let page = ids
            .into_iter()
            .skip(start)
            .take(limit.map_or(usize::MAX, |limit| {
                usize::try_from(limit).unwrap_or(usize::MAX)
            }))
            .collect();
        Ok(QueryResult::new(
            page,
            start as u64,
            Some(total),
            State::from(state),
            false,
        ))
    }

    async fn query_changes<O: QueryObject + Send + Sync>(
        &self,
        _caller: &Account,
        _account_id: &Id,
        _since_query_state: &State,
        _filter: Option<&O::Filter>,
        _sort: Option<&[O::Comparator]>,
        _max_changes: Option<u64>,
        _up_to_id: Option<&Id>,
        _collapse_threads: bool,
    ) -> Result<QueryChangesResult, BackendChangesError<Self::Error>> {
        // Decision mimid-1wgh.12.22.
        Err(BackendChangesError::CannotCalculate)
    }

    /// The advertised `maxObjectsInGet`. The limit itself is enforced once,
    /// for every method, by `api.rs`; this keeps crate-jmap's handlers in
    /// step with it.
    fn max_objects_in_get(&self, _caller: &Account, _account_id: &Id) -> u64 {
        MAX_OBJECTS_IN_GET as u64
    }

    /// The advertised `maxObjectsInSet`, enforced once by `api.rs`.
    fn max_objects_in_set(&self, _caller: &Account, _account_id: &Id) -> u64 {
        MAX_OBJECTS_IN_SET as u64
    }
}

/// RFC 8620 §5.1 `/get`, reading the state in the same transaction as the
/// objects, so the state never runs ahead of them (crate-jmap's
/// `handle_get` reads it afterwards).
async fn get(
    projection: &Projection,
    kind: Kind,
    args: Value,
    account: &Account,
) -> Result<Value, JmapError> {
    let Value::Object(args) = args else {
        return Err(JmapError::invalid_arguments("arguments must be an object"));
    };
    let account_id = match args.get("accountId") {
        Some(Value::String(account_id)) => account_id,
        _ => return Err(JmapError::invalid_arguments("accountId is required")),
    };
    account
        .check_account_id(account_id)
        .map_err(|_| JmapError::account_not_found())?;
    let strings = |key: &str| -> Result<Option<Vec<String>>, JmapError> {
        match args.get(key) {
            None | Some(Value::Null) => Ok(None),
            Some(value) => serde_json::from_value(value.clone())
                .map(Some)
                .map_err(|_| JmapError::invalid_arguments(format!("{key} must be a string array"))),
        }
    };
    let ids = strings("ids")?;
    let properties = strings("properties")?;
    if let Some(unknown) = properties
        .iter()
        .flatten()
        .find(|property| !kind.properties().contains(&property.as_str()))
    {
        return Err(JmapError::invalid_arguments(format!(
            "unknown property {unknown}"
        )));
    }
    let (state, list) = projection
        .records(kind, account, ids.as_deref(), properties.as_deref())
        .await?;
    let found: BTreeSet<&str> = list
        .iter()
        .filter_map(|object| object.get("id")?.as_str())
        .collect();
    // RFC 8620 §5.1: a repeated id is reported once.
    let not_found: BTreeSet<&str> = ids
        .iter()
        .flatten()
        .map(String::as_str)
        .filter(|id| !found.contains(id))
        .collect();
    Ok(json!({
        "accountId": account_id,
        "state": state,
        "list": list,
        "notFound": not_found,
    }))
}

/// What a projection handler does.
#[derive(Debug, Clone, Copy)]
enum Operation {
    Get,
    Changes,
    Query,
    QueryChanges,
}

/// One registered projection method.
struct Handler {
    projection: Arc<Projection>,
    kind: Kind,
    operation: Operation,
}

impl JmapHandler<Account> for Handler {
    fn call(
        &self,
        _method: String,
        _call_id: String,
        args: Value,
        caller: Account,
    ) -> HandlerFuture {
        let projection = Arc::clone(&self.projection);
        let (kind, operation) = (self.kind, self.operation);
        Box::pin(async move {
            let projection = projection.as_ref();
            let caller = &caller;
            match (kind, operation) {
                (_, Operation::Get) => {
                    return get(projection, kind, args, caller)
                        .await
                        .map(|v| (v, Vec::new()));
                }
                (Kind::Chat, Operation::Changes) => {
                    handle_changes::<ChatRecord, _>(projection, caller, args).await
                }
                (Kind::Message, Operation::Changes) => {
                    handle_changes::<MessageRecord, _>(projection, caller, args).await
                }
                (Kind::ChatContact, Operation::Changes) => {
                    handle_changes::<ContactRecord, _>(projection, caller, args).await
                }
                (Kind::Chat, Operation::Query) => {
                    handle_query::<ChatRecord, _>(projection, caller, args).await
                }
                (Kind::Message, Operation::Query) => {
                    handle_query::<MessageRecord, _>(projection, caller, args).await
                }
                (Kind::ChatContact, Operation::Query) => {
                    handle_query::<ContactRecord, _>(projection, caller, args).await
                }
                (Kind::Chat, Operation::QueryChanges) => {
                    handle_query_changes::<ChatRecord, _>(projection, caller, args).await
                }
                (Kind::Message, Operation::QueryChanges) => {
                    handle_query_changes::<MessageRecord, _>(projection, caller, args).await
                }
                (Kind::ChatContact, Operation::QueryChanges) => {
                    handle_query_changes::<ContactRecord, _>(projection, caller, args).await
                }
            }
        })
    }
}

/// Registers `Chat`, `Message` and `ChatContact` `/get`, `/changes`,
/// `/query` and `/queryChanges` (decisions mimid-1wgh.12.22,
/// mimid-1wgh.12.33).
pub(crate) fn register(methods: &mut Methods, projection: &Arc<Projection>) {
    const METHODS: [(&str, Kind, Operation); 12] = [
        ("Chat/get", Kind::Chat, Operation::Get),
        ("Chat/changes", Kind::Chat, Operation::Changes),
        ("Chat/query", Kind::Chat, Operation::Query),
        ("Chat/queryChanges", Kind::Chat, Operation::QueryChanges),
        ("Message/get", Kind::Message, Operation::Get),
        ("Message/changes", Kind::Message, Operation::Changes),
        ("Message/query", Kind::Message, Operation::Query),
        (
            "Message/queryChanges",
            Kind::Message,
            Operation::QueryChanges,
        ),
        ("ChatContact/get", Kind::ChatContact, Operation::Get),
        ("ChatContact/changes", Kind::ChatContact, Operation::Changes),
        ("ChatContact/query", Kind::ChatContact, Operation::Query),
        (
            "ChatContact/queryChanges",
            Kind::ChatContact,
            Operation::QueryChanges,
        ),
    ];
    for (name, kind, operation) in METHODS {
        methods.add(
            name,
            Arc::new(Handler {
                projection: Arc::clone(projection),
                kind,
                operation,
            }),
        );
    }
}

/// How a `/set` refuses a create or update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Refusal {
    /// The entry gets the SetError `forbidden`.
    Forbidden,
    /// The whole call gets the method-level error `invalidArguments`
    /// (RFC 8620 §3.6.2), which mimi-00 §mls-messages names for a Message
    /// create and a body change (decision mimid-1wgh.11.8).
    InvalidArguments,
}

/// The SetError `forbidden`.
fn forbidden() -> Value {
    serde_json::to_value(SetError::new(SetErrorType::Forbidden))
        .unwrap_or_else(|_| json!({"type": "serverFail"}))
}

/// The rules of a `/set` that changes nothing.
#[derive(Clone, Copy)]
pub(crate) struct RefusingSet {
    /// What every create gets.
    pub(crate) create: Refusal,
    /// What an update of an existing object with this patch gets.
    pub(crate) update: fn(&Map<String, Value>) -> Refusal,
}

/// RFC 8620 §5.3 `/set` for a projected `kind` that refuses every create,
/// update and destroy by `rules`: an update or destroy of an object the
/// account cannot see is `notFound`, and `ifInState` is checked first.
async fn refuse_set(
    projection: &Projection,
    kind: Kind,
    rules: &RefusingSet,
    args: Value,
    account: &Account,
) -> Result<Value, JmapError> {
    let Value::Object(args) = args else {
        return Err(JmapError::invalid_arguments("arguments must be an object"));
    };
    let account_id = match args.get("accountId") {
        Some(Value::String(account_id)) => account_id.clone(),
        _ => return Err(JmapError::invalid_arguments("accountId is required")),
    };
    account
        .check_account_id(&account_id)
        .map_err(|_| JmapError::account_not_found())?;
    let object = |key: &str| match args.get(key) {
        None | Some(Value::Null) => Ok(Map::new()),
        Some(Value::Object(map)) => Ok(map.clone()),
        Some(_) => Err(JmapError::invalid_arguments(format!(
            "{key} must be an object"
        ))),
    };
    let create = object("create")?;
    let update = object("update")?;
    let destroy: Vec<String> = match args.get("destroy") {
        None | Some(Value::Null) => Vec::new(),
        Some(value) => serde_json::from_value(value.clone())
            .map_err(|_| JmapError::invalid_arguments("destroy must be an Id array"))?,
    };
    let mut patches = Vec::with_capacity(update.len());
    for (id, patch) in &update {
        let Value::Object(patch) = patch else {
            return Err(JmapError::invalid_arguments(
                "an update must be a PatchObject",
            ));
        };
        patches.push((id.clone(), patch));
    }
    let named: Vec<String> = update
        .keys()
        .cloned()
        .chain(destroy.iter().cloned())
        .collect();
    let (state, found) = projection
        .records(kind, account, Some(&named), Some(&[][..]))
        .await?;
    let found: BTreeSet<String> = found
        .iter()
        .filter_map(|object| object.get("id")?.as_str().map(str::to_owned))
        .collect();
    match args.get("ifInState") {
        None | Some(Value::Null) => {}
        Some(Value::String(expected)) if *expected == state => {}
        Some(Value::String(_)) => return Err(JmapError::state_mismatch()),
        Some(_) => return Err(JmapError::invalid_arguments("ifInState must be a string")),
    }
    // Decision mimid-1wgh.11.8: one such entry refuses the whole call.
    let refuses_call = (!create.is_empty() && rules.create == Refusal::InvalidArguments)
        || patches.iter().any(|(id, patch)| {
            found.contains(id) && (rules.update)(patch) == Refusal::InvalidArguments
        });
    if refuses_call {
        return Err(JmapError::invalid_arguments(
            "server-created Messages cannot be created or have their content changed",
        ));
    }
    let not_found = || json!({"type": "notFound"});
    let refused = |id: &String| {
        if found.contains(id) {
            forbidden()
        } else {
            not_found()
        }
    };
    let not_created: BTreeMap<String, Value> = create
        .keys()
        .map(|key| (key.clone(), forbidden()))
        .collect();
    let not_updated: BTreeMap<String, Value> = patches
        .iter()
        .map(|(id, _)| (id.clone(), refused(id)))
        .collect();
    let not_destroyed: BTreeMap<String, Value> =
        destroy.iter().map(|id| (id.clone(), refused(id))).collect();
    let or_null = |map: BTreeMap<String, Value>| {
        if map.is_empty() {
            Value::Null
        } else {
            json!(map)
        }
    };
    Ok(json!({
        "accountId": account_id,
        "oldState": state,
        "newState": state,
        "created": null,
        "updated": null,
        "destroyed": null,
        "notCreated": or_null(not_created),
        "notUpdated": or_null(not_updated),
        "notDestroyed": or_null(not_destroyed),
    }))
}

/// A `/set` handler that refuses by its rules.
struct SetHandler {
    projection: Arc<Projection>,
    kind: Kind,
    rules: RefusingSet,
}

impl JmapHandler<Account> for SetHandler {
    fn call(
        &self,
        _method: String,
        _call_id: String,
        args: Value,
        caller: Account,
    ) -> HandlerFuture {
        let projection = Arc::clone(&self.projection);
        let (kind, rules) = (self.kind, self.rules);
        Box::pin(async move {
            refuse_set(&projection, kind, &rules, args, &caller)
                .await
                .map(|response| (response, Vec::new()))
        })
    }
}

/// Registers `Chat/set` with `rules`.
pub(crate) fn register_chat_set(
    methods: &mut Methods,
    projection: &Arc<Projection>,
    rules: RefusingSet,
) {
    methods.add(
        "Chat/set",
        Arc::new(SetHandler {
            projection: Arc::clone(projection),
            kind: Kind::Chat,
            rules,
        }),
    );
}

/// Registers `Message/set` with `rules`.
pub(crate) fn register_message_set(
    methods: &mut Methods,
    projection: &Arc<Projection>,
    rules: RefusingSet,
) {
    methods.add(
        "Message/set",
        Arc::new(SetHandler {
            projection: Arc::clone(projection),
            kind: Kind::Message,
            rules,
        }),
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle: Python `datetime.fromtimestamp(ms // 1000, tz=utc)` with the
    // milliseconds appended when non-zero.
    #[test]
    fn utc_dates_match_reference_values() {
        for (ms, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_700_000_100_000, "2023-11-14T22:15:00Z"),
            (1_700_000_100_123, "2023-11-14T22:15:00.123Z"),
            (951_782_400_001, "2000-02-29T00:00:00.001Z"),
            (4_102_444_799_999, "2099-12-31T23:59:59.999Z"),
            (253_402_300_799_000, "9999-12-31T23:59:59Z"),
        ] {
            assert_eq!(utc_date(ms), expected, "{ms}");
        }
    }

    // Oracle: Python, ULID(1_700_000_000_001, first 10 octets of
    // SHA-256(b"fanout one")) in Crockford base32.
    #[test]
    fn sender_msg_id_matches_reference_value() {
        let hash: [u8; 32] = Sha256::digest(b"fanout one").into();
        assert_eq!(
            sender_msg_id(1_700_000_000_001, &hash),
            "01HF7YAT01M0CMTXN7P89EE5B8"
        );
    }

    // Oracle: Python, unpadded base64url of SHA-256(provider URI)[:16].
    #[test]
    fn contact_ids_match_reference_values() {
        assert_eq!(contact_id("a.example"), "milU-_r22QJDeOC98n79JQ");
        assert_eq!(contact_id("c.example"), "KGHDjfpVn_xYcJS1VP092w");
    }

    #[test]
    fn state_counters_are_strict() {
        assert_eq!(parse_counter("0"), Some(0));
        assert_eq!(
            parse_counter("9223372036854775807"),
            Some(9_223_372_036_854_775_807)
        );
        for bad in [
            "",
            "-1",
            "+1",
            " 1",
            "1 ",
            "0x1",
            "9223372036854775808",
            "1.0",
            "\u{0661}",
        ] {
            assert_eq!(parse_counter(bad), None, "{bad:?}");
        }
        assert_eq!(
            parse_message_state("3.1"),
            Some(ProjectionCursor { seq: 3, member: 1 })
        );
        for bad in ["3", "3.", ".1", "3.1.0", "a.b"] {
            assert_eq!(parse_message_state(bad), None, "{bad:?}");
        }
    }
}
