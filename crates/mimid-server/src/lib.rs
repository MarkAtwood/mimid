//! The library behind the `mimid` binary: the MIMI provider server of the
//! mimid reference implementation.
//!
//! One server plays both MIMI roles at once: hub for the rooms this provider
//! hosts and follower for rooms hosted elsewhere (decision mimid-1wgh.15).
//! It also serves the provider's JMAP Chat endpoint to local users
//! ([`jmap`]). The binary is a thin wrapper; the modules live here so
//! integration tests can use them.
//!
//! # Limitations
//!
//! - The JMAP Chat endpoint is a subset of draft-atwood-jmap-chat-00 and
//!   -mimi-00; [`jmap`] lists what is missing (decision mimid-1wgh.12.22).
//! - Providers authenticate with RFC 9421 request signatures (keys
//!   configured per peer or published in DNS), PKIX client certificates
//!   or DANE (mimid-75nk; decision mimid-1wgh.17 reversed), but a peer in
//!   observe mode is let through unauthenticated. Both halves of the
//!   mutually authenticated TLS protocol-07 §4.1 requires are written
//!   (mimid-75nk.4, .5, .6) but not yet deployed or tested with a peer
//!   (bead mimid-6x2f): mimid does not claim conformance to it. With BasicCredential, a provider can still claim
//!   any identity for its own users.
//! - Peer providers are found through the configured peer map, not DNS.
//! - The listener speaks plain HTTP unless `[tls]` is configured, when it
//!   serves HTTPS and asks for client certificates ([`tls`]).
//! - keyMaterial for users of this provider is served from the KeyPackages
//!   they upload, with implicit consent ([`follower::key_packages`];
//!   decision mimid-1wgh.7.9). The hub proxies keyMaterial for users of
//!   other providers. reportAbuse checks `canReportAbuse`, validates
//!   franks, counts unfranked messages (mimid's own `abuse_extensions`
//!   component 0xF020, INVENTED, NOT FROM SPEC; decision mimid-1wgh.60) as
//!   unverified and logs the outcome; no action follows (decision
//!   mimid-1wgh.21). A user sends one with `Room/reportAbuse`, a JMAP
//!   method draft-atwood-jmap-chat-mimi-00 does not define (INVENTED,
//!   NOT FROM SPEC; decision mimid-1wgh.58).
//! - [`peer`] sends `/notify` requests to configured peers, and
//!   [`hub::fanout`] delivers the outbox through it, at least once, so
//!   followers must deduplicate ([`follower`] does, decision
//!   mimid-1wgh.7.3).
//! - Attachments (bead mimid-1wgh.14): the server stores encrypted blobs
//!   and serves them at an unauthenticated asset URL, and fetches a
//!   room's attachments for its members through the room's hub
//!   ([`jmap::blobs`]). Blobs are never deleted, and room-policy-04's
//!   `asset_policy` is not consulted ([`hub::assets`]).
//! - The follower runs no MLS Observer: it checks decoding and envelope
//!   consistency only (decision mimid-1wgh.7.2). Its other limitations are
//!   listed in [`follower`].
//! - The hub's signing and franking keys are stored unencrypted in the
//!   database, which must be readable by its owner only (mode 0600; see
//!   [`store`]).
//! - Every client of a user carries the same BasicCredential identity, the
//!   user URI (decision mimid-1wgh.6.1). Stock mls-rs clients reject two
//!   leaves with the same identity, so a user with two devices cannot share
//!   a group with mls-rs-based members.
//! - draft-atwood-mls-didwebvh-credential-01 (bead mimid-1wgh.4.81.18): the
//!   hub enforces the draft's group rules in every hosted room under the
//!   code points of `[did_webvh]` (default the suggested credential type
//!   0x0008 and the private-use component 0xf013), and KeyPackage upload
//!   accepts a `did_webvh` KeyPackage whose log names the uploading user.
//!   The record is an `app_data_dictionary` component changed by
//!   AppDataUpdate, not the draft's GroupContext extension (decision
//!   mimid-1wgh.4.81.33, INVENTED, NOT FROM SPEC), so the hub refuses every
//!   GroupContextExtensions proposal (decision mimid-1wgh.6.2) and room
//!   policy needs no capability for the record. A `did_webvh` leaf is
//!   taken to belong to the one `mimi:` URI its log lists in `alsoKnownAs`
//!   (decision mimid-1wgh.4.81.21, INVENTED, NOT FROM SPEC), and room
//!   policy judges it by that URI. A Remove the rules require of a Commit
//!   (a revoked device) needs no capability (decisions mimid-1wgh.4.81.26,
//!   mimid-1wgh.4.81.31). A keyMaterial request that requires `did_webvh`
//!   is served only KeyPackages that list the record component (decision
//!   mimid-1wgh.4.81.36). keyMaterial requests still carry a
//!   BasicCredential for the requester. The hub
//!   cannot itself bring a newer log to a room (draft §Withheld or Stale
//!   Logs).
//! - Room policy ([`hub::policy`]):
//!   - A room without a `base_room_policy` is an open room, in which every
//!     participant holds every capability (decision mimid-1wgh.52). The
//!     hub hosts a new one only if its operator sets `require_room_policy
//!     = false` (bead mimid-jf20); a peer cannot make it host one, since
//!     only local Room/create and the local control route create rooms,
//!     and no Commit can remove a room's `base_room_policy`. Rooms stored
//!     before the setting was turned on stay open rooms (logged at start
//!     as `open_room_kept`). Rooms other providers host follow their
//!     hub's policy: the follower relays them whatever they carry, and a
//!     local user may join a policy-less room hosted elsewhere.
//!   - Only BasicCredential is supported, and it carries no claims, so
//!     preauthorization matches only `preauth_list` entries with an empty
//!     `claimset` (room-policy-04 §4; decision mimid-1wgh.3.47).
//!   - Join codes are not supported: `canUseJoinCode` never authorizes
//!     anything, and a GroupInfo request with a joining code is refused
//!     (decision mimid-1wgh.6.13).
//!   - `room_uri` in `room_metadata` cannot be changed by anyone, in any
//!     room: room-policy-04 §8.2 gives it no capability (decision
//!     mimid-1wgh.64). AppDataUpdates to the room-policy §6 and §7
//!     components are refused as unknown to the hub (decision
//!     mimid-1wgh.6.53).
//!   - The room-policy-04 §5 rule that ordinary users of a fixed-membership
//!     room cannot leave or be removed is not enforced (decision
//!     mimid-1wgh.3.50). The §5 `parent_dependant` subset rule and
//!     `pseudonyms_allowed` are not checked: the hub has no parent room
//!     state and BasicCredential has no notion of a pseudonym.
//!   - `canDestroyRoom` is not enforced: the hub offers no way to destroy a
//!     room.
//!   - The hub is a hosted room's only MLS external sender (decision
//!     mimid-1wgh.4.21). Its external proposals are accepted only as a
//!     Remove or a `participant_list` update, which it sends for operator
//!     remove and ban (decision mimid-1wgh.6.46 as amended 2026-11-15; an
//!     operator power outside the drafts); any other is refused.
//!   - A new-member (external) proposal can only add a client of a user
//!     already in the participant list (`canAddOwnClient`);
//!     preauthorization is consulted only for external Commits (decision
//!     mimid-1wgh.6.46).
//!   - An AppDataUpdate `remove` of a hub-tracked component is refused, and
//!     so is any AppDataUpdate of `franking_agent`, which must stay the
//!     hub's key (decisions mimid-1wgh.6.3, mimid-1wgh.6.42).
//!   - A `base_room_policy` update needs `canChangeRoomMembershipStyle`
//!     whatever fields it changes (decision mimid-1wgh.6.43).

#![forbid(unsafe_code)]

pub mod admin;
pub mod config;
pub mod directory;
pub mod follower;
pub mod http;
pub mod httpsig;
pub mod hub;
pub mod jmap;
pub mod limits;
pub mod local;
pub mod logging;
pub mod peer;
pub mod peer_clock;
pub mod provider_auth;
pub mod store;
pub mod telemetry;
pub mod tls;
