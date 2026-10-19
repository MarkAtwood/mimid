//! The library behind the `mimid` binary: the MIMI provider server of the
//! mimid reference implementation.
//!
//! One server plays both MIMI roles at once: hub for the rooms this provider
//! hosts and follower for rooms hosted elsewhere (decision mimid-1wgh.15).
//! The binary is a thin wrapper; the modules live here so integration tests
//! can use them.
//!
//! # Limitations
//!
//! - There is no authentication between providers (decision mimid-1wgh.17).
//!   protocol-06 requires mutually authenticated TLS; mimid does not
//!   implement it and does not claim conformance to it. Combined with
//!   BasicCredential, mimid offers no protection against a malicious or
//!   impersonated provider.
//! - Peer providers are found through the configured peer map, not DNS.
//! - The listener speaks plain HTTP; TLS must be terminated in front of it.
//! - keyMaterial for users of this provider is served from the KeyPackages
//!   they upload, with implicit consent ([`follower::key_packages`];
//!   decision mimid-1wgh.7.9). The hub proxies keyMaterial for users of
//!   other providers. reportAbuse validates franks and logs the outcome;
//!   no action follows (decision mimid-1wgh.21).
//! - [`peer`] sends `/notify` requests to configured peers, and
//!   [`hub::fanout`] delivers the outbox through it, at least once, so
//!   followers must deduplicate ([`follower`] does, decision
//!   mimid-1wgh.7.3).
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
//! - Room policy ([`hub::policy`]):
//!   - Only BasicCredential is supported, and it carries no claims, so
//!     preauthorization matches only `preauth_list` entries with an empty
//!     `claimset` (room-policy-04 §4; decision mimid-1wgh.3.47).
//!   - Join codes are not supported: `canUseJoinCode` never authorizes
//!     anything, and a GroupInfo request with a joining code is refused
//!     (decision mimid-1wgh.6.13).
//!   - The §8.2 metadata capabilities are not enforced (decision
//!     mimid-1wgh.6.2); updates to `room_metadata` are carried without a
//!     capability check. AppDataUpdates to the room-policy §6 and §7
//!     components are refused as unknown to the hub (decision
//!     mimid-1wgh.6.53).
//!   - The room-policy-04 §5 rule that ordinary users of a fixed-membership
//!     room cannot leave or be removed is not enforced (decision
//!     mimid-1wgh.3.50). The §5 `parent_dependant` subset rule and
//!     `pseudonyms_allowed` are not checked: the hub has no parent room
//!     state and BasicCredential has no notion of a pseudonym.
//!   - `canDestroyRoom` is not enforced: the hub offers no way to destroy a
//!     room.
//!   - Proposals from an MLS external sender are refused: the hub is the
//!     only external sender (decision mimid-1wgh.4.21) and v1 sends none
//!     (decision mimid-1wgh.6.46).
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

pub mod config;
pub mod directory;
pub mod follower;
pub mod http;
pub mod hub;
pub mod peer;
pub mod store;
