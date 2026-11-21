//! The agent's own notices in a room (INVENTED, NOT FROM SPEC): their
//! keys, which make each one idempotent across journal replays, and their
//! texts. A front end shows a notice its own way; these are the words.
//!
//! - The identity notice: a contact's did:webvh SCID changed
//!   (`Event::IdentityChanged`; bead mimid-1wgh.4.81.27).
//! - The removal notice: a client of a member was removed because its app
//!   lacks AppDataUpdate (`Event::RemovedWithoutAppDataUpdate`; bead
//!   mimid-4lp4.4).
//! - The lost-messages notice: messages of the room could not be
//!   delivered, because the provider no longer had what this device
//!   missed (`Event::MessagesLost`; decision mimid-1wgh.83).
//!
//! # Limitations
//!
//! - The texts are English only.

use sha2::{Digest, Sha256};

use crate::convert::MessageRef;

/// The reference octets (the random part of `senderMsgId`) of the identity
/// notice for one mismatch: the first 10 octets of SHA-256 over a label and
/// the room, user, pinned SCID and presented SCID (`basic` for a
/// BasicCredential leaf), each ended by a NUL. INVENTED, NOT FROM SPEC.
#[must_use]
pub fn notice_ref(room: &str, user: &str, pinned: &str, presented: Option<&str>) -> MessageRef {
    let mut hash = Sha256::new();
    for part in [
        "mimid identity-changed notice",
        room,
        user,
        pinned,
        presented.unwrap_or("basic"),
    ] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    let digest = hash.finalize();
    let mut out = [0u8; 10];
    out.copy_from_slice(&digest[..10]);
    out
}

/// The [`MessageRef`] of the removal notice for a client of `user` removed
/// in `room` at `epoch` (bead mimid-4lp4.4): the first 10 octets of
/// SHA-256 over the parts, each ended by a NUL.
#[must_use]
pub fn removal_notice_ref(room: &str, user: &str, epoch: u64) -> MessageRef {
    let mut hash = Sha256::new();
    for part in [
        "mimid removed-without-app-data-update notice",
        room,
        user,
        &epoch.to_string(),
    ] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    let digest = hash.finalize();
    let mut out = [0u8; 10];
    out.copy_from_slice(&digest[..10]);
    out
}

/// The [`MessageRef`] of the lost-messages notice for the gap in `room`
/// that ends at `to` (decision mimid-1wgh.83): the first 10 octets of
/// SHA-256 over the parts, each ended by a NUL.
#[must_use]
pub fn lost_notice_ref(room: &str, to: u64) -> MessageRef {
    let mut hash = Sha256::new();
    for part in ["mimid messages-lost notice", room, &to.to_string()] {
        hash.update(part.as_bytes());
        hash.update([0]);
    }
    let digest = hash.finalize();
    let mut out = [0u8; 10];
    out.copy_from_slice(&digest[..10]);
    out
}

/// The text of a lost-messages notice for the messages between `from`
/// and `to`, hub acceptance times in milliseconds since the UNIX epoch,
/// shown as UTC (decision mimid-1wgh.83).
#[must_use]
pub fn lost_notice(from: Option<u64>, to: u64) -> String {
    let to = crate::convert::utc_date(to);
    match from {
        Some(from) => format!(
            "Notice from your mimid agent: messages from {} to {to} could not be delivered. \
             Your server no longer had them when this device came back.",
            crate::convert::utc_date(from)
        ),
        None => format!(
            "Notice from your mimid agent: messages up to {to} could not be delivered. \
             Your server no longer had them when this device came back."
        ),
    }
}

/// The text of a removal notice for `name` (bead mimid-4lp4.4).
#[must_use]
pub fn removal_notice(name: &str) -> String {
    format!(
        "Notice from your mimid agent: a device of {name} was removed from this chat. Its app \
         could not take part in a security update of the chat (it does not support MLS \
         AppDataUpdate). {name} is still a participant and can rejoin from an app that \
         supports it."
    )
}

/// The text of an identity notice for contact `name`. Only public values:
/// the name and the SCIDs.
#[must_use]
pub fn identity_notice(name: &str, pinned: &str, presented: Option<&str>) -> String {
    let change = match presented {
        Some(presented) => format!(
            "A device of {name} now presents a different did:webvh identity (SCID {presented}) \
             from the one first seen for them (SCID {pinned})."
        ),
        None => format!(
            "A device of {name} presents no did:webvh credential, but {name} was first seen \
             with one (SCID {pinned})."
        ),
    };
    format!(
        "Security notice from your mimid agent, not from {name}: the identity of {name} \
         changed. {change} Verify the new identity with {name} by other means before you \
         trust messages from that device."
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle: Python, hashlib.sha256(b"mimid removed-without-app-data-update
    // notice\0mimi://a.example/r/one\0mimi://b.example/u/erin\05\0")
    // .digest()[:10].hex().
    const REMOVAL_KEY: &str = "571a45c0fb47ce2bb9b1";

    // Oracle: Python, hashlib.sha256(b"mimid messages-lost notice\0
    // mimi://a.example/r/one\01700000100123\0").digest()[:10].hex(); the
    // dates from datetime.fromtimestamp(ms / 1000, timezone.utc).
    #[test]
    fn lost_notices_are_keyed_by_room_and_end_and_name_both_times() {
        let key = lost_notice_ref("mimi://a.example/r/one", 1_700_000_100_123);
        assert_eq!(
            key,
            [0x68, 0x94, 0xed, 0xe7, 0xd4, 0xd6, 0xac, 0x97, 0xa9, 0xb8]
        );
        assert_ne!(
            key,
            lost_notice_ref("mimi://a.example/r/one", 1_700_000_100_124)
        );
        let text = lost_notice(Some(1_700_000_000_001), 1_700_000_100_123);
        assert!(
            text.contains("messages from 2023-11-14T22:13:20.001Z to 2023-11-14T22:15:00.123Z could not be delivered"),
            "{text}"
        );
        let text = lost_notice(None, 1_700_000_100_123);
        assert!(
            text.contains("messages up to 2023-11-14T22:15:00.123Z could not be delivered"),
            "{text}"
        );
    }

    #[test]
    fn removal_notices_are_keyed_by_room_user_and_epoch() {
        let key = removal_notice_ref("mimi://a.example/r/one", "mimi://b.example/u/erin", 5);
        assert_eq!(hex::encode(key), REMOVAL_KEY);
        assert_ne!(
            key,
            removal_notice_ref("mimi://a.example/r/one", "mimi://b.example/u/erin", 6)
        );
        assert_ne!(
            key,
            notice_ref(
                "mimi://a.example/r/one",
                "mimi://b.example/u/erin",
                "5",
                None
            )
        );
        let text = removal_notice("Erin");
        assert!(text.contains("a device of Erin was removed"), "{text}");
        assert!(text.contains("AppDataUpdate"), "{text}");
        assert!(text.contains("can rejoin"), "{text}");
    }
}
