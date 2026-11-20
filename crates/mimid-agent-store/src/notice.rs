//! The agent's own notices in a room (INVENTED, NOT FROM SPEC): their
//! keys, which make each one idempotent across journal replays, and their
//! texts. A front end shows a notice its own way; these are the words.
//!
//! - The identity notice: a contact's did:webvh SCID changed
//!   (`Event::IdentityChanged`; bead mimid-1wgh.4.81.27).
//! - The removal notice: a client of a member was removed because its app
//!   lacks AppDataUpdate (`Event::RemovedWithoutAppDataUpdate`; bead
//!   mimid-4lp4.4).
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
