//! The media key material of a call room (bead mimid-1wgh.108;
//! draft-atwood-mimi-calls §4).
//!
//! A call is its own MIMI room, parent-dependent on the chat it belongs to
//! (room-policy-04 §5; decision mimid-1wgh.113), and its media key comes
//! from that room's own MLS group through the forward-secure exporter of
//! mls-extensions-11 §4.4, under the `media_keys` component
//! ([`mimi_protocol::component_id::MEDIA_KEYS`]). Nothing is sent to key
//! the media: every member of the call's group computes the same secret
//! from the epoch it is already in, which is the whole point of giving a
//! call a room of its own.
//!
//! §4.4's exporter is forward-secure, and it pays for that by being
//! usable once: the Exporter Tree leaf for a component is punctured when
//! it is read, so a second read in the same epoch fails. The agent
//! therefore reads it at most once per epoch and keeps the result in
//! memory for as long as that epoch lasts
//! ([`Agent::media_secret`](crate::Agent::media_secret)). A new epoch is
//! a new secret, so a call's media key rolls whenever the call's
//! membership changes.
//!
//! # Limitations
//!
//! - The secret is held in process memory for the life of the epoch,
//!   because a media stack needs it for the life of the stream. It is
//!   zeroized when dropped and never written to the database, and it is
//!   dropped when the room's epoch moves past it or the agent leaves the
//!   room. A secret of an epoch that is over can outlive it by that much:
//!   until the agent next handles something in that room.
//! - A restart inside an epoch loses THAT EPOCH'S secret for good. The
//!   secret was only ever in memory, and §4.4's leaf was punctured when
//!   it was read, with the puncture written to the store -- which is §4.4
//!   working as specified, not a defect. The way out is a new epoch:
//!   [`Agent::rekey`](crate::Agent::rekey) commits an empty Commit so
//!   every member derives a fresh secret, and
//!   [`AgentError::SecretConsumed`](crate::AgentError::SecretConsumed) is
//!   the one export failure that says so (bead mimid-1wgh.129). The
//!   JMAP front end rolls on it, since a restart also puts back the
//!   `VTCCall` the client names (bead mimid-1wgh.114.14); an embedder of
//!   this crate does it itself, holding its own call state.
//! - It is the whole group's: every member of the call's room derives it,
//!   so it confines media to the room's members and to nobody smaller. A
//!   call among fewer people is a smaller room, not a smaller key.
//! - Deriving the media keys themselves from it (an SFrame base key, say)
//!   is the media layer's, and mimid has none: this is the key schedule's
//!   last MIMI step (bead mimid-1wgh.108).

use zeroize::Zeroizing;

/// A call room's exported media secret for one epoch
/// (mls-extensions-11 §4.4).
///
/// `Debug` prints no part of it, and the type implements neither
/// `Display` nor `Serialize`, so it cannot reach a log by accident;
/// [`MediaSecret::expose_secret`] is the only way to read it. The bytes
/// are zeroized when the value is dropped.
#[derive(Clone, PartialEq, Eq)]
pub struct MediaSecret {
    secret: Zeroizing<Vec<u8>>,
    epoch: u64,
}

impl MediaSecret {
    /// Wraps `secret`, exported in `epoch`.
    pub(crate) fn new(secret: Vec<u8>, epoch: u64) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            epoch,
        }
    }

    /// The secret's bytes. Never log them.
    #[must_use]
    pub fn expose_secret(&self) -> &[u8] {
        &self.secret
    }

    /// The epoch of the call room's MLS group this secret belongs to
    /// (RFC 9420 §8.1). Every member of that epoch derives these same
    /// bytes, and the next epoch has others.
    #[must_use]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }
}

impl std::fmt::Debug for MediaSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "MediaSecret {{ epoch: {}, secret: <redacted> }}",
            self.epoch
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_no_part_of_the_secret() {
        let secret = MediaSecret::new(vec![0xab; 32], 7);
        let text = format!("{secret:?}");
        assert!(text.contains("epoch: 7"), "{text}");
        assert!(text.contains("<redacted>"), "{text}");
        assert!(!text.contains("ab"), "{text}");
        assert!(!text.contains("171"), "{text}");
    }
}
