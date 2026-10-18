//! MessageId derivation (§3.3).

use sha2::{Digest, Sha256};

use crate::content::MessageId;

/// Longest sender or room URI, in octets, that §3.3 can hash: its length
/// prefix is a big-endian unsigned 16-bit integer.
pub const MAX_MESSAGE_ID_URI_LEN: usize = u16::MAX as usize;

/// Why a [`MessageId`] could not be computed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum MessageIdError {
    /// The sender URI is longer than [`MAX_MESSAGE_ID_URI_LEN`] octets.
    #[error("sender URI is {len} octets; at most {MAX_MESSAGE_ID_URI_LEN} are allowed")]
    SenderUriTooLong {
        /// Length of the sender URI in octets.
        len: usize,
    },
    /// The room URI is longer than [`MAX_MESSAGE_ID_URI_LEN`] octets.
    #[error("room URI is {len} octets; at most {MAX_MESSAGE_ID_URI_LEN} are allowed")]
    RoomUriTooLong {
        /// Length of the room URI in octets.
        len: usize,
    },
}

impl MessageId {
    /// IANA Named Information hash algorithm ID of SHA-256, the §3.3
    /// default and the only algorithm [`MessageId::compute`] uses.
    pub const HASH_ALG_SHA256: u8 = 0x01;

    /// Computes the message ID of a received message (§3.3):
    ///
    /// ```text
    /// hash_output = SHA-256( senderUriLength || senderUri ||
    ///                        roomUriLength   || roomUri   ||
    ///                        message         || salt )
    /// messageId   = 0x01 || hash_output[0..30]
    /// ```
    ///
    /// The lengths are big-endian `u16` octet counts.
    ///
    /// `message` must be the `mimiContent` bytes exactly as received. They
    /// are hashed as given and never re-encoded (decision mimid-1wgh.2.11).
    /// `salt` must be the `salt` field of that same message.
    ///
    /// `sender_uri` is the authenticated sender's user URI and `room_uri`
    /// the authenticated room URI. The caller supplies them, whether or not
    /// the `senderUri` and `roomUri` extensions are present. Checking that
    /// those extensions match the URIs is the caller's job (decision
    /// mimid-1wgh.2.10).
    ///
    /// # Errors
    ///
    /// [`MessageIdError::SenderUriTooLong`] or
    /// [`MessageIdError::RoomUriTooLong`] if a URI is longer than
    /// [`MAX_MESSAGE_ID_URI_LEN`] octets.
    pub fn compute(
        sender_uri: &str,
        room_uri: &str,
        message: &[u8],
        salt: &[u8; 16],
    ) -> Result<Self, MessageIdError> {
        let sender_len =
            u16::try_from(sender_uri.len()).map_err(|_| MessageIdError::SenderUriTooLong {
                len: sender_uri.len(),
            })?;
        let room_len =
            u16::try_from(room_uri.len()).map_err(|_| MessageIdError::RoomUriTooLong {
                len: room_uri.len(),
            })?;
        let hash_output = Sha256::new()
            .chain_update(sender_len.to_be_bytes())
            .chain_update(sender_uri)
            .chain_update(room_len.to_be_bytes())
            .chain_update(room_uri)
            .chain_update(message)
            .chain_update(salt)
            .finalize();
        let mut id = [0u8; 32];
        id[0] = Self::HASH_ALG_SHA256;
        id[1..].copy_from_slice(&hash_output[..31]);
        Ok(Self(id))
    }
}
