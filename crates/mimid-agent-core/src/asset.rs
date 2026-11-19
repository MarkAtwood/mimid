//! Attachment encryption (bead mimid-1wgh.14): the content of an
//! ExternalPart (mimi-content-10 §4.5), sealed before upload and opened
//! after download.
//!
//! [`seal`] encrypts with AES-128-GCM, the algorithm §4.5 makes mandatory
//! to implement, under a fresh random key and nonce with empty additional
//! authenticated data (§4.5's default), and hashes what is stored (the
//! ciphertext and tag) with SHA-256: "The contentHash is computed over the
//! content as stored at the URL, which is the ciphertext when encAlg is not
//! zero." [`open`] checks that hash before it decrypts.
//!
//! # Limitations
//!
//! - Only AES-128-GCM (and unencrypted content) and SHA-256 (or no hash)
//!   are supported; any other algorithm is [`AssetError::Unsupported`].
//! - `size` is not checked: §4.5 does not say whether it counts the
//!   plaintext or the stored octets. [`seal`]'s callers set it to the
//!   stored octets.
//! - `expires` is not checked here; the caller has the clock.
//! - [`expiry`] counts from the sender's clock at the start of the upload,
//!   not the server's upload time: an RFC 8620 §6.1 upload response
//!   carries no time. A sender clock behind the server's only makes the
//!   stated expiry early; one ahead makes it late.
//! - The whole content is in memory.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Nonce};
use mimi_content::ExternalPart;
use sha2::{Digest, Sha256};

use crate::AgentError;

/// The IANA AEAD Algorithms number of AEAD_AES_128_GCM (RFC 5116 §5.1).
pub const AES_128_GCM: u16 = 1;

/// The IANA Named Information Hash Algorithm Registry number of sha-256
/// (RFC 6920 §9.4).
pub const SHA_256: u8 = 1;

/// AES-128-GCM key length (RFC 5116 §5.1).
const KEY_LEN: usize = 16;

/// AES-128-GCM nonce length (RFC 5116 §5.1).
const NONCE_LEN: usize = 12;

/// Why stored content could not be opened.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssetError {
    /// The part names an algorithm this implementation does not have.
    #[error("unsupported {what} {value}")]
    Unsupported {
        /// `encAlg` or `hashAlg`.
        what: &'static str,
        /// Its value.
        value: u16,
    },
    /// The key or nonce has the wrong length for `encAlg`.
    #[error("the {0} has the wrong length")]
    BadLength(&'static str),
    /// The stored content does not have the `contentHash`.
    #[error("the content does not match its contentHash")]
    HashMismatch,
    /// Decryption failed: the content, key, nonce or aad is wrong.
    #[error("the content does not decrypt")]
    Decrypt,
}

/// Content sealed for upload: what to store at the URL and what the
/// ExternalPart carries.
#[derive(Clone, PartialEq, Eq)]
pub struct Sealed {
    /// The ciphertext with its tag: what is uploaded.
    pub stored: Vec<u8>,
    /// The key.
    pub key: [u8; KEY_LEN],
    /// The nonce.
    pub nonce: [u8; NONCE_LEN],
    /// SHA-256 of `stored`.
    pub content_hash: [u8; 32],
}

impl std::fmt::Debug for Sealed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sealed")
            .field("stored", &self.stored.len())
            .finish_non_exhaustive()
    }
}

impl Sealed {
    /// The ExternalPart for this content stored at `url`, which stops
    /// working at `expires` (mimi-content-10 §4.5: seconds since the UNIX
    /// epoch, or 0 if it does not expire; see [`expiry`]). `size` is the
    /// stored octets (see the module's Limitations).
    pub fn part(
        &self,
        url: String,
        content_type: String,
        filename: String,
        description: String,
        expires: u32,
    ) -> ExternalPart {
        ExternalPart {
            content_type,
            url,
            expires,
            size: self.stored.len() as u64,
            enc_alg: AES_128_GCM,
            key: self.key.to_vec(),
            nonce: self.nonce.to_vec(),
            aad: Vec::new(),
            hash_alg: SHA_256,
            content_hash: self.content_hash.to_vec(),
            description,
            filename,
        }
    }
}

/// The ExternalPart `expires` (mimi-content-10 §4.5) of content uploaded
/// at `uploaded_at` (seconds since the UNIX epoch) to a server that keeps
/// it `lifetime` seconds, its mimi capability's `assetLifetime`
/// (draft-atwood-jmap-chat-mimi-00 §Account-Level Capability Object,
/// jmap-chat-spec 120db2c: a client MAY set `expires` to the upload time
/// plus `assetLifetime`).
///
/// `None` (no limit stated) is 0, "does not expire". The sum saturates at
/// `u32::MAX`, the largest `uint .size 4`, so a lifetime past 2106 reads
/// as the latest time the field can carry; and it is at least 1, so that
/// it never reads as 0.
pub fn expiry(uploaded_at: u64, lifetime: Option<u64>) -> u32 {
    lifetime.map_or(0, |lifetime| {
        u32::try_from(uploaded_at.saturating_add(lifetime))
            .unwrap_or(u32::MAX)
            .max(1)
    })
}

/// Encrypts `plaintext` under a fresh random key and nonce.
///
/// # Errors
///
/// [`AgentError::Mls`] if the system has no randomness, and
/// [`AgentError::Invalid`] for a plaintext over AES-GCM's limit.
pub fn seal(plaintext: &[u8]) -> Result<Sealed, AgentError> {
    let key = mimi_mls::label::random_array::<KEY_LEN>()
        .map_err(|e| AgentError::mls("an attachment key", e))?;
    let nonce = mimi_mls::label::random_array::<NONCE_LEN>()
        .map_err(|e| AgentError::mls("an attachment nonce", e))?;
    seal_with(plaintext, key, nonce)
}

fn seal_with(
    plaintext: &[u8],
    key: [u8; KEY_LEN],
    nonce: [u8; NONCE_LEN],
) -> Result<Sealed, AgentError> {
    // With a valid key and nonce this fails only for a plaintext over
    // AES-GCM's limit (2^36 - 32 octets).
    let stored = Aes128Gcm::new(&key.into())
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| AgentError::Invalid("the attachment is too large to encrypt".to_owned()))?;
    let content_hash = Sha256::digest(&stored).into();
    Ok(Sealed {
        stored,
        key,
        nonce,
        content_hash,
    })
}

/// Checks `stored`, the content fetched from `part.url`, against the
/// part's hash, and decrypts it.
///
/// # Errors
///
/// An [`AssetError`]: an unsupported algorithm, a bad key or nonce
/// length, a hash mismatch, or content that does not decrypt.
pub fn open(part: &ExternalPart, stored: &[u8]) -> Result<Vec<u8>, AssetError> {
    match part.hash_alg {
        0 => {}
        SHA_256 => {
            if Sha256::digest(stored).as_slice() != part.content_hash.as_slice() {
                return Err(AssetError::HashMismatch);
            }
        }
        other => {
            return Err(AssetError::Unsupported {
                what: "hashAlg",
                value: other.into(),
            });
        }
    }
    match part.enc_alg {
        0 => Ok(stored.to_vec()),
        AES_128_GCM => {
            let key: [u8; KEY_LEN] = part
                .key
                .as_slice()
                .try_into()
                .map_err(|_| AssetError::BadLength("key"))?;
            if part.nonce.len() != NONCE_LEN {
                return Err(AssetError::BadLength("nonce"));
            }
            Aes128Gcm::new(&key.into())
                .decrypt(
                    Nonce::from_slice(&part.nonce),
                    Payload {
                        msg: stored,
                        aad: &part.aad,
                    },
                )
                .map_err(|_| AssetError::Decrypt)
        }
        other => Err(AssetError::Unsupported {
            what: "encAlg",
            value: other,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s).unwrap()
    }

    /// The GCM specification's Test Case 2 (McGrew and Viega, "The
    /// Galois/Counter Mode of Operation", Appendix B): K = 0^128,
    /// IV = 0^96, P = 0^128 gives C = 0388dace...fe78 and
    /// T = ab6e47d4...bddf. The stored content is C || T.
    #[test]
    fn sealing_matches_the_gcm_known_answer() {
        let sealed = seal_with(&[0u8; 16], [0u8; KEY_LEN], [0u8; NONCE_LEN]).unwrap();
        assert_eq!(
            sealed.stored,
            unhex("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
        );
        assert_eq!(
            sealed.content_hash.as_slice(),
            Sha256::digest(&sealed.stored).as_slice()
        );
        let part = sealed.part(
            "https://a.example/assets/x".into(),
            "application/octet-stream".into(),
            String::new(),
            String::new(),
            0,
        );
        assert_eq!(
            (part.enc_alg, part.hash_alg, part.size, part.aad.len()),
            (AES_128_GCM, SHA_256, 32, 0)
        );
        assert_eq!(open(&part, &sealed.stored).unwrap(), [0u8; 16]);
    }

    /// mimi-content-10 §4.5: `expires` is a `uint .size 4` of seconds
    /// since the UNIX epoch, 0 for never. 1_763_510_400 is
    /// 2025-11-19T00:00:00Z; 4_294_967_295 (2^32 - 1) is the largest
    /// value of the field.
    #[test]
    fn expiry_is_upload_time_plus_lifetime_within_the_field() {
        assert_eq!(expiry(1_763_510_400, None), 0);
        assert_eq!(expiry(1_763_510_400, Some(2_592_000)), 1_766_102_400);
        assert_eq!(expiry(1_763_510_400, Some(0)), 1_763_510_400);
        assert_eq!(expiry(4_294_967_000, Some(295)), 4_294_967_295);
        assert_eq!(expiry(4_294_967_000, Some(296)), u32::MAX);
        assert_eq!(expiry(1_763_510_400, Some(u64::MAX)), u32::MAX);
        assert_eq!(expiry(u64::MAX, Some(1)), u32::MAX);
        // A clock before 1970 reads as 0; the result still is not "never".
        assert_eq!(expiry(0, Some(0)), 1);
        let part = seal(b"x").unwrap().part(
            "u".into(),
            "t".into(),
            String::new(),
            String::new(),
            expiry(1_763_510_400, Some(3_600)),
        );
        assert_eq!(part.expires, 1_763_514_000);
    }

    #[test]
    fn fresh_keys_and_round_trip() {
        let a = seal(b"a file").unwrap();
        let b = seal(b"a file").unwrap();
        assert_ne!((a.key, a.nonce), (b.key, b.nonce));
        let part = a.part(
            "u".into(),
            "text/plain".into(),
            "f.txt".into(),
            String::new(),
            0,
        );
        assert_eq!(open(&part, &a.stored).unwrap(), b"a file");
    }

    #[test]
    fn tampering_and_bad_parts_are_refused() {
        let sealed = seal(b"secret").unwrap();
        let part = sealed.part("u".into(), "t".into(), String::new(), String::new(), 0);
        let mut changed = sealed.stored.clone();
        changed[0] ^= 1;
        assert_eq!(open(&part, &changed), Err(AssetError::HashMismatch));
        // Without a hash the AEAD tag still catches it.
        let unhashed = ExternalPart {
            hash_alg: 0,
            ..part.clone()
        };
        assert_eq!(open(&unhashed, &changed), Err(AssetError::Decrypt));
        let wrong_key = ExternalPart {
            key: vec![0; KEY_LEN],
            ..part.clone()
        };
        assert_eq!(open(&wrong_key, &sealed.stored), Err(AssetError::Decrypt));
        let short = ExternalPart {
            nonce: vec![0; 8],
            ..part.clone()
        };
        assert_eq!(
            open(&short, &sealed.stored),
            Err(AssetError::BadLength("nonce"))
        );
        let other = ExternalPart {
            enc_alg: 2,
            ..part.clone()
        };
        assert_eq!(
            open(&other, &sealed.stored),
            Err(AssetError::Unsupported {
                what: "encAlg",
                value: 2
            })
        );
        let plain = ExternalPart {
            enc_alg: 0,
            hash_alg: 0,
            ..part
        };
        assert_eq!(open(&plain, b"as is").unwrap(), b"as is");
    }
}
