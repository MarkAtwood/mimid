//! Attachment links (docs/design/agent-frontends.md §7.30; epic
//! mimid-qqtk): a URL on the agent's HTTP listener that gives one
//! attachment's plaintext to whoever holds it, until it expires, for
//! front ends whose clients cannot send the bearer header that JMAP
//! download needs (IRC, Matrix, XMPP).
//!
//! A link is `<base>/attachment/<blobId>/<expires>/<mac>/<name>`:
//! `expires` in seconds since the UNIX epoch, `mac` the first 16 octets,
//! as hex, of HMAC-SHA256 under the link key over
//! `"mimid-attachment-link-v1" 0x00 blobId 0x00 expires`, and `name`
//! the file name, percent-encoded, which the MAC does not cover (it only
//! names the download). The link key is the agent's own (the daemon
//! derives it from its local token), so replacing the token revokes
//! every link. [`AttachmentLinks::check`] is the one place a link is
//! checked.
//!
//! # Limitations
//!
//! - Anyone who reads a link (a chat log, a client's link preview) can
//!   fetch the attachment until it expires, while the daemon runs and the
//!   blob is kept. A link cannot be revoked alone.
//! - The lifetime is the caller's, at most [`MAX_LINK_LIFETIME`].

use std::time::Duration;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

/// The path prefix of an attachment link.
pub const LINK_PATH: &str = "/attachment";

/// The lifetime a front end gives a link unless it has a reason to give
/// another: one hour (Mark, 2026-11-21, decision mimid-1wgh.88).
/// INVENTED, NOT FROM SPEC.
pub const DEFAULT_LINK_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// The longest lifetime a link may have: one day (Mark, 2026-11-21,
/// decision mimid-1wgh.88). INVENTED, NOT FROM SPEC.
pub const MAX_LINK_LIFETIME: Duration = Duration::from_secs(24 * 60 * 60);

/// The octets of the MAC a link carries.
const MAC_LEN: usize = 16;

/// The label the MAC covers first.
const LABEL: &[u8] = b"mimid-attachment-link-v1";

/// Makes and checks attachment links (see the module documentation).
#[derive(Clone)]
pub struct AttachmentLinks {
    key: [u8; 32],
    base: String,
}

impl std::fmt::Debug for AttachmentLinks {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttachmentLinks")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl AttachmentLinks {
    /// Links under `base` (`http://127.0.0.1:8484`, no trailing slash),
    /// keyed with `key`.
    #[must_use]
    pub fn new(key: [u8; 32], base: impl Into<String>) -> Self {
        Self {
            key,
            base: base.into().trim_end_matches('/').to_owned(),
        }
    }

    fn mac(&self, blob_id: &str, expires: u64) -> Hmac<Sha256> {
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&self.key)
            .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
        mac.update(LABEL);
        mac.update(&[0]);
        mac.update(blob_id.as_bytes());
        mac.update(&[0]);
        mac.update(expires.to_string().as_bytes());
        mac
    }

    /// The link to blob `blob_id`, downloaded as `name`, valid until
    /// `expires` (seconds since the UNIX epoch).
    #[must_use]
    pub fn link(&self, blob_id: &str, name: &str, expires: u64) -> String {
        let tag = self.mac(blob_id, expires).finalize().into_bytes();
        format!(
            "{}{LINK_PATH}/{blob_id}/{expires}/{}/{}",
            self.base,
            crate::blobs::hex(&tag[..MAC_LEN]),
            percent_encode(if name.is_empty() { "attachment" } else { name }),
        )
    }

    /// Whether `mac` is the MAC of a link to blob `blob_id` valid until
    /// `expires`, and `expires` is not before `now` (both in seconds
    /// since the UNIX epoch).
    #[must_use]
    pub fn check(&self, blob_id: &str, expires: u64, mac: &str, now: u64) -> bool {
        let Some(tag) = crate::content::unhex(mac) else {
            return false;
        };
        tag.len() == MAC_LEN
            && expires >= now
            && self
                .mac(blob_id, expires)
                .verify_truncated_left(&tag)
                .is_ok()
    }
}

/// `name` for a URL path segment: ASCII letters, digits, `.`, `-` and
/// `_` as they are, every other octet `%XX`.
fn percent_encode(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    for byte in name.bytes() {
        if byte.is_ascii_alphanumeric() || b".-_".contains(&byte) {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Oracle: the module documentation's MAC, computed here with the
    /// hmac crate over the bytes written out by hand.
    #[test]
    fn a_link_names_its_blob_expiry_and_mac() {
        let links = AttachmentLinks::new([7; 32], "http://127.0.0.1:8484/");
        let link = links.link("sab", "a b/é.txt", 1_800_000_000);
        let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(&[7; 32]).unwrap();
        mac.update(b"mimid-attachment-link-v1\x00sab\x001800000000");
        let tag = crate::blobs::hex(&mac.finalize().into_bytes()[..16]);
        assert_eq!(
            link,
            format!("http://127.0.0.1:8484/attachment/sab/1800000000/{tag}/a%20b%2F%C3%A9.txt")
        );
        assert!(links.check("sab", 1_800_000_000, &tag, 1_800_000_000));
        // Expired, another blob, another expiry, another key, a bad MAC.
        assert!(!links.check("sab", 1_800_000_000, &tag, 1_800_000_001));
        assert!(!links.check("sac", 1_800_000_000, &tag, 0));
        assert!(!links.check("sab", 1_800_000_001, &tag, 0));
        assert!(!AttachmentLinks::new([8; 32], "x").check("sab", 1_800_000_000, &tag, 0));
        assert!(!links.check("sab", 1_800_000_000, &tag[..30], 0));
        assert!(!links.check("sab", 1_800_000_000, "zz", 0));
    }
}
