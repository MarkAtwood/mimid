//! The plaintext blob store (bead mimid-1wgh.14): the attachments a client
//! uploads to the local endpoint and those the agent fetched and decrypted,
//! as files under one directory (`<state_dir>/blobs` in the daemon).
//!
//! Blobs are content-addressed: a blob's id is `s` and the lowercase hex
//! SHA-256 of its content (65 characters, a valid RFC 8620 §1.2 Id), and
//! its file is named by that id. The id gives the digest and the file's
//! length the size, so there is no metadata to keep. Identical content
//! has one id (RFC 8620 §6.1 allows returning the existing blobId).
//!
//! The directory is created 0700 and every file 0600. A blob is written to
//! a uniquely named temporary file, flushed, then renamed to its id, so a
//! crash leaves a whole blob or none. A blob is at most
//! [`MAX_ATTACHMENT_LEN`] octets.
//!
//! # Limitations
//!
//! - Blobs are never deleted: unreferenced uploads (RFC 8620 §6) and the
//!   blobs of destroyed Messages stay on disk. There is no quota.
//! - The whole blob is read into memory, and file I/O blocks the calling
//!   thread.
//! - A blob read back is checked against its id; a file changed on disk is
//!   an error, not repaired.

use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use jmap_server::Id;
use sha2::{Digest, Sha256};

/// The largest blob, in octets: 16 MiB less the 16-octet AES-128-GCM tag,
/// so a sealed attachment fits the 16 MiB mimid-server stores and
/// mimid-agent-core fetches (`MAX_ASSET_LEN`). INVENTED, NOT FROM SPEC.
pub const MAX_ATTACHMENT_LEN: usize = 16 * 1024 * 1024 - 16;

/// The prefix of a blob id, before the hex digest.
const ID_PREFIX: char = 's';

/// Distinguishes the temporary files of concurrent writes.
static TEMPORARY: AtomicU64 = AtomicU64::new(0);

/// Why the blob store failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BlobError {
    /// The blob is over [`MAX_ATTACHMENT_LEN`] octets.
    #[error("the blob is {len} octets, over the limit of {MAX_ATTACHMENT_LEN}")]
    TooLarge {
        /// Its length.
        len: usize,
    },
    /// A file or the directory could not be read or written.
    #[error("the blob store {path}: cannot {what}")]
    Io {
        /// The file or directory.
        path: PathBuf,
        /// What was being done.
        what: &'static str,
        /// The failure.
        #[source]
        source: std::io::Error,
    },
    /// The directory or a file can be reached by group or others, or a
    /// stored blob does not match its id.
    #[error("the blob store {path}: {reason}")]
    Unsafe {
        /// The file or directory.
        path: PathBuf,
        /// What is wrong.
        reason: String,
    },
}

/// What the store knows of one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    /// Its id.
    pub id: Id,
    /// Its length in octets.
    pub size: u64,
    /// The SHA-256 of its content.
    pub sha256: [u8; 32],
}

/// Plaintext blobs under one directory. See the module documentation.
#[derive(Debug, Clone)]
pub struct BlobStore {
    dir: PathBuf,
}

fn io<'a>(path: &'a Path, what: &'static str) -> impl FnOnce(std::io::Error) -> BlobError + 'a {
    move |source| BlobError::Io {
        path: path.to_owned(),
        what,
        source,
    }
}

impl BlobStore {
    /// The store in `dir`, which is created (with missing parents) mode
    /// 0700 if it does not exist.
    ///
    /// # Errors
    ///
    /// [`BlobError::Io`] if it cannot be created, and
    /// [`BlobError::Unsafe`] if it exists and group or others can reach it.
    pub fn open(dir: impl Into<PathBuf>) -> Result<Self, BlobError> {
        let dir = dir.into();
        let mut builder = DirBuilder::new();
        builder.recursive(true);
        #[cfg(unix)]
        builder.mode(0o700);
        builder.create(&dir).map_err(io(&dir, "create"))?;
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&dir)
                .map_err(io(&dir, "inspect"))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(BlobError::Unsafe {
                    path: dir,
                    reason: format!(
                        "has mode {:#o}; it must not be accessible to group or others",
                        mode & 0o777
                    ),
                });
            }
        }
        Ok(Self { dir })
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Stores `content` and returns its id, size and digest. Storing
    /// content the store already has changes nothing.
    ///
    /// # Errors
    ///
    /// [`BlobError::TooLarge`] for content over [`MAX_ATTACHMENT_LEN`], and
    /// [`BlobError::Io`] if the file cannot be written.
    pub fn put(&self, content: &[u8]) -> Result<BlobInfo, BlobError> {
        if content.len() > MAX_ATTACHMENT_LEN {
            return Err(BlobError::TooLarge { len: content.len() });
        }
        let sha256: [u8; 32] = Sha256::digest(content).into();
        let id = blob_id(&sha256);
        let info = BlobInfo {
            id: Id::from(id.as_str()),
            size: content.len() as u64,
            sha256,
        };
        let path = self.dir.join(&id);
        if path.is_file() {
            return Ok(info);
        }
        let temporary = self.dir.join(format!(
            ".{id}.{}.{}.tmp",
            std::process::id(),
            TEMPORARY.fetch_add(1, Ordering::Relaxed)
        ));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let written = options
            .open(&temporary)
            .map_err(io(&temporary, "create"))
            .and_then(|mut file| {
                file.write_all(content)
                    .and_then(|()| file.sync_all())
                    .map_err(io(&temporary, "write"))
            })
            .and_then(|()| std::fs::rename(&temporary, &path).map_err(io(&path, "replace")));
        if written.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        written.map(|()| info)
    }

    /// The id, size and digest of blob `id`, or `None` if the store has no
    /// such blob (or `id` is not a blob id). The content is not read.
    ///
    /// # Errors
    ///
    /// [`BlobError::Io`] if the file exists but cannot be inspected.
    pub fn info(&self, id: &str) -> Result<Option<BlobInfo>, BlobError> {
        let Some(sha256) = digest_of(id) else {
            return Ok(None);
        };
        let path = self.dir.join(id);
        match std::fs::metadata(&path) {
            Ok(meta) if meta.is_file() => Ok(Some(BlobInfo {
                id: Id::from(id),
                size: meta.len(),
                sha256,
            })),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io(&path, "inspect")(e)),
        }
    }

    /// The content of blob `id`, or `None` if the store has no such blob
    /// (or `id` is not a blob id).
    ///
    /// # Errors
    ///
    /// [`BlobError::Io`] if the file cannot be read, and
    /// [`BlobError::Unsafe`] if its content no longer matches its id.
    pub fn get(&self, id: &str) -> Result<Option<Vec<u8>>, BlobError> {
        let Some(sha256) = digest_of(id) else {
            return Ok(None);
        };
        let path = self.dir.join(id);
        let content = match std::fs::read(&path) {
            Ok(content) => content,
            Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io(&path, "read")(e)),
        };
        if Sha256::digest(&content).as_slice() != sha256 {
            return Err(BlobError::Unsafe {
                path,
                reason: "the content does not match its id".to_owned(),
            });
        }
        Ok(Some(content))
    }
}

/// The blob id of content with digest `sha256`.
fn blob_id(sha256: &[u8; 32]) -> String {
    let mut id = String::with_capacity(65);
    id.push(ID_PREFIX);
    id.push_str(&hex(sha256));
    id
}

/// Lowercase hex of `octets`.
pub(crate) fn hex(octets: &[u8]) -> String {
    octets.iter().map(|b| format!("{b:02x}")).collect()
}

/// The digest a blob id names, or `None` if `id` is not `s` and 64
/// lowercase hex digits. Anything else (a path, `..`) never reaches the
/// file system.
fn digest_of(id: &str) -> Option<[u8; 32]> {
    let digits = id.strip_prefix(ID_PREFIX)?.as_bytes();
    if digits.len() != 64 {
        return None;
    }
    let value = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    let (pairs, _) = digits.as_chunks::<2>();
    for (octet, [high, low]) in out.iter_mut().zip(pairs) {
        *octet = value(*high)? << 4 | value(*low)?;
    }
    Some(out)
}

/// Whether `text` is a syntactically valid media type: RFC 6838 §4.2
/// `type "/" subtype`, each a restricted-name, then any number of RFC 2045
/// §5.1 `";" attribute "=" value` parameters, a value being a token or a
/// quoted string of printable characters without `"` or `\`. Whitespace
/// around the parts is allowed.
pub fn is_media_type(text: &str) -> bool {
    let restricted = |name: &str| {
        let bytes = name.as_bytes();
        (1..=127).contains(&bytes.len())
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(b))
    };
    // RFC 2045 §5.1: any CHAR except SPACE, CTLs and tspecials.
    let token = |t: &str| {
        !t.is_empty()
            && t.bytes()
                .all(|b| b.is_ascii_graphic() && !b"()<>@,;:\\\"/[]?=".contains(&b))
    };
    let quoted = |v: &str| {
        v.len() >= 2
            && v.starts_with('"')
            && v.ends_with('"')
            && v[1..v.len() - 1]
                .bytes()
                .all(|b| (b == b' ' || b.is_ascii_graphic()) && b != b'"' && b != b'\\')
    };
    let mut parts = text.split(';');
    let essence = parts.next().unwrap_or_default().trim();
    let Some((kind, subtype)) = essence.split_once('/') else {
        return false;
    };
    restricted(kind)
        && restricted(subtype)
        && parts.all(|parameter| {
            parameter.split_once('=').is_some_and(|(name, value)| {
                let value = value.trim();
                token(name.trim()) && (token(value) || quoted(value))
            })
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SHA-256("abc"), FIPS 180-2 Appendix B.1.
    const SHA256_ABC: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    fn store() -> (tempfile::TempDir, BlobStore) {
        let dir = tempfile::tempdir().unwrap();
        let store = BlobStore::open(dir.path().join("blobs")).unwrap();
        (dir, store)
    }

    #[test]
    fn the_id_is_the_sha256_of_the_content() {
        let (_dir, store) = store();
        let info = store.put(b"abc").unwrap();
        assert_eq!(info.id.as_ref(), format!("s{SHA256_ABC}"));
        assert_eq!(hex(&info.sha256), SHA256_ABC);
        assert_eq!(info.size, 3);
        assert_eq!(store.info(info.id.as_ref()).unwrap(), Some(info.clone()));
        assert_eq!(store.get(info.id.as_ref()).unwrap().unwrap(), b"abc");
        // The same content again: the same id, one file.
        assert_eq!(store.put(b"abc").unwrap(), info);
        let files: Vec<_> = std::fs::read_dir(store.dir()).unwrap().collect();
        assert_eq!(files.len(), 1, "{files:?}");
    }

    #[test]
    fn empty_and_largest_blobs_round_trip() {
        let (_dir, store) = store();
        let empty = store.put(b"").unwrap();
        // SHA-256 of the empty string (FIPS 180-2).
        assert_eq!(
            hex(&empty.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(store.get(empty.id.as_ref()).unwrap().unwrap(), b"");
        let largest = vec![7u8; MAX_ATTACHMENT_LEN];
        let info = store.put(&largest).unwrap();
        assert_eq!(info.size, MAX_ATTACHMENT_LEN as u64);
        assert_eq!(store.get(info.id.as_ref()).unwrap().unwrap(), largest);
    }

    #[test]
    fn content_over_the_limit_is_refused_and_not_written() {
        let (_dir, store) = store();
        let too_large = vec![0u8; MAX_ATTACHMENT_LEN + 1];
        assert!(matches!(
            store.put(&too_large),
            Err(BlobError::TooLarge { len }) if len == MAX_ATTACHMENT_LEN + 1
        ));
        assert_eq!(std::fs::read_dir(store.dir()).unwrap().count(), 0);
    }

    #[test]
    fn ids_that_are_not_blob_ids_find_nothing() {
        let (dir, store) = store();
        std::fs::write(dir.path().join("secret"), b"x").unwrap();
        let upper = format!("s{}", SHA256_ABC.to_uppercase());
        let short = format!("s{}", &SHA256_ABC[..62]);
        let long = format!("s{SHA256_ABC}00");
        let unprefixed = SHA256_ABC.to_owned();
        store.put(b"abc").unwrap();
        for bad in [
            "",
            "s",
            "../secret",
            "s/../../secret",
            upper.as_str(),
            short.as_str(),
            long.as_str(),
            unprefixed.as_str(),
        ] {
            assert_eq!(store.get(bad).unwrap(), None, "{bad}");
            assert_eq!(store.info(bad).unwrap(), None, "{bad}");
        }
        // A well-formed id of content never stored.
        let missing = format!("s{}", "0".repeat(64));
        assert_eq!(store.get(&missing).unwrap(), None);
        assert_eq!(store.info(&missing).unwrap(), None);
    }

    #[test]
    fn media_types_follow_rfc_6838_and_rfc_2045() {
        for good in [
            "text/plain",
            "application/octet-stream",
            "image/svg+xml",
            "application/vnd.ms-excel",
            "text/plain; charset=utf-8",
            "text/plain;charset=\"utf-8\"",
            "multipart/mixed; boundary=\"a b\"; x=1",
        ] {
            assert!(is_media_type(good), "{good}");
        }
        for bad in [
            "",
            "text",
            "text/",
            "/plain",
            "text/plain/x",
            "-text/plain",
            "te xt/plain",
            "text/plain; charset",
            "text/plain; charset=",
            "text/plain; =utf-8",
            "text/plain; a=b c",
            "text/plain; a=\"b\"c\"",
            "text/plain\r\nX-Evil: 1",
            "text/plain; a=\u{7f}",
            "text/pl\u{e4}in",
        ] {
            assert!(!is_media_type(bad), "{bad:?}");
        }
    }

    #[test]
    fn a_changed_file_is_an_error() {
        let (_dir, store) = store();
        let info = store.put(b"abc").unwrap();
        let path = store.dir().join(info.id.as_ref());
        std::fs::write(&path, b"abx").unwrap();
        assert!(matches!(
            store.get(info.id.as_ref()),
            Err(BlobError::Unsafe { .. })
        ));
    }

    #[cfg(unix)]
    #[test]
    fn the_directory_is_0700_and_files_0600() {
        let (dir, store) = store();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(store.dir()), 0o700);
        let info = store.put(b"abc").unwrap();
        assert_eq!(mode(&store.dir().join(info.id.as_ref())), 0o600);
        // An existing directory others can reach is refused.
        let open = dir.path().join("open");
        std::fs::create_dir(&open).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(matches!(
            BlobStore::open(&open),
            Err(BlobError::Unsafe { .. })
        ));
    }
}
