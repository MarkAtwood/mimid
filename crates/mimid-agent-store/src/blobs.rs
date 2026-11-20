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
//! Unreferenced blobs have a quota of their own (RFC 8620 §6; decision
//! mimid-1wgh.68): [`BlobQuota`], by default
//! [`MAX_UNREFERENCED_BLOB_BYTES`] and [`MAX_UNREFERENCED_BLOBS`]. The
//! caller says which blobs are referenced (mimid-agent-jmap's
//! `AgentChat::referenced_blobs`: any blob id a stored object names). When an upload
//! ([`BlobStore::put_upload`]) would take the unreferenced blobs over the
//! quota, the oldest are deleted first, by file modification time, until
//! there is room; none younger than [`MIN_UNREFERENCED_AGE`] is ever
//! deleted, and if deleting every older one would not make room, nothing
//! is deleted and the upload is refused ([`BlobError::OverQuota`]). A
//! blob's time is reset whenever it is stored again
//! ([`BlobStore::put`], [`BlobStore::put_upload`]) or read to be sent
//! ([`BlobStore::touch`]). One lock serializes every write and deletion.
//!
//! # Limitations
//!
//! - Unreferenced blobs are deleted only when an upload needs room: there
//!   is no sweep, so they stay on disk up to the quota.
//! - Referenced blobs (received attachments and those of kept Messages)
//!   have no quota.
//! - Each upload lists the directory, and the caller reads every stored
//!   object to find the references: fine for one user's device.
//! - The whole blob is read into memory, and file I/O blocks the calling
//!   thread.
//! - A blob read back is checked against its id; a file changed on disk is
//!   an error, not repaired.

use std::collections::BTreeSet;
use std::fs::{DirBuilder, OpenOptions};
use std::io::{ErrorKind, Write};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use sha2::{Digest, Sha256};

/// The largest blob, in octets: 16 MiB less the 16-octet AES-128-GCM tag,
/// so a sealed attachment fits the 16 MiB mimid-server stores and
/// mimid-agent-core fetches (`MAX_ASSET_LEN`). INVENTED, NOT FROM SPEC.
pub const MAX_ATTACHMENT_LEN: usize = 16 * 1024 * 1024 - 16;

/// The most octets of unreferenced blobs kept: twice the most one Message
/// references (`MAX_ATTACHMENTS_PER_MESSAGE` × [`MAX_ATTACHMENT_LEN`]),
/// so RFC 8620 §6's "at least the maximum total size that a single object
/// can reference" holds. INVENTED VALUE, NOT FROM SPEC (decision
/// mimid-1wgh.68).
pub const MAX_UNREFERENCED_BLOB_BYTES: u64 = 256 * 1024 * 1024;

/// The most unreferenced blobs kept. INVENTED VALUE, NOT FROM SPEC
/// (decision mimid-1wgh.68).
pub const MAX_UNREFERENCED_BLOBS: u64 = 256;

/// How long an unreferenced blob is kept at least, from its upload: RFC
/// 8620 §6's one hour, which mimid keeps even under quota pressure
/// (decision mimid-1wgh.68).
pub const MIN_UNREFERENCED_AGE: Duration = Duration::from_secs(3600);

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
    /// Unreferenced blobs would exceed the [`BlobQuota`] even after every
    /// one older than [`MIN_UNREFERENCED_AGE`] was deleted. Nothing was
    /// deleted or written.
    #[error("the unreferenced blobs are over quota")]
    OverQuota,
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

/// A blob id: `s` and the lowercase hex SHA-256 of the blob's content,
/// 65 characters. Only the store makes one; it serializes as the string.
///
/// Not a bare `String`, so that `id.as_ref()` has one meaning (`&str`)
/// wherever a caller passes it on.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize)]
#[serde(transparent)]
pub struct BlobId(String);

impl BlobId {
    /// The id as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for BlobId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for BlobId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<BlobId> for String {
    fn from(id: BlobId) -> Self {
        id.0
    }
}

/// What the store knows of one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlobInfo {
    /// Its id.
    pub id: BlobId,
    /// Its length in octets.
    pub size: u64,
    /// The SHA-256 of its content.
    pub sha256: [u8; 32],
}

/// The quota of unreferenced blobs (RFC 8620 §6; see the module
/// documentation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct BlobQuota {
    /// The most octets of unreferenced blobs.
    pub max_bytes: u64,
    /// The most unreferenced blobs.
    pub max_count: u64,
}

impl BlobQuota {
    /// A quota of `max_bytes` octets and `max_count` blobs.
    #[must_use]
    pub fn new(max_bytes: u64, max_count: u64) -> Self {
        Self {
            max_bytes,
            max_count,
        }
    }
}

impl Default for BlobQuota {
    /// [`MAX_UNREFERENCED_BLOB_BYTES`] and [`MAX_UNREFERENCED_BLOBS`].
    fn default() -> Self {
        Self::new(MAX_UNREFERENCED_BLOB_BYTES, MAX_UNREFERENCED_BLOBS)
    }
}

/// Plaintext blobs under one directory. See the module documentation.
#[derive(Debug, Clone)]
pub struct BlobStore {
    dir: PathBuf,
    quota: BlobQuota,
    /// Held across every write and deletion, so an eviction cannot remove
    /// a blob another thread is storing or touching.
    writing: Arc<Mutex<()>>,
}

/// A stored blob no one references, for eviction.
struct Unreferenced {
    path: PathBuf,
    size: u64,
    modified: SystemTime,
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
        Ok(Self {
            dir,
            quota: BlobQuota::default(),
            writing: Arc::new(Mutex::new(())),
        })
    }

    /// This store with unreferenced blobs held to `quota`.
    #[must_use]
    pub fn with_quota(mut self, quota: BlobQuota) -> Self {
        self.quota = quota;
        self
    }

    /// The quota of unreferenced blobs.
    pub fn quota(&self) -> BlobQuota {
        self.quota
    }

    /// The directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Stores `content`, with no quota, and returns its id, size and
    /// digest: for content a Message references as soon as it is stored (a
    /// received attachment). Storing content the store already has
    /// rewrites nothing but resets its time to now.
    ///
    /// # Errors
    ///
    /// [`BlobError::TooLarge`] for content over [`MAX_ATTACHMENT_LEN`], and
    /// [`BlobError::Io`] if the file cannot be written.
    pub fn put(&self, content: &[u8]) -> Result<BlobInfo, BlobError> {
        let _writing = self.lock();
        self.write(content, SystemTime::now())
    }

    /// Stores `content` uploaded at `now` as an unreferenced blob, and
    /// returns its id, size and digest. `referenced` is every blob id a
    /// stored object names. If the unreferenced blobs would then exceed
    /// the quota, the oldest not in `referenced` and older than
    /// [`MIN_UNREFERENCED_AGE`] at `now` are deleted first, until there is
    /// room. Uploading content the store already has deletes nothing and
    /// resets its time to `now` (RFC 8620 §6: "this SHOULD reset the
    /// expiry time").
    ///
    /// # Errors
    ///
    /// [`BlobError::TooLarge`] for content over [`MAX_ATTACHMENT_LEN`],
    /// [`BlobError::OverQuota`] if deleting every blob it may would not
    /// make room (nothing is deleted then), and [`BlobError::Io`] if the
    /// directory cannot be listed or a file written or deleted.
    pub fn put_upload(
        &self,
        content: &[u8],
        referenced: &BTreeSet<String>,
        now: SystemTime,
    ) -> Result<BlobInfo, BlobError> {
        if content.len() > MAX_ATTACHMENT_LEN {
            return Err(BlobError::TooLarge { len: content.len() });
        }
        let _writing = self.lock();
        let id = blob_id(&Sha256::digest(content).into());
        if !self.dir.join(&id).is_file() {
            self.make_room(content.len() as u64, referenced, now)?;
        }
        self.write(content, now)
    }

    /// Resets blob `id`'s time to `now`, so it is not evicted for another
    /// [`MIN_UNREFERENCED_AGE`]: a Message/set create calls it for each
    /// blob it sends, before the Message that references it is stored.
    /// Returns whether the store has the blob.
    ///
    /// # Errors
    ///
    /// [`BlobError::Io`] if the file exists but its time cannot be set.
    pub fn touch(&self, id: &str, now: SystemTime) -> Result<bool, BlobError> {
        if digest_of(id).is_none() {
            return Ok(false);
        }
        let _writing = self.lock();
        let path = self.dir.join(id);
        match set_modified(&path, now) {
            Ok(()) => Ok(true),
            Err(BlobError::Io { source, .. }) if source.kind() == ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ()> {
        self.writing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Deletes the oldest unreferenced blobs older than
    /// [`MIN_UNREFERENCED_AGE`] at `now` until one more of `len` octets
    /// fits the quota, or deletes none and refuses if that is not enough.
    /// The caller holds the lock.
    fn make_room(
        &self,
        len: u64,
        referenced: &BTreeSet<String>,
        now: SystemTime,
    ) -> Result<(), BlobError> {
        let mut unreferenced = self.unreferenced(referenced)?;
        let mut bytes: u64 = unreferenced.iter().map(|b| b.size).sum();
        let mut count = unreferenced.len() as u64;
        let fits = |bytes: u64, count: u64| {
            bytes.saturating_add(len) <= self.quota.max_bytes && count < self.quota.max_count
        };
        if fits(bytes, count) {
            return Ok(());
        }
        // Oldest first; ties by path, so the order is fixed.
        unreferenced.sort_by(|a, b| a.modified.cmp(&b.modified).then(a.path.cmp(&b.path)));
        let mut evict = 0;
        for blob in &unreferenced {
            let old_enough = now
                .duration_since(blob.modified)
                .is_ok_and(|age| age >= MIN_UNREFERENCED_AGE);
            if !old_enough {
                // The rest are younger still.
                break;
            }
            bytes -= blob.size;
            count -= 1;
            evict += 1;
            if fits(bytes, count) {
                break;
            }
        }
        if !fits(bytes, count) {
            return Err(BlobError::OverQuota);
        }
        for blob in &unreferenced[..evict] {
            match std::fs::remove_file(&blob.path) {
                Ok(()) => {}
                Err(e) if e.kind() == ErrorKind::NotFound => {}
                Err(e) => return Err(io(&blob.path, "delete")(e)),
            }
        }
        tracing::debug!(
            evicted = evict,
            "unreferenced blobs deleted to make room for an upload"
        );
        Ok(())
    }

    /// The stored blobs whose ids are not in `referenced`. Temporary files
    /// and anything else that is not named by a blob id are left out.
    fn unreferenced(&self, referenced: &BTreeSet<String>) -> Result<Vec<Unreferenced>, BlobError> {
        let mut found = Vec::new();
        for entry in std::fs::read_dir(&self.dir).map_err(io(&self.dir, "list"))? {
            let entry = entry.map_err(io(&self.dir, "list"))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if digest_of(name).is_none() || referenced.contains(name) {
                continue;
            }
            let path = entry.path();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(e) if e.kind() == ErrorKind::NotFound => continue,
                Err(e) => return Err(io(&path, "inspect")(e)),
            };
            if !meta.is_file() {
                continue;
            }
            let modified = meta.modified().map_err(io(&path, "inspect"))?;
            found.push(Unreferenced {
                path,
                size: meta.len(),
                modified,
            });
        }
        Ok(found)
    }

    /// Writes `content` (or finds it already written) and sets its time
    /// to `now`. The caller holds the lock.
    fn write(&self, content: &[u8], now: SystemTime) -> Result<BlobInfo, BlobError> {
        if content.len() > MAX_ATTACHMENT_LEN {
            return Err(BlobError::TooLarge { len: content.len() });
        }
        let sha256: [u8; 32] = Sha256::digest(content).into();
        let id = blob_id(&sha256);
        let info = BlobInfo {
            id: BlobId(id.clone()),
            size: content.len() as u64,
            sha256,
        };
        let path = self.dir.join(&id);
        if path.is_file() {
            set_modified(&path, now)?;
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
                    .and_then(|()| file.set_modified(now))
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
                id: BlobId(id.to_owned()),
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

/// Sets the modification time of the file at `path` to `when`.
fn set_modified(path: &Path, when: SystemTime) -> Result<(), BlobError> {
    OpenOptions::new()
        .write(true)
        .open(path)
        .and_then(|file| file.set_modified(when))
        .map_err(io(path, "set the time of"))
}

/// The blob id of content with digest `sha256`.
fn blob_id(sha256: &[u8; 32]) -> String {
    let mut id = String::with_capacity(65);
    id.push(ID_PREFIX);
    id.push_str(&hex(sha256));
    id
}

/// Lowercase hex of `octets`.
#[must_use]
pub fn hex(octets: &[u8]) -> String {
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

    /// A fixed start, so ages are exact.
    fn t0() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_800_000_000)
    }

    fn mins(m: u64) -> Duration {
        Duration::from_secs(60 * m)
    }

    fn quota_store(quota: BlobQuota) -> (tempfile::TempDir, BlobStore) {
        let (dir, store) = store();
        (dir, store.with_quota(quota))
    }

    fn has(store: &BlobStore, blob: &BlobInfo) -> bool {
        store.info(blob.id.as_ref()).unwrap().is_some()
    }

    #[test]
    fn an_upload_over_the_count_quota_evicts_the_oldest_old_enough_blob() {
        let (_dir, store) = quota_store(BlobQuota::new(1000, 2));
        let none = BTreeSet::new();
        let a = store.put_upload(b"a", &none, t0()).unwrap();
        let b = store.put_upload(b"b", &none, t0() + mins(1)).unwrap();
        // Two hours on, both are old enough; only the oldest goes.
        let c = store.put_upload(b"c", &none, t0() + mins(120)).unwrap();
        assert!(!has(&store, &a));
        assert!(has(&store, &b));
        assert!(has(&store, &c));
    }

    #[test]
    fn a_referenced_blob_is_never_evicted() {
        let (_dir, store) = quota_store(BlobQuota::new(1000, 1));
        let none = BTreeSet::new();
        let a = store.put_upload(b"a", &none, t0()).unwrap();
        let referenced = BTreeSet::from([a.id.as_ref().to_owned()]);
        let b = store.put_upload(b"b", &referenced, t0() + mins(1)).unwrap();
        // B is the one unreferenced blob: C evicts it, not the older A.
        let c = store
            .put_upload(b"c", &referenced, t0() + mins(120))
            .unwrap();
        assert!(has(&store, &a));
        assert!(!has(&store, &b));
        assert!(has(&store, &c));
    }

    #[test]
    fn no_blob_younger_than_an_hour_is_evicted_and_the_upload_is_refused() {
        let (dir, store) = quota_store(BlobQuota::new(1000, 1));
        let none = BTreeSet::new();
        let a = store.put_upload(b"a", &none, t0()).unwrap();
        // One second short of an hour: refused, nothing deleted or written.
        let before = t0() + mins(60) - Duration::from_secs(1);
        assert!(matches!(
            store.put_upload(b"b", &none, before),
            Err(BlobError::OverQuota)
        ));
        assert!(has(&store, &a));
        assert_eq!(
            std::fs::read_dir(dir.path().join("blobs")).unwrap().count(),
            1
        );
        // At the hour it may go.
        let b = store.put_upload(b"b", &none, t0() + mins(60)).unwrap();
        assert!(!has(&store, &a));
        assert!(has(&store, &b));
    }

    #[test]
    fn the_byte_quota_evicts_only_what_makes_room() {
        let (_dir, store) = quota_store(BlobQuota::new(10, 100));
        let none = BTreeSet::new();
        let a = store.put_upload(&[1; 6], &none, t0()).unwrap();
        let b = store.put_upload(&[2; 4], &none, t0() + mins(1)).unwrap();
        // 5 more: evicting A (6) leaves 4 + 5 = 9, which fits.
        let c = store.put_upload(&[3; 5], &none, t0() + mins(120)).unwrap();
        assert!(!has(&store, &a));
        assert!(has(&store, &b));
        assert!(has(&store, &c));
    }

    #[test]
    fn a_refused_upload_deletes_nothing_even_when_some_could_go() {
        let (_dir, store) = quota_store(BlobQuota::new(10, 100));
        let none = BTreeSet::new();
        let old = store.put_upload(&[1; 6], &none, t0()).unwrap();
        let young = store.put_upload(&[2; 4], &none, t0() + mins(90)).unwrap();
        // 8 more needs both gone, and the younger may not go yet.
        assert!(matches!(
            store.put_upload(&[3; 8], &none, t0() + mins(120)),
            Err(BlobError::OverQuota)
        ));
        assert!(has(&store, &old));
        assert!(has(&store, &young));
    }

    #[test]
    fn uploading_again_or_touching_resets_the_time() {
        let (_dir, store) = quota_store(BlobQuota::new(1000, 2));
        let none = BTreeSet::new();
        let a = store.put_upload(b"a", &none, t0()).unwrap();
        let b = store.put_upload(b"b", &none, t0() + mins(1)).unwrap();
        // A again at 90 minutes: the same id, nothing evicted, and A is
        // now the younger.
        assert_eq!(store.put_upload(b"a", &none, t0() + mins(90)).unwrap(), a);
        assert!(has(&store, &b));
        let c = store.put_upload(b"c", &none, t0() + mins(121)).unwrap();
        assert!(has(&store, &a));
        assert!(!has(&store, &b));
        // Touching C keeps it: at 3 hours A goes instead.
        assert!(store.touch(c.id.as_ref(), t0() + mins(170)).unwrap());
        let d = store.put_upload(b"d", &none, t0() + mins(180)).unwrap();
        assert!(!has(&store, &a));
        assert!(has(&store, &c));
        assert!(has(&store, &d));
        // Touching what is not there says so.
        assert!(!store.touch(b.id.as_ref(), t0()).unwrap());
        assert!(!store.touch("../x", t0()).unwrap());
    }

    #[test]
    fn put_has_no_quota_and_temporary_files_are_not_blobs() {
        let (dir, store) = quota_store(BlobQuota::new(1, 1));
        store.put(b"received").unwrap();
        store.put(b"received too").unwrap();
        assert_eq!(
            std::fs::read_dir(dir.path().join("blobs")).unwrap().count(),
            2
        );
        // A stray temporary file is neither counted nor deleted.
        let stray = dir.path().join("blobs").join(".stray.tmp");
        std::fs::write(&stray, b"half a blob").unwrap();
        let referenced = BTreeSet::new();
        let far = SystemTime::now() + mins(24 * 60);
        store.put_upload(b"", &referenced, far).unwrap();
        assert!(stray.exists());
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
