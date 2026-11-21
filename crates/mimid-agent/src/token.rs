//! The local bearer token: what a JMAP client presents to the daemon.
//!
//! [`LocalToken::load_or_create`] makes it on first start, 32 octets of the
//! OS RNG as unpadded base64url in [`TOKEN_FILE`] under the state
//! directory, and reads it on later starts. The file is created with mode
//! 0600 (never chmod-ed afterwards, so it is never readable by others, even
//! briefly); a client running as the same user reads it there.

use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use subtle::ConstantTimeEq;

/// The token file's name in the state directory.
pub const TOKEN_FILE: &str = "agent-token";

/// Random octets in a token.
pub const TOKEN_OCTETS: usize = 32;

/// The token's length as unpadded base64url.
const TOKEN_LEN: usize = (TOKEN_OCTETS * 4).div_ceil(3);

/// The local bearer token. Its `Debug` output is redacted.
#[derive(Clone)]
pub struct LocalToken(String);

impl std::fmt::Debug for LocalToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LocalToken(..)")
    }
}

impl LocalToken {
    /// The token in `<state_dir>/agent-token`, made if the file does not
    /// exist. `state_dir` is created with mode 0700 if missing.
    ///
    /// # Errors
    ///
    /// [`TokenError::Io`] if the directory or file cannot be made or read,
    /// [`TokenError::Random`] if the OS RNG fails, and
    /// [`TokenError::Malformed`] if the file holds something other than a
    /// token this function made.
    pub fn load_or_create(state_dir: &Path) -> Result<Self, TokenError> {
        let path = state_dir.join(TOKEN_FILE);
        let io = |source| TokenError::Io {
            path: path.clone(),
            source,
        };
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)
            .map_err(|source| TokenError::Io {
                path: state_dir.to_owned(),
                source,
            })?;
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
        {
            Ok(mut file) => {
                let mut octets = [0u8; TOKEN_OCTETS];
                getrandom::fill(&mut octets).map_err(|_| TokenError::Random)?;
                let token = URL_SAFE_NO_PAD.encode(octets);
                file.write_all(token.as_bytes()).map_err(io)?;
                file.sync_all().map_err(io)?;
                Ok(Self(token))
            }
            Err(e) if e.kind() == ErrorKind::AlreadyExists => {
                let mut text = String::new();
                OpenOptions::new()
                    .read(true)
                    .open(&path)
                    .and_then(|mut file| file.read_to_string(&mut text))
                    .map_err(io)?;
                Self::parse(text.trim()).ok_or(TokenError::Malformed(path))
            }
            Err(e) => Err(io(e)),
        }
    }

    /// Writes a new token to `<state_dir>/agent-token` in place of the old
    /// one (`app-password rotate-token`): written to a temporary file of
    /// mode 0600 beside it, then renamed over it, so a reader sees the old
    /// token or the new one, never part of one.
    ///
    /// # Errors
    ///
    /// [`TokenError::Io`] and [`TokenError::Random`].
    pub fn replace(state_dir: &Path) -> Result<Self, TokenError> {
        let path = state_dir.join(TOKEN_FILE);
        let temporary = state_dir.join(format!("{TOKEN_FILE}.new"));
        let io = |source| TokenError::Io {
            path: path.clone(),
            source,
        };
        let mut octets = [0u8; TOKEN_OCTETS];
        getrandom::fill(&mut octets).map_err(|_| TokenError::Random)?;
        let token = URL_SAFE_NO_PAD.encode(octets);
        let _ = std::fs::remove_file(&temporary);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(io)?;
        file.write_all(token.as_bytes()).map_err(io)?;
        file.sync_all().map_err(io)?;
        std::fs::rename(&temporary, &path).map_err(io)?;
        Ok(Self(token))
    }

    /// `text` as a token, if it is one this module made.
    fn parse(text: &str) -> Option<Self> {
        (text.len() == TOKEN_LEN
            && URL_SAFE_NO_PAD
                .decode(text)
                .is_ok_and(|octets| octets.len() == TOKEN_OCTETS))
        .then(|| Self(text.to_owned()))
    }

    /// The key attachment links are made with
    /// (mimid_agent_store::links): HMAC-SHA256 under the token of
    /// `"mimid-attachment-link-key-v1"`, so a new token revokes every
    /// link, and a link shows nothing of the token.
    #[must_use]
    pub fn link_key(&self) -> [u8; 32] {
        use hmac::{Hmac, KeyInit, Mac};
        let mut mac = <Hmac<sha2::Sha256> as KeyInit>::new_from_slice(self.0.as_bytes())
            .unwrap_or_else(|_| unreachable!("HMAC takes a key of any length"));
        mac.update(b"mimid-attachment-link-key-v1");
        mac.finalize().into_bytes().into()
    }

    /// The token's octets, for the credential table
    /// (`mimid_agent_store::credentials`, which keeps only its verifier).
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    /// Whether `presented` is this token, compared in constant time (a
    /// length mismatch shows only that the length differs).
    pub fn matches(&self, presented: &[u8]) -> bool {
        self.0.as_bytes().ct_eq(presented).into()
    }
}

/// Why the local token could not be had.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// The state directory or token file could not be made or read.
    #[error("{}", path.display())]
    Io {
        /// The path concerned.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The OS RNG failed.
    #[error("the OS random number generator failed")]
    Random,
    /// The token file does not hold a token.
    #[error("{} does not hold an agent token", .0.display())]
    Malformed(PathBuf),
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use super::*;

    #[test]
    fn the_token_file_is_created_0600_and_reused() {
        let dir = tempfile::tempdir().unwrap();
        let state = dir.path().join("state");
        let first = LocalToken::load_or_create(&state).unwrap();
        let path = state.join(TOKEN_FILE);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.len(), TOKEN_LEN);
        assert_eq!(URL_SAFE_NO_PAD.decode(&text).unwrap().len(), TOKEN_OCTETS);
        assert!(first.matches(text.as_bytes()));

        let second = LocalToken::load_or_create(&state).unwrap();
        assert!(second.matches(text.as_bytes()));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), text);

        // A token from another state directory is another token.
        let other = LocalToken::load_or_create(&dir.path().join("other")).unwrap();
        assert!(!other.matches(text.as_bytes()));
    }

    #[test]
    fn matching_is_exact() {
        let dir = tempfile::tempdir().unwrap();
        let token = LocalToken::load_or_create(dir.path()).unwrap();
        let text = token.0.clone();
        assert!(token.matches(text.as_bytes()));
        assert!(!token.matches(b""));
        assert!(!token.matches(&text.as_bytes()[1..]));
        assert!(!token.matches(format!("{text}x").as_bytes()));
        let mut flipped = text.into_bytes();
        flipped[0] ^= 1;
        assert!(!token.matches(&flipped));
    }

    #[test]
    fn a_malformed_token_file_is_refused_not_replaced() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(TOKEN_FILE);
        std::fs::write(&path, "short").unwrap();
        assert!(matches!(
            LocalToken::load_or_create(dir.path()),
            Err(TokenError::Malformed(_))
        ));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "short");
    }

    #[test]
    fn debug_output_hides_the_token() {
        let dir = tempfile::tempdir().unwrap();
        let token = LocalToken::load_or_create(dir.path()).unwrap();
        assert_eq!(format!("{token:?}"), "LocalToken(..)");
    }
}
