//! [`AgentError`], the one error type of the public API.

use std::error::Error as StdError;
use std::path::PathBuf;

/// A boxed error source.
pub type Source = Box<dyn StdError + Send + Sync + 'static>;

/// Why an [`crate::Agent`] operation failed.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AgentError {
    /// The server could not be reached, or the connection failed.
    #[error("{what}: the server could not be reached")]
    Http {
        /// The request.
        what: String,
        /// What the HTTP client said.
        #[source]
        source: reqwest::Error,
    },
    /// The server answered with an HTTP error status.
    #[error("{what}: the server answered HTTP {status}")]
    Status {
        /// The request.
        what: String,
        /// The status code.
        status: u16,
        /// The start of the response body.
        body: String,
    },
    /// The server answered a JMAP method with a method error (RFC 8620
    /// §3.6.2) or a SetError.
    #[error("{method}: {kind}{}", if .description.is_empty() { String::new() } else { format!(": {}", .description) })]
    Method {
        /// The method.
        method: String,
        /// The error `type`.
        kind: String,
        /// The error `description`, or empty.
        description: String,
    },
    /// The server's answer is not what the draft says it is.
    #[error("{what}: the server's answer is malformed: {detail}")]
    Malformed {
        /// The request.
        what: String,
        /// What is wrong.
        detail: String,
    },
    /// The room's hub refused an update or a message.
    #[error("{what} was refused: {reason}")]
    Refused {
        /// The operation.
        what: String,
        /// The response code and description.
        reason: String,
    },
    /// The user has no usable key material for us.
    #[error("keyMaterial for {user}: {code}")]
    NoKeyMaterial {
        /// The target user.
        user: String,
        /// The `userStatus`, or why the answer had no KeyPackage.
        code: String,
    },
    /// The caller asked for something that cannot be done.
    #[error("{0}")]
    Invalid(String),
    /// No room with that URI is known to this agent, or it is not active.
    #[error("no active room {0}")]
    NoSuchRoom(String),
    /// No pending invite with that number.
    #[error("no pending invite {0}")]
    NoSuchInvite(u64),
    /// A fetched attachment could not be opened.
    #[error("the attachment: {0}")]
    Asset(#[from] crate::asset::AssetError),
    /// An MLS operation failed.
    #[error("{what}")]
    Mls {
        /// The operation.
        what: String,
        /// The mimi-mls error.
        #[source]
        source: Source,
    },
    /// A message could not be encoded or decoded.
    #[error("{what}")]
    Encoding {
        /// What was being encoded or decoded.
        what: String,
        /// The codec's error.
        #[source]
        source: Source,
    },
    /// The agent's database failed.
    #[error("{}: {what}", .path.display())]
    Database {
        /// The database file.
        path: PathBuf,
        /// What was being done.
        what: String,
        /// SQLite's error.
        #[source]
        source: Source,
    },
    /// The state directory cannot be used.
    #[error("{}: {detail}", .path.display())]
    State {
        /// The file or directory.
        path: PathBuf,
        /// What is wrong.
        detail: String,
        /// The I/O error, if any.
        #[source]
        source: Option<std::io::Error>,
    },
}

impl AgentError {
    pub(crate) fn mls(what: impl Into<String>, source: impl Into<Source>) -> Self {
        Self::Mls {
            what: what.into(),
            source: source.into(),
        }
    }

    pub(crate) fn encoding(what: impl Into<String>, source: impl Into<Source>) -> Self {
        Self::Encoding {
            what: what.into(),
            source: source.into(),
        }
    }

    /// A tls_codec error, which does not implement [`std::error::Error`]
    /// in every version, as an encoding error.
    pub(crate) fn tls(what: impl Into<String>, error: impl std::fmt::Debug) -> Self {
        Self::Encoding {
            what: what.into(),
            source: format!("{error:?}").into(),
        }
    }

    pub(crate) fn malformed(what: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::Malformed {
            what: what.into(),
            detail: detail.into(),
        }
    }
}
