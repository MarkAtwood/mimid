//! `IdentifierUri` (protocol-06 §5.2), validated per decision mimid-1wgh.36.

use std::io::{Read, Write};

use iri_string::types::UriStr;
use tls_codec::{Deserialize, Serialize, Size, VLByteSlice, VLBytes};

use crate::Error;

/// A URI identifying a provider, user, client or room (protocol-06 §5.2).
///
/// Wire form: `struct { opaque uri<V>; } IdentifierUri;`. Also used where
/// the draft writes `IdentifierURI` or `RoomId` (decision mimid-1wgh.5.19).
///
/// The value is either empty or matches the RFC 3986 §3 `URI` production:
/// a scheme is required, a fragment is allowed, and relative references are
/// rejected. That makes it ASCII-only (decision mimid-1wgh.36). An empty
/// value means "absent", e.g. a zero-length room ID (decision
/// mimid-1wgh.5.27).
///
/// The value is never normalized: encoding emits exactly the bytes that
/// were decoded or passed to [`IdentifierUri::new`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct IdentifierUri {
    uri: String,
}

impl IdentifierUri {
    /// Wraps `uri` after checking it is empty or an RFC 3986 `URI`.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUri`] if `uri` is neither empty nor an RFC 3986
    /// `URI`.
    pub fn new(uri: &str) -> Result<Self, Error> {
        if uri.is_empty() || UriStr::new(uri).is_ok() {
            Ok(Self {
                uri: uri.to_owned(),
            })
        } else {
            Err(Error::InvalidUri)
        }
    }

    /// The URI text, exactly as received.
    pub fn as_str(&self) -> &str {
        &self.uri
    }

    /// Whether the value is empty, meaning "absent" (decision
    /// mimid-1wgh.5.27).
    pub fn is_empty(&self) -> bool {
        self.uri.is_empty()
    }
}

impl Size for IdentifierUri {
    fn tls_serialized_len(&self) -> usize {
        VLByteSlice(self.uri.as_bytes()).tls_serialized_len()
    }
}

impl Serialize for IdentifierUri {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        VLByteSlice(self.uri.as_bytes()).tls_serialize(writer)
    }
}

impl Deserialize for IdentifierUri {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let raw: Vec<u8> = VLBytes::tls_deserialize(bytes)?.into();
        std::str::from_utf8(&raw)
            .map_err(|_| Error::InvalidUri)
            .and_then(Self::new)
            .map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}
