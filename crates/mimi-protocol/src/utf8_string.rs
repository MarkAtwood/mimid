//! `UTF8String` (protocol-06 §7.6), also used where the draft writes
//! `string` (decision mimid-1wgh.5.20).

use std::fmt;
use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, VLByteSlice, VLBytes};

use crate::Error;

/// "A sequence of valid UTF8 without nulls" (protocol-06 §7.6).
///
/// Wire form: `struct { opaque string<V>; } UTF8String;`. Only the null
/// character is excluded. Bidi controls and zero-width characters are valid
/// here, so renderers must isolate them.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct Utf8String {
    string: String,
}

impl Utf8String {
    /// Wraps `string` after checking it contains no null.
    ///
    /// # Errors
    ///
    /// [`Error::NullInUtf8String`] if `string` contains U+0000.
    pub fn new(string: impl Into<String>) -> Result<Self, Error> {
        let string = string.into();
        match string.find('\0') {
            Some(index) => Err(Error::NullInUtf8String { index }),
            None => Ok(Self { string }),
        }
    }

    /// Validates `bytes` as UTF-8 without nulls.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidUtf8`] if `bytes` is not valid UTF-8 (including
    /// overlong forms and surrogates), or [`Error::NullInUtf8String`] if it
    /// contains U+0000.
    pub fn from_utf8(bytes: Vec<u8>) -> Result<Self, Error> {
        Self::new(String::from_utf8(bytes).map_err(Error::InvalidUtf8)?)
    }

    /// The string content.
    pub fn as_str(&self) -> &str {
        &self.string
    }
}

impl AsRef<str> for Utf8String {
    fn as_ref(&self) -> &str {
        &self.string
    }
}

impl fmt::Display for Utf8String {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.string)
    }
}

impl Size for Utf8String {
    fn tls_serialized_len(&self) -> usize {
        VLByteSlice(self.string.as_bytes()).tls_serialized_len()
    }
}

impl Serialize for Utf8String {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        VLByteSlice(self.string.as_bytes()).tls_serialize(writer)
    }
}

impl Deserialize for Utf8String {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let raw: Vec<u8> = VLBytes::tls_deserialize(bytes)?.into();
        Self::from_utf8(raw).map_err(|e| tls_codec::Error::DecodingError(e.to_string()))
    }
}
