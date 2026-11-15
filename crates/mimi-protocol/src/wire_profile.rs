//! Which encoding of the messages the #190 extension points change
//! (bead mimid-1wgh.55.5).
//!
//! The draft change on MarkAtwood/mimi-protocol branch
//! `extension-points-190` (for mimi-protocol issue 190) adds an
//! `AppDataDictionary` extension point to `KeyMaterialRequest` (and its
//! TBS), `ClientKeyMaterial`, `UpdateRequest` and `UpdateRoomResponse`.
//! That is a wire change, so each of those messages has a
//! profile-aware encoder and decoder, taking or returning the extensions
//! beside the message; the `tls_codec` traits stay protocol-07.

use std::io::Read;

use mimi_mls::wire::AppDataDictionary;
use tls_codec::{Deserialize, Serialize};

/// The encoding a peer speaks for the messages #190 extends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum WireProfile {
    /// draft-ietf-mimi-protocol-07 as published: no extension fields.
    #[default]
    Draft07,
    /// protocol-07 with the #190 extension points. INVENTED, NOT FROM
    /// SPEC: the draft change is not adopted.
    Extensions190,
}

impl WireProfile {
    /// Writes `extensions` where the profile has the field; under
    /// [`WireProfile::Draft07`] writes nothing and refuses non-empty
    /// extensions, which that encoding cannot carry.
    pub(crate) fn write_extensions<W: std::io::Write>(
        self,
        extensions: &AppDataDictionary,
        writer: &mut W,
    ) -> Result<usize, tls_codec::Error> {
        match self {
            Self::Draft07 if extensions.is_empty() => Ok(0),
            Self::Draft07 => Err(tls_codec::Error::EncodingError(
                "protocol-07 has no field for extensions".to_owned(),
            )),
            Self::Extensions190 => extensions.tls_serialize(writer),
        }
    }

    /// Reads the extensions where the profile has the field; empty under
    /// [`WireProfile::Draft07`].
    pub(crate) fn read_extensions<R: Read>(
        self,
        bytes: &mut R,
    ) -> Result<AppDataDictionary, tls_codec::Error> {
        match self {
            Self::Draft07 => Ok(AppDataDictionary::default()),
            Self::Extensions190 => AppDataDictionary::tls_deserialize(bytes),
        }
    }
}

/// Decodes all of `bytes` with `read`, refusing trailing bytes.
pub(crate) fn exact<T>(
    bytes: &[u8],
    read: impl FnOnce(&mut &[u8]) -> Result<T, tls_codec::Error>,
) -> Result<T, tls_codec::Error> {
    let mut reader = bytes;
    let value = read(&mut reader)?;
    if reader.is_empty() {
        Ok(value)
    } else {
        Err(tls_codec::Error::TrailingData)
    }
}
