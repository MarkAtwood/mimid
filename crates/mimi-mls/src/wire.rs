//! MLS wire types for the protocol crate, as newtypes whose TLS encoding
//! delegates to OpenMLS.
//!
//! mimi-protocol embeds MLS structures in its own TLS-encoded messages
//! without a length prefix, so it needs types that implement
//! [`tls_codec`]'s traits but do not expose OpenMLS (decision
//! mimid-1wgh.4.24). Each type here is named after the RFC 9420,
//! mls-extensions-10 or ratchet-tree-options-01 structure it carries.
//!
//! # Decoding
//!
//! Decode with [`tls_codec::Deserialize`]: `tls_deserialize` for a value
//! embedded in a larger structure, or `tls_deserialize_exact` for a whole
//! buffer, which rejects trailing bytes. Decoding is strict: after OpenMLS
//! has parsed a value, it is re-encoded and must reproduce the input
//! exactly, so non-canonical encodings fail. Enum values outside the
//! defined range are rejected.
//!
//! None of these types implement [`tls_codec::DeserializeBytes`]. In
//! tls_codec 0.5.0 that path panics in debug builds on truncated input
//! (bug mimid-1wgh.33), so it must never see untrusted bytes.
//!
//! # Encoding
//!
//! Every type keeps the exact bytes it was decoded from, and
//! [`tls_codec::Serialize`] writes those bytes back unchanged. `as_bytes()`
//! returns them, so signatures and hashes are computed over the bytes as
//! received. Extensions that OpenMLS does not know round-trip unchanged.
//!
//! # Limitations
//!
//! - The only size limit is tls_codec's: each variable-length vector holds
//!   at most 2^30 - 1 bytes. Callers must bound the size of a whole message
//!   before decoding it.
//! - [`KeyPackage`], [`Welcome`], [`GroupInfo`] and [`MLSMessage`] carrying
//!   those reject ciphersuites OpenMLS does not implement, because OpenMLS
//!   parses the ciphersuite as a closed enum. [`CipherSuite`] itself accepts
//!   any value.
//! - Apart from [`MLSMessage`]'s clear header fields
//!   ([`MLSMessage::wire_format`], [`MLSMessage::content_type`],
//!   [`MLSMessage::group_id`], [`MLSMessage::epoch`] and
//!   [`MLSMessage::authenticated_data`]), [`AppDataDictionary`]'s entries and the fields of the
//!   ratchet-tree-options-01 types, the types expose only their encoding.
//! - Decoding checks structure only. No signature, MAC or membership check
//!   happens here.

mod app_data;
mod ratchet_tree_options;
mod rfc9420;

use std::io::{self, Read, Write};

use tls_codec::{Deserialize, Serialize};

pub use app_data::AppDataDictionary;
pub use ratchet_tree_options::{
    PartialGroupInfo, RatchetTreeOption, RatchetTreePresence, RatchetTreeRepresentation,
};
pub use rfc9420::{
    Capabilities, CipherSuite, ContentType, Credential, ExternalSender, GroupInfo, HPKECiphertext,
    HPKEPublicKey, KeyPackage, KeyPackageRef, MLSMessage, ProposalRef, RequiredCapabilities,
    SignaturePublicKey, Welcome, WireFormat,
};

/// A reader that keeps a copy of every byte read through it.
struct Recorder<'a, R> {
    inner: &'a mut R,
    consumed: Vec<u8>,
}

impl<R: Read> Read for Recorder<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.inner.read(buf)?;
        let read = buf
            .get(..n)
            .ok_or_else(|| io::Error::other("reader returned more bytes than requested"))?;
        self.consumed.extend_from_slice(read);
        Ok(n)
    }
}

/// Reads one `T` with its Read-based decoder and returns it together with
/// the exact bytes it consumed.
///
/// # Errors
///
/// Returns the decoder's error, or [`tls_codec::Error::DecodingError`] if
/// re-encoding the value does not reproduce the consumed bytes.
fn decode_canonical<T, R>(reader: &mut R) -> Result<(T, Vec<u8>), tls_codec::Error>
where
    T: Deserialize + Serialize,
    R: Read,
{
    let mut recorder = Recorder {
        inner: reader,
        consumed: Vec::new(),
    };
    let value = T::tls_deserialize(&mut recorder)?;
    if value.tls_serialize_detached()? != recorder.consumed {
        return Err(tls_codec::Error::DecodingError(
            "non-canonical encoding".to_owned(),
        ));
    }
    Ok((value, recorder.consumed))
}

/// Writes the kept bytes of a wire type.
fn write_bytes<W: Write>(writer: &mut W, bytes: &[u8]) -> Result<usize, tls_codec::Error> {
    writer.write_all(bytes)?;
    Ok(bytes.len())
}

/// Implements `as_bytes`, `AsRef<[u8]>`, [`tls_codec::Size`] and
/// [`tls_codec::Serialize`] for a type whose `bytes` field holds its exact
/// encoding.
macro_rules! impl_encoding_from_bytes {
    ($name:ident) => {
        impl $name {
            /// Returns the exact TLS encoding of this value, as it was
            /// received.
            pub fn as_bytes(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl AsRef<[u8]> for $name {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }

        impl tls_codec::Size for $name {
            fn tls_serialized_len(&self) -> usize {
                self.bytes.len()
            }
        }

        impl tls_codec::Serialize for $name {
            fn tls_serialize<W: std::io::Write>(
                &self,
                writer: &mut W,
            ) -> Result<usize, tls_codec::Error> {
                crate::wire::write_bytes(writer, &self.bytes)
            }
        }
    };
}

/// Defines a wire type that holds only its encoding and decodes through
/// the OpenMLS type `$openmls`.
macro_rules! opaque_wire_type {
    ($(#[$meta:meta])* $name:ident => $openmls:ty) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name {
            bytes: Vec<u8>,
        }

        crate::wire::impl_encoding_from_bytes!($name);

        impl tls_codec::Deserialize for $name {
            fn tls_deserialize<R: std::io::Read>(
                bytes: &mut R,
            ) -> Result<Self, tls_codec::Error> {
                let (_, bytes) = crate::wire::decode_canonical::<$openmls, R>(bytes)?;
                Ok(Self { bytes })
            }
        }
    };
}

use impl_encoding_from_bytes;
use opaque_wire_type;
