//! The frank_aad Safe AAD component (protocol-06 §5.4.1).

use tls_codec::{TlsDeserialize, TlsSerialize, TlsSize};

/// `struct { uint8 franking_tag[32]; } FrankAAD;` (protocol-06 §5.4.1).
///
/// The `aad_item_data` of a `SafeAADItem` with component ID
/// [`FRANK_AAD`](crate::component_id::FRANK_AAD) (mls-extensions-10 §4.9;
/// decision mimid-1wgh.4.17). The fixed-size array has no length prefix, so
/// the encoding is exactly 32 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct FrankAad {
    /// `HMAC_SHA256(salt, application_data)` (§5.4.1.1).
    pub franking_tag: [u8; 32],
}
