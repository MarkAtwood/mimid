//! Franking wire types (protocol-06 §5.4, §5.4.1).

use mimi_mls::wire::CipherSuite;
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

/// `Frank` (protocol-06 §5.4): the hub's frank on an application message,
/// carried in a `SubmitMessageResponse` and a [`FanoutMessage`](crate::FanoutMessage).
///
/// Decoding checks the wire form only. Neither `server_frank` nor the
/// signature is verified here.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct Frank {
    /// `uint8 server_frank[32]` (§5.4.1.2).
    pub server_frank: [u8; 32],
    /// The ciphersuite of `franking_integrity_signature`. Any `uint16`
    /// decodes.
    pub franking_signature_ciphersuite: CipherSuite,
    /// `opaque franking_integrity_signature<V>` (§5.4.1.2).
    pub franking_integrity_signature: Vec<u8>,
}
