//! The keyMaterial endpoint (protocol-07 §5.2):
//! `POST /keyMaterial/{targetUser}`.
//!
//! The requester signs a [`KeyMaterialRequestTbs`] with
//! [`KeyMaterialRequestTbs::sign`]; the target provider checks it with
//! [`KeyMaterialRequest::verify`] and answers with a
//! [`KeyMaterialResponse`].
//!
//! The signature is verified over the TBS bytes exactly as received: a
//! decoded [`KeyMaterialRequest`] keeps them, and encoding writes them back
//! unchanged.

use std::io::{Read, Write};

use mimi_mls::label;
use mimi_mls::wire::{
    AppDataDictionary, Capabilities, CipherSuite, Credential, KeyPackage, RequiredCapabilities,
    SignaturePublicKey,
};
use tls_codec::{
    Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize, VLByteSlice, VLBytes,
};

use crate::group_info::{Recorder, key_bytes};
use crate::wire_profile::{WireProfile, exact};
use crate::{Error, IdentifierUri, Protocol};

/// SignWithLabel label for [`KeyMaterialRequestTbs`] (protocol-07 §5.2).
const REQUEST_TBS_LABEL: &str = "KeyMaterialRequestTBS";

/// RFC 9420 suite 1, the only suite whose signature scheme
/// [`mimi_mls::label`] implements (decision mimid-1wgh.23).
const SIGNING_CIPHER_SUITE: u16 = 0x0001;

/// Checks that suite 1, whose signature scheme signs the request, is among
/// `acceptable_ciphersuites`.
///
/// protocol-07 §5.2 names no suite for `key_material_request_signature`;
/// mimid signs and verifies with suite 1's scheme (Ed25519) and requires
/// suite 1 to be acceptable to the requester (decision mimid-1wgh.5.61).
fn check_signing_suite(acceptable_ciphersuites: &[CipherSuite]) -> Result<(), Error> {
    // protocol-07 §5.2; decision mimid-1wgh.5.61
    let first = acceptable_ciphersuites
        .first()
        .ok_or(Error::EmptyCipherSuites)?;
    if acceptable_ciphersuites
        .iter()
        .any(|suite| u16::from(*suite) == SIGNING_CIPHER_SUITE)
    {
        Ok(())
    } else {
        Err(Error::UnsupportedCipherSuite {
            cipher_suite: u16::from(*first),
        })
    }
}

/// `KeyMaterialRequestTBS` (protocol-07 §5.2), the part of a
/// [`KeyMaterialRequest`] the requester signs.
///
/// `protocol` is the only `Protocol` value, `mls10`, so its `select` is
/// always the `mls10` arm. `acceptable_ciphersuites` must not be empty:
/// decoding and encoding reject an empty list (decision mimid-1wgh.5.62).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize)]
pub struct KeyMaterialRequestTbs {
    /// `Protocol protocol`.
    pub protocol: Protocol,
    /// `IdentifierUri requestingUser`.
    pub requesting_user: IdentifierUri,
    /// `IdentifierUri targetUser`.
    pub target_user: IdentifierUri,
    /// `IdentifierUri roomId`: the room the KeyPackages are for. Empty
    /// means absent, for a request made outside any room (decision
    /// mimid-1wgh.5.27).
    pub room_id: IdentifierUri,
    /// `CipherSuite acceptableCiphersuites<V>`: non-empty.
    pub acceptable_ciphersuites: Vec<CipherSuite>,
    /// `RequiredCapabilities requiredCapabilities`.
    pub required_capabilities: RequiredCapabilities,
    /// `SignaturePublicKey requesterSignatureKey`.
    pub requester_signature_key: SignaturePublicKey,
    /// `Credential requesterCredential`.
    pub requester_credential: Credential,
}

/// Rejects an empty `acceptableCiphersuites` list (protocol-07 §5.2).
fn check_acceptable(acceptable_ciphersuites: &[CipherSuite]) -> Result<(), String> {
    // protocol-07 §5.2; decision mimid-1wgh.5.62
    if acceptable_ciphersuites.is_empty() {
        Err(Error::EmptyCipherSuites.to_string())
    } else {
        Ok(())
    }
}

impl Serialize for KeyMaterialRequestTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.write(writer, WireProfile::Draft07, &AppDataDictionary::default())
    }
}

impl KeyMaterialRequestTbs {
    fn write<W: Write>(
        &self,
        writer: &mut W,
        profile: WireProfile,
        extensions: &AppDataDictionary,
    ) -> Result<usize, tls_codec::Error> {
        check_acceptable(&self.acceptable_ciphersuites).map_err(tls_codec::Error::EncodingError)?;
        Ok(self.protocol.tls_serialize(writer)?
            + self.requesting_user.tls_serialize(writer)?
            + self.target_user.tls_serialize(writer)?
            + self.room_id.tls_serialize(writer)?
            + profile.write_extensions(extensions, writer)?
            + self.acceptable_ciphersuites.tls_serialize(writer)?
            + self.required_capabilities.tls_serialize(writer)?
            + self.requester_signature_key.tls_serialize(writer)?
            + self.requester_credential.tls_serialize(writer)?)
    }
}

impl Deserialize for KeyMaterialRequestTbs {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Self::read(bytes, WireProfile::Draft07).map(|(tbs, _)| tbs)
    }
}

impl KeyMaterialRequestTbs {
    fn read<R: Read>(
        bytes: &mut R,
        profile: WireProfile,
    ) -> Result<(Self, AppDataDictionary), tls_codec::Error> {
        let protocol = Protocol::tls_deserialize(bytes)?;
        let requesting_user = IdentifierUri::tls_deserialize(bytes)?;
        let target_user = IdentifierUri::tls_deserialize(bytes)?;
        let room_id = IdentifierUri::tls_deserialize(bytes)?;
        let extensions = profile.read_extensions(bytes)?;
        let acceptable_ciphersuites = Vec::<CipherSuite>::tls_deserialize(bytes)?;
        check_acceptable(&acceptable_ciphersuites).map_err(tls_codec::Error::DecodingError)?;
        let tbs = Self {
            protocol,
            requesting_user,
            target_user,
            room_id,
            acceptable_ciphersuites,
            required_capabilities: RequiredCapabilities::tls_deserialize(bytes)?,
            requester_signature_key: SignaturePublicKey::tls_deserialize(bytes)?,
            requester_credential: Credential::tls_deserialize(bytes)?,
        };
        Ok((tbs, extensions))
    }
}

impl KeyMaterialRequestTbs {
    /// Signs this TBS: `SignWithLabel(requesterSignatureKey,
    /// "KeyMaterialRequestTBS", KeyMaterialRequestTBS)`.
    ///
    /// `signature_private_key` is the key pair whose public key is
    /// `requester_signature_key`: Ed25519, the scheme of suite 1, which
    /// `acceptable_ciphersuites` must contain.
    ///
    /// # Errors
    ///
    /// [`Error::EmptyCipherSuites`] if `acceptable_ciphersuites` is empty,
    /// [`Error::UnsupportedCipherSuite`] (naming the first listed suite)
    /// if it lacks suite 1, [`Error::Encoding`] if the TBS cannot be
    /// encoded, and [`Error::Label`] if signing fails.
    pub fn sign(
        self,
        signature_private_key: &label::SignatureKeyPair,
    ) -> Result<KeyMaterialRequest, Error> {
        self.sign_with(
            WireProfile::Draft07,
            AppDataDictionary::default(),
            signature_private_key,
        )
    }

    /// [`KeyMaterialRequestTbs::sign`] under `profile`, with `extensions`
    /// (the #190 `key_material_request_extensions`, after `roomId`), which
    /// the signature covers.
    ///
    /// # Errors
    ///
    /// As [`KeyMaterialRequestTbs::sign`]; [`Error::Encoding`] also if
    /// `extensions` is not empty under [`WireProfile::Draft07`].
    pub fn sign_with(
        self,
        profile: WireProfile,
        extensions: AppDataDictionary,
        signature_private_key: &label::SignatureKeyPair,
    ) -> Result<KeyMaterialRequest, Error> {
        check_signing_suite(&self.acceptable_ciphersuites)?;
        let mut tbs_bytes = Vec::new();
        self.write(&mut tbs_bytes, profile, &extensions)
            .map_err(Error::Encoding)?;
        let signature = signature_private_key
            .sign_with_label(REQUEST_TBS_LABEL, &tbs_bytes)
            .map_err(Error::Label)?;
        Ok(KeyMaterialRequest {
            tbs: self,
            tbs_bytes,
            signature,
            extensions,
        })
    }
}

/// `KeyMaterialRequest` (protocol-07 §5.2), the body of
/// `POST /keyMaterial/{targetUser}`.
///
/// Built only by decoding or by [`KeyMaterialRequestTbs::sign`], so the
/// kept TBS bytes always match [`KeyMaterialRequest::tbs`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct KeyMaterialRequest {
    tbs: KeyMaterialRequestTbs,
    tbs_bytes: Vec<u8>,
    signature: Vec<u8>,
    extensions: AppDataDictionary,
}

impl KeyMaterialRequest {
    /// The signed fields.
    pub fn tbs(&self) -> &KeyMaterialRequestTbs {
        &self.tbs
    }

    /// The #190 `key_material_request_extensions`, signed with the TBS;
    /// empty under [`WireProfile::Draft07`].
    pub fn extensions(&self) -> &AppDataDictionary {
        &self.extensions
    }

    /// Decodes all of `bytes` under `profile`.
    ///
    /// # Errors
    ///
    /// A tls_codec error for anything malformed, or trailing bytes.
    pub fn decode(profile: WireProfile, bytes: &[u8]) -> Result<Self, tls_codec::Error> {
        exact(bytes, |reader| Self::read(reader, profile))
    }

    fn read<R: Read>(bytes: &mut R, profile: WireProfile) -> Result<Self, tls_codec::Error> {
        let mut recorder = Recorder::new(bytes);
        let (tbs, extensions) = KeyMaterialRequestTbs::read(&mut recorder, profile)?;
        let tbs_bytes = recorder.consumed;
        let signature = Vec::<u8>::tls_deserialize(bytes)?;
        Ok(Self {
            tbs,
            tbs_bytes,
            signature,
            extensions,
        })
    }

    /// `opaque key_material_request_signature<V>`.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Checks the signature with `requesterSignatureKey`, over the TBS
    /// bytes as received, using suite 1's signature scheme.
    ///
    /// This proves only that the requester holds the private key for the
    /// key it sent. Binding that key to `requesterCredential` and the
    /// requesting provider, checking that `targetUser` matches the request
    /// path, and checking consent are the caller's job.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] (naming the first listed suite)
    /// unless `acceptable_ciphersuites` contains suite 1,
    /// [`Error::Decoding`] if the key encoding is malformed, and
    /// [`Error::Label`] if the signature does not verify.
    pub fn verify(&self) -> Result<(), Error> {
        check_signing_suite(&self.tbs.acceptable_ciphersuites)?;
        let key = key_bytes(self.tbs.requester_signature_key.as_bytes())?;
        label::verify_with_label(
            key.as_slice(),
            REQUEST_TBS_LABEL,
            &self.tbs_bytes,
            &self.signature,
        )
        .map_err(Error::Label)
    }
}

impl Size for KeyMaterialRequest {
    fn tls_serialized_len(&self) -> usize {
        self.tbs_bytes.len() + VLByteSlice(&self.signature).tls_serialized_len()
    }
}

impl Serialize for KeyMaterialRequest {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        writer.write_all(&self.tbs_bytes)?;
        Ok(self.tbs_bytes.len() + VLByteSlice(&self.signature).tls_serialize(writer)?)
    }
}

impl Deserialize for KeyMaterialRequest {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Self::read(bytes, WireProfile::Draft07)
    }
}

/// `KeyMaterialUserCode` (protocol-07 §5.2).
///
/// Decoding rejects the undefined values 8 to 255 with
/// [`tls_codec::Error::UnknownValue`] (decision mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum KeyMaterialUserCode {
    /// `success(0)`: key material for every client of the target user.
    Success = 0,
    /// `partialSuccess(1)`: key material for at least one client.
    PartialSuccess = 1,
    /// `incompatibleProtocol(2)`: the protocol is not supported.
    IncompatibleProtocol = 2,
    /// `noCompatibleMaterial(3)`: no client could supply key material
    /// compatible with `requiredCapabilities`.
    NoCompatibleMaterial = 3,
    /// `userUnknown(4)`: the target user is not known.
    UserUnknown = 4,
    /// `noConsent(5)`: the requester lacks consent, or the provider hides
    /// the reason.
    NoConsent = 5,
    /// `noConsentForThisRoom(6)`: no consent for this room.
    NoConsentForThisRoom = 6,
    /// `userDeleted(7)`: the target user was deleted.
    UserDeleted = 7,
}

/// `KeyMaterialClientCode` (protocol-07 §5.2).
///
/// Decoding rejects the undefined values 3 to 255 with
/// [`tls_codec::Error::UnknownValue`], because the `select (clientStatus)`
/// that follows cannot be parsed for them (decision mimid-1wgh.5.36).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum KeyMaterialClientCode {
    /// `success(0)`: a KeyPackage is provided for the client.
    Success = 0,
    /// `keyMaterialExhausted(1)`: the client has no key material left.
    KeyMaterialExhausted = 1,
    /// `nothingCompatible(2)`: the client has no key material compatible
    /// with `requiredCapabilities`.
    NothingCompatible = 2,
}

/// `ClientKeyMaterial` (protocol-07 §5.2), one arm per
/// [`KeyMaterialClientCode`].
///
/// On the wire `clientStatus` and `clientUri` come first. The `select
/// (protocol)` is always the `mls10` arm, the enclosing response's only
/// possible `protocol` (decision mimid-1wgh.5.23). `keyMaterialExhausted`
/// has no arm in the `select (clientStatus)`, so it carries no further
/// fields (decision mimid-1wgh.5.64).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ClientKeyMaterial {
    /// `success(0)`.
    Success {
        /// `IdentifierUri clientUri`.
        client_uri: IdentifierUri,
        /// `KeyPackage keyPackage`.
        key_package: KeyPackage,
    },
    /// `keyMaterialExhausted(1)`.
    KeyMaterialExhausted {
        /// `IdentifierUri clientUri`.
        client_uri: IdentifierUri,
    },
    /// `nothingCompatible(2)`.
    NothingCompatible {
        /// `IdentifierUri clientUri`.
        client_uri: IdentifierUri,
        /// `optional<Capabilities> clientCapabilities`: absent when the
        /// provider withholds them for privacy.
        client_capabilities: Option<Capabilities>,
    },
}

impl ClientKeyMaterial {
    /// The `clientStatus` this arm belongs to.
    pub fn client_status(&self) -> KeyMaterialClientCode {
        match self {
            Self::Success { .. } => KeyMaterialClientCode::Success,
            Self::KeyMaterialExhausted { .. } => KeyMaterialClientCode::KeyMaterialExhausted,
            Self::NothingCompatible { .. } => KeyMaterialClientCode::NothingCompatible,
        }
    }

    /// `IdentifierUri clientUri`.
    pub fn client_uri(&self) -> &IdentifierUri {
        match self {
            Self::Success { client_uri, .. }
            | Self::KeyMaterialExhausted { client_uri }
            | Self::NothingCompatible { client_uri, .. } => client_uri,
        }
    }
}

impl Size for ClientKeyMaterial {
    fn tls_serialized_len(&self) -> usize {
        let arm = match self {
            Self::Success { key_package, .. } => key_package.tls_serialized_len(),
            Self::KeyMaterialExhausted { .. } => 0,
            Self::NothingCompatible {
                client_capabilities,
                ..
            } => client_capabilities.tls_serialized_len(),
        };
        self.client_status().tls_serialized_len() + self.client_uri().tls_serialized_len() + arm
    }
}

impl Serialize for ClientKeyMaterial {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.write(writer, WireProfile::Draft07, &AppDataDictionary::default())
    }
}

impl ClientKeyMaterial {
    fn write<W: Write>(
        &self,
        writer: &mut W,
        profile: WireProfile,
        extensions: &AppDataDictionary,
    ) -> Result<usize, tls_codec::Error> {
        let head = self.client_status().tls_serialize(writer)?
            + self.client_uri().tls_serialize(writer)?
            + profile.write_extensions(extensions, writer)?;
        let arm = match self {
            Self::Success { key_package, .. } => key_package.tls_serialize(writer)?,
            Self::KeyMaterialExhausted { .. } => 0,
            Self::NothingCompatible {
                client_capabilities,
                ..
            } => client_capabilities.tls_serialize(writer)?,
        };
        Ok(head + arm)
    }
}

impl Deserialize for ClientKeyMaterial {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Self::read(bytes, WireProfile::Draft07).map(|(client, _)| client)
    }
}

impl ClientKeyMaterial {
    fn read<R: Read>(
        bytes: &mut R,
        profile: WireProfile,
    ) -> Result<(Self, AppDataDictionary), tls_codec::Error> {
        let client_status = KeyMaterialClientCode::tls_deserialize(bytes)?;
        let client_uri = IdentifierUri::tls_deserialize(bytes)?;
        let extensions = profile.read_extensions(bytes)?;
        let client = match client_status {
            KeyMaterialClientCode::Success => Self::Success {
                client_uri,
                key_package: KeyPackage::tls_deserialize(bytes)?,
            },
            // protocol-07 §5.2; decision mimid-1wgh.5.64
            KeyMaterialClientCode::KeyMaterialExhausted => {
                Self::KeyMaterialExhausted { client_uri }
            }
            KeyMaterialClientCode::NothingCompatible => Self::NothingCompatible {
                client_uri,
                client_capabilities: Option::<Capabilities>::tls_deserialize(bytes)?,
            },
        };
        Ok((client, extensions))
    }
}

/// `KeyMaterialResponse` (protocol-07 §5.2), the response body of
/// `POST /keyMaterial/{targetUser}`.
///
/// Decoding and encoding check `clients` against `user_status`, as §5.2
/// describes the codes:
///
/// - `success`: every client has `clientStatus` `success`;
/// - `partialSuccess`: at least one client has `success`;
/// - `noCompatibleMaterial`: the list may be populated, but no client has
///   `success`;
/// - any other code: the list is empty ("MUST NOT populate").
///
/// Decision mimid-1wgh.5.63.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize)]
pub struct KeyMaterialResponse {
    /// `Protocol protocol`.
    pub protocol: Protocol,
    /// `KeyMaterialUserCode userStatus`.
    pub user_status: KeyMaterialUserCode,
    /// `IdentifierUri userUri`.
    pub user_uri: IdentifierUri,
    /// `ClientKeyMaterial clients<V>`.
    pub clients: Vec<ClientKeyMaterial>,
}

/// Checks `clients` against `user_status` (protocol-07 §5.2).
fn check_clients(
    user_status: KeyMaterialUserCode,
    clients: &[ClientKeyMaterial],
) -> Result<(), String> {
    // protocol-07 §5.2; decision mimid-1wgh.5.63
    let successes = clients
        .iter()
        .filter(|c| c.client_status() == KeyMaterialClientCode::Success)
        .count();
    let consistent = match user_status {
        KeyMaterialUserCode::Success => successes == clients.len(),
        KeyMaterialUserCode::PartialSuccess => successes > 0,
        KeyMaterialUserCode::NoCompatibleMaterial => successes == 0,
        KeyMaterialUserCode::IncompatibleProtocol
        | KeyMaterialUserCode::UserUnknown
        | KeyMaterialUserCode::NoConsent
        | KeyMaterialUserCode::NoConsentForThisRoom
        | KeyMaterialUserCode::UserDeleted => clients.is_empty(),
    };
    if consistent {
        Ok(())
    } else {
        Err(Error::KeyMaterialClientsMismatch { user_status }.to_string())
    }
}

impl Serialize for KeyMaterialResponse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        check_clients(self.user_status, &self.clients).map_err(tls_codec::Error::EncodingError)?;
        Ok(self.protocol.tls_serialize(writer)?
            + self.user_status.tls_serialize(writer)?
            + self.user_uri.tls_serialize(writer)?
            + self.clients.tls_serialize(writer)?)
    }
}

/// A departure from protocol-07 §5.2 that
/// [`KeyMaterialResponse::decode_for_requester`] accepts and reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyMaterialDivergence {
    /// `partialSuccess` with no `success` client: every listed client is
    /// `keyMaterialExhausted` or `nothingCompatible`. §5.2 defines
    /// `partialSuccess` as key material for at least one client and has no
    /// code for "every client exhausted" (Haven sends this, its DIV-13;
    /// mimi-protocol issue 184). Read as `noCompatibleMaterial`.
    PartialSuccessWithoutKeyMaterial,
}

impl KeyMaterialResponse {
    /// Encodes this response under `profile`, with `client_extensions`
    /// (the #190 `client_key_material_extensions`, one per client in
    /// order; an empty slice means none for every client).
    ///
    /// # Errors
    ///
    /// A tls_codec error if `clients` does not fit `user_status`, if
    /// `client_extensions` is neither empty nor one per client, if a
    /// field cannot be encoded, or if any extensions are not empty under
    /// [`WireProfile::Draft07`].
    pub fn encode(
        &self,
        profile: WireProfile,
        client_extensions: &[AppDataDictionary],
    ) -> Result<Vec<u8>, tls_codec::Error> {
        check_clients(self.user_status, &self.clients).map_err(tls_codec::Error::EncodingError)?;
        if !client_extensions.is_empty() && client_extensions.len() != self.clients.len() {
            return Err(tls_codec::Error::EncodingError(
                "client extensions must be one per client".to_owned(),
            ));
        }
        let none = AppDataDictionary::default();
        let mut clients = Vec::new();
        for (i, client) in self.clients.iter().enumerate() {
            client.write(
                &mut clients,
                profile,
                client_extensions.get(i).unwrap_or(&none),
            )?;
        }
        let mut out = Vec::new();
        self.protocol.tls_serialize(&mut out)?;
        self.user_status.tls_serialize(&mut out)?;
        self.user_uri.tls_serialize(&mut out)?;
        VLBytes::new(clients).tls_serialize(&mut out)?;
        Ok(out)
    }

    /// Decodes all of `bytes` under `profile`, strictly: the response and
    /// each client's extensions, in order (all empty under
    /// [`WireProfile::Draft07`]).
    ///
    /// # Errors
    ///
    /// A tls_codec error for anything malformed, `clients` that do not fit
    /// `userStatus`, or trailing bytes.
    pub fn decode(
        profile: WireProfile,
        bytes: &[u8],
    ) -> Result<(Self, Vec<AppDataDictionary>), tls_codec::Error> {
        let (response, extensions) = Self::read_unchecked(bytes, profile)?;
        check_clients(response.user_status, &response.clients)
            .map_err(tls_codec::Error::DecodingError)?;
        Ok((response, extensions))
    }

    /// [`KeyMaterialResponse::decode_for_requester`] under `profile`, with
    /// each client's extensions in order.
    ///
    /// # Errors
    ///
    /// As [`KeyMaterialResponse::decode_for_requester`].
    pub fn decode_for_requester_with(
        profile: WireProfile,
        bytes: &[u8],
    ) -> Result<(Self, Option<KeyMaterialDivergence>, Vec<AppDataDictionary>), tls_codec::Error>
    {
        let (response, extensions) = Self::read_unchecked(bytes, profile)?;
        let (response, divergence) = Self::lenient(response)?;
        Ok((response, divergence, extensions))
    }

    /// Reads every field and each client's extensions, without checking
    /// `clients` against `userStatus`.
    fn read_unchecked(
        bytes: &[u8],
        profile: WireProfile,
    ) -> Result<(Self, Vec<AppDataDictionary>), tls_codec::Error> {
        exact(bytes, |reader| {
            let protocol = Protocol::tls_deserialize(reader)?;
            let user_status = KeyMaterialUserCode::tls_deserialize(reader)?;
            let user_uri = IdentifierUri::tls_deserialize(reader)?;
            let list = VLBytes::tls_deserialize(reader)?;
            let mut items = list.as_slice();
            let (mut clients, mut extensions) = (Vec::new(), Vec::new());
            while !items.is_empty() {
                let (client, ext) = ClientKeyMaterial::read(&mut items, profile)?;
                clients.push(client);
                extensions.push(ext);
            }
            let response = Self {
                protocol,
                user_status,
                user_uri,
                clients,
            };
            Ok((response, extensions))
        })
    }

    /// Decodes `bytes` for the requesting side: as
    /// [`Deserialize::tls_deserialize_exact`], except that a response with
    /// a known [`KeyMaterialDivergence`] is accepted, rewritten to the §5.2
    /// code with the same meaning to a requester, and the divergence is
    /// returned beside it. The clients are kept as sent.
    ///
    /// The strict decoder stays the one for anything that checks a peer
    /// for conformance; this is for code that needs the answer (decision
    /// in bead mimid-1wgh.46.1.7.1).
    ///
    /// # Errors
    ///
    /// Returns the strict decoder's error for anything else it refuses,
    /// including trailing bytes.
    pub fn decode_for_requester(
        bytes: &[u8],
    ) -> Result<(Self, Option<KeyMaterialDivergence>), tls_codec::Error> {
        let (response, _) = Self::read_unchecked(bytes, WireProfile::Draft07)?;
        Self::lenient(response)
    }

    /// Checks `clients` against `userStatus`, accepting and rewriting a
    /// known [`KeyMaterialDivergence`].
    fn lenient(
        mut response: Self,
    ) -> Result<(Self, Option<KeyMaterialDivergence>), tls_codec::Error> {
        let nothing_usable = !response.clients.is_empty()
            && response.clients.iter().all(|c| {
                matches!(
                    c.client_status(),
                    KeyMaterialClientCode::KeyMaterialExhausted
                        | KeyMaterialClientCode::NothingCompatible
                )
            });
        match check_clients(response.user_status, &response.clients) {
            Ok(()) => Ok((response, None)),
            Err(_)
                if response.user_status == KeyMaterialUserCode::PartialSuccess
                    && nothing_usable =>
            {
                response.user_status = KeyMaterialUserCode::NoCompatibleMaterial;
                Ok((
                    response,
                    Some(KeyMaterialDivergence::PartialSuccessWithoutKeyMaterial),
                ))
            }
            Err(reason) => Err(tls_codec::Error::DecodingError(reason)),
        }
    }
}

impl Deserialize for KeyMaterialResponse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let response = Self {
            protocol: Protocol::tls_deserialize(bytes)?,
            user_status: KeyMaterialUserCode::tls_deserialize(bytes)?,
            user_uri: IdentifierUri::tls_deserialize(bytes)?,
            clients: Vec::<ClientKeyMaterial>::tls_deserialize(bytes)?,
        };
        check_clients(response.user_status, &response.clients)
            .map_err(tls_codec::Error::DecodingError)?;
        Ok(response)
    }
}
