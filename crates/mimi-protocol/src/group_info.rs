//! The groupInfo endpoint (protocol-06 §5.6): `POST /groupInfo/{roomId}`.
//!
//! The requester signs a [`GroupInfoRequestTbs`] with
//! [`GroupInfoRequestTbs::sign`]; the hub checks it with
//! [`GroupInfoRequest::verify`]. On success the hub encrypts a
//! [`GroupInfoRatchetTreeTbe`] with [`encrypt_group_info`], signs a
//! [`GroupInfoResponseTbs`] with [`GroupInfoResponseTbs::sign`], and the
//! requester checks it with [`GroupInfoSuccess::verify`] and decrypts with
//! [`decrypt_group_info`].
//!
//! Signatures are verified over the TBS bytes exactly as received: a
//! decoded [`GroupInfoRequest`] or [`GroupInfoSuccess`] keeps them, and
//! encoding writes them back unchanged.

use std::io::{self, Read, Write};

use mimi_mls::label;
use mimi_mls::wire::{
    CipherSuite, Credential, ExternalSender, GroupInfo, HPKECiphertext, HPKEPublicKey, MLSMessage,
    RatchetTreeOption, SignaturePublicKey,
};
use tls_codec::{
    Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize, VLByteSlice, VLBytes,
};

use crate::update::check_proposals;
use crate::{Error, Protocol};

/// SignWithLabel label for [`GroupInfoRequestTbs`] (protocol-06 §5.6).
const REQUEST_TBS_LABEL: &str = "GroupInfoRequestTBS";
/// SignWithLabel label for [`GroupInfoResponseTbs`] (protocol-06 §5.6).
const RESPONSE_TBS_LABEL: &str = "GroupInfoResponseTBS";
/// EncryptWithLabel label for [`GroupInfoRatchetTreeTbe`] (protocol-06
/// §5.6).
const ENCRYPTION_LABEL: &str = "GroupInfo and ratchet_tree encryption";

/// RFC 9420 suite 1, the only suite [`mimi_mls::label`] implements
/// (decision mimid-1wgh.23).
const SUPPORTED_CIPHER_SUITE: u16 = 0x0001;

/// A reader that keeps a copy of every byte read through it, so a TBS can
/// be verified over the bytes as received.
struct Recorder<'a, R> {
    inner: &'a mut R,
    consumed: Vec<u8>,
}

impl<'a, R: Read> Recorder<'a, R> {
    fn new(inner: &'a mut R) -> Self {
        Self {
            inner,
            consumed: Vec::new(),
        }
    }
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

fn check_cipher_suite(cipher_suite: CipherSuite) -> Result<(), Error> {
    match u16::from(cipher_suite) {
        SUPPORTED_CIPHER_SUITE => Ok(()),
        other => Err(Error::UnsupportedCipherSuite {
            cipher_suite: other,
        }),
    }
}

/// Returns the raw key bytes of an `opaque key<V>` encoding.
fn key_bytes(encoded: &[u8]) -> Result<VLBytes, Error> {
    VLBytes::tls_deserialize_exact(encoded).map_err(Error::Decoding)
}

/// `HPKECiphertext` (RFC 9420 §7.6) split into its fields.
#[derive(TlsSerialize, TlsDeserialize, TlsSize)]
struct HpkeCiphertextFields {
    kem_output: VLBytes,
    ciphertext: VLBytes,
}

/// `GroupInfoRequestTBS` (protocol-06 §5.6), the part of a
/// [`GroupInfoRequest`] the requester signs.
///
/// `joiningCode` is optional here and in the request (decision
/// mimid-1wgh.5.22), so the TBS is exactly the request without its
/// signature. `protocol` is the only `Protocol` value, `mls10`, so its
/// `select` is always the `mls10` arm.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct GroupInfoRequestTbs {
    /// `Protocol protocol`.
    pub protocol: Protocol,
    /// `CipherSuite cipher_suite`: a suite in common with the hub, used
    /// only to sign the request and the response.
    pub cipher_suite: CipherSuite,
    /// `SignaturePublicKey requestingSignatureKey`.
    pub requesting_signature_key: SignaturePublicKey,
    /// `Credential requestingCredential`.
    pub requesting_credential: Credential,
    /// `HPKEPublicKey groupInfoPublicKey`: the key the response is
    /// encrypted to.
    pub group_info_public_key: HPKEPublicKey,
    /// `optional opaque joiningCode<V>`.
    pub joining_code: Option<Vec<u8>>,
}

impl GroupInfoRequestTbs {
    /// Signs this TBS: `SignWithLabel(requestingSignatureKey,
    /// "GroupInfoRequestTBS", GroupInfoRequestTBS)`.
    ///
    /// `signature_private_key` is the raw private key matching
    /// `requesting_signature_key` (a 32-byte Ed25519 seed for suite 1).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] unless `cipher_suite` is 1,
    /// [`Error::Encoding`] if the TBS cannot be encoded, and
    /// [`Error::Label`] if signing fails.
    pub fn sign(self, signature_private_key: &[u8]) -> Result<GroupInfoRequest, Error> {
        check_cipher_suite(self.cipher_suite)?;
        let tbs_bytes = self.tls_serialize_detached().map_err(Error::Encoding)?;
        let signature =
            label::sign_with_label(signature_private_key, REQUEST_TBS_LABEL, &tbs_bytes)
                .map_err(Error::Label)?;
        Ok(GroupInfoRequest {
            tbs: self,
            tbs_bytes,
            signature,
        })
    }
}

/// `GroupInfoRequest` (protocol-06 §5.6), the body of
/// `POST /groupInfo/{roomId}`.
///
/// Built only by decoding or by [`GroupInfoRequestTbs::sign`], so the kept
/// TBS bytes always match [`GroupInfoRequest::tbs`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupInfoRequest {
    tbs: GroupInfoRequestTbs,
    tbs_bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl GroupInfoRequest {
    /// The signed fields.
    pub fn tbs(&self) -> &GroupInfoRequestTbs {
        &self.tbs
    }

    /// `opaque signature<V>`.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Checks the signature with `requestingSignatureKey`, over the TBS
    /// bytes as received.
    ///
    /// This proves only that the requester holds the private key for the
    /// key it sent. Binding that key to the credential and authorizing the
    /// request are the caller's job.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] unless `cipher_suite` is 1,
    /// [`Error::Decoding`] if the key encoding is malformed, and
    /// [`Error::Label`] if the signature does not verify.
    pub fn verify(&self) -> Result<(), Error> {
        check_cipher_suite(self.tbs.cipher_suite)?;
        let key = key_bytes(self.tbs.requesting_signature_key.as_bytes())?;
        label::verify_with_label(
            key.as_slice(),
            REQUEST_TBS_LABEL,
            &self.tbs_bytes,
            &self.signature,
        )
        .map_err(Error::Label)
    }
}

impl Size for GroupInfoRequest {
    fn tls_serialized_len(&self) -> usize {
        self.tbs_bytes.len() + VLByteSlice(&self.signature).tls_serialized_len()
    }
}

impl Serialize for GroupInfoRequest {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        writer.write_all(&self.tbs_bytes)?;
        Ok(self.tbs_bytes.len() + VLByteSlice(&self.signature).tls_serialize(writer)?)
    }
}

impl Deserialize for GroupInfoRequest {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let mut recorder = Recorder::new(bytes);
        let tbs = GroupInfoRequestTbs::tls_deserialize(&mut recorder)?;
        let tbs_bytes = recorder.consumed;
        let signature = Vec::<u8>::tls_deserialize(bytes)?;
        Ok(Self {
            tbs,
            tbs_bytes,
            signature,
        })
    }
}

/// `GroupInfoCode` (protocol-06 §5.6).
///
/// Decoding rejects `reserved(0)` and the undefined values 4 to 255 with
/// [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum GroupInfoCode {
    /// `success(1)`: the GroupInfo and ratchet tree are provided.
    Success = 1,
    /// `notAuthorized(2)`: the requester may not access the GroupInfo, or
    /// the hub hides whether the room exists.
    NotAuthorized = 2,
    /// `noSuchRoom(3)`: the room does not exist.
    NoSuchRoom = 3,
}

/// `PendingProposal` (protocol-06 §5.6): a proposal the hub accepted
/// during the current epoch.
///
/// `proposal` must be a PublicMessage carrying a proposal, as for
/// `moreProposals` (decision mimid-1wgh.5.54). Decoding
/// rejects anything else, and so does encoding.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize)]
pub struct PendingProposal {
    /// `MLSMessage proposal`.
    pub proposal: MLSMessage,
    /// `uint64 hub_accepted_time`.
    pub hub_accepted_time: u64,
}

impl Serialize for PendingProposal {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        // protocol-06 §5.6; decision mimid-1wgh.5.54
        check_proposals(std::slice::from_ref(&self.proposal))
            .map_err(|e| tls_codec::Error::EncodingError(e.to_string()))?;
        Ok(self.proposal.tls_serialize(writer)? + self.hub_accepted_time.tls_serialize(writer)?)
    }
}

impl Deserialize for PendingProposal {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let proposal = MLSMessage::tls_deserialize(bytes)?;
        // protocol-06 §5.6; decision mimid-1wgh.5.54
        check_proposals(std::slice::from_ref(&proposal))?;
        Ok(Self {
            proposal,
            hub_accepted_time: u64::tls_deserialize(bytes)?,
        })
    }
}

/// `GroupInfoRatchetTreeTBE` (protocol-06 §5.6), the plaintext of
/// `encrypted_groupinfo_and_tree`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct GroupInfoRatchetTreeTbe {
    /// `GroupInfo groupInfo`, without the ratchet_tree extension.
    pub group_info: GroupInfo,
    /// `RatchetTreeOption ratchetTreeOption`.
    pub ratchet_tree_option: RatchetTreeOption,
    /// `PendingProposal pending_proposals<V>`. May be empty.
    pub pending_proposals: Vec<PendingProposal>,
}

/// Encrypts the hub's answer to the requester:
/// `EncryptWithLabel(groupInfoPublicKey, "GroupInfo and ratchet_tree
/// encryption", room_id, group_info_ratchet_tree_tbe)` (protocol-06 §5.6).
///
/// `room_id` is the raw bytes of the room URI, with no length prefix
/// (decision mimid-1wgh.5.30). HPKE uses suite 1's algorithms (decision
/// mimid-1wgh.5.55).
///
/// # Errors
///
/// [`Error::Decoding`] if `group_info_public_key` is malformed,
/// [`Error::Encoding`] if `tbe` cannot be encoded, and [`Error::Label`] if
/// encryption fails.
pub fn encrypt_group_info(
    group_info_public_key: &HPKEPublicKey,
    room_id: &[u8],
    tbe: &GroupInfoRatchetTreeTbe,
) -> Result<HPKECiphertext, Error> {
    let public_key = key_bytes(group_info_public_key.as_bytes())?;
    let plaintext = tbe.tls_serialize_detached().map_err(Error::Encoding)?;
    // protocol-06 §5.6; decision mimid-1wgh.5.55 (suite-1 HPKE)
    let sealed =
        label::encrypt_with_label(public_key.as_slice(), ENCRYPTION_LABEL, room_id, &plaintext)
            .map_err(Error::Label)?;
    let encoded = HpkeCiphertextFields {
        kem_output: sealed.kem_output.into(),
        ciphertext: sealed.ciphertext.into(),
    }
    .tls_serialize_detached()
    .map_err(Error::Encoding)?;
    HPKECiphertext::tls_deserialize_exact(encoded).map_err(Error::Decoding)
}

/// Decrypts and decodes `encrypted_groupinfo_and_tree` (protocol-06 §5.6).
///
/// `group_info_private_key` is the raw private key for the request's
/// `groupInfoPublicKey` (32-byte X25519: suite-1 HPKE, decision
/// mimid-1wgh.5.55). `room_id` is the raw
/// bytes of the room URI the requester asked for (decision
/// mimid-1wgh.5.30). The plaintext is decoded strictly, with no trailing
/// bytes.
///
/// # Errors
///
/// [`Error::Label`] if decryption fails (wrong key or room ID, or
/// tampered ciphertext), and [`Error::Decoding`] if the ciphertext
/// encoding or the decrypted plaintext is malformed.
pub fn decrypt_group_info(
    group_info_private_key: &[u8],
    room_id: &[u8],
    encrypted_groupinfo_and_tree: &HPKECiphertext,
) -> Result<GroupInfoRatchetTreeTbe, Error> {
    let fields = HpkeCiphertextFields::tls_deserialize_exact(encrypted_groupinfo_and_tree)
        .map_err(Error::Decoding)?;
    // protocol-06 §5.6; decision mimid-1wgh.5.55 (suite-1 HPKE)
    let plaintext = label::decrypt_with_label(
        group_info_private_key,
        ENCRYPTION_LABEL,
        room_id,
        fields.kem_output.as_slice(),
        fields.ciphertext.as_slice(),
    )
    .map_err(Error::Label)?;
    GroupInfoRatchetTreeTbe::tls_deserialize_exact(plaintext).map_err(Error::Decoding)
}

/// `GroupInfoResponseTBS` (protocol-06 §5.6), the part of a successful
/// [`GroupInfoResponse`] the hub signs.
///
/// A TBS exists only on success (decision mimid-1wgh.5.26), so `status`
/// is not a field: it is always encoded as `success(1)`. `version` is the
/// `Protocol` the `select (protocol)` refers to (decision
/// mimid-1wgh.5.23).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupInfoResponseTbs {
    /// `Protocol version`.
    pub version: Protocol,
    /// `opaque room_id<V>`.
    pub room_id: Vec<u8>,
    /// `CipherSuite cipher_suite`: the suite the response is signed with.
    pub cipher_suite: CipherSuite,
    /// `ExternalSender hub_sender`: holds the key that signs the response.
    pub hub_sender: ExternalSender,
    /// `HPKECiphertext encrypted_groupinfo_and_tree`, from
    /// [`encrypt_group_info`].
    pub encrypted_groupinfo_and_tree: HPKECiphertext,
}

impl Size for GroupInfoResponseTbs {
    fn tls_serialized_len(&self) -> usize {
        self.version.tls_serialized_len()
            + self.room_id.tls_serialized_len()
            + GroupInfoCode::Success.tls_serialized_len()
            + self.cipher_suite.tls_serialized_len()
            + self.hub_sender.tls_serialized_len()
            + self.encrypted_groupinfo_and_tree.tls_serialized_len()
    }
}

impl Serialize for GroupInfoResponseTbs {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.version.tls_serialize(writer)?
            + self.room_id.tls_serialize(writer)?
            + GroupInfoCode::Success.tls_serialize(writer)?
            + self.cipher_suite.tls_serialize(writer)?
            + self.hub_sender.tls_serialize(writer)?
            + self.encrypted_groupinfo_and_tree.tls_serialize(writer)?)
    }
}

impl GroupInfoResponseTbs {
    /// Signs this TBS: `SignWithLabel(hub_sender.signature_key,
    /// "GroupInfoResponseTBS", GroupInfoResponseTBS)`.
    ///
    /// `signature_private_key` is the raw private key matching
    /// `hub_sender`'s signature key (a 32-byte Ed25519 seed for suite 1).
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] unless `cipher_suite` is 1,
    /// [`Error::Encoding`] if the TBS cannot be encoded, and
    /// [`Error::Label`] if signing fails.
    pub fn sign(self, signature_private_key: &[u8]) -> Result<GroupInfoSuccess, Error> {
        check_cipher_suite(self.cipher_suite)?;
        let tbs_bytes = self.tls_serialize_detached().map_err(Error::Encoding)?;
        let signature =
            label::sign_with_label(signature_private_key, RESPONSE_TBS_LABEL, &tbs_bytes)
                .map_err(Error::Label)?;
        Ok(GroupInfoSuccess {
            tbs: self,
            tbs_bytes,
            signature,
        })
    }
}

/// The `case success` arm of a [`GroupInfoResponse`]: the signed fields
/// and `opaque signature<V>`.
///
/// Built only by decoding or by [`GroupInfoResponseTbs::sign`], so the kept
/// TBS bytes always match [`GroupInfoSuccess::tbs`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct GroupInfoSuccess {
    tbs: GroupInfoResponseTbs,
    tbs_bytes: Vec<u8>,
    signature: Vec<u8>,
}

impl GroupInfoSuccess {
    /// The signed fields.
    pub fn tbs(&self) -> &GroupInfoResponseTbs {
        &self.tbs
    }

    /// `opaque signature<V>`.
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    /// Checks the signature with `hub_sender.signature_key`, over the TBS
    /// bytes as received.
    ///
    /// The key comes from the response itself, so this proves only that
    /// the response is consistent. The caller must check that
    /// `hub_sender` is the room's hub and that `room_id` is the room it
    /// asked for.
    ///
    /// # Errors
    ///
    /// [`Error::UnsupportedCipherSuite`] unless `cipher_suite` is 1,
    /// [`Error::Decoding`] if the key encoding is malformed, and
    /// [`Error::Label`] if the signature does not verify.
    pub fn verify(&self) -> Result<(), Error> {
        check_cipher_suite(self.tbs.cipher_suite)?;
        // RFC 9420 §12.1.8.1: ExternalSender starts with
        // `SignaturePublicKey signature_key`.
        let mut sender = self.tbs.hub_sender.as_bytes();
        let key = VLBytes::tls_deserialize(&mut sender).map_err(Error::Decoding)?;
        label::verify_with_label(
            key.as_slice(),
            RESPONSE_TBS_LABEL,
            &self.tbs_bytes,
            &self.signature,
        )
        .map_err(Error::Label)
    }
}

/// `GroupInfoResponse` (protocol-06 §5.6), the response body of
/// `POST /groupInfo/{roomId}`, one arm per [`GroupInfoCode`].
///
/// On the wire `version`, `room_id` and `status` come first; only
/// `success` has further fields.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum GroupInfoResponse {
    /// `success(1)`.
    Success(GroupInfoSuccess),
    /// `notAuthorized(2)`: the `default: struct{}` arm.
    NotAuthorized {
        /// `Protocol version`.
        version: Protocol,
        /// `opaque room_id<V>`.
        room_id: Vec<u8>,
    },
    /// `noSuchRoom(3)`: the `default: struct{}` arm.
    NoSuchRoom {
        /// `Protocol version`.
        version: Protocol,
        /// `opaque room_id<V>`.
        room_id: Vec<u8>,
    },
}

impl GroupInfoResponse {
    /// The `status` this arm belongs to.
    pub fn status(&self) -> GroupInfoCode {
        match self {
            Self::Success(_) => GroupInfoCode::Success,
            Self::NotAuthorized { .. } => GroupInfoCode::NotAuthorized,
            Self::NoSuchRoom { .. } => GroupInfoCode::NoSuchRoom,
        }
    }
}

impl Size for GroupInfoResponse {
    fn tls_serialized_len(&self) -> usize {
        match self {
            Self::Success(success) => {
                success.tbs_bytes.len() + VLByteSlice(&success.signature).tls_serialized_len()
            }
            Self::NotAuthorized { version, room_id } | Self::NoSuchRoom { version, room_id } => {
                version.tls_serialized_len() + room_id.tls_serialized_len() + 1
            }
        }
    }
}

impl Serialize for GroupInfoResponse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        match self {
            Self::Success(success) => {
                writer.write_all(&success.tbs_bytes)?;
                Ok(success.tbs_bytes.len()
                    + VLByteSlice(&success.signature).tls_serialize(writer)?)
            }
            Self::NotAuthorized { version, room_id } | Self::NoSuchRoom { version, room_id } => {
                Ok(version.tls_serialize(writer)?
                    + room_id.tls_serialize(writer)?
                    + self.status().tls_serialize(writer)?)
            }
        }
    }
}

impl Deserialize for GroupInfoResponse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let mut recorder = Recorder::new(bytes);
        let version = Protocol::tls_deserialize(&mut recorder)?;
        let room_id = Vec::<u8>::tls_deserialize(&mut recorder)?;
        match GroupInfoCode::tls_deserialize(&mut recorder)? {
            GroupInfoCode::NotAuthorized => Ok(Self::NotAuthorized { version, room_id }),
            GroupInfoCode::NoSuchRoom => Ok(Self::NoSuchRoom { version, room_id }),
            GroupInfoCode::Success => {
                let tbs = GroupInfoResponseTbs {
                    version,
                    room_id,
                    cipher_suite: CipherSuite::tls_deserialize(&mut recorder)?,
                    hub_sender: ExternalSender::tls_deserialize(&mut recorder)?,
                    encrypted_groupinfo_and_tree: HPKECiphertext::tls_deserialize(&mut recorder)?,
                };
                let tbs_bytes = recorder.consumed;
                let signature = Vec::<u8>::tls_deserialize(bytes)?;
                Ok(Self::Success(GroupInfoSuccess {
                    tbs,
                    tbs_bytes,
                    signature,
                }))
            }
        }
    }
}
