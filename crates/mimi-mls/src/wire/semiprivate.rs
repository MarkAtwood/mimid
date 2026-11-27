//! draft-mahy-mls-semiprivatemessage-08 §3.1 structures.
//!
//! A SemiPrivateMessage is a handshake message encrypted to the group as
//! a PrivateMessage is, plus a copy of the per-message key and nonces
//! encrypted to each *external receiver*, so a party outside the group --
//! a MIMI hub -- can read handshakes without being a member.
//!
//! What is here is the frame: what a party can decode from the wire
//! without holding any key. [`SemiPrivateMessage`] is the message as
//! received, [`SemiPrivateContentAAD`] is the additional authenticated
//! data its decryption needs, and [`KeyForExternalReceiver`] is one
//! external receiver's copy of the keys.
//!
//! [`SemiPrivateMessageContent`] is the decrypted plaintext, which a
//! party holding the keys decodes with the content type the frame
//! carried.
//!
//! # Limitations
//!
//! Nothing here decrypts or authenticates. A decoded value says what the
//! sender claims, not that any of it is valid: the hash in
//! `framed_content_tbs_hash` is unchecked, and §3.3's check that it
//! matches the members' own FramedContentTBS needs the GroupContext.

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, TlsSize, VLBytes};

use openmls::framing::FramedContentAuthData;
use openmls::messages::CommitIn;
use openmls::messages::proposals_in::ProposalIn;

use super::rfc9420::{ContentType, Credential, HPKECiphertext, HPKEPublicKey};

/// The most external receivers one message may carry.
///
/// INVENTED, NOT FROM SPEC: semiprivatemessage-08 gives
/// `keys_for_external_receivers` no bound, and a `<V>` vector's own limit
/// is 2^30 octets, so a decoder with no cap would allocate from one
/// message whatever a sender asked for. A room has one hub and
/// mls-extensions-11 §4.6's `external_receivers` is small by nature, so
/// the cap is generous and still refuses an obvious attack.
pub const MAX_EXTERNAL_RECEIVERS: usize = 64;

/// semiprivatemessage-08 §3.1: `ExternalReceiverRef`, a hash of the
/// `ExternalReceiver` it names.
///
/// Carried as `opaque<V>`. Any length decodes, including an empty one:
/// the hash is a reference whose algorithm comes from the group's
/// ciphersuite, which the frame does not carry, so a decoder cannot know
/// the right length.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalReceiverRef(VLBytes);

impl ExternalReceiverRef {
    /// The hash itself.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl Size for ExternalReceiverRef {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl Serialize for ExternalReceiverRef {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.0.tls_serialize(writer)
    }
}

impl Deserialize for ExternalReceiverRef {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self(VLBytes::tls_deserialize(bytes)?))
    }
}

/// semiprivatemessage-08 §3.1: `KeyForExternalReceiver`.
///
/// ~~~text
/// struct {
///   ExternalReceiverRef external_receiver_ref;
///   HPKECiphertext encrypted_keys_and_nonces;
/// } KeyForExternalReceiver;
/// ~~~
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct KeyForExternalReceiver {
    /// Which external receiver this copy is for.
    pub external_receiver_ref: ExternalReceiverRef,
    /// The `PerMessageKeyAndNonces` sealed to that receiver's public key
    /// under the `SemiPrivateMessageReceiver` label.
    pub encrypted_keys_and_nonces: HPKECiphertext,
}

impl Size for KeyForExternalReceiver {
    fn tls_serialized_len(&self) -> usize {
        self.external_receiver_ref.tls_serialized_len()
            + self.encrypted_keys_and_nonces.tls_serialized_len()
    }
}

impl Serialize for KeyForExternalReceiver {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.external_receiver_ref.tls_serialize(writer)?
            + self.encrypted_keys_and_nonces.tls_serialize(writer)?)
    }
}

impl Deserialize for KeyForExternalReceiver {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self {
            external_receiver_ref: ExternalReceiverRef::tls_deserialize(bytes)?,
            encrypted_keys_and_nonces: HPKECiphertext::tls_deserialize(bytes)?,
        })
    }
}

/// Decodes `keys_for_external_receivers<V>`, refusing more than
/// [`MAX_EXTERNAL_RECEIVERS`] entries.
fn read_receivers<R: Read>(bytes: &mut R) -> Result<Vec<KeyForExternalReceiver>, tls_codec::Error> {
    let keys = Vec::<KeyForExternalReceiver>::tls_deserialize(bytes)?;
    if keys.len() > MAX_EXTERNAL_RECEIVERS {
        return Err(tls_codec::Error::DecodingError(format!(
            "{} external receivers, more than {MAX_EXTERNAL_RECEIVERS}",
            keys.len()
        )));
    }
    Ok(keys)
}

/// semiprivatemessage-08 §3.1: `SemiPrivateMessage`.
///
/// ~~~text
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     opaque partial_context_hash<V>;
///     KeyForExternalReceiver keys_for_external_receivers<V>;
///     opaque framed_content_tbs_hash<V>;
///     opaque encrypted_sender_data<V>;
///     opaque ciphertext<V>;
/// } SemiPrivateMessage;
/// ~~~
///
/// `content_type` is never `application`: §3.1 says the content is a
/// Proposal or a Commit, and an application message has no reason to be
/// readable by a non-member. Decoding refuses `application` for that
/// reason, which is stricter than the presentation language alone.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SemiPrivateMessage {
    /// The group this message belongs to.
    pub group_id: VLBytes,
    /// The epoch it was sent in.
    pub epoch: u64,
    /// `proposal` or `commit`; never `application`.
    pub content_type: ContentType,
    /// Data authenticated but not encrypted.
    pub authenticated_data: VLBytes,
    /// `hash(sender_leaf_index || nonce)`, the part of the decryption
    /// context an external receiver cannot derive for itself.
    pub partial_context_hash: VLBytes,
    /// One entry per external receiver.
    pub keys_for_external_receivers: Vec<KeyForExternalReceiver>,
    /// `hash(FramedContentTBS)`, which §3.3 has a receiver check against
    /// the content the members see, so a sender cannot send one thing to
    /// the group and another to the hub.
    pub framed_content_tbs_hash: VLBytes,
    /// The sender data, encrypted as in RFC 9420 §6.3.2.
    pub encrypted_sender_data: VLBytes,
    /// The `SemiPrivateMessageContent`, encrypted to the group.
    pub ciphertext: VLBytes,
}

impl SemiPrivateMessage {
    /// Decodes one `SemiPrivateMessage`, which must be the whole of
    /// `bytes`.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if `bytes` is short, has trailing bytes,
    /// carries a `content_type` of `application` or an unknown value, or
    /// names more than [`MAX_EXTERNAL_RECEIVERS`] external receivers.
    pub fn decode(bytes: &[u8]) -> Result<Self, tls_codec::Error> {
        Self::tls_deserialize_exact(bytes)
    }
}

impl Size for SemiPrivateMessage {
    fn tls_serialized_len(&self) -> usize {
        self.group_id.tls_serialized_len()
            + self.epoch.tls_serialized_len()
            + self.content_type.tls_serialized_len()
            + self.authenticated_data.tls_serialized_len()
            + self.partial_context_hash.tls_serialized_len()
            + self.keys_for_external_receivers.tls_serialized_len()
            + self.framed_content_tbs_hash.tls_serialized_len()
            + self.encrypted_sender_data.tls_serialized_len()
            + self.ciphertext.tls_serialized_len()
    }
}

impl Serialize for SemiPrivateMessage {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.group_id.tls_serialize(writer)?
            + self.epoch.tls_serialize(writer)?
            + self.content_type.tls_serialize(writer)?
            + self.authenticated_data.tls_serialize(writer)?
            + self.partial_context_hash.tls_serialize(writer)?
            + self.keys_for_external_receivers.tls_serialize(writer)?
            + self.framed_content_tbs_hash.tls_serialize(writer)?
            + self.encrypted_sender_data.tls_serialize(writer)?
            + self.ciphertext.tls_serialize(writer)?)
    }
}

impl Deserialize for SemiPrivateMessage {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let group_id = VLBytes::tls_deserialize(bytes)?;
        let epoch = u64::tls_deserialize(bytes)?;
        let content_type = ContentType::tls_deserialize(bytes)?;
        if content_type == ContentType::Application {
            return Err(tls_codec::Error::DecodingError(
                "a SemiPrivateMessage carries a proposal or a commit, not an application message"
                    .to_owned(),
            ));
        }
        Ok(Self {
            group_id,
            epoch,
            content_type,
            authenticated_data: VLBytes::tls_deserialize(bytes)?,
            partial_context_hash: VLBytes::tls_deserialize(bytes)?,
            keys_for_external_receivers: read_receivers(bytes)?,
            framed_content_tbs_hash: VLBytes::tls_deserialize(bytes)?,
            encrypted_sender_data: VLBytes::tls_deserialize(bytes)?,
            ciphertext: VLBytes::tls_deserialize(bytes)?,
        })
    }
}

/// semiprivatemessage-08 §3.1: `SemiPrivateContentAAD`.
///
/// ~~~text
/// struct {
///     opaque group_id<V>;
///     uint64 epoch;
///     ContentType content_type;
///     opaque authenticated_data<V>;
///     opaque partial_context_hash<V>;
///     KeyForExternalReceiver keys_for_external_receivers<V>;
///     opaque framed_content_tbs_hash<V>;
/// } SemiPrivateContentAAD;
///
/// ~~~
///
/// The same fields as [`SemiPrivateMessage`] without the two ciphertexts,
/// so it is built from a received message rather than decoded on its own
/// ([`SemiPrivateMessage::content_aad`]). It is still [`Deserialize`], so
/// a fixture can hold one.
#[derive(Clone, Debug, PartialEq, Eq, Hash, TlsSize)]
pub struct SemiPrivateContentAAD {
    /// As [`SemiPrivateMessage::group_id`].
    pub group_id: VLBytes,
    /// As [`SemiPrivateMessage::epoch`].
    pub epoch: u64,
    /// As [`SemiPrivateMessage::content_type`].
    pub content_type: ContentType,
    /// As [`SemiPrivateMessage::authenticated_data`].
    pub authenticated_data: VLBytes,
    /// As [`SemiPrivateMessage::partial_context_hash`].
    pub partial_context_hash: VLBytes,
    /// As [`SemiPrivateMessage::keys_for_external_receivers`].
    pub keys_for_external_receivers: Vec<KeyForExternalReceiver>,
    /// As [`SemiPrivateMessage::framed_content_tbs_hash`].
    pub framed_content_tbs_hash: VLBytes,
}

impl SemiPrivateMessage {
    /// The additional authenticated data for this message's decryption.
    #[must_use]
    pub fn content_aad(&self) -> SemiPrivateContentAAD {
        SemiPrivateContentAAD {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            content_type: self.content_type,
            authenticated_data: self.authenticated_data.clone(),
            partial_context_hash: self.partial_context_hash.clone(),
            keys_for_external_receivers: self.keys_for_external_receivers.clone(),
            framed_content_tbs_hash: self.framed_content_tbs_hash.clone(),
        }
    }
}

impl Serialize for SemiPrivateContentAAD {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.group_id.tls_serialize(writer)?
            + self.epoch.tls_serialize(writer)?
            + self.content_type.tls_serialize(writer)?
            + self.authenticated_data.tls_serialize(writer)?
            + self.partial_context_hash.tls_serialize(writer)?
            + self.keys_for_external_receivers.tls_serialize(writer)?
            + self.framed_content_tbs_hash.tls_serialize(writer)?)
    }
}

impl Deserialize for SemiPrivateContentAAD {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self {
            group_id: VLBytes::tls_deserialize(bytes)?,
            epoch: u64::tls_deserialize(bytes)?,
            content_type: ContentType::tls_deserialize(bytes)?,
            authenticated_data: VLBytes::tls_deserialize(bytes)?,
            partial_context_hash: VLBytes::tls_deserialize(bytes)?,
            keys_for_external_receivers: read_receivers(bytes)?,
            framed_content_tbs_hash: VLBytes::tls_deserialize(bytes)?,
        })
    }
}

/// semiprivatemessage-08 §3.1: `SemiPrivateMessageContent`, the
/// decrypted plaintext of a [`SemiPrivateMessage`].
///
/// ~~~text
/// struct {
///     select (SemiPrivateMessage.content_type) {
///         case proposal:
///           Proposal proposal;
///         case commit:
///           Commit commit;
///     };
///     FramedContentAuthData auth;
///     opaque padding[length_of_padding];
/// } SemiPrivateMessageContent;
/// ~~~
///
/// The discriminant is not in these bytes: it is the `content_type` of
/// the frame that carried them, so this is decoded with
/// [`SemiPrivateMessageContent::decode`] rather than through
/// [`Deserialize`]. §3.1 says the content is never an application
/// message, which [`SemiPrivateMessage`] enforces at the frame.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum SemiPrivateMessageContent {
    /// `case proposal`.
    Proposal {
        /// The proposal, as received and unvalidated.
        proposal: Box<ProposalIn>,
        /// `FramedContentAuthData` for a proposal: a signature, no
        /// confirmation tag.
        auth: FramedContentAuthData,
    },
    /// `case commit`.
    Commit {
        /// The commit, unvalidated. OpenMLS keeps its fields private
        /// until `CommitIn::validate` has run against a group.
        commit: Box<CommitIn>,
        /// `FramedContentAuthData` for a commit: a signature and a
        /// confirmation tag.
        auth: FramedContentAuthData,
    },
}

impl SemiPrivateMessageContent {
    /// Decodes the plaintext of a message whose frame said
    /// `content_type`.
    ///
    /// The padding that follows is required to be all zero, as RFC 9420
    /// §6.3.2 requires of a PrivateMessageContent's: a receiver that
    /// accepted anything there would let a sender pass bytes nobody
    /// reads.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if `bytes` is short or malformed, if
    /// `content_type` is [`ContentType::Application`], which §3.1 does
    /// not define for this structure, or if the padding is not zero.
    pub fn decode(bytes: &[u8], content_type: ContentType) -> Result<Self, tls_codec::Error> {
        Self::decode_parts(bytes, content_type).map(|(content, _)| content)
    }

    /// As [`SemiPrivateMessageContent::decode`], also returning the
    /// spans of the `content` field and of the signature, exactly as
    /// they arrived.
    ///
    /// `framed_content_tbs_hash` covers a FramedContent holding these
    /// bytes, and re-encoding a decoded Proposal or Commit is not
    /// guaranteed to reproduce them, so the hash is taken over the
    /// received span.
    ///
    /// # Errors
    ///
    /// As [`SemiPrivateMessageContent::decode`].
    pub fn decode_parts(
        bytes: &[u8],
        content_type: ContentType,
    ) -> Result<(Self, ContentSpans<'_>), tls_codec::Error> {
        let mut reader = bytes;
        let (content, content_len) = match content_type {
            ContentType::Application => {
                return Err(tls_codec::Error::DecodingError(
                    "a SemiPrivateMessageContent is a proposal or a commit".to_owned(),
                ));
            }
            ContentType::Proposal => {
                let proposal = Box::new(ProposalIn::tls_deserialize(&mut reader)?);
                // The content field ends here; the auth data follows it
                // and is not part of the FramedContent.
                let content_len = bytes.len() - reader.len();
                let auth = FramedContentAuthData::deserialize(
                    &mut reader,
                    openmls::framing::ContentType::Proposal,
                )?;
                (Self::Proposal { proposal, auth }, content_len)
            }
            ContentType::Commit => {
                let commit = Box::new(CommitIn::tls_deserialize(&mut reader)?);
                let content_len = bytes.len() - reader.len();
                let auth = FramedContentAuthData::deserialize(
                    &mut reader,
                    openmls::framing::ContentType::Commit,
                )?;
                (Self::Commit { commit, auth }, content_len)
            }
        };
        if reader.iter().any(|byte| *byte != 0) {
            return Err(tls_codec::Error::DecodingError(
                "the padding of a SemiPrivateMessageContent is not zero".to_owned(),
            ));
        }
        let spans = ContentSpans::new(bytes, content_len)?;
        Ok((content, spans))
    }
}

/// The component id `external_receivers` is carried under.
///
/// semiprivatemessage-08 §5.2 registers 0x0007 as an MLS Component Type,
/// which is what decision mimid-1wgh.4.79.4 follows. The draft's prose
/// also calls it a GroupContext extension; as an extension type 0x0007
/// collides with mls-extensions-11's `supported_wire_formats`, so only
/// the component reading leaves the author's own codepoint usable.
pub const EXTERNAL_RECEIVERS_COMPONENT: u16 = 0x0007;

/// The most external receivers a group may list.
///
/// INVENTED, NOT FROM SPEC, and the same reasoning as
/// [`MAX_EXTERNAL_RECEIVERS`]: the draft bounds the list not at all.
/// This bounds what a group may agree to; `MAX_EXTERNAL_RECEIVERS`
/// bounds what one message may carry. They are equal and separate
/// because a message naming more receivers than the group has is already
/// wrong for a different reason.
pub const MAX_LISTED_EXTERNAL_RECEIVERS: usize = MAX_EXTERNAL_RECEIVERS;

/// semiprivatemessage-08 §3: `ExternalReceiver`.
///
/// ~~~text
/// struct {
///   HPKEPublicKey external_receiver_public_key;
///   Credential credential;
/// } ExternalReceiver;
/// ~~~
///
/// The syntax mirrors RFC 9420's `external_senders`, which is the
/// comparison §3 draws.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct ExternalReceiver {
    /// The key a sender seals this receiver's copy of the per-message
    /// keys to.
    pub external_receiver_public_key: HPKEPublicKey,
    /// Who the receiver is. Nothing here checks it.
    pub credential: Credential,
}

impl Size for ExternalReceiver {
    fn tls_serialized_len(&self) -> usize {
        self.external_receiver_public_key.tls_serialized_len()
            + self.credential.tls_serialized_len()
    }
}

impl Serialize for ExternalReceiver {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.external_receiver_public_key.tls_serialize(writer)?
            + self.credential.tls_serialize(writer)?)
    }
}

impl Deserialize for ExternalReceiver {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self {
            external_receiver_public_key: HPKEPublicKey::tls_deserialize(bytes)?,
            credential: Credential::tls_deserialize(bytes)?,
        })
    }
}

/// The `external_receivers` component's data: the list every member of
/// the epoch agrees on (§3).
///
/// Carried as an `app_data_dictionary` entry under
/// [`EXTERNAL_RECEIVERS_COMPONENT`], a component rather than a
/// GroupContext extension (decision mimid-1wgh.4.79.4).
///
/// In mimid the list is set when a room is created and cannot be
/// changed afterwards: `mimi_protocol`'s `is_known_component` does not
/// cover this id, so an AppDataUpdate naming it is refused, and
/// GroupContextExtensions proposals are refused outright. Changing it
/// would need the §4.7 application logic for this component and a
/// policy rule for who may propose it, since a list a member can
/// rewrite is a list a member can point at itself. Bead
/// mimid-1wgh.4.79.12.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct ExternalReceivers(Vec<ExternalReceiver>);

impl ExternalReceivers {
    /// The receivers, in the order the group agreed them.
    #[must_use]
    pub fn as_slice(&self) -> &[ExternalReceiver] {
        &self.0
    }

    /// Decodes the component's data, which must be exactly `bytes`.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if `bytes` is short, has trailing bytes, or
    /// lists more than [`MAX_LISTED_EXTERNAL_RECEIVERS`] receivers.
    pub fn decode(bytes: &[u8]) -> Result<Self, tls_codec::Error> {
        Self::tls_deserialize_exact(bytes)
    }
}

impl Size for ExternalReceivers {
    fn tls_serialized_len(&self) -> usize {
        self.0.tls_serialized_len()
    }
}

impl Serialize for ExternalReceivers {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        self.0.tls_serialize(writer)
    }
}

impl Deserialize for ExternalReceivers {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let list = Vec::<ExternalReceiver>::tls_deserialize(bytes)?;
        if list.len() > MAX_LISTED_EXTERNAL_RECEIVERS {
            return Err(tls_codec::Error::DecodingError(format!(
                "{} external receivers listed, more than {MAX_LISTED_EXTERNAL_RECEIVERS}",
                list.len()
            )));
        }
        Ok(Self(list))
    }
}

/// semiprivatemessage-08 §3.1: `PerMessageKeyAndNonces`, the payload a
/// sender seals to each external receiver.
///
/// ~~~text
/// struct {
///   opaque key<V>;
///   opaque nonce<V>;
///   opaque reuse_guard[4];
///   uint32 sender_leaf_index;
/// } PerMessageKeyAndNonces;
/// ~~~
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PerMessageKeyAndNonces {
    /// The AEAD key for this message's ciphertext.
    pub key: VLBytes,
    /// The AEAD nonce, before the `reuse_guard` is applied.
    pub nonce: VLBytes,
    /// Four octets XORed into the nonce's first four, as RFC 9420
    /// §6.3.2 does for a PrivateMessage.
    pub reuse_guard: [u8; 4],
    /// Which leaf sent the message.
    pub sender_leaf_index: u32,
}

impl PerMessageKeyAndNonces {
    /// `hash(sender_leaf_index || nonce)` of §3.1, over the TLS
    /// encodings of both fields.
    ///
    /// The draft does not say how the concatenation is encoded; decision
    /// mimid-1wgh.4.79.6 takes the encoded form, length prefix included,
    /// because a context hash has to be injective over (index, nonce)
    /// pairs and the raw form is not.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if either field cannot be encoded.
    pub fn partial_context_hash(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let mut input = self.sender_leaf_index.tls_serialize_detached()?;
        input.extend_from_slice(&self.nonce.tls_serialize_detached()?);
        crate::label::hash(&input)
            .map_err(|_| tls_codec::Error::EncodingError("the ciphersuite hash failed".to_owned()))
    }

    /// The nonce with the `reuse_guard` XORed into its first four
    /// octets, which is what decrypts the ciphertext (RFC 9420 §6.3.2).
    #[must_use]
    pub fn guarded_nonce(&self) -> Vec<u8> {
        let mut nonce = self.nonce.as_slice().to_vec();
        for (byte, guard) in nonce.iter_mut().zip(self.reuse_guard) {
            *byte ^= guard;
        }
        nonce
    }
}

impl Size for PerMessageKeyAndNonces {
    fn tls_serialized_len(&self) -> usize {
        self.key.tls_serialized_len() + self.nonce.tls_serialized_len() + 4 + 4
    }
}

impl Serialize for PerMessageKeyAndNonces {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.key.tls_serialize(writer)? + self.nonce.tls_serialize(writer)?;
        writer.write_all(&self.reuse_guard)?;
        written += 4;
        written += self.sender_leaf_index.tls_serialize(writer)?;
        Ok(written)
    }
}

impl Deserialize for PerMessageKeyAndNonces {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let key = VLBytes::tls_deserialize(bytes)?;
        let nonce = VLBytes::tls_deserialize(bytes)?;
        let mut reuse_guard = [0u8; 4];
        bytes.read_exact(&mut reuse_guard)?;
        Ok(Self {
            key,
            nonce,
            reuse_guard,
            sender_leaf_index: u32::tls_deserialize(bytes)?,
        })
    }
}

/// semiprivatemessage-08 §3.1: `SemiPrivateMessageContext`, the HPKE
/// context the per-message keys are sealed under.
///
/// ~~~text
/// struct {
///   opaque group_id<V>;
///   uint64 epoch;
///   opaque partial_context_hash<V>;
/// } SemiPrivateMessageContext;
/// ~~~
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SemiPrivateMessageContext {
    /// The group.
    pub group_id: VLBytes,
    /// The epoch.
    pub epoch: u64,
    /// The hash of §3.1, which the frame also carries so a receiver can
    /// build this context before decrypting anything.
    pub partial_context_hash: VLBytes,
}

impl Size for SemiPrivateMessageContext {
    fn tls_serialized_len(&self) -> usize {
        self.group_id.tls_serialized_len()
            + self.epoch.tls_serialized_len()
            + self.partial_context_hash.tls_serialized_len()
    }
}

impl Serialize for SemiPrivateMessageContext {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        Ok(self.group_id.tls_serialize(writer)?
            + self.epoch.tls_serialize(writer)?
            + self.partial_context_hash.tls_serialize(writer)?)
    }
}

impl Deserialize for SemiPrivateMessageContext {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        Ok(Self {
            group_id: VLBytes::tls_deserialize(bytes)?,
            epoch: u64::tls_deserialize(bytes)?,
            partial_context_hash: VLBytes::tls_deserialize(bytes)?,
        })
    }
}

/// The HPKE label §3.1 seals an external receiver's keys under.
pub const RECEIVER_LABEL: &str = "SemiPrivateMessageReceiver";

impl SemiPrivateMessage {
    /// The HPKE context for this message, as §3.1 builds it.
    #[must_use]
    pub fn context(&self) -> SemiPrivateMessageContext {
        SemiPrivateMessageContext {
            group_id: self.group_id.clone(),
            epoch: self.epoch,
            partial_context_hash: self.partial_context_hash.clone(),
        }
    }

    /// This message's entry for the external receiver `reference`, or
    /// `None` if it carries none.
    #[must_use]
    pub fn key_for(&self, reference: &[u8]) -> Option<&KeyForExternalReceiver> {
        self.keys_for_external_receivers
            .iter()
            .find(|key| key.external_receiver_ref.as_slice() == reference)
    }
}

/// Why an external receiver could not read a [`SemiPrivateMessage`].
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum UnsealError {
    /// The message carries no entry for this receiver. A sender is free
    /// to leave one out; the receiver simply cannot read the message.
    #[error("the message has no entry for this receiver")]
    NotAddressed,
    /// The HPKE decryption failed: the wrong private key, or a
    /// ciphertext built under a different context.
    #[error("the sealed keys did not decrypt")]
    Decrypt,
    /// The sealed payload is not a `PerMessageKeyAndNonces`.
    #[error("the sealed keys are malformed")]
    Malformed(#[source] tls_codec::Error),
    /// `partial_context_hash` in the frame does not match the hash of
    /// the keys that came out of it (semiprivatemessage-08 §3.1;
    /// decision mimid-1wgh.4.79.6).
    ///
    /// The frame's copy is what builds the HPKE context, so a sender
    /// cannot change it without the decryption failing. This catches the
    /// remaining case: a sender whose sealed `sender_leaf_index` or
    /// `nonce` disagrees with the hash it committed to.
    #[error("partial_context_hash does not match the sealed keys")]
    ContextHashMismatch,
    /// `framed_content_tbs_hash` does not match the content that came
    /// out of the ciphertext (semiprivatemessage-08 §3.1).
    ///
    /// This is the check that keeps a sender from encrypting one thing
    /// to the members and another to the external receivers.
    #[error("framed_content_tbs_hash does not match the content")]
    ContentHashMismatch,
    /// The signature in the `FramedContentAuthData` does not verify
    /// against the sender's leaf (RFC 9420 §6.1).
    #[error("the handshake's signature does not verify")]
    Signature,
    /// The sealed keys name a leaf the receiver's own ratchet tree does
    /// not have, or one that is blank.
    ///
    /// Distinct from [`UnsealError::Signature`]: the sender named a leaf
    /// that does not exist, rather than failing to prove it owns one.
    #[error("the sealed keys name leaf {0}, which this receiver does not have")]
    UnknownSender(u32),
}

impl ExternalReceiver {
    /// `ExternalReceiverRef = hash(ExternalReceiver)`
    /// (semiprivatemessage-08 §3), over this entry's TLS encoding with
    /// the group's ciphersuite hash.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if the entry cannot be encoded or the hash
    /// fails.
    pub fn reference(&self) -> Result<Vec<u8>, tls_codec::Error> {
        let encoded = self.tls_serialize_detached()?;
        crate::label::hash(&encoded)
            .map_err(|_| tls_codec::Error::EncodingError("the ciphersuite hash failed".to_owned()))
    }
}

impl SemiPrivateMessage {
    /// Unseals this message's per-message keys for the external receiver
    /// `reference`, whose private key is `private_key`
    /// (semiprivatemessage-08 §3.1).
    ///
    /// The keys returned open [`SemiPrivateMessage::ciphertext`]; the
    /// nonce to use is [`PerMessageKeyAndNonces::guarded_nonce`].
    ///
    /// # Errors
    ///
    /// See [`UnsealError`]. A failure is never a reason to treat the
    /// group as broken: a member may address a message to a different
    /// set of receivers.
    pub fn unseal_keys(
        &self,
        reference: &[u8],
        private_key: &crate::label::HpkePrivateKey,
    ) -> Result<PerMessageKeyAndNonces, UnsealError> {
        let entry = self.key_for(reference).ok_or(UnsealError::NotAddressed)?;
        let context = self
            .context()
            .tls_serialize_detached()
            .map_err(UnsealError::Malformed)?;
        let (kem_output, ciphertext) = entry
            .encrypted_keys_and_nonces
            .parts()
            .map_err(UnsealError::Malformed)?;
        let opened = private_key
            .decrypt_with_label(RECEIVER_LABEL, &context, &kem_output, &ciphertext)
            .map_err(|_| UnsealError::Decrypt)?;
        let keys = PerMessageKeyAndNonces::tls_deserialize_exact(&opened)
            .map_err(UnsealError::Malformed)?;
        // The frame's partial_context_hash built the context above, so it
        // is already authenticated. What is not is whether the sealed
        // index and nonce are the ones it hashes to.
        let recomputed = keys
            .partial_context_hash()
            .map_err(UnsealError::Malformed)?;
        if recomputed != self.partial_context_hash.as_slice() {
            return Err(UnsealError::ContextHashMismatch);
        }
        Ok(keys)
    }
}

/// The `WireFormat` value for a SemiPrivateMessage
/// (semiprivatemessage-08 §5.1: TBD1, suggested 0x0011).
///
/// This is the value that goes in the `FramedContentTBS` the signature
/// and `framed_content_tbs_hash` cover, not `mls_private_message`
/// (decision mimid-1wgh.4.79.9): RFC 9420 §6.1 includes the wire format
/// so the signature binds the framing, and a signature that did not
/// distinguish the two would let a SemiPrivateMessage be repackaged as a
/// PrivateMessage with its external receivers stripped off.
pub const SEMIPRIVATE_WIRE_FORMAT: u16 = 0x0011;

/// RFC 9420 §6.1 `ProtocolVersion.mls10`.
const MLS10: u16 = 0x0001;

/// `Sender.sender_type` for a member (RFC 9420 §6).
const SENDER_TYPE_MEMBER: u8 = 1;

impl SemiPrivateMessage {
    /// Rebuilds the `FramedContentTBS` (RFC 9420 §6.1) this message's
    /// `framed_content_tbs_hash` covers, for an external receiver.
    ///
    /// `content` is the span [`SemiPrivateMessageContent::decode_parts`]
    /// returns, `sender_leaf_index` comes from the unsealed
    /// [`PerMessageKeyAndNonces`] -- the frame does not carry the sender
    /// in the clear, and an external receiver cannot read the
    /// `SenderData` that would give it -- and `group_context` is the
    /// receiver's own copy, which §3.3 makes the condition for checking
    /// the signature at all.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if a field cannot be encoded.
    pub fn framed_content_tbs(
        &self,
        content: &[u8],
        sender_leaf_index: u32,
        group_context: &[u8],
    ) -> Result<Vec<u8>, tls_codec::Error> {
        let mut out = MLS10.tls_serialize_detached()?;
        out.extend(SEMIPRIVATE_WIRE_FORMAT.tls_serialize_detached()?);
        // FramedContent.
        out.extend(self.group_id.tls_serialize_detached()?);
        out.extend(self.epoch.tls_serialize_detached()?);
        out.push(SENDER_TYPE_MEMBER);
        out.extend(sender_leaf_index.tls_serialize_detached()?);
        out.extend(self.authenticated_data.tls_serialize_detached()?);
        out.extend(self.content_type.tls_serialize_detached()?);
        out.extend(content);
        // sender_type is member, so the GroupContext follows (§6.1).
        out.extend(group_context);
        Ok(out)
    }

    /// Checks `framed_content_tbs_hash` against the content that came
    /// out of the ciphertext (semiprivatemessage-08 §3.1, §3.3).
    ///
    /// Takes the same arguments as
    /// [`SemiPrivateMessage::framed_content_tbs`] and returns the bytes
    /// it built, which are also what the signature is verified over.
    ///
    /// # Errors
    ///
    /// [`UnsealError::Malformed`] if a field cannot be encoded, and
    /// [`UnsealError::ContentHashMismatch`] if the hash does not match.
    pub fn check_framed_content_tbs(
        &self,
        content: &[u8],
        sender_leaf_index: u32,
        group_context: &[u8],
    ) -> Result<Vec<u8>, UnsealError> {
        let tbs = self
            .framed_content_tbs(content, sender_leaf_index, group_context)
            .map_err(UnsealError::Malformed)?;
        let hashed = crate::label::hash(&tbs).map_err(|_| {
            UnsealError::Malformed(tls_codec::Error::EncodingError(
                "the ciphersuite hash failed".to_owned(),
            ))
        })?;
        if hashed != self.framed_content_tbs_hash.as_slice() {
            return Err(UnsealError::ContentHashMismatch);
        }
        Ok(tbs)
    }
}

/// Where a decoded [`SemiPrivateMessageContent`]'s signed material sits
/// in the bytes it was decoded from.
///
/// Both are the received bytes, not a re-encoding:
/// `framed_content_tbs_hash` covers a FramedContent holding `content`,
/// and the signature is verified over the FramedContentTBS built from
/// it, so neither may be rebuilt from the decoded structures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ContentSpans<'a> {
    /// The `content` field of RFC 9420 §6.1's FramedContent: the encoded
    /// Proposal or Commit alone, without the
    /// `FramedContentAuthData` after it or the padding after that.
    pub content: &'a [u8],
    /// The `signature` of the `FramedContentAuthData` (RFC 9420 §6.1),
    /// which signs the FramedContentTBS under the label
    /// `"FramedContentTBS"`.
    ///
    /// Read from the bytes rather than from OpenMLS's
    /// `FramedContentAuthData`, whose fields are private.
    pub signature: &'a [u8],
}

impl<'a> ContentSpans<'a> {
    /// Splits `bytes` at `content_len`, the end of the `content` field,
    /// and reads the signature that follows it.
    fn new(bytes: &'a [u8], content_len: usize) -> Result<Self, tls_codec::Error> {
        let content = bytes
            .get(..content_len)
            .ok_or_else(|| tls_codec::Error::DecodingError("short content".to_owned()))?;
        let mut auth = bytes
            .get(content_len..)
            .ok_or_else(|| tls_codec::Error::DecodingError("no auth data".to_owned()))?;
        // FramedContentAuthData starts with `opaque signature<V>`; a
        // commit's confirmation_tag follows it and is not signed.
        let start = auth;
        let signature = VLBytes::tls_deserialize(&mut auth)?;
        let offset = start.len() - auth.len() - signature.as_slice().len();
        let signature = start
            .get(offset..offset + signature.as_slice().len())
            .ok_or_else(|| tls_codec::Error::DecodingError("short signature".to_owned()))?;
        Ok(Self { content, signature })
    }
}

/// RFC 9420 §6.1: the label the FramedContentTBS signature uses.
const FRAMED_CONTENT_TBS_LABEL: &str = "FramedContentTBS";

/// What an external receiver recovered from a [`SemiPrivateMessage`].
#[derive(Debug)]
#[non_exhaustive]
pub struct Opened {
    /// The handshake: a Proposal or a Commit.
    pub content: SemiPrivateMessageContent,
    /// Which leaf sent it, from the sealed keys. The frame does not
    /// carry the sender in the clear.
    pub sender_leaf_index: u32,
}

impl SemiPrivateMessage {
    /// The external receiver's whole path through
    /// semiprivatemessage-08 §3.3: unseal the per-message keys, verify
    /// `partial_context_hash`, open the ciphertext with the guarded
    /// nonce, check the padding, check `framed_content_tbs_hash`, and
    /// verify the signature.
    ///
    /// `group_context` is the receiver's own copy of the GroupContext.
    /// §3.3 makes the signature check conditional on having one;
    /// mimid's hub always does, so it always checks, and a failure is a
    /// refusal (decision mimid-1wgh.4.79.5).
    ///
    /// `sender_key` is asked for the signature key of a leaf, and must
    /// answer from the receiver's own ratchet tree: the leaf index comes
    /// from the sealed keys, so the caller cannot know it before this
    /// call, and nothing the message carries may be trusted for it. It
    /// returns `None` for a blank or out-of-range leaf, which is
    /// [`UnsealError::UnknownSender`].
    ///
    /// # Errors
    ///
    /// See [`UnsealError`]. Every failure means the message is not one
    /// this receiver can act on; none of them means the group is broken.
    pub fn open_as_external_receiver(
        &self,
        reference: &[u8],
        private_key: &crate::label::HpkePrivateKey,
        group_context: &[u8],
        sender_key: impl FnOnce(u32) -> Option<Vec<u8>>,
    ) -> Result<Opened, UnsealError> {
        let keys = self.unseal_keys(reference, private_key)?;
        // Through content_aad, not rebuilt here: this is the one place
        // the AAD is security-critical, and a second copy of its
        // construction would let the two drift apart silently.
        let aad = self
            .content_aad()
            .tls_serialize_detached()
            .map_err(UnsealError::Malformed)?;
        let plaintext = crate::label::aead_open(
            keys.key.as_slice(),
            &keys.guarded_nonce(),
            &aad,
            self.ciphertext.as_slice(),
        )
        .map_err(|_| UnsealError::Decrypt)?;
        // decode_parts checks the padding is zero and gives back the
        // received spans the hash and the signature cover.
        let (content, spans) =
            SemiPrivateMessageContent::decode_parts(&plaintext, self.content_type)
                .map_err(UnsealError::Malformed)?;
        let tbs =
            self.check_framed_content_tbs(spans.content, keys.sender_leaf_index, group_context)?;
        let key = sender_key(keys.sender_leaf_index)
            .ok_or(UnsealError::UnknownSender(keys.sender_leaf_index))?;
        crate::label::verify_with_label(&key, FRAMED_CONTENT_TBS_LABEL, &tbs, spans.signature)
            .map_err(|_| UnsealError::Signature)?;
        Ok(Opened {
            content,
            sender_leaf_index: keys.sender_leaf_index,
        })
    }
}
