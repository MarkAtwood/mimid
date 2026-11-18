//! Recipient checks of a message's frank (protocol-07 §5.4.1.3; bead
//! mimid-1wgh.13.6).
//!
//! A frank is two halves: the sender's `franking_tag` in the message's
//! Safe AAD (a `frank_aad` item) and the hub's [`Frank`] in the
//! FanoutMessage. Per rohanmahy on mimi-protocol#159 (2026-10-19):
//!
//! - In a room whose Safe AAD requires `frank_aad`, a message without both
//!   halves is discarded.
//! - In any room, a message with only one half is discarded.
//! - A message with both is verified: the room's `franking_agent`
//!   credential must name the room's hub, then [`ReceivedFrank::verify`]
//!   checks the ciphersuite, the hub's signature, the tag, and that the
//!   content's `senderUri` and `roomUri` are the MLS sender and the room.
//!   URIs are compared as strings (RFC 3986 §6.2.1; decision
//!   mimid-1wgh.5.58).
//!
//! The hub is the provider of the room ID's domain, and its credential is
//! taken to name it when its BasicCredential identity is `mimi://<domain>`
//! (mimid's hub, decision mimid-1wgh.6.35) or the bare domain, compared
//! ASCII case-insensitively. Identity-to-domain mapping beyond that is
//! open (mimi-protocol#159; draft-mahy-mimi-identity has no rule).

use mimi_content::MimiContent;
use mimi_mls::member::Member;
use mimi_mls::tls_codec::{Deserialize, Serialize};
use mimi_mls::wire::CipherSuite;
use mimi_protocol::component_id::{FRANK_AAD, FRANKING_AGENT};
use mimi_protocol::{
    AbusiveMessage, Frank, FrankAad, FrankingAgentData, IdentifierUri, ReceivedFrank,
    ServerFrankingContext,
};

use crate::AgentError;

/// The one ciphersuite mimi-mls supports, so the suite of every group the
/// agent is in (MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519, RFC 9420
/// §17.1).
const GROUP_CIPHER_SUITE: u16 = 0x0001;

/// The `safe_aad` component (mls-extensions-11 §4.9).
const SAFE_AAD: u16 = 0x0002;

/// A verified frank, kept with its message (protocol-07 §5.4.1.3: "The
/// receiver needs to store the server_frank, franking_signature_ciphersuite,
/// franking_integrity_signature, and context fields").
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedFrank {
    /// The hub's frank.
    pub frank: Frank,
    /// The context the hub signed.
    pub context: ServerFrankingContext,
}

/// The TLS encoding of `message` (protocol-07 §5.9), for a caller that
/// keeps what [`crate::ReceivedMessage::abusive_message`] gave until the
/// user reports it.
///
/// # Errors
///
/// [`AgentError::Encoding`] if it does not encode (a field over the
/// codec's length limit).
pub fn encode_abusive_message(message: &AbusiveMessage) -> Result<Vec<u8>, AgentError> {
    message
        .tls_serialize_detached()
        .map_err(|e| AgentError::tls("an AbusiveMessage", e))
}

/// An AbusiveMessage back from [`encode_abusive_message`]'s bytes, decoded
/// strictly.
///
/// # Errors
///
/// [`AgentError::Encoding`] if `bytes` are not one AbusiveMessage.
pub fn decode_abusive_message(bytes: &[u8]) -> Result<AbusiveMessage, AgentError> {
    AbusiveMessage::tls_deserialize_exact(bytes)
        .map_err(|e| AgentError::tls("a kept AbusiveMessage", e))
}

/// Whether `member`'s room requires `frank_aad` in the Safe AAD.
pub(crate) fn requires_frank(member: &Member) -> bool {
    member.component(SAFE_AAD).is_some_and(|list| {
        list.get(1..)
            .is_some_and(|ids| ids.chunks(2).any(|id| id == FRANK_AAD.to_be_bytes()))
    })
}

/// Everything about one received application message the checks need.
pub(crate) struct Received<'a> {
    pub member: &'a Member,
    pub room: &'a str,
    pub sender: &'a str,
    pub data: &'a [u8],
    pub content: &'a MimiContent,
    pub safe_aad: &'a [(u16, Vec<u8>)],
    pub frank: Option<&'a Frank>,
    pub accepted_at: u64,
}

/// Runs the checks in the module documentation: `Ok(None)` for an
/// unfranked message a room allows, `Ok(Some(_))` for a verified frank,
/// and `Err` with the reason to discard the message.
pub(crate) fn check(received: &Received<'_>) -> Result<Option<VerifiedFrank>, String> {
    let tag = received
        .safe_aad
        .iter()
        .find(|(id, _)| *id == FRANK_AAD)
        .map(|(_, data)| {
            FrankAad::tls_deserialize_exact(&data[..])
                .map_err(|e| format!("the frank_aad item does not decode: {e}"))
        })
        .transpose()?;
    let (tag, frank) = match (tag, received.frank) {
        (None, None) if requires_frank(received.member) => {
            return Err("the room requires franking and the message has no frank".to_owned());
        }
        (None, None) => return Ok(None),
        (Some(_), None) => {
            return Err("the message has a franking_tag but the hub sent no frank".to_owned());
        }
        (None, Some(_)) => {
            return Err("the hub sent a frank for a message with no franking_tag".to_owned());
        }
        (Some(tag), Some(frank)) => (tag, frank),
    };
    let agent = received
        .member
        .component(FRANKING_AGENT)
        .ok_or("the message is franked but the room has no franking_agent")?;
    let agent = FrankingAgentData::tls_deserialize_exact(agent)
        .map_err(|e| format!("the franking_agent does not decode: {e}"))?;
    let hub = room_domain(received.room).ok_or("the room ID has no domain")?;
    if !names_domain(agent.credential.identity(), hub) {
        return Err(format!("the franking_agent does not name the hub {hub}"));
    }
    let extensions = &received.content.mimi_extensions;
    let content_sender = extensions
        .sender_uri
        .as_deref()
        .ok_or("the franked message has no senderUri")?;
    let content_room = extensions
        .room_uri
        .as_deref()
        .ok_or("the franked message has no roomUri")?;
    let uri = |s: &str, what: &str| {
        IdentifierUri::new(s).map_err(|e| format!("the {what} is not a MIMI URI: {e}"))
    };
    let content_sender = uri(content_sender, "senderUri")?;
    let content_room = uri(content_room, "roomUri")?;
    let sender = uri(received.sender, "MLS sender")?;
    let room = uri(received.room, "room ID")?;
    let context = ReceivedFrank {
        frank,
        accepted_timestamp: received.accepted_at,
        franking_tag: &tag.franking_tag,
        group_cipher_suite: CipherSuite::from(GROUP_CIPHER_SUITE),
        franking_agent: &agent,
        salt: &received.content.salt,
        application_data: received.data,
        content_sender_uri: &content_sender,
        content_room_uri: &content_room,
        authenticated_sender_uri: &sender,
        notify_room_uri: &room,
    }
    .verify()
    .map_err(|e| format!("the frank does not verify: {e}"))?;
    Ok(Some(VerifiedFrank {
        frank: frank.clone(),
        context,
    }))
}

/// The authority of a `mimi://<domain>/r/<id>` room ID.
fn room_domain(room: &str) -> Option<&str> {
    let rest = room.strip_prefix("mimi://")?;
    let domain = rest.split('/').next()?;
    (!domain.is_empty()).then_some(domain)
}

/// Whether a BasicCredential identity names `domain`: `mimi://<domain>`
/// or `<domain>`.
fn names_domain(identity: Option<&[u8]>, domain: &str) -> bool {
    let Some(identity) = identity.and_then(|i| std::str::from_utf8(i).ok()) else {
        return false;
    };
    let named = identity.strip_prefix("mimi://").unwrap_or(identity);
    named.eq_ignore_ascii_case(domain)
}

#[cfg(test)]
mod tests {
    use mimi_content::{Disposition, Extensions, NestedPart, Part};
    use mimi_mls::Identity;
    use mimi_mls::Store;
    use mimi_mls::label::SignatureKeyPair;
    use mimi_mls::tls_codec::{Serialize, VLBytes};
    use mimi_mls::wire::{Credential, SignaturePublicKey};
    use mimi_protocol::{FrankingIntegrityTbs, franking_tag};

    use super::*;

    const ALICE: &str = "mimi://a.example/u/alice";
    const ROOM: &str = "mimi://a.example/r/frank-test";
    const AT: u64 = 1_763_000_000_000;

    /// A one-member group of alice's, franked by `hub_key` under the
    /// credential `hub_identity` when `franked`, else with no components.
    struct Fixture {
        _dir: tempfile::TempDir,
        member: Member,
        hub: SignatureKeyPair,
    }

    fn fixture(franked: bool, hub_identity: &str) -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&dir.path().join("mls.sqlite")).unwrap();
        let identity = Identity::generate(ALICE.as_bytes(), store).unwrap();
        let hub = SignatureKeyPair::generate().unwrap();
        let components = if franked {
            let mut key = vec![0x20];
            key.extend_from_slice(hub.verification_key());
            let mut credential = vec![0x00, 0x01];
            credential.extend(
                VLBytes::new(hub_identity.as_bytes().to_vec())
                    .tls_serialize_detached()
                    .unwrap(),
            );
            let agent = FrankingAgentData {
                franking_signature_key: SignaturePublicKey::tls_deserialize_exact(&key[..])
                    .unwrap(),
                credential: Credential::tls_deserialize_exact(&credential[..]).unwrap(),
            }
            .tls_serialize_detached()
            .unwrap();
            vec![
                (0x0001, vec![0x02, 0x00, 0x21]),
                (SAFE_AAD, vec![0x02, 0x00, 0x20]),
                (FRANKING_AGENT, agent),
            ]
        } else {
            Vec::new()
        };
        let member = Member::create(&identity, b"frank-test", &[], &components).unwrap();
        Fixture {
            _dir: dir,
            member,
            hub,
        }
    }

    fn content(sender: &str, room: &str) -> MimiContent {
        MimiContent {
            salt: [9; 16],
            replaces: None,
            topic_id: Vec::new(),
            expires: None,
            in_reply_to: None,
            mimi_extensions: Extensions {
                sender_uri: Some(sender.to_owned()),
                room_uri: Some(room.to_owned()),
                ..Extensions::default()
            },
            nested_part: NestedPart {
                disposition: Disposition::RENDER,
                language: String::new(),
                part: Part::Single {
                    content_type: "text/plain".to_owned(),
                    content: b"hi".to_vec(),
                },
            },
        }
    }

    /// The hub's frank over `sender`, `room` and [`AT`].
    fn sign(hub: &SignatureKeyPair, sender: &str, room: &str) -> Frank {
        FrankingIntegrityTbs {
            server_frank: [7; 32],
            franking_signature_ciphersuite: CipherSuite::from(GROUP_CIPHER_SUITE),
            context: ServerFrankingContext {
                sender_uri: IdentifierUri::new(sender).unwrap(),
                room_uri: IdentifierUri::new(room).unwrap(),
                accepted_timestamp: AT,
            },
        }
        .sign(hub)
        .unwrap()
    }

    fn run(
        member: &Member,
        content: &MimiContent,
        tag: Option<[u8; 32]>,
        frank: Option<&Frank>,
    ) -> Result<Option<VerifiedFrank>, String> {
        let data = content.encode().unwrap();
        let safe_aad: Vec<(u16, Vec<u8>)> = tag
            .map(|tag| vec![(FRANK_AAD, tag.to_vec())])
            .unwrap_or_default();
        check(&Received {
            member,
            room: ROOM,
            sender: ALICE,
            data: &data,
            content,
            safe_aad: &safe_aad,
            frank,
            accepted_at: AT,
        })
    }

    fn tag_of(content: &MimiContent) -> [u8; 32] {
        franking_tag(&content.salt, &content.encode().unwrap())
    }

    #[test]
    fn a_good_frank_verifies_and_is_kept() {
        let f = fixture(true, "mimi://a.example");
        let content = content(ALICE, ROOM);
        let frank = sign(&f.hub, ALICE, ROOM);
        let verified = run(&f.member, &content, Some(tag_of(&content)), Some(&frank))
            .unwrap()
            .expect("verified");
        assert_eq!(verified.frank, frank);
        assert_eq!(verified.context.accepted_timestamp, AT);
    }

    #[test]
    fn a_franked_room_discards_what_is_not_properly_franked() {
        let f = fixture(true, "mimi://a.example");
        let good = content(ALICE, ROOM);
        let tag = tag_of(&good);
        let frank = sign(&f.hub, ALICE, ROOM);
        // Absent or partial (mimi-protocol#159).
        assert!(run(&f.member, &good, None, None).is_err());
        assert!(run(&f.member, &good, Some(tag), None).is_err());
        assert!(run(&f.member, &good, None, Some(&frank)).is_err());
        // A tag over other bytes.
        assert!(run(&f.member, &good, Some([0; 32]), Some(&frank)).is_err());
        // Signed by another key, or over another sender.
        let other = SignatureKeyPair::generate().unwrap();
        assert!(
            run(
                &f.member,
                &good,
                Some(tag),
                Some(&sign(&other, ALICE, ROOM))
            )
            .is_err()
        );
        let bob = "mimi://a.example/u/bob";
        assert!(run(&f.member, &good, Some(tag), Some(&sign(&f.hub, bob, ROOM))).is_err());
        // The content claims another sender, consistently signed.
        let claims_bob = content(bob, ROOM);
        assert!(
            run(
                &f.member,
                &claims_bob,
                Some(tag_of(&claims_bob)),
                Some(&sign(&f.hub, bob, ROOM))
            )
            .is_err()
        );
        // No senderUri in a franked message.
        let mut bare = content(ALICE, ROOM);
        bare.mimi_extensions.sender_uri = None;
        assert!(run(&f.member, &bare, Some(tag_of(&bare)), Some(&frank)).is_err());
    }

    #[test]
    fn the_franking_agent_must_name_the_rooms_hub() {
        let f = fixture(true, "mimi://b.example");
        let content = content(ALICE, ROOM);
        let frank = sign(&f.hub, ALICE, ROOM);
        let refused = run(&f.member, &content, Some(tag_of(&content)), Some(&frank));
        assert!(refused.unwrap_err().contains("does not name the hub"));
    }

    #[test]
    fn an_unfranked_room_takes_unfranked_messages_only_whole() {
        let f = fixture(false, "");
        let content = content(ALICE, ROOM);
        assert_eq!(run(&f.member, &content, None, None), Ok(None));
        assert!(run(&f.member, &content, Some(tag_of(&content)), None).is_err());
        let frank = sign(&f.hub, ALICE, ROOM);
        assert!(run(&f.member, &content, None, Some(&frank)).is_err());
    }

    #[test]
    fn a_hub_credential_names_the_room_domain() {
        assert_eq!(room_domain("mimi://a.example/r/x"), Some("a.example"));
        assert_eq!(room_domain("mimi:///r/x"), None);
        assert_eq!(room_domain("https://a.example/r/x"), None);
        for ok in ["mimi://a.example", "a.example", "mimi://A.Example"] {
            assert!(names_domain(Some(ok.as_bytes()), "a.example"), "{ok}");
        }
        for bad in [
            "mimi://b.example",
            "mimi://a.example/u/hub",
            "mimi://a.example.evil",
            "",
        ] {
            assert!(!names_domain(Some(bad.as_bytes()), "a.example"), "{bad}");
        }
        assert!(!names_domain(None, "a.example"));
        assert!(!names_domain(Some(&[0xff]), "a.example"));
    }
}
