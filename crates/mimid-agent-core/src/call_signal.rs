//! Call signalling carried in a call's own room (bead mimid-1wgh.114.5;
//! draft-atwood-jmap-chat-mimi-00 §Calls).
//!
//! A call has a MIMI room of its own, and the room carries the call's
//! WebRTC signalling as ordinary messages: a session description or an
//! ICE candidate in an inline `session` part (mimi-content-10 §5.10's
//! first half, "a description of a multimedia session"), with the kind
//! of signal in one extension key.
//!
//! What that buys, and neither comes from anything here:
//!
//! - the room's hub orders the messages it accepts, so an offer and its
//!   answer arrive in that order with no sequence numbers of ours.
//!   ARRIVAL ORDER IS NOT PROCESSING ORDER: applying a session
//!   description waits on the user's permission to use a microphone and
//!   on the media layer, so a candidate that arrived after the offer can
//!   reach a client still applying it. A client holds such a candidate
//!   until the remote description is set and then applies what it held
//!   (draft-atwood-jmap-vtc-00 §VTCCallSignal). Nothing here can do that
//!   for it: the media layer is the client's;
//! - the sender is the authenticated MLS sender, so the certificate
//!   fingerprints (RFC 8122) a session description carries are bound to
//!   that sender's credential. A call signalled this way needs no
//!   fingerprint comparison between its participants.
//!
//! # Limitations
//!
//! - The signal reaches every member of the call's room, because that is
//!   the granularity at which MLS encrypts. Right for two parties and
//!   for a forwarding unit that is itself a member; in a mesh call among
//!   three or more, the description meant for one peer is readable by
//!   all of them, and nothing here makes it otherwise.
//! - A signal may be delivered more than once, because the agent's
//!   journal is replayed after a crash. Nothing here dedupes: a second
//!   copy of an offer a client has applied is the client's to ignore,
//!   and a repeated candidate is harmless to apply again.
//! - The extension key is private use (mimi-content-10 §4.3) and
//!   provisional: decision mimid-1wgh.116 for the key's shape, and
//!   INVENTED, NOT FROM SPEC until a MIMI Content Extension Key is
//!   assigned.
//! - `sdpMLineIndex` is not carried. A candidate's `a=mid:` line names
//!   its media description, which is what a client needs; WebRTC takes
//!   either.

use std::collections::BTreeMap;

use mimi_content::{Disposition, ExtensionKey, MimiContent, NestedPart, Part, RawValue};

/// The media type of a session description and of a candidate fragment
/// (RFC 8866; RFC 8840 for the fragment).
pub const SDP_CONTENT_TYPE: &str = "application/sdp";

/// The extension key naming the kind of signal. Private use under
/// mimi-content-10 §4.3, provisional: decision mimid-1wgh.116.
/// INVENTED, NOT FROM SPEC.
pub const SIGNAL_KEY: &str = "draft-atwood-mimi-calls/signal";

/// The longest session description this agent sends or accepts, in
/// octets. INVENTED, NOT FROM SPEC: an SDP offer with a handful of
/// codecs and candidates is a few kilobytes, and a longer one is more
/// likely a mistake than a call.
pub const MAX_SDP_LEN: usize = 16_384;

/// Which signal a message carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum SignalKind {
    /// An SDP offer.
    Offer,
    /// An SDP answer.
    Answer,
    /// One ICE candidate, as an SDP fragment (RFC 8840).
    Candidate,
}

impl SignalKind {
    /// The token the extension key carries.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Offer => "offer",
            Self::Answer => "answer",
            Self::Candidate => "candidate",
        }
    }

    /// The kind `token` names, or `None` for any other token: a signal
    /// this agent does not know is not one it guesses at.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        match token {
            "offer" => Some(Self::Offer),
            "answer" => Some(Self::Answer),
            "candidate" => Some(Self::Candidate),
            _ => None,
        }
    }
}

/// One signal: its kind and the SDP it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallSignal {
    /// Which signal it is.
    pub kind: SignalKind,
    /// The session description, or the candidate fragment.
    pub sdp: String,
}

/// The CBOR text string `token`, deterministically encoded (RFC 8949
/// §4.2.1): major type 3 with the length in the head. Every token of
/// [`SignalKind`] is shorter than 24 octets, so the head is one byte.
fn cbor_text(token: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(token.len() + 1);
    debug_assert!(token.len() < 24, "a longer token needs a longer head");
    out.push(0x60 | u8::try_from(token.len()).unwrap_or(0));
    out.extend_from_slice(token.as_bytes());
    out
}

/// The token a CBOR text string of fewer than 24 octets holds, or `None`
/// for any other item: the value is ours and we wrote it, so anything
/// else is a signal from an implementation we do not know.
fn text_of(value: &RawValue) -> Option<&str> {
    let bytes = value.as_bytes();
    let (&head, rest) = bytes.split_first()?;
    let len = usize::from(head.checked_sub(0x60)?);
    if len >= 24 || rest.len() != len {
        return None;
    }
    std::str::from_utf8(rest).ok()
}

impl CallSignal {
    /// The parts of a message carrying this signal: the extension entry
    /// and the body part.
    ///
    /// # Errors
    ///
    /// [`Invalid`](crate::AgentError::Invalid) if the SDP is empty or
    /// longer than [`MAX_SDP_LEN`].
    pub fn to_content(
        &self,
    ) -> Result<(BTreeMap<ExtensionKey, RawValue>, NestedPart), crate::AgentError> {
        if self.sdp.is_empty() {
            return Err(crate::AgentError::Invalid(
                "a call signal carries no SDP".to_owned(),
            ));
        }
        if self.sdp.len() > MAX_SDP_LEN {
            return Err(crate::AgentError::Invalid(format!(
                "a call signal's SDP is longer than {MAX_SDP_LEN} octets"
            )));
        }
        let value = RawValue::new(&cbor_text(self.kind.as_str())).map_err(|e| {
            crate::AgentError::Invalid(format!("the signal's extension value: {e}"))
        })?;
        let mut extensions = BTreeMap::new();
        extensions.insert(ExtensionKey::Text(SIGNAL_KEY.to_owned()), value);
        Ok((
            extensions,
            NestedPart {
                disposition: Disposition::SESSION,
                language: String::new(),
                part: Part::Single {
                    content_type: SDP_CONTENT_TYPE.to_owned(),
                    content: self.sdp.clone().into_bytes(),
                },
            },
        ))
    }

    /// The signal `content` carries, or `None` for a message that is not
    /// one: no signal extension, a kind this agent does not know, a body
    /// that is not one inline `application/sdp` session part, or SDP
    /// that is empty, too long or not UTF-8.
    ///
    /// A message that is not a signal is an ordinary message, so this
    /// never fails: it answers whether the message is signalling.
    #[must_use]
    pub fn of_content(content: &MimiContent) -> Option<Self> {
        let key = ExtensionKey::Text(SIGNAL_KEY.to_owned());
        let kind = SignalKind::from_token(text_of(content.mimi_extensions.other.get(&key)?)?)?;
        let part = &content.nested_part;
        if part.disposition != Disposition::SESSION {
            return None;
        }
        let Part::Single {
            content_type,
            content: body,
        } = &part.part
        else {
            return None;
        };
        if !content_type
            .split(';')
            .next()
            .is_some_and(|base| base.trim().eq_ignore_ascii_case(SDP_CONTENT_TYPE))
        {
            return None;
        }
        if body.is_empty() || body.len() > MAX_SDP_LEN {
            return None;
        }
        Some(Self {
            kind,
            sdp: String::from_utf8(body.clone()).ok()?,
        })
    }
}
