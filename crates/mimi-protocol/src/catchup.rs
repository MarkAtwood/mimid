//! The catchUp operation: `POST /catchUp/{roomId}`, by which a follower
//! asks a hub for the fanout it missed.
//!
//! INVENTED, NOT FROM SPEC. protocol-07 has no follower catch-up: a
//! follower that misses a `/notify` loses that ciphertext for good, with
//! no notification to anyone. The design is
//! `docs/design/mimi-catchup.md` and the proposal is bead
//! mimid-1wgh.37.104, to go to the working group as protocol-08 text
//! rather than a separate extension (decision mimid-1wgh.105).
//!
//! The operation is discovered through the directory, not negotiated: a
//! provider that does not publish a `catchUp` template does not support
//! it, and a requester learns that without a failed request (§5).
//!
//! # The sequence travels inside the answer
//!
//! A fanout's per-room sequence rides BESIDE the message rather than
//! inside [`FanoutMessage`] (decision mimid-1wgh.104), which on
//! `POST /notify/{roomId}` is an HTTP header, because one notify carries
//! one fanout. An answer here carries many, so a header cannot pair a
//! number with its message; each [`CatchUpEntry`] carries its own
//! (decision mimid-1wgh.37.104.6).
//!
//! That decision turned on two things. The answer is a new structure, so
//! keeping the sequence out of it protects nothing: decision
//! mimid-1wgh.104's reasons were about not changing `FanoutMessage` or
//! the `/notify` body, which other implementations already parse. And a
//! list header paralleling the body would pair positionally with nothing
//! to detect a misalignment, because a response carries no signature:
//! mimid signs requests only.
//!
//! # Limitations
//!
//! - [`MAX_CATCH_UP_ENTRIES`] caps what one answer decodes, so a
//!   follower behind by more than that asks again from the last sequence
//!   it got. [`CatchUpResponse::highest_sequence`] is how it knows to.
//! - An answer says nothing about which sequences are MISSING from it. A
//!   hub bounds what it serves by retention (§6) and by the requester's
//!   own participation (§8), so a gap in the returned sequences is
//!   expected and is not a protocol error. §5.1's refusal is what says
//!   a request cannot be filled at all.

use tls_codec::{Deserialize, Serialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::notify::FanoutMessage;

/// The most fanouts mimid asks for in one catch-up.
///
/// INVENTED, NOT FROM SPEC (`docs/design/mimi-catchup.md` §5): a hub may
/// return fewer, and a follower that wants more asks again.
pub const CATCH_UP_LIMIT: u32 = 256;

/// The most entries a [`CatchUpResponse`] decodes, which is
/// [`CATCH_UP_LIMIT`]: an answer longer than mimid would ever ask for is
/// refused rather than buffered.
///
/// INVENTED, NOT FROM SPEC.
pub const MAX_CATCH_UP_ENTRIES: usize = CATCH_UP_LIMIT as usize;

/// `CatchUpRequest` (INVENTED, NOT FROM SPEC;
/// `docs/design/mimi-catchup.md` §5): what the follower holds and how
/// much it will take.
///
/// ~~~text
/// struct {
///     uint64 from;
///     uint32 limit;
/// } CatchUpRequest;
/// ~~~
///
/// The room is in the request path, as every other per-room operation's
/// is (protocol-07 §5.5; decision mimid-1wgh.5.18), so it is not
/// repeated here.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct CatchUpRequest {
    /// The sequence the follower already has: it wants fanout AFTER
    /// this. Zero asks for everything the hub still holds, which is what
    /// a follower with no record of the room sends.
    pub from: u64,
    /// The most fanouts it will accept in one answer. A hub may return
    /// fewer, and caps it at [`MAX_CATCH_UP_ENTRIES`].
    pub limit: u32,
}

impl CatchUpRequest {
    /// Decodes a request body, which must be exactly one
    /// `CatchUpRequest`.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if the body is short, has trailing bytes, or
    /// asks for a `limit` of zero, which would request nothing and is
    /// more likely a caller that left the field unset.
    pub fn decode(body: &[u8]) -> Result<Self, tls_codec::Error> {
        let request = Self::tls_deserialize_exact(body)?;
        if request.limit == 0 {
            return Err(tls_codec::Error::DecodingError(
                "catchUp limit is zero".to_owned(),
            ));
        }
        Ok(request)
    }

    /// The request as a body.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if encoding fails.
    pub fn to_body(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    /// How many entries a hub should return for this request: the
    /// requester's `limit`, never more than [`MAX_CATCH_UP_ENTRIES`].
    #[must_use]
    pub fn bounded_limit(&self) -> usize {
        (self.limit as usize).min(MAX_CATCH_UP_ENTRIES)
    }
}

/// One fanout in a [`CatchUpResponse`], with the sequence it was fanned
/// out at (INVENTED, NOT FROM SPEC).
///
/// ~~~text
/// struct {
///     uint64 sequence;
///     FanoutMessage message;
/// } CatchUpEntry;
/// ~~~
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct CatchUpEntry {
    /// The room's fanout sequence for this delivery
    /// (`docs/design/mimi-catchup.md` §4). Never zero: a fanout from
    /// before sequences existed cannot be named and is not served.
    pub sequence: u64,
    /// The fanout exactly as it was delivered.
    pub message: FanoutMessage,
}

/// `CatchUpResponse` (INVENTED, NOT FROM SPEC;
/// `docs/design/mimi-catchup.md` §5): fanouts in hub order, each with its
/// sequence, and the hub's current highest so the follower knows whether
/// it is caught up.
///
/// ~~~text
/// struct {
///     uint64 highest_sequence;
///     CatchUpEntry entries<V>;
/// } CatchUpResponse;
/// ~~~
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
pub struct CatchUpResponse {
    /// The highest sequence the hub has assigned in this room. A
    /// follower whose last entry is lower than this asks again; one
    /// whose is equal is caught up.
    ///
    /// It is the counter and not the last entry served, so it still
    /// names a fanout the hub no longer holds. That is what lets a
    /// follower tell "caught up" from "there is more I cannot have".
    pub highest_sequence: u64,
    /// The fanouts, in hub order, by increasing sequence. May be shorter
    /// than the request's `limit`, and may skip sequences the hub does
    /// not serve: retention (§6) and the requester's own participation
    /// (§8) both bound it.
    pub entries: Vec<CatchUpEntry>,
}

impl CatchUpResponse {
    /// Decodes a response body, which must be exactly one
    /// `CatchUpResponse`.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if the body is short, has trailing bytes,
    /// carries more than [`MAX_CATCH_UP_ENTRIES`] entries, carries an
    /// entry whose sequence is zero, or carries entries out of
    /// increasing order. The order matters: a follower applies them in
    /// the order given, and the hub's order is the room's order
    /// (protocol-07 §5.5).
    pub fn decode(body: &[u8]) -> Result<Self, tls_codec::Error> {
        let response = Self::tls_deserialize_exact(body)?;
        if response.entries.len() > MAX_CATCH_UP_ENTRIES {
            return Err(tls_codec::Error::DecodingError(format!(
                "catchUp answer has {} entries, more than {MAX_CATCH_UP_ENTRIES}",
                response.entries.len()
            )));
        }
        let mut previous = 0u64;
        for entry in &response.entries {
            if entry.sequence == 0 {
                return Err(tls_codec::Error::DecodingError(
                    "catchUp entry has sequence 0".to_owned(),
                ));
            }
            if entry.sequence <= previous {
                return Err(tls_codec::Error::DecodingError(format!(
                    "catchUp entries are not increasing: {} after {previous}",
                    entry.sequence
                )));
            }
            previous = entry.sequence;
        }
        if previous > response.highest_sequence {
            return Err(tls_codec::Error::DecodingError(format!(
                "catchUp served {previous} above its highest {}",
                response.highest_sequence
            )));
        }
        Ok(response)
    }

    /// The response as a body.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if encoding fails.
    pub fn to_body(&self) -> Result<Vec<u8>, tls_codec::Error> {
        self.tls_serialize_detached()
    }

    /// Whether the follower is caught up: the hub has nothing after what
    /// this answer's last entry carries.
    #[must_use]
    pub fn caught_up(&self) -> bool {
        self.entries
            .last()
            .is_none_or(|entry| entry.sequence >= self.highest_sequence)
    }
}
