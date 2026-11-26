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

use std::io::{Read, Write};

use tls_codec::{Deserialize, Serialize, Size, TlsDeserialize, TlsSerialize, TlsSize};

use crate::Utf8String;
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

/// `CatchUpResponseCode` (INVENTED, NOT FROM SPEC;
/// `docs/design/mimi-catchup.md` §5; bead mimid-1wgh.37.104.14).
///
/// The names and their values follow protocol-07's `GroupInfoCode`,
/// which carries the same pair of refusals and the same problem: a hub
/// that will not reveal whether a room exists to a requester with no
/// participants in it answers `notAuthorized` for both. The value of
/// `success` follows the four response code enums that put it at 0
/// rather than `GroupInfoCode`, which alone reserves 0.
///
/// `OutOfWindow` has no protocol-07 counterpart: no operation there can
/// run out of history to serve.
///
/// Decoding rejects the undefined values 4 to 255 with
/// [`tls_codec::Error::UnknownValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, TlsSerialize, TlsDeserialize, TlsSize)]
#[repr(u8)]
pub enum CatchUpResponseCode {
    /// `success(0)`: the answer carries what the hub holds and may
    /// serve.
    Success = 0,
    /// `outOfWindow(1)`: the range asked for is older than the hub
    /// holds, so it cannot be supplied -- not now and not later (§5.1).
    OutOfWindow = 1,
    /// `notAuthorized(2)`: the requester may not be served this room.
    NotAuthorized = 2,
    /// `noSuchRoom(3)`: the room does not exist. A hub that will not
    /// reveal that answers `NotAuthorized` instead.
    NoSuchRoom = 3,
}

/// The `select (responseCode)` arms of a [`CatchUpResponse`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum CatchUpResult {
    /// `case success`.
    Success {
        /// `uint64 highestSequence`: the highest sequence the hub has
        /// assigned in this room.
        ///
        /// It is the counter and not the last entry served, so it still
        /// names a fanout the hub no longer holds. That is what lets a
        /// follower tell "caught up" from "there is more I cannot have".
        highest_sequence: u64,
        /// `CatchUpEntry entries<V>`: the fanouts, in hub order, by
        /// increasing sequence. May be shorter than the request's
        /// `limit`, and may skip sequences the hub does not serve:
        /// retention (§6) and the requester's own participation (§8)
        /// both bound it.
        entries: Vec<CatchUpEntry>,
    },
    /// `case outOfWindow`.
    OutOfWindow {
        /// `uint64 oldestHeld`: the oldest sequence the hub still holds
        /// for the room, or 0 if it holds none.
        oldest_held: u64,
    },
    /// `notAuthorized`, which has no arm and carries nothing.
    NotAuthorized,
    /// `noSuchRoom`, which has no arm and carries nothing.
    NoSuchRoom,
}

impl CatchUpResult {
    /// The `responseCode` this arm belongs to.
    #[must_use]
    pub fn response_code(&self) -> CatchUpResponseCode {
        match self {
            Self::Success { .. } => CatchUpResponseCode::Success,
            Self::OutOfWindow { .. } => CatchUpResponseCode::OutOfWindow,
            Self::NotAuthorized => CatchUpResponseCode::NotAuthorized,
            Self::NoSuchRoom => CatchUpResponseCode::NoSuchRoom,
        }
    }
}

/// `CatchUpResponse` (INVENTED, NOT FROM SPEC;
/// `docs/design/mimi-catchup.md` §5).
///
/// ~~~text
/// struct {
///     CatchUpResponseCode responseCode;
///     UTF8String errorDescription;
///     select (responseCode) {
///       case success:
///         uint64 highestSequence;
///         CatchUpEntry entries<V>;
///       case outOfWindow:
///         uint64 oldestHeld;
///     };
/// } CatchUpResponse;
/// ~~~
///
/// A refusal is a response code and NOT an HTTP status, so that it
/// cannot be confused with a status produced by something other than
/// the hub -- a proxy, a gateway, a cache. An out-of-window answer
/// makes a follower record a permanent loss and tell its users history
/// is missing, which is not a thing to do on an intermediary's word
/// (bead mimid-1wgh.37.104.14).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CatchUpResponse {
    /// `UTF8String errorDescription` (a [`Utf8String`], decision
    /// mimid-1wgh.5.20).
    pub error_description: Utf8String,
    /// `responseCode` and its arm.
    pub result: CatchUpResult,
}

impl Size for CatchUpResponse {
    fn tls_serialized_len(&self) -> usize {
        1 + self.error_description.tls_serialized_len()
            + match &self.result {
                CatchUpResult::Success {
                    entries,
                    highest_sequence: _,
                } => 8 + entries.tls_serialized_len(),
                CatchUpResult::OutOfWindow { .. } => 8,
                CatchUpResult::NotAuthorized | CatchUpResult::NoSuchRoom => 0,
            }
    }
}

impl Serialize for CatchUpResponse {
    fn tls_serialize<W: Write>(&self, writer: &mut W) -> Result<usize, tls_codec::Error> {
        let mut written = self.result.response_code().tls_serialize(writer)?;
        written += self.error_description.tls_serialize(writer)?;
        written += match &self.result {
            CatchUpResult::Success {
                highest_sequence,
                entries,
            } => highest_sequence.tls_serialize(writer)? + entries.tls_serialize(writer)?,
            CatchUpResult::OutOfWindow { oldest_held } => oldest_held.tls_serialize(writer)?,
            CatchUpResult::NotAuthorized | CatchUpResult::NoSuchRoom => 0,
        };
        Ok(written)
    }
}

impl Deserialize for CatchUpResponse {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let response_code = CatchUpResponseCode::tls_deserialize(bytes)?;
        let error_description = Utf8String::tls_deserialize(bytes)?;
        let result = match response_code {
            CatchUpResponseCode::Success => CatchUpResult::Success {
                highest_sequence: u64::tls_deserialize(bytes)?,
                entries: Vec::<CatchUpEntry>::tls_deserialize(bytes)?,
            },
            CatchUpResponseCode::OutOfWindow => CatchUpResult::OutOfWindow {
                oldest_held: u64::tls_deserialize(bytes)?,
            },
            CatchUpResponseCode::NotAuthorized => CatchUpResult::NotAuthorized,
            CatchUpResponseCode::NoSuchRoom => CatchUpResult::NoSuchRoom,
        };
        Ok(Self {
            error_description,
            result,
        })
    }
}

impl CatchUpResponse {
    /// A successful answer.
    #[must_use]
    pub fn served(highest_sequence: u64, entries: Vec<CatchUpEntry>) -> Self {
        Self {
            error_description: Utf8String::default(),
            result: CatchUpResult::Success {
                highest_sequence,
                entries,
            },
        }
    }

    /// The §5.1 refusal: the range asked for is older than the hub
    /// holds. `oldest_held` is the oldest sequence it still has, or 0.
    #[must_use]
    pub fn out_of_window(oldest_held: u64) -> Self {
        Self {
            error_description: Utf8String::default(),
            result: CatchUpResult::OutOfWindow { oldest_held },
        }
    }

    /// The entries served, empty for any answer but a successful one.
    #[must_use]
    pub fn entries(&self) -> &[CatchUpEntry] {
        match &self.result {
            CatchUpResult::Success { entries, .. } => entries,
            _ => &[],
        }
    }

    /// Decodes a response body, which must be exactly one
    /// `CatchUpResponse`.
    ///
    /// # Errors
    ///
    /// [`tls_codec::Error`] if the body is short, has trailing bytes,
    /// carries an unknown response code, or -- for a successful answer
    /// -- carries more than [`MAX_CATCH_UP_ENTRIES`] entries, an entry
    /// whose sequence is zero, entries out of increasing order, or an
    /// entry above the stated highest. The order matters: a follower
    /// applies them in the order given, and the hub's order is the
    /// room's order (protocol-07 §5.5).
    pub fn decode(body: &[u8]) -> Result<Self, tls_codec::Error> {
        let response = Self::tls_deserialize_exact(body)?;
        let CatchUpResult::Success {
            highest_sequence,
            entries,
        } = &response.result
        else {
            return Ok(response);
        };
        if entries.len() > MAX_CATCH_UP_ENTRIES {
            return Err(tls_codec::Error::DecodingError(format!(
                "catchUp answer has {} entries, more than {MAX_CATCH_UP_ENTRIES}",
                entries.len()
            )));
        }
        let mut previous = 0u64;
        for entry in entries {
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
        if previous > *highest_sequence {
            return Err(tls_codec::Error::DecodingError(format!(
                "catchUp served {previous} above its highest {highest_sequence}"
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
        match &self.result {
            CatchUpResult::Success {
                highest_sequence,
                entries,
            } => entries
                .last()
                .is_none_or(|entry| entry.sequence >= *highest_sequence),
            // Nothing more will come, so there is nothing to ask again
            // for.
            _ => true,
        }
    }
}
