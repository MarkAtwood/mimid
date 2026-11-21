//! The delivery journal (bead mimid-s4b1): the events [`crate::Agent`]
//! found and its caller has not acknowledged, kept in the `journal` table
//! of the agent's database (`agent.sqlite`, [`crate::DATABASE_FILE`]).
//!
//! Receiving consumes MLS secrets (RFC 9420 §9.2): a message decrypted once
//! cannot be decrypted again. So an event is written to the journal, with
//! the server position it came from, before [`crate::Agent::receive`]
//! returns it, and leaves the journal only at
//! [`crate::Agent::acknowledge`] or [`crate::Agent::acknowledge_in`], after
//! the caller has stored it. A crash in between delivers it again at the
//! next start.
//!
//! OpenMLS writes the consumed secrets through the same connection as the
//! journal, and [`crate::Agent::receive`] handles each server Message in
//! one transaction (bead mimid-1vul.10): the secrets it consumes, the
//! group state, its events in the journal and that it was handled commit
//! together, or none of them does and the Message is handled again. A
//! caller that keeps its records in the same database removes the
//! events it stored in the transaction that stores them
//! ([`crate::Agent::acknowledge_in`]), so storing and acknowledging
//! commit together too.
//!
//! # Limitations
//!
//! - A Message whose proposals this agent commits as a leave
//!   (`Agent::receive`) is handled in two transactions, since the Commit
//!   goes to the server between them: the first ends with how far into
//!   the Message it got, and the leave Commit's own writes commit as it
//!   is merged. A crash after the merge and before the second
//!   transaction loses the leave's `MembersChanged` event (the
//!   membership the agent reports afterwards still shows it).
//! - A caller that acknowledges with [`crate::Agent::acknowledge`] after
//!   storing elsewhere sees an event again after a crash between the two,
//!   so it must tolerate one it has already stored.

use mimi_content::{MessageId, MimiContent};
use mimi_mls::tls_codec::{Deserialize as _, Serialize as _};
use mimi_protocol::{Frank, ServerFrankingContext};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use crate::agent::{Event, ReceivedMessage};
use crate::frank::VerifiedFrank;

/// One journaled [`Event`]. Binary fields are hex: a received message's
/// content is its `application_data` as received (mimi-content CBOR), its
/// frank and the frank's context their TLS encodings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase"
)]
pub(crate) enum Journaled {
    InviteArrived {
        number: u64,
    },
    Message {
        room: String,
        sender: String,
        message_id: String,
        accepted_at: u64,
        content: String,
        text: Option<String>,
        frank: Option<(String, String)>,
        /// A message this device sent ([`Event::Sent`]); absent for a
        /// received one.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        own: bool,
    },
    MembersChanged {
        room: String,
        epoch: u64,
        participants: Vec<String>,
        /// Absent in entries written before bead mimid-cqof, which read
        /// as an unknown committer.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        committer: Option<String>,
    },
    Proposal {
        room: String,
        sender: Option<String>,
    },
    Left {
        room: String,
    },
    IdentityChanged {
        room: String,
        user: String,
        pinned: String,
        presented: Option<String>,
    },
    RemovedWithoutAppDataUpdate {
        room: String,
        user: String,
        epoch: u64,
    },
    Problem {
        room: Option<String>,
        description: String,
    },
}

impl Journaled {
    /// The journal form of `event`. A message whose content or frank does
    /// not encode becomes a [`Journaled::Problem`]; neither happens for
    /// values that were decoded.
    pub fn of(event: Event) -> Self {
        match event {
            Event::InviteArrived { number } => Self::InviteArrived { number },
            Event::Message(message) => {
                let room = message.room.clone();
                message_of(*message, false).unwrap_or_else(|why| Self::Problem {
                    room: Some(room),
                    description: format!("a received message could not be journaled: {why}"),
                })
            }
            Event::Sent(message) => {
                let room = message.room.clone();
                message_of(*message, true).unwrap_or_else(|why| Self::Problem {
                    room: Some(room),
                    description: format!("a sent message could not be journaled: {why}"),
                })
            }
            Event::MembersChanged {
                room,
                epoch,
                participants,
                committer,
            } => Self::MembersChanged {
                room,
                epoch,
                participants,
                committer,
            },
            Event::Proposal { room, sender } => Self::Proposal { room, sender },
            Event::Left { room } => Self::Left { room },
            Event::IdentityChanged {
                room,
                user,
                pinned,
                presented,
            } => Self::IdentityChanged {
                room,
                user,
                pinned,
                presented,
            },
            Event::RemovedWithoutAppDataUpdate { room, user, epoch } => {
                Self::RemovedWithoutAppDataUpdate { room, user, epoch }
            }
            Event::Problem { room, description } => Self::Problem { room, description },
        }
    }

    /// The event back. An entry that no longer decodes (a hand-edited
    /// database) is an [`Event::Problem`].
    pub fn event(&self) -> Event {
        match self.clone() {
            Self::InviteArrived { number } => Event::InviteArrived { number },
            Self::Message { room, own, .. } => match self.message() {
                Ok(message) if own => Event::Sent(Box::new(message)),
                Ok(message) => Event::Message(Box::new(message)),
                Err(why) => Event::Problem {
                    room: Some(room),
                    description: format!("a journaled message does not decode: {why}"),
                },
            },
            Self::MembersChanged {
                room,
                epoch,
                participants,
                committer,
            } => Event::MembersChanged {
                room,
                epoch,
                participants,
                committer,
            },
            Self::Proposal { room, sender } => Event::Proposal { room, sender },
            Self::Left { room } => Event::Left { room },
            Self::IdentityChanged {
                room,
                user,
                pinned,
                presented,
            } => Event::IdentityChanged {
                room,
                user,
                pinned,
                presented,
            },
            Self::RemovedWithoutAppDataUpdate { room, user, epoch } => {
                Event::RemovedWithoutAppDataUpdate { room, user, epoch }
            }
            Self::Problem { room, description } => Event::Problem { room, description },
        }
    }

    fn message(&self) -> Result<ReceivedMessage, String> {
        let Self::Message {
            room,
            sender,
            message_id,
            accepted_at,
            content,
            text,
            frank,
            ..
        } = self
        else {
            return Err("not a message".to_owned());
        };
        let id: [u8; 32] = unhex(message_id, "the message ID")?
            .try_into()
            .map_err(|_| "the message ID is not 32 octets".to_owned())?;
        let application_data = unhex(content, "the content")?;
        let content =
            MimiContent::decode(&application_data).map_err(|e| format!("the content: {e}"))?;
        let frank = match frank {
            None => None,
            Some((frank, context)) => Some(VerifiedFrank {
                frank: Frank::tls_deserialize_exact(&unhex(frank, "the frank")?[..])
                    .map_err(|e| format!("the frank: {e}"))?,
                context: ServerFrankingContext::tls_deserialize_exact(
                    &unhex(context, "the frank context")?[..],
                )
                .map_err(|e| format!("the frank context: {e}"))?,
            }),
        };
        Ok(ReceivedMessage {
            room: room.clone(),
            sender: sender.clone(),
            message_id: MessageId(id),
            accepted_at: *accepted_at,
            content,
            application_data,
            text: text.clone(),
            frank,
        })
    }
}

fn message_of(message: ReceivedMessage, own: bool) -> Result<Journaled, String> {
    let frank = match &message.frank {
        None => None,
        Some(verified) => Some((
            hex::encode(
                verified
                    .frank
                    .tls_serialize_detached()
                    .map_err(|e| format!("the frank: {e}"))?,
            ),
            hex::encode(
                verified
                    .context
                    .tls_serialize_detached()
                    .map_err(|e| format!("the frank context: {e}"))?,
            ),
        )),
    };
    Ok(Journaled::Message {
        room: message.room,
        sender: message.sender,
        message_id: hex::encode(message.message_id.0),
        accepted_at: message.accepted_at,
        content: hex::encode(&message.application_data),
        text: message.text,
        frank,
        own,
    })
}

fn unhex(text: &str, what: &str) -> Result<Vec<u8>, String> {
    hex::decode(text).map_err(|_| format!("{what} is not hex"))
}

/// What [`crate::Agent::receive`] delivered, for
/// [`crate::Agent::acknowledge`] or [`crate::Agent::acknowledge_in`]: the
/// journal entries up to sequence number `through` (0: none).
#[derive(Debug, PartialEq, Eq)]
#[must_use = "events stay in the journal and come again until acknowledged"]
pub struct Receipt {
    pub(crate) through: i64,
}

/// Appends `entries` to the journal, in order.
pub(crate) fn append(connection: &Connection, entries: &[Journaled]) -> rusqlite::Result<()> {
    if entries.is_empty() {
        return Ok(());
    }
    let mut insert = connection.prepare_cached("INSERT INTO journal (entry) VALUES (?1)")?;
    for entry in entries {
        let text = serde_json::to_string(entry)
            .map_err(|e| rusqlite::Error::ToSqlConversionFailure(e.into()))?;
        insert.execute([text])?;
    }
    Ok(())
}

/// Every event in the journal, oldest first, and the receipt for them. An
/// entry that no longer parses (a hand-edited database) is an
/// [`Event::Problem`].
pub(crate) fn read(connection: &Connection) -> rusqlite::Result<(Vec<Event>, Receipt)> {
    let mut select = connection.prepare("SELECT seq, entry FROM journal ORDER BY seq")?;
    let rows = select.query_map([], |row| {
        Ok((row.get::<_, i64>(0)?, row.get::<_, String>(1)?))
    })?;
    let mut events = Vec::new();
    let mut through = 0;
    for row in rows {
        let (seq, entry) = row?;
        through = seq;
        events.push(match serde_json::from_str::<Journaled>(&entry) {
            Ok(journaled) => journaled.event(),
            Err(e) => Event::Problem {
                room: None,
                description: format!("journal entry {seq} does not parse: {e}"),
            },
        });
    }
    Ok((events, Receipt { through }))
}

/// Removes the entries `receipt` names.
pub(crate) fn remove(connection: &Connection, receipt: &Receipt) -> rusqlite::Result<()> {
    if receipt.through > 0 {
        connection.execute("DELETE FROM journal WHERE seq <= ?1", [receipt.through])?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A `membersChanged` entry as the `journal` table holds it, decoded to the
    /// expected event and encoded back to the same bytes: one written
    /// before bead mimid-cqof, without `committer`, reads as an unknown
    /// committer; one with it keeps it. The entries are written by hand,
    /// in the journal's documented form (serde's internal `kind` tag,
    /// camelCase fields).
    #[test]
    fn members_changed_entries_round_trip_with_and_without_a_committer() {
        let cases = [
            (
                r#"{"kind":"membersChanged","room":"mimi://a.example/r/one","epoch":7,"participants":["mimi://a.example/u/alice","mimi://a.example/u/bob"]}"#,
                None,
            ),
            (
                r#"{"kind":"membersChanged","room":"mimi://a.example/r/one","epoch":7,"participants":["mimi://a.example/u/alice","mimi://a.example/u/bob"],"committer":"mimi://a.example/u/bob"}"#,
                Some("mimi://a.example/u/bob".to_owned()),
            ),
        ];
        for (entry, committer) in cases {
            let journaled: Journaled = serde_json::from_str(entry).unwrap();
            let event = journaled.event();
            assert_eq!(
                event,
                Event::MembersChanged {
                    room: "mimi://a.example/r/one".to_owned(),
                    epoch: 7,
                    participants: vec![
                        "mimi://a.example/u/alice".to_owned(),
                        "mimi://a.example/u/bob".to_owned(),
                    ],
                    committer,
                },
                "{entry}"
            );
            assert_eq!(serde_json::to_string(&Journaled::of(event)).unwrap(), entry);
        }
    }
}
