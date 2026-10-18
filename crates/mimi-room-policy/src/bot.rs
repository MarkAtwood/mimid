//! The `bot_policy` component of room-policy-04 §6.7.

use std::io::Read;

use tls_codec::{Deserialize, TlsDeserialize, TlsSerialize, TlsSize};

use crate::{Bool, NO_ROLE_INDEX, PolicyError, Uri};

/// The `Bot` struct of room-policy-04 §6.7: one allowed chat bot.
///
/// `name` and `description` are opaque and "merely descriptive"; the draft
/// does not call them text, so this crate does not require UTF-8 or check
/// them in any way (decision mimid-1wgh.3.62). Rendering them safely is the
/// caller's job.
///
/// Whether a non-zero `bot_role_index` names a defined role is not checked,
/// since §6.7 does not state it (decision mimid-1wgh.3.64).
#[derive(Debug, Clone, PartialEq, Eq, Hash, TlsSize, TlsSerialize, TlsDeserialize)]
pub struct Bot {
    /// `opaque name<V>`.
    // room-policy-04 §6.7; decision mimid-1wgh.3.62
    pub name: Vec<u8>,
    /// `opaque description<V>`.
    // room-policy-04 §6.7; decision mimid-1wgh.3.62
    pub description: Vec<u8>,
    /// `Uri homepage`; a zero-length value means absent (decisions
    /// mimid-1wgh.3.18, mimid-1wgh.3.64).
    // room-policy-04 §6.7; decision mimid-1wgh.3.64
    pub homepage: Uri,
    /// `bool local_client_bot`. If true, the bot is not a participant and
    /// sees the room only through another user's client.
    pub local_client_bot: Bool,
    /// `uint32 bot_role_index`: the role the bot operates in; 0 means it is
    /// not an active participant.
    pub bot_role_index: u32,
    /// `bool can_target_message_in_group`. If true, the bot may send
    /// messages to specific individual users in the room.
    pub can_target_message_in_group: Bool,
    /// `bool per_user_content`. If true, the bot may send distinct content
    /// to each member.
    pub per_user_content: Bool,
}

/// The `BotPolicy` struct of room-policy-04 §6.7: the chat bots allowed in
/// the room, and the data of the `bot_policy` component.
///
/// Decoding checks the wire format and [`BotPolicy::validate`]. A value
/// built in code is not checked until `validate` is called; encoding does
/// not check it.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default, TlsSize, TlsSerialize)]
pub struct BotPolicy {
    /// `Bot allowed_bots<V>`.
    pub allowed_bots: Vec<Bot>,
}

/// `BotPolicy BotPolicyData` of room-policy-04 §6.7.
pub type BotPolicyData = BotPolicy;

/// `BotPolicy BotPolicyUpdate` of room-policy-04 §6.7: an `AppDataUpdate`
/// that replaces the whole `bot_policy` (decision mimid-1wgh.3.20).
pub type BotPolicyUpdate = BotPolicy;

impl BotPolicy {
    /// Checks the structural rule room-policy-04 §6.7 states for this
    /// component: "A bot with local_client_bot set to true has a
    /// bot_role_index of 0."
    ///
    /// # Errors
    ///
    /// [`PolicyError::LocalClientBotWithRole`] for the first bot that
    /// breaks the rule.
    pub fn validate(&self) -> Result<(), PolicyError> {
        for (position, bot) in self.allowed_bots.iter().enumerate() {
            if bool::from(bot.local_client_bot) && bot.bot_role_index != NO_ROLE_INDEX {
                return Err(PolicyError::LocalClientBotWithRole {
                    bot: position,
                    bot_role_index: bot.bot_role_index,
                });
            }
        }
        Ok(())
    }
}

impl Deserialize for BotPolicy {
    fn tls_deserialize<R: Read>(bytes: &mut R) -> Result<Self, tls_codec::Error> {
        let policy = Self {
            allowed_bots: Vec::tls_deserialize(bytes)?,
        };
        policy
            .validate()
            .map_err(|error| tls_codec::Error::DecodingError(error.to_string()))?;
        Ok(policy)
    }
}
