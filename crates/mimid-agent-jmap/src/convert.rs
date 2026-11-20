//! The conversion rules of draft-atwood-jmap-chat-mimi-00 that need no
//! state ([`mimid_agent_store::convert`]), with JMAP types.

use jmap_server::{Id, UTCDate};
use mimi_content::MessageId;

pub(crate) use mimid_agent_store::convert::message_ref;

/// [`mimid_agent_store::convert::sender_msg_id`] as a JMAP Id.
pub(crate) fn sender_msg_id(accepted_at: u64, id: &MessageId) -> Id {
    Id::from(mimid_agent_store::convert::sender_msg_id(accepted_at, id))
}

/// [`mimid_agent_store::convert::utc_date`] as a JMAP UTCDate.
pub(crate) fn utc_date(ms: u64) -> UTCDate {
    UTCDate::from(mimid_agent_store::convert::utc_date(ms).as_str())
}
