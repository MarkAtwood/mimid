//! The conversion rules of draft-atwood-jmap-chat-mimi-00 that need no
//! state ([`mimid_agent_store::convert`]), with JMAP types.

use jmap_server::UTCDate;

/// [`mimid_agent_store::convert::utc_date`] as a JMAP UTCDate.
pub(crate) fn utc_date(ms: u64) -> UTCDate {
    UTCDate::from(mimid_agent_store::convert::utc_date(ms).as_str())
}
