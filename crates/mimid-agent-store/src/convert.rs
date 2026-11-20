//! The conversion rules of draft-atwood-jmap-chat-mimi-00 that need no
//! state: `senderMsgId`, message references, `topicId`, and RFC 3339 UTC
//! dates. Every front end shows a message under the same `senderMsgId`.

use mimi_content::MessageId;
use ulid::Ulid;

/// Octets 1 through 10 of a MIMI message ID, counting from 0: the ten
/// octets after the hash algorithm octet. A Message's `senderMsgId` carries
/// them as its random component, and a MIMI reference resolves by them
/// (draft-atwood-jmap-chat-mimi-00 §Message Identifiers).
pub type MessageRef = [u8; 10];

/// The reference octets of `id`.
#[must_use]
pub fn message_ref(id: &MessageId) -> MessageRef {
    let mut out = [0u8; 10];
    out.copy_from_slice(&id.0[1..11]);
    out
}

/// The `senderMsgId` of a MIMI message: the ULID whose time is the hub's
/// acceptance time `accepted_at` in milliseconds and whose random component
/// is octets 1 through 10 of its message ID (draft-atwood-jmap-chat-mimi-00
/// §Message Identifiers), as its 26 Crockford base32 characters.
#[must_use]
pub fn sender_msg_id(accepted_at: u64, id: &MessageId) -> String {
    let mut random = [0u8; 16];
    random[6..].copy_from_slice(&message_ref(id));
    Ulid::from_parts(accepted_at, u128::from_be_bytes(random)).to_string()
}

/// The JMAP `topicId` of a MIMI `topicId` (draft-atwood-jmap-chat-mimi-00
/// §Topics): the octets as UTF-8, or none when they are empty, not UTF-8,
/// or over 255 octets.
#[must_use]
pub fn topic_id(octets: &[u8]) -> Option<String> {
    if octets.is_empty() || octets.len() > 255 {
        return None;
    }
    String::from_utf8(octets.to_vec()).ok()
}

/// An RFC 8620 §1.4 UTCDate for `ms` milliseconds since the UNIX epoch,
/// with the fraction omitted when it is zero. The same rendering as
/// mimid-server's JMAP projection.
#[must_use]
pub fn utc_date(ms: u64) -> String {
    let secs = ms / 1000;
    let millis = ms % 1000;
    let days = secs / 86_400;
    let rest = secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let time = format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}",
        rest / 3600,
        rest / 60 % 60,
        rest % 60
    );
    if millis == 0 {
        format!("{time}Z")
    } else {
        format!("{time}.{millis:03}Z")
    }
}

/// The proleptic Gregorian date `days` after 1970-01-01 (H. Hinnant,
/// "chrono-Compatible Low-Level Date Algorithms", `civil_from_days`).
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z % 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    // Oracle: Python, ULID(1_700_000_000_001, bytes 1..11 of the ID) in
    // Crockford base32, where the ID's octets 1..11 are 0x01..0x0a:
    //   t = 1_700_000_000_001; r = int.from_bytes(bytes(range(1, 11)), "big")
    //   n = (t << 80) | r; base32 of n over 26 characters.
    #[test]
    fn sender_msg_id_matches_reference_value() {
        let mut id = [0u8; 32];
        for (i, b) in id.iter_mut().enumerate() {
            *b = i as u8;
        }
        assert_eq!(
            sender_msg_id(1_700_000_000_001, &MessageId(id)),
            "01HF7YAT01041061050R3GG28A"
        );
    }

    #[test]
    fn sender_msg_id_ignores_the_hash_octet_and_the_tail() {
        let mut a = [7u8; 32];
        let mut b = a;
        a[0] = 1;
        b[0] = 2;
        b[11..].fill(9);
        assert_eq!(
            sender_msg_id(5, &MessageId(a)),
            sender_msg_id(5, &MessageId(b))
        );
        b[10] = 0;
        assert_ne!(
            sender_msg_id(5, &MessageId(a)),
            sender_msg_id(5, &MessageId(b))
        );
    }

    #[test]
    fn topic_ids_follow_the_draft() {
        assert_eq!(topic_id(b"plans").as_deref(), Some("plans"));
        assert_eq!(topic_id(b""), None);
        assert_eq!(topic_id(&[0xff, 0xfe]), None);
        assert_eq!(topic_id(&[b'a'; 255]).map(|t| t.len()), Some(255));
        assert_eq!(topic_id(&[b'a'; 256]), None);
    }

    #[test]
    fn utc_dates() {
        for (ms, expected) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_700_000_000_001, "2023-11-14T22:13:20.001Z"),
            (951_782_400_000, "2000-02-29T00:00:00Z"),
        ] {
            assert_eq!(utc_date(ms), expected, "{ms}");
        }
    }
}
