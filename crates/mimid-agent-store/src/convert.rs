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

/// The milliseconds since the UNIX epoch of an RFC 3339 date in UTC as
/// [`utc_date`] writes it: `YYYY-MM-DDTHH:MM:SS`, an optional fraction of
/// 1 to 9 digits (cut to milliseconds), then `Z`. `None` for anything
/// else, or a date before 1970 or a field out of range.
#[must_use]
pub fn parse_utc_date(text: &str) -> Option<u64> {
    let bytes = text.as_bytes();
    if bytes.len() < 20 || bytes.last() != Some(&b'Z') {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u64> {
        let digits = bytes.get(range)?;
        digits.iter().try_fold(0u64, |n, d| {
            d.is_ascii_digit().then(|| n * 10 + u64::from(d - b'0'))
        })
    };
    let separators = [(4, b'-'), (7, b'-'), (10, b'T'), (13, b':'), (16, b':')];
    if separators.iter().any(|&(i, c)| bytes[i] != c) {
        return None;
    }
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let (hour, minute, second) = (number(11..13)?, number(14..16)?, number(17..19)?);
    let millis = match &bytes[19..bytes.len() - 1] {
        [] => 0,
        [b'.', fraction @ ..] if (1..=9).contains(&fraction.len()) => {
            let mut digits = [b'0'; 3];
            for (slot, d) in digits.iter_mut().zip(fraction) {
                *slot = *d;
            }
            if !fraction.iter().all(u8::is_ascii_digit) {
                return None;
            }
            u64::from(digits[0] - b'0') * 100
                + u64::from(digits[1] - b'0') * 10
                + u64::from(digits[2] - b'0')
        }
        _ => return None,
    };
    if year < 1970 || !(1..=12).contains(&month) || hour > 23 || minute > 59 || second > 59 {
        return None;
    }
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let month_days = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    if day == 0 || day > month_days[usize::try_from(month - 1).ok()?] {
        return None;
    }
    let days = days_from_civil(year, month, day);
    let secs = days * 86_400 + hour * 3600 + minute * 60 + second;
    secs.checked_mul(1000)?.checked_add(millis)
}

/// The days from 1970-01-01 to a proleptic Gregorian date on or after it
/// (H. Hinnant, "chrono-Compatible Low-Level Date Algorithms",
/// `days_from_civil`).
fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let year = if month <= 2 { year - 1 } else { year };
    let era = year / 400;
    let yoe = year % 400;
    let mp = if month > 2 { month - 3 } else { month + 9 };
    let doy = (153 * mp + 2) / 5 + day - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
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
    fn utc_dates_parse_back() {
        // The same reference values as `utc_dates`, read back.
        for (ms, text) in [
            (0, "1970-01-01T00:00:00Z"),
            (1_700_000_000_001, "2023-11-14T22:13:20.001Z"),
            (951_782_400_000, "2000-02-29T00:00:00Z"),
        ] {
            assert_eq!(parse_utc_date(text), Some(ms), "{text}");
        }
        // Every millisecond of a span round-trips through utc_date.
        for ms in (0..400 * 366 * 86_400_000u64).step_by(86_399_999) {
            assert_eq!(parse_utc_date(&utc_date(ms)), Some(ms), "{ms}");
        }
        assert_eq!(
            parse_utc_date("2026-11-16T12:00:00.5Z"),
            parse_utc_date("2026-11-16T12:00:00.500Z")
        );
        assert_eq!(
            parse_utc_date("2026-11-16T12:00:00.123456789Z"),
            parse_utc_date("2026-11-16T12:00:00.123Z")
        );
        for bad in [
            "",
            "2026-11-16T12:00:00",
            "2026-11-16 12:00:00Z",
            "2026-11-16T12:00:00+00:00",
            "2026-02-29T00:00:00Z",
            "1900-02-29T00:00:00Z",
            "1969-12-31T23:59:59Z",
            "2026-13-01T00:00:00Z",
            "2026-11-16T24:00:00Z",
            "2026-11-16T12:00:60Z",
            "2026-11-16T12:00:00.Z",
            "2026-11-16T12:00:00.1234567890Z",
            "2026-11-16T12:00:00.12aZ",
            "+026-11-16T12:00:00Z",
            "2026-11-16T12:00:00Z\0",
        ] {
            assert_eq!(parse_utc_date(bad), None, "{bad:?}");
        }
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
