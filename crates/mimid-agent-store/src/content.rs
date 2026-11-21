//! What a received message's content becomes in the store: its body type,
//! the safe file names of its attachments, and its calls to join
//! (docs/design/agent-frontends.md §7.24).
//!
//! # Limitations
//!
//! - Only `text/markdown` is told apart from plain text; every other
//!   single part is plain.
//! - A file name is made safe by character, not by meaning: bidi and
//!   zero-width characters stay, for the front end to render safely.
//! - An inline session part is a call only if it is text: its first line
//!   that is not empty or a `text/uri-list` comment is the URL. Any other
//!   inline session description (SDP, say) is left out.
//! - A call's URL is a link only if it is `https` or `wss` and plain
//!   ASCII ([`is_call_link`]); the check is by characters, not a URL
//!   parser.

use mimi_content::{MimiContent, NestedPart, Part};

use crate::record::Call;

/// The longest call URL kept, in octets; a longer one is cut (and then is
/// no link). INVENTED, NOT FROM SPEC.
pub const MAX_CALL_URL_LEN: usize = 2048;

/// The longest call description kept, in characters; a longer one is
/// cut. INVENTED, NOT FROM SPEC.
pub const MAX_CALL_DESCRIPTION_CHARS: usize = 256;

/// The most calls kept of one received message; the rest are left out.
/// INVENTED, NOT FROM SPEC.
pub const MAX_CALLS_PER_MESSAGE: usize = 4;

/// The longest file name kept for a received attachment, in characters;
/// a longer one is cut. INVENTED, NOT FROM SPEC.
pub const MAX_FILENAME_CHARS: usize = 255;

/// The file name of a received attachment that has none.
pub const FALLBACK_FILENAME: &str = "attachment";

/// The body type of a stored message, saved as its media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[non_exhaustive]
pub enum BodyType {
    /// `text/plain`.
    #[serde(rename = "text/plain")]
    Plain,
    /// `text/markdown`.
    #[serde(rename = "text/markdown")]
    Markdown,
}

/// The body type of received `content`: [`BodyType::Markdown`] for a
/// `text/markdown` single part, [`BodyType::Plain`] otherwise.
#[must_use]
pub fn body_type(content: &MimiContent) -> BodyType {
    match &content.nested_part.part {
        Part::Single { content_type, .. }
            if content_type
                .to_ascii_lowercase()
                .starts_with("text/markdown") =>
        {
            BodyType::Markdown
        }
        _ => BodyType::Plain,
    }
}

/// A received attachment's file name as an Attachment may carry it
/// (draft-atwood-jmap-chat-00 §Attachment: no `/`, `\` or null): those
/// and other control characters become `_`, it is cut to
/// [`MAX_FILENAME_CHARS`], and an empty one is [`FALLBACK_FILENAME`].
#[must_use]
pub fn safe_filename(name: &str) -> String {
    let safe: String = name
        .chars()
        .take(MAX_FILENAME_CHARS)
        .map(|c| {
            if c == '/' || c == '\\' || c.is_control() {
                '_'
            } else {
                c
            }
        })
        .collect();
    if safe.trim().is_empty() {
        FALLBACK_FILENAME.to_owned()
    } else {
        safe
    }
}

/// The call that session part `part` names (mimi-content-10 §5.10), or
/// `None` for a part that is not of disposition `session`, or an inline
/// one that is not text or names no URL. Nothing is fetched.
#[must_use]
pub fn call_of(part: &NestedPart) -> Option<Call> {
    if part.disposition != mimi_content::Disposition::SESSION {
        return None;
    }
    let (url, description, expires) = match &part.part {
        Part::External(external) => (
            external.url.clone(),
            external.description.clone(),
            (external.expires != 0).then_some(external.expires),
        ),
        Part::Single {
            content_type,
            content,
        } if content_type.to_ascii_lowercase().starts_with("text/") => {
            let text = String::from_utf8_lossy(content);
            let url = text
                .lines()
                .map(str::trim)
                .find(|line| !line.is_empty() && !line.starts_with('#'))?
                .to_owned();
            (url, String::new(), None)
        }
        _ => return None,
    };
    if url.is_empty() {
        return None;
    }
    Some(Call {
        url: cut_to_octets(url, MAX_CALL_URL_LEN),
        description: description
            .chars()
            .take(MAX_CALL_DESCRIPTION_CHARS)
            .collect(),
        expires,
    })
}

/// `text` cut to at most `max` octets, on a character boundary.
fn cut_to_octets(mut text: String, max: usize) -> String {
    if text.len() > max {
        let mut end = max;
        while !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
    }
    text
}

/// Whether call URL `url` may be shown as a link
/// (docs/design/agent-frontends.md §7.24): its scheme is `https` or `wss`
/// (in any case), a host follows `//`, and it is printable ASCII with no
/// space, at most [`MAX_CALL_URL_LEN`] octets. Anything else is shown as
/// text and never opened.
#[must_use]
pub fn is_call_link(url: &str) -> bool {
    let Some((scheme, rest)) = url.split_once("://") else {
        return false;
    };
    let host = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.rsplit_once('@').map_or(host, |(_, host)| host);
    (scheme.eq_ignore_ascii_case("https") || scheme.eq_ignore_ascii_case("wss"))
        && !host.is_empty()
        && !host.starts_with(':')
        && url.len() <= MAX_CALL_URL_LEN
        && url.bytes().all(|b| b.is_ascii_graphic())
}

#[cfg(test)]
mod tests {
    use super::*;
    use mimi_content::{Disposition, ExternalPart};

    fn external(url: &str, description: &str, expires: u32) -> NestedPart {
        NestedPart {
            disposition: Disposition::SESSION,
            language: String::new(),
            part: Part::External(ExternalPart {
                content_type: String::new(),
                url: url.to_owned(),
                expires,
                size: 0,
                enc_alg: 0,
                key: Vec::new(),
                nonce: Vec::new(),
                aad: Vec::new(),
                hash_alg: 0,
                content_hash: Vec::new(),
                description: description.to_owned(),
                filename: String::new(),
            }),
        }
    }

    /// Oracle: mimi-content-10 §5.10's example part.
    #[test]
    fn the_conferencing_example_is_a_call() {
        let part = external(
            "https://example.com/join/12345",
            "Join the Foo 118 conference",
            0,
        );
        let call = call_of(&part).unwrap();
        assert_eq!(
            call,
            Call {
                url: "https://example.com/join/12345".to_owned(),
                description: "Join the Foo 118 conference".to_owned(),
                expires: None,
            }
        );
        assert!(call.is_link());
        assert_eq!(
            call_of(&external("wss://x.example/r", "", 7))
                .unwrap()
                .expires,
            Some(7)
        );
        // Another disposition is no call.
        let mut attachment = part.clone();
        attachment.disposition = Disposition::ATTACHMENT;
        assert_eq!(call_of(&attachment), None);
        assert_eq!(call_of(&external("", "x", 0)), None);
    }

    /// Oracle: RFC 2483 §5 `text/uri-list`: `#` lines are comments.
    #[test]
    fn an_inline_session_part_is_a_call_if_it_is_text() {
        let inline = |content_type: &str, content: &[u8]| NestedPart {
            disposition: Disposition::SESSION,
            language: String::new(),
            part: Part::Single {
                content_type: content_type.to_owned(),
                content: content.to_vec(),
            },
        };
        let call = call_of(&inline(
            "text/uri-list",
            b"# the call\r\nhttps://example.com/join/12345\r\nhttps://other.example/\r\n",
        ))
        .unwrap();
        assert_eq!(call.url, "https://example.com/join/12345");
        assert_eq!(call.description, "");
        assert_eq!(
            call_of(&inline("text/plain", b"  sip:alice@example.com \n"))
                .unwrap()
                .url,
            "sip:alice@example.com"
        );
        assert_eq!(call_of(&inline("application/sdp", b"v=0\r\n")), None);
        assert_eq!(call_of(&inline("text/plain", b"\n# only\n")), None);
    }

    #[test]
    fn only_plain_https_and_wss_urls_are_links() {
        for link in [
            "https://example.com/join/12345",
            "HTTPS://example.com",
            "wss://example.com:8443/room?x=1#y",
            "https://user@example.com/",
        ] {
            assert!(is_call_link(link), "{link}");
        }
        for text in [
            "http://example.com/join",
            "sip:alice@example.com",
            "tel:+15555550100",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https:example.com",
            "https://",
            "https:///path",
            "https://:443/",
            "https://example.com/a b",
            "https://example.com/\r\nPRIVMSG #x :hi",
            "https://ex\u{0430}mple.com/",
            "https://example.com/\u{202e}",
            "",
        ] {
            assert!(!is_call_link(text), "{text:?}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_CALL_URL_LEN));
        assert!(!is_call_link(&long));
    }

    /// Oracle: docs/design/agent-frontends.md §7.24, written out by hand.
    #[test]
    fn calls_as_text() {
        let call = |url: &str, description: &str| Call {
            url: url.to_owned(),
            description: description.to_owned(),
            expires: None,
        };
        assert_eq!(
            call(
                "https://example.com/join/12345",
                "Join the Foo 118 conference"
            )
            .text(),
            "call: Join the Foo 118 conference <https://example.com/join/12345>"
        );
        assert_eq!(
            call("wss://example.com/r", "").text(),
            "call: <wss://example.com/r>"
        );
        assert_eq!(
            call("sip:alice@example.com", "Ring me").text(),
            "call: Ring me (not a web link: sip:alice@example.com)"
        );
        // One line, whatever the peer sent.
        assert_eq!(
            call("http://x\r\nQUIT", "a\nb\u{1}").text(),
            "call: a b (not a web link: http://x  QUIT)"
        );
    }

    #[test]
    fn received_calls_are_cut_to_the_limits() {
        let url = format!("https://example.com/{}", "\u{e9}".repeat(MAX_CALL_URL_LEN));
        let description = "d".repeat(MAX_CALL_DESCRIPTION_CHARS + 1);
        let call = call_of(&external(&url, &description, 0)).unwrap();
        assert!(call.url.len() <= MAX_CALL_URL_LEN);
        assert!(url.starts_with(&call.url));
        assert_eq!(call.description.chars().count(), MAX_CALL_DESCRIPTION_CHARS);
    }

    #[test]
    fn received_file_names_are_made_safe() {
        assert_eq!(safe_filename("report.pdf"), "report.pdf");
        assert_eq!(safe_filename("../../etc/passwd"), ".._.._etc_passwd");
        assert_eq!(safe_filename("a\\b\0c\nd"), "a_b_c_d");
        assert_eq!(safe_filename(""), FALLBACK_FILENAME);
        assert_eq!(safe_filename("   "), FALLBACK_FILENAME);
        // Bidi and zero-width characters are the client's to render
        // safely; they are not control characters (Cc) and stay.
        assert_eq!(safe_filename("a\u{202e}b\u{200b}"), "a\u{202e}b\u{200b}");
        let long = "\u{e9}".repeat(MAX_FILENAME_CHARS + 10);
        assert_eq!(safe_filename(&long).chars().count(), MAX_FILENAME_CHARS);
    }
}
