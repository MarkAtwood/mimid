//! What a received message's content becomes in the store: its body type,
//! and the safe file names of its attachments.
//!
//! # Limitations
//!
//! - Only `text/markdown` is told apart from plain text; every other
//!   single part is plain.
//! - A file name is made safe by character, not by meaning: bidi and
//!   zero-width characters stay, for the front end to render safely.

use mimi_content::{MimiContent, Part};

/// The longest file name kept for a received attachment, in characters;
/// a longer one is cut. INVENTED, NOT FROM SPEC.
pub const MAX_FILENAME_CHARS: usize = 255;

/// The file name of a received attachment that has none.
pub const FALLBACK_FILENAME: &str = "attachment";

/// The body type of a stored message.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum BodyType {
    /// `text/plain`.
    Plain,
    /// `text/markdown`.
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

#[cfg(test)]
mod tests {
    use super::*;

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
