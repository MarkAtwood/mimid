//! IRC lines: parsing what a client sends, writing what the server sends,
//! message-tag escaping (IRCv3 Message Tags, "Escaping values"), and
//! splitting text so that no line the server writes passes
//! [`MAX_LINE`] octets.
//!
//! # Limitations
//!
//! - At most [`MAX_PARAMS`] parameters are read; the rest of a line past
//!   them is the last one, as RFC 1459 §2.3 has it.
//! - Text is split on UTF-8 character boundaries, not between words, so
//!   that the pieces put together give the text back exactly.

/// The most octets of a line without its tags, CR-LF included (RFC 1459
/// §2.3; `LINELEN=512` in 005).
pub const MAX_LINE: usize = 512;

/// The most octets of a line's tag part, `@` and the space after it
/// included, that a client may send once message-tags is on (IRCv3
/// Message Tags, "Size limit").
pub const MAX_CLIENT_TAGS: usize = 8191;

/// The most parameters read from one line (RFC 1459 §2.3.1).
pub const MAX_PARAMS: usize = 15;

/// The octets no parameter may hold, whichever one it is: `middle` is
/// `nospcrlfcl *( ":" / nospcrlfcl )` and `trailing` is `*( ":" / " " /
/// nospcrlfcl )`, and `nospcrlfcl` is "any character except NUL, CR, LF,
/// colon and SPACE" (Modern §"Parameters"). [`Out::to_wire`] writes a
/// space for each of these in a last parameter and `*` for a middle one
/// that holds any.
const FORBIDDEN: [char; 3] = ['\r', '\n', '\0'];

/// The longest name a client sent that this crate writes back into a
/// parameter that is not the last one.
///
/// A reply that says a name is not here echoes the name so that a client
/// can tell which request it answers. No name longer than the longest
/// this daemon could have issued -- a nick, a channel, or a user URI --
/// names anything here, so a longer one is answered with `*`: it tells
/// the client nothing a cut name would, and the reply has to fit
/// [`MAX_LINE`], which [`Out::cut_to_room`] cannot arrange for a
/// parameter that is not the last one without changing which parameter
/// it is.
pub const MAX_ECHO: usize = crate::names::MAX_ACCOUNT;

const _: () = assert!(
    MAX_ECHO >= crate::names::NICKLEN && MAX_ECHO >= crate::names::CHANNELLEN,
    "every name this daemon can issue must be short enough to echo back"
);

/// A line a client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Line {
    /// The tags, in order, with their values unescaped; a tag without a
    /// value has an empty one.
    pub tags: Vec<(String, String)>,
    /// The source (`:prefix`), if any; clients should send none.
    pub source: Option<String>,
    /// The command, as sent (commands are compared case-insensitively).
    pub command: String,
    /// The parameters, the trailing one included.
    pub params: Vec<String>,
}

impl Line {
    /// The command in upper case.
    #[must_use]
    pub fn verb(&self) -> String {
        self.command.to_ascii_uppercase()
    }

    /// Parameter `i`, if there is one.
    #[must_use]
    pub fn param(&self, i: usize) -> Option<&str> {
        self.params.get(i).map(String::as_str)
    }

    /// The value of tag `key` (the last one, if it repeats).
    #[must_use]
    pub fn tag(&self, key: &str) -> Option<&str> {
        self.tags
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }
}

/// Parses `text`, one line without its CR-LF. `None` for a line with no
/// command (empty, or only tags and a source).
#[must_use]
pub fn parse(text: &str) -> Option<Line> {
    let mut rest = text.trim_end_matches(['\r', '\n']);
    let mut tags = Vec::new();
    if let Some(after) = rest.strip_prefix('@') {
        let (raw, tail) = after.split_once(' ').unwrap_or((after, ""));
        tags = parse_tags(raw);
        rest = tail;
    }
    rest = rest.trim_start_matches(' ');
    let mut source = None;
    if let Some(after) = rest.strip_prefix(':') {
        let (raw, tail) = after.split_once(' ').unwrap_or((after, ""));
        source = Some(raw.to_owned());
        rest = tail;
    }
    rest = rest.trim_start_matches(' ');
    let (command, mut rest) = rest.split_once(' ').unwrap_or((rest, ""));
    if command.is_empty() {
        return None;
    }
    let mut params = Vec::new();
    loop {
        rest = rest.trim_start_matches(' ');
        if rest.is_empty() {
            break;
        }
        if let Some(trailing) = rest.strip_prefix(':') {
            params.push(trailing.to_owned());
            break;
        }
        if params.len() + 1 == MAX_PARAMS {
            params.push(rest.to_owned());
            break;
        }
        let (param, tail) = rest.split_once(' ').unwrap_or((rest, ""));
        params.push(param.to_owned());
        rest = tail;
    }
    Some(Line {
        tags,
        source,
        command: command.to_owned(),
        params,
    })
}

/// The tags of `raw` (the tag part without `@`): `key[=value]` separated
/// by `;`, values unescaped. Empty items are skipped.
fn parse_tags(raw: &str) -> Vec<(String, String)> {
    raw.split(';')
        .filter(|item| !item.is_empty())
        .map(|item| match item.split_once('=') {
            Some((key, value)) => (key.to_owned(), unescape_tag_value(value)),
            None => (item.to_owned(), String::new()),
        })
        .collect()
}

/// IRCv3 Message Tags, "Escaping values": `\:` is `;`, `\s` a space, `\\`
/// a backslash, `\r` CR and `\n` LF; a backslash before any other
/// character is dropped (`\b` is `b`), and so is a backslash at the end.
#[must_use]
pub fn unescape_tag_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some(':') => out.push(';'),
            Some('s') => out.push(' '),
            Some('\\') => out.push('\\'),
            Some('r') => out.push('\r'),
            Some('n') => out.push('\n'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// The escaped form of tag value `value` (the inverse of
/// [`unescape_tag_value`]).
#[must_use]
pub fn escape_tag_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            ';' => out.push_str("\\:"),
            ' ' => out.push_str("\\s"),
            '\\' => out.push_str("\\\\"),
            '\r' => out.push_str("\\r"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out
}

/// A line the server writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Out {
    /// Tags, written to a client that takes them
    /// (`crate::conn::Caps::takes_tag`).
    pub tags: Vec<(String, String)>,
    /// The source: the server's name or a hostmask.
    pub source: String,
    /// The command or numeric.
    pub command: String,
    /// The parameters; the last is written as trailing if it must be.
    pub params: Vec<String>,
}

impl Out {
    /// A line from `source`.
    #[must_use]
    pub fn new(source: &str, command: &str, params: Vec<String>) -> Self {
        Self {
            tags: Vec::new(),
            source: source.to_owned(),
            command: command.to_owned(),
            params,
        }
    }

    /// The line with tag `key` set to `value`.
    #[must_use]
    pub fn tag(mut self, key: &str, value: &str) -> Self {
        self.tags.push((key.to_owned(), value.to_owned()));
        self
    }

    /// The line on the wire, CR-LF included; tags only if `with_tags`.
    ///
    /// The server's own tags are written before the client-only ones
    /// (those whose key starts with `+`), whatever order the caller
    /// built them in: "Any server-sent tags attached to messages MUST be
    /// included before client-only tags to prevent them from being
    /// pushed outside of the byte limit"
    /// (~/PROJECT/IETF/specs/ircv3-message-tags.md, "Client-only tags").
    #[must_use]
    pub fn to_wire(&self, with_tags: bool) -> String {
        let mut out = String::new();
        if with_tags && !self.tags.is_empty() {
            out.push('@');
            let server = self.tags.iter().filter(|(key, _)| !key.starts_with('+'));
            let client_only = self.tags.iter().filter(|(key, _)| key.starts_with('+'));
            for (i, (key, value)) in server.chain(client_only).enumerate() {
                if i > 0 {
                    out.push(';');
                }
                out.push_str(key);
                if !value.is_empty() {
                    out.push('=');
                    out.push_str(&escape_tag_value(value));
                }
            }
            out.push(' ');
        }
        out.push(':');
        out.push_str(&self.source);
        out.push(' ');
        out.push_str(&self.command);
        let last = self.params.len().saturating_sub(1);
        for (i, param) in self.params.iter().enumerate() {
            out.push(' ');
            if i == last {
                if param.contains(FORBIDDEN) {
                    // Replacing them leaves a space, so the parameter
                    // needs its `:` whether or not it held one before.
                    out.push(':');
                    out.push_str(&param.replace(FORBIDDEN, " "));
                } else {
                    if param.is_empty() || param.contains(' ') || param.starts_with(':') {
                        out.push(':');
                    }
                    out.push_str(param);
                }
            } else if is_middle_param(param) {
                out.push_str(param);
            } else {
                // Nothing the wire can carry here: the value would end
                // the line, split it, shift the parameters after it, or
                // be read back as the last one.
                out.push('*');
            }
        }
        out.push_str("\r\n");
        out
    }

    /// Cuts the last parameter on a UTF-8 boundary so that the line, tags
    /// included if `with_tags`, fits [`MAX_LINE`]: for peer text that is
    /// shown on one line only (a topic).
    pub fn cut_to_fit(&mut self, with_tags: bool) {
        self.cut_to_room(self.room_for_trailing(with_tags));
    }

    /// Cuts the last parameter on a UTF-8 boundary to `room` octets: for
    /// a caller that worked out the room itself, the tags a given client
    /// takes counted in (`Session::room_for`).
    pub fn cut_to_room(&mut self, room: usize) {
        if let Some(last) = self.params.last_mut()
            && last.len() > room
        {
            let mut end = room;
            while !last.is_char_boundary(end) {
                end -= 1;
            }
            last.truncate(end);
        }
    }

    /// The octets this line takes on the wire with an empty last
    /// parameter written as trailing: what is left of [`MAX_LINE`] is
    /// the room for that parameter's text. Tags count if `with_tags`.
    #[must_use]
    pub fn room_for_trailing(&self, with_tags: bool) -> usize {
        let mut empty = self.clone();
        if let Some(last) = empty.params.last_mut() {
            last.clear();
        }
        MAX_LINE.saturating_sub(empty.to_wire(with_tags).len())
    }
}

/// Whether `text` can be sent as a parameter that is not the last one.
///
/// The Modern IRC Client Protocol §"Parameters" writes a middle
/// parameter as `nospcrlfcl *( ":" / nospcrlfcl )`, where `nospcrlfcl`
/// is any character but NUL, CR, LF, `:` and SPACE, and requires a
/// parameter that holds a space, is empty or begins with `:` to be sent
/// as the last one with a `:` before it. A colon anywhere after the
/// first octet is part of one token and passes.
///
/// This is the grammar and not what [`Out::to_wire`] gets away with:
/// that writes the `:` for the last parameter only, and so never has to
/// decide about the CR, LF or NUL that no middle parameter may carry.
#[must_use]
pub fn is_middle_param(text: &str) -> bool {
    !text.is_empty() && !text.starts_with(':') && !text.contains([' ', '\r', '\n', '\0'])
}

/// `text`, to be written back as a parameter that is not the last one,
/// or `*` where it cannot be: longer than [`MAX_ECHO`], or refused by
/// the grammar ([`is_middle_param`]).
///
/// [`Out::to_wire`] already answers the grammar with `*`, so this is the
/// length bound and the one place a caller states that the value came
/// from the client.
#[must_use]
pub fn echoed(text: &str) -> &str {
    if text.len() <= MAX_ECHO && is_middle_param(text) {
        text
    } else {
        "*"
    }
}

/// `text` cut into pieces of at most `max` octets each, on UTF-8
/// character boundaries, in order; together they are `text`. A `max`
/// smaller than one character still gives one character a piece.
#[must_use]
pub fn split_text(text: &str, max: usize) -> Vec<&str> {
    let mut pieces = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let mut end = rest.len().min(max.max(1));
        while !rest.is_char_boundary(end) {
            end -= 1;
        }
        if end == 0 {
            // One character longer than max: it goes whole.
            end = rest.chars().next().map_or(rest.len(), char::len_utf8);
        }
        let (piece, tail) = rest.split_at(end);
        pieces.push(piece);
        rest = tail;
    }
    pieces
}

/// Packs `words` into lines of at most `room` octets each, a space
/// between words (for 353 NAMES and CAP LS). A word longer than `room`
/// gets a line of its own.
#[must_use]
pub fn pack_words(words: &[String], room: usize) -> Vec<String> {
    pack(words, room, ' ')
}

/// Packs `items` into lines of at most `room` octets each, `sep` between
/// items; an item longer than `room` gets a line of its own.
///
/// `sep` is `' '` for a space-separated list (353 NAMES, CAP LS) and
/// `','` for a comma-separated one (730 to 734, whose lists the IRCv3
/// Monitor spec writes `target[,target2]*` and bounds only by the 512
/// octets of the line). Together the lines hold every item once, in
/// order.
#[must_use]
pub fn pack(items: &[String], room: usize, sep: char) -> Vec<String> {
    let sep_len = sep.len_utf8();
    let mut lines = Vec::new();
    let mut line = String::new();
    for item in items {
        if !line.is_empty() && line.len() + sep_len + item.len() > room {
            lines.push(std::mem::take(&mut line));
        }
        if !line.is_empty() {
            line.push(sep);
        }
        line.push_str(item);
    }
    if !line.is_empty() {
        lines.push(line);
    }
    lines
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect()
    }

    /// Oracle: RFC 1459 §2.3.1 and the IRCv3 Message Tags grammar; the
    /// values are written out by hand.
    #[test]
    fn lines_parse_into_tags_source_command_and_params() {
        let line = parse("@a=1;+b;c= :nick!u@h PRIVMSG #chan :hello  there :x").unwrap();
        assert_eq!(line.tags, tags(&[("a", "1"), ("+b", ""), ("c", "")]));
        assert_eq!(line.source.as_deref(), Some("nick!u@h"));
        assert_eq!(line.command, "PRIVMSG");
        assert_eq!(line.params, ["#chan", "hello  there :x"]);

        let line = parse("join   #a,#b  key\r\n").unwrap();
        assert_eq!(line.verb(), "JOIN");
        assert_eq!(line.params, ["#a,#b", "key"]);
        assert!(line.tags.is_empty() && line.source.is_none());

        // An empty trailing parameter is a parameter.
        assert_eq!(parse("TOPIC #c :").unwrap().params, ["#c", ""]);
        assert_eq!(parse("PING").unwrap().params, Vec::<String>::new());
        assert_eq!(parse(""), None);
        assert_eq!(parse("   "), None);
        assert_eq!(parse("@a=b"), None);
        assert_eq!(parse(":src"), None);
        // Past MAX_PARAMS the rest is the last parameter.
        let many = (1..=17).map(|n| n.to_string()).collect::<Vec<_>>();
        let line = parse(&format!("X {}", many.join(" "))).unwrap();
        assert_eq!(line.params.len(), MAX_PARAMS);
        assert_eq!(line.params[14], "15 16 17");
    }

    /// Oracle: IRCv3 Message Tags, "Escaping values", including its two
    /// rules for a bad escape: an unknown `\x` is `x`, and a backslash at
    /// the end is dropped (docs/irc-lessons.md "Tags").
    #[test]
    fn tag_values_unescape_per_the_spec() {
        assert_eq!(unescape_tag_value(r"a\:b\sc\\d\re\nf"), "a;b c\\d\re\nf");
        assert_eq!(unescape_tag_value(r"\b\x\0"), "bx0");
        assert_eq!(unescape_tag_value("end\\"), "end");
        assert_eq!(unescape_tag_value("\\"), "");
        assert_eq!(unescape_tag_value("\\\\\\"), "\\");
        // A NUL in a value stays a NUL (meshIRCd's placeholder lost it).
        assert_eq!(unescape_tag_value("a\0b"), "a\0b");
        let line = parse(r"@+draft/reply=x\sy;k=\:\: TAGMSG #c").unwrap();
        assert_eq!(line.tag("+draft/reply"), Some("x y"));
        assert_eq!(line.tag("k"), Some(";;"));
        // The last of a repeated tag wins.
        assert_eq!(parse("@k=1;k=2 X").unwrap().tag("k"), Some("2"));
        for value in ["a;b c\\d\r\n", "", "plain", "\\s"] {
            assert_eq!(unescape_tag_value(&escape_tag_value(value)), value);
        }
        assert_eq!(escape_tag_value("a; b\\"), r"a\:\sb\\");
    }

    #[test]
    fn lines_are_written_with_a_trailing_parameter_only_when_needed() {
        let out = Out::new("srv.example", "001", vec!["n".into(), "Hi there".into()]);
        assert_eq!(out.to_wire(true), ":srv.example 001 n :Hi there\r\n");
        let out = Out::new(
            "srv.example",
            "PONG",
            vec!["srv.example".into(), "tok".into()],
        );
        assert_eq!(out.to_wire(true), ":srv.example PONG srv.example tok\r\n");
        let out = Out::new("s.x", "X", vec![":a".into()]);
        assert_eq!(out.to_wire(false), ":s.x X ::a\r\n");
        let out = Out::new("s.x", "X", vec![String::new()]);
        assert_eq!(out.to_wire(false), ":s.x X :\r\n");
        let out = Out::new("s.x", "PRIVMSG", vec!["#c".into(), "a b".into()])
            .tag("msgid", "01J")
            .tag("+draft/reply", "x y");
        assert_eq!(
            out.to_wire(true),
            "@msgid=01J;+draft/reply=x\\sy :s.x PRIVMSG #c :a b\r\n"
        );
        assert_eq!(out.to_wire(false), ":s.x PRIVMSG #c :a b\r\n");
        let room = out.room_for_trailing(true);
        assert_eq!(
            room,
            MAX_LINE - "@msgid=01J;+draft/reply=x\\sy :s.x PRIVMSG #c :\r\n".len()
        );
    }

    /// Oracle: ~/PROJECT/IETF/specs/ircv3-message-tags.md, "Client-only
    /// tags": "Any server-sent tags attached to messages MUST be
    /// included before client-only tags to prevent them from being
    /// pushed outside of the byte limit."
    ///
    /// A caller adds tags in the order its own line reads best —
    /// `msgid`, then the client-only `+draft/reply`, then `time` and
    /// `account` for every line of a split message — so the order is
    /// settled here and not at each call.
    #[test]
    fn server_tags_are_written_before_client_only_tags() {
        let out = Out::new("s.x", "PRIVMSG", vec!["#c".into(), "hi".into()])
            .tag("msgid", "01J")
            .tag("+draft/reply", "01H")
            .tag("time", "2026-11-28T00:00:00.000Z")
            .tag("account", "mimi://a.example/u/alice");
        assert_eq!(
            out.to_wire(true),
            "@msgid=01J;time=2026-11-28T00:00:00.000Z;account=mimi://a.example/u/alice;\
             +draft/reply=01H :s.x PRIVMSG #c hi\r\n"
        );
        // The room for the text counts the same octets, wherever the
        // tags were added.
        assert_eq!(
            out.room_for_trailing(true),
            MAX_LINE
                - "@msgid=01J;time=2026-11-28T00:00:00.000Z;account=mimi://a.example/u/alice;\
                   +draft/reply=01H :s.x PRIVMSG #c :\r\n"
                    .len()
        );
    }

    #[test]
    fn text_splits_on_character_boundaries_and_joins_back() {
        let text = "aé€😀b";
        for max in 1..=12 {
            let pieces = split_text(text, max);
            assert_eq!(pieces.concat(), text, "max {max}");
            for piece in &pieces {
                assert!(
                    piece.len() <= max || piece.chars().count() == 1,
                    "{piece:?} over {max}"
                );
            }
        }
        assert_eq!(split_text("abcdef", 4), ["abcd", "ef"]);
        assert_eq!(split_text("€€", 4), ["€", "€"]);
        assert!(split_text("", 4).is_empty());
    }

    #[test]
    fn words_pack_into_lines_within_the_room() {
        let words: Vec<String> = ["aa", "bbb", "c", "dddd"]
            .iter()
            .map(|w| (*w).to_owned())
            .collect();
        assert_eq!(pack_words(&words, 6), ["aa bbb", "c dddd"]);
        assert_eq!(pack_words(&words, 3), ["aa", "bbb", "c", "dddd"]);
        assert_eq!(pack_words(&words, 100), ["aa bbb c dddd"]);
        assert!(pack_words(&[], 10).is_empty());
    }

    /// Oracle: ircv3-monitor.md:56-58 ("the length of the target list is
    /// limited only by the buffer size of 512 chars") and :107, :121,
    /// :133, :146, whose lists are `target[,target2]*`. A 730 or 731 over
    /// the limit is cut by the client into a nick that is not the one
    /// sent, so the separator has to be the comma and every line has to
    /// fit the room.
    #[test]
    fn items_pack_into_comma_lists_within_the_room() {
        let items: Vec<String> = ["aa", "bbb", "c", "dddd"]
            .iter()
            .map(|w| (*w).to_owned())
            .collect();
        assert_eq!(pack(&items, 6, ','), ["aa,bbb", "c,dddd"]);
        assert_eq!(pack(&items, 3, ','), ["aa", "bbb", "c", "dddd"]);
        assert_eq!(pack(&items, 100, ','), ["aa,bbb,c,dddd"]);
        assert!(pack(&[], 10, ',').is_empty());
        // Every line fits, and the lines hold the items once each, in
        // order.
        let many: Vec<String> = (0..100).map(|n| format!("nick-{n}")).collect();
        let lines = pack(&many, 40, ',');
        assert!(lines.len() > 1, "{lines:?}");
        for line in &lines {
            assert!(line.len() <= 40, "{line:?}");
        }
        assert_eq!(lines.join(",").split(',').collect::<Vec<_>>(), many);
    }

    /// Oracle: docs/irc-lessons.md "Writing": a line is at most 512
    /// octets; a topic longer than that is cut on a UTF-8 boundary.
    #[test]
    fn a_long_last_parameter_is_cut_to_the_line_limit() {
        let topic = "é".repeat(400);
        let mut out = Out::new(
            "alice-a!alice@a.example",
            "TOPIC",
            vec!["#lobby".to_owned(), topic.clone()],
        );
        out.cut_to_fit(false);
        let wire = out.to_wire(false);
        // At most 512; short of it by a cut 2-octet character and the
        // `:` that text without a space does not need.
        assert!(
            (MAX_LINE - 2..=MAX_LINE).contains(&wire.len()),
            "{}",
            wire.len()
        );
        let text = &out.params[1];
        assert!(!text.is_empty() && topic.starts_with(text.as_str()));
        // A short one is left alone.
        let mut short = Out::new("s", "TOPIC", vec!["#c".to_owned(), "hi".to_owned()]);
        short.cut_to_fit(true);
        assert_eq!(short.params[1], "hi");
    }
    /// Oracle: the Modern IRC Client Protocol §"Parameters", written out
    /// by hand -- `nospcrlfcl` is "any characters except NUL, CR, LF,
    /// colon (`:`) and SPACE", `middle ::= nospcrlfcl *( ":" /
    /// nospcrlfcl )`, and "Parameters that contain spaces, are empty, or
    /// begin with a `':'` character MUST be sent with a preceding
    /// `':'`", which only the last parameter may have.
    #[test]
    fn is_middle_param_rejects_what_a_middle_parameter_cannot_hold() {
        for text in [
            "",
            ":leading",
            "two words",
            "line\rbreak",
            "line\nbreak",
            "nul\0byte",
            " ",
            ":",
        ] {
            assert!(!is_middle_param(text), "{text:?}");
        }
        // A colon past the first octet is one token, and so is anything
        // else the grammar does not name: a zero-width character is a
        // path's business, not the wire's.
        for text in [
            "/etc/mimid.toml",
            "a:b",
            "a::",
            "/home/\u{200b}/mimid.toml",
            "\u{fffd}",
        ] {
            assert!(is_middle_param(text), "{text:?}");
        }
        // What passes goes out as one middle parameter and is read back
        // as one. The `:` before a last parameter that needs none is
        // optional (§"Parameters"), and `Out::to_wire` leaves it off.
        let out = Out::new(
            "s",
            "382",
            vec!["val".to_owned(), "a:b".to_owned(), "Rehashing".to_owned()],
        );
        assert_eq!(out.to_wire(false), ":s 382 val a:b Rehashing\r\n");
        assert_eq!(
            parse("382 val a:b Rehashing").unwrap().params,
            ["val", "a:b", "Rehashing"]
        );
    }

    /// Oracle: the Modern IRC Client Protocol §"Parameters", written out
    /// by hand. `middle` is `nospcrlfcl *( ":" / nospcrlfcl )` and
    /// `trailing` is `*( ":" / " " / nospcrlfcl )`, so NUL, CR and LF
    /// belong to no parameter at all, and a value that holds a space, is
    /// empty or begins with `:` may only be the last one.
    ///
    /// A caller that hands such a value to a parameter that is not the
    /// last one has nothing the wire can carry, so `*` goes out instead
    /// of a line that would split, shift the parameters after it, or
    /// carry an octet RFC 1459 §2.3 forbids.
    #[test]
    fn no_parameter_goes_out_holding_what_the_grammar_refuses() {
        for refused in [
            "",
            ":leading",
            "two words",
            "a\rb",
            "a\nb",
            "a\0b",
            " ",
            ":",
        ] {
            let out = Out::new(
                "s",
                "402",
                vec![
                    "val".to_owned(),
                    refused.to_owned(),
                    "No such server".to_owned(),
                ],
            );
            assert_eq!(
                out.to_wire(false),
                ":s 402 val * :No such server\r\n",
                "{refused:?}"
            );
        }
        // The last parameter may hold a space and a colon, and does; CR,
        // LF and NUL are not its to hold either, and become spaces, as
        // the text around them is still the text.
        let trailing = |text: &str| {
            Out::new("s", "NOTICE", vec!["val".to_owned(), text.to_owned()]).to_wire(false)
        };
        assert_eq!(trailing("two words"), ":s NOTICE val :two words\r\n");
        assert_eq!(trailing(":x"), ":s NOTICE val ::x\r\n");
        assert_eq!(trailing("a\r\nQUIT"), ":s NOTICE val :a  QUIT\r\n");
        assert_eq!(trailing("a\0b"), ":s NOTICE val :a b\r\n");
        // Every line still ends with exactly one CR-LF.
        for text in ["a\rb", "a\nb", "a\r\nb", "plain"] {
            let wire = trailing(text);
            assert_eq!(wire.matches("\r\n").count(), 1, "{text:?} -> {wire:?}");
        }
    }

    /// Oracle: [`MAX_ECHO`] against [`MAX_LINE`] -- a name longer than
    /// the longest this daemon could have issued is answered with `*`,
    /// because a parameter that is not the last one cannot be cut to fit
    /// the line without changing which parameter it is.
    #[test]
    fn a_name_too_long_to_echo_is_answered_with_a_star() {
        let longest = "n".repeat(MAX_ECHO);
        assert_eq!(echoed(&longest), longest);
        assert_eq!(echoed(&"n".repeat(MAX_ECHO + 1)), "*");
        assert_eq!(echoed("nobody-x"), "nobody-x");
        // The grammar is checked as well as the length.
        assert_eq!(echoed("two words"), "*");
        assert_eq!(echoed(""), "*");
        // The reply that echoes the longest name it may still fits.
        let out = Out::new(
            "a.very.long.server.name.example",
            "406",
            vec![
                "n".repeat(crate::names::NICKLEN),
                echoed(&longest).to_owned(),
                "There was no such nickname".to_owned(),
            ],
        );
        assert!(out.to_wire(true).len() <= MAX_LINE, "{}", out.to_wire(true));
    }
}
