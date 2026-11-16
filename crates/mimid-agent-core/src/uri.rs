//! MIMI URIs: the RFC 3986 normal form used to compare them, and the
//! `mimi://<domain>/u/<id>` user URI shape (protocol-07 §2.1).
//!
//! [`normalized_uri`] is a copy of mimid-server's `hub::normalized_uri`
//! (bead mimid-1wgh.13.8; see [`crate::components`] for why this crate
//! carries copies). Keep the two in step.

/// `uri` in the normal form of RFC 3986 §6.2.2.1 and §6.2.2.2: the scheme
/// and host in lowercase, percent-encoding hex digits in uppercase, and
/// percent-encoded unreserved characters (§2.3: ALPHA, DIGIT, `-`, `.`,
/// `_`, `~`) decoded. Two URIs with the same normal form are the same URI.
///
/// protocol-07 §5.8 says only that a handle "matches exactly", and §5.2 and
/// §5.7 do not say how user URIs compare. mimid reads RFC 3986 equivalence
/// as the clear meaning and looks a user or room up by this form (decision
/// mimid-1wgh.52). It is applied only to lookups: MLS credentials, the
/// participant list and anything signed are still compared byte for byte.
/// Nothing else is changed: the path keeps its case, and there is no
/// Unicode normalization or case folding. A URI with userinfo keeps its
/// authority as is, and a `%` not followed by two hex digits is left alone.
pub fn normalized_uri(uri: &str) -> std::borrow::Cow<'_, str> {
    let Some((scheme, rest)) = uri.split_once(':') else {
        return uri.into();
    };
    let scheme_ok = scheme
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic())
        && scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'));
    if !scheme_ok {
        return uri.into();
    }
    let mut out = scheme.to_ascii_lowercase();
    out.push(':');
    let rest = match rest.strip_prefix("//") {
        Some(after) => {
            let end = after.find(['/', '?', '#']).unwrap_or(after.len());
            let (authority, tail) = after.split_at(end);
            out.push_str("//");
            if authority.contains('@') {
                out.push_str(&normalize_percent(authority));
            } else {
                out.push_str(&normalize_percent(authority).to_ascii_lowercase());
            }
            tail
        }
        None => rest,
    };
    out.push_str(&normalize_percent(rest));
    if out == uri { uri.into() } else { out.into() }
}

/// RFC 3986 §6.2.2.1 and §6.2.2.2 on percent-encodings: hex digits in
/// uppercase, unreserved characters decoded.
fn normalize_percent(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    while i < bytes.len() {
        let hex = |b: u8| char::from(b).to_digit(16);
        if bytes[i] == b'%'
            && let (Some(&h), Some(&l)) = (bytes.get(i + 1), bytes.get(i + 2))
            && let (Some(h), Some(l)) = (hex(h), hex(l))
        {
            let byte = u8::try_from(h * 16 + l).expect("two hex digits fit a byte");
            if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
                out.push(char::from(byte));
            } else {
                out.push_str(&format!("%{byte:02X}"));
            }
            i += 3;
            continue;
        }
        // Copy one UTF-8 character.
        let ch = text[i..]
            .chars()
            .next()
            .expect("i is on a character boundary");
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// The provider domain of a user URI `mimi://<domain>/u/<id>`, or `None`
/// for any other string.
pub fn user_uri_domain(uri: &str) -> Option<&str> {
    let rest = uri.strip_prefix("mimi://")?;
    let (domain, path) = rest.split_once('/')?;
    let id = path.strip_prefix("u/")?;
    (!domain.is_empty() && !id.is_empty() && !id.contains(['/', '?', '#'])).then_some(domain)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalized_uri_follows_rfc3986_6_2_2() {
        for (input, expected) in [
            ("mimi://b.example/u/bob", "mimi://b.example/u/bob"),
            ("MIMI://B.Example/u/bob", "mimi://b.example/u/bob"),
            (
                "mimi://b.example/u/%c3%a9mile",
                "mimi://b.example/u/%C3%A9mile",
            ),
            ("mimi://b.example/u/%62%6F%62", "mimi://b.example/u/bob"),
            ("mimi://b.example/u/a%2Fb", "mimi://b.example/u/a%2Fb"),
            ("mimi://b.example/u/a%2fb%7e", "mimi://b.example/u/a%2Fb~"),
            // The path keeps its case; no Unicode normalization.
            ("mimi://b.example/u/BOB", "mimi://b.example/u/BOB"),
            ("mimi://b.example/u/e%CC%81", "mimi://b.example/u/e%CC%81"),
            ("mimi://b.example/u/\u{e9}", "mimi://b.example/u/\u{e9}"),
            // Userinfo keeps its case; broken escapes are left alone.
            ("mimi://Eve@B.example/u/x", "mimi://Eve@B.example/u/x"),
            ("mimi://b.example/u/%G1%4", "mimi://b.example/u/%G1%4"),
            ("not a uri", "not a uri"),
            ("", ""),
        ] {
            assert_eq!(normalized_uri(input), expected, "{input}");
        }
        assert!(matches!(
            normalized_uri("mimi://b.example/u/bob"),
            std::borrow::Cow::Borrowed(_)
        ));
    }

    #[test]
    fn user_uris_name_their_domain() {
        assert_eq!(
            user_uri_domain("mimi://a.example/u/alice"),
            Some("a.example")
        );
        for uri in [
            "mimi://a.example",
            "mimi://a.example/r/room",
            "mimi://a.example/u/",
            "mimi://a.example/u/a/b",
            "https://a.example/u/alice",
            "mimi:///u/alice",
        ] {
            assert_eq!(user_uri_domain(uri), None, "{uri}");
        }
    }
}
