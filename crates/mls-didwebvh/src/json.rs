//! The I-JSON (RFC 7493) check the draft's profile requires of each log
//! entry and of `witness_file` (§did:webvh Profile, Encoding: "Each log
//! entry, and `witness_file`, MUST be I-JSON [RFC7493]; in particular, an
//! object with duplicate member names is rejected").
//!
//! `serde_json` already enforces UTF-8 (RFC 7493 §2.1), refuses lone
//! surrogate escapes, and refuses numbers outside the IEEE 754 double range
//! such as `1E400`. This module adds the rest:
//!
//! - duplicate member names (§2.3), compared after unescaping;
//! - noncharacters, in strings and in member names (§2.1: "MUST NOT include
//!   code points that identify Surrogates or Noncharacters");
//! - numbers with an integral value whose magnitude is above 2^53 - 1,
//!   however written (`9007199254740993`, `1e20`), since past that a double
//!   no longer holds every integer exactly (§2.2, a SHOULD NOT that the profile's "MUST be I-JSON"
//!   makes a MUST; decision mimid-1wgh.4.81.9).
//!
//! Non-integer numbers are accepted as `serde_json` parses them: excess
//! precision such as `3.141592653589793238462643383279` is not detected
//! (decision mimid-1wgh.4.81.9).
//!
//! Nesting is bounded by `serde_json`'s recursion limit of 128 levels;
//! deeper input is refused.

use std::collections::HashSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};

/// The largest integer magnitude a double holds exactly: 2^53 - 1
/// (RFC 7493 §2.2).
pub const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

/// Whether `c` is a Unicode noncharacter: U+FDD0..U+FDEF, or the last two
/// code points of any plane.
fn is_noncharacter(c: char) -> bool {
    let c = u32::from(c);
    (0xfdd0..=0xfdef).contains(&c) || c & 0xfffe == 0xfffe
}

fn check_text<E: de::Error>(s: &str) -> Result<(), E> {
    if s.chars().any(is_noncharacter) {
        Err(E::custom("string holds a Unicode noncharacter"))
    } else {
        Ok(())
    }
}

/// Walks a JSON value, accepting it only if it is I-JSON.
struct Strict;

impl<'de> DeserializeSeed<'de> for Strict {
    type Value = ();

    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict {
    type Value = ();

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("an I-JSON value")
    }

    fn visit_bool<E: de::Error>(self, _: bool) -> Result<(), E> {
        Ok(())
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<(), E> {
        if v.unsigned_abs() > MAX_SAFE_INTEGER {
            Err(E::custom("integer magnitude above 2^53 - 1"))
        } else {
            Ok(())
        }
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<(), E> {
        if v > MAX_SAFE_INTEGER {
            Err(E::custom("integer magnitude above 2^53 - 1"))
        } else {
            Ok(())
        }
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<(), E> {
        // MAX_SAFE_INTEGER is below 2^53, so the conversion is exact.
        #[allow(clippy::cast_precision_loss)]
        let max = MAX_SAFE_INTEGER as f64;
        if !v.is_finite() {
            Err(E::custom("number is not finite"))
        } else if v.fract() == 0.0 && v.abs() > max {
            Err(E::custom("integer magnitude above 2^53 - 1"))
        } else {
            Ok(())
        }
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<(), E> {
        check_text(v)
    }

    fn visit_unit<E: de::Error>(self) -> Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(Strict)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut names = HashSet::new();
        while let Some(name) = map.next_key::<String>()? {
            check_text::<A::Error>(&name)?;
            if !names.insert(name) {
                return Err(de::Error::custom("duplicate member name"));
            }
            map.next_value_seed(Strict)?;
        }
        Ok(())
    }
}

/// Why a JSON text is not I-JSON.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not I-JSON: {0}")]
pub struct IJsonError(String);

/// Checks that `text` is exactly one I-JSON value, with nothing but JSON
/// whitespace around it.
///
/// # Errors
///
/// Returns [`IJsonError`] describing the first violation.
pub fn check_i_json(text: &[u8]) -> Result<(), IJsonError> {
    let mut deserializer = serde_json::Deserializer::from_slice(text);
    Strict
        .deserialize(&mut deserializer)
        .and_then(|()| deserializer.end())
        .map_err(|e| IJsonError(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_json_passes() {
        check_i_json(br#"{"a":[1,-2,3.5,true,false,null,"x"],"b":{"c":"d"}}"#).unwrap();
        check_i_json(b"  [ ]  ").unwrap();
    }

    #[test]
    fn duplicate_names_are_refused_even_when_escaped_differently() {
        assert!(check_i_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(check_i_json(br#"{"a":1,"a":2}"#).is_err());
        assert!(check_i_json(br#"{"x":{"a":1,"a":1}}"#).is_err());
        // The same name in sibling objects is fine.
        check_i_json(br#"[{"a":1},{"a":2}]"#).unwrap();
    }

    #[test]
    fn surrogates_and_noncharacters_are_refused() {
        assert!(check_i_json(br#""\ud800""#).is_err(), "lone surrogate");
        assert!(check_i_json(br#""\udc00x""#).is_err(), "lone trail");
        check_i_json(br#""\ud83d\ude00""#).unwrap(); // a valid pair
        assert!(check_i_json(br#""\uffff""#).is_err());
        assert!(check_i_json("\"\u{fdd0}\"".as_bytes()).is_err());
        assert!(check_i_json("\"\u{10fffe}\"".as_bytes()).is_err());
        assert!(check_i_json("{\"\u{fffe}\":1}".as_bytes()).is_err());
    }

    #[test]
    fn invalid_utf8_and_bom_are_refused() {
        assert!(check_i_json(b"\"\xff\"").is_err());
        assert!(check_i_json(b"\xef\xbb\xbf{}").is_err());
    }

    #[test]
    fn integers_past_2_pow_53_are_refused() {
        check_i_json(b"9007199254740991").unwrap();
        check_i_json(b"-9007199254740991").unwrap();
        assert!(check_i_json(b"9007199254740992").is_err());
        assert!(check_i_json(b"-9007199254740992").is_err());
        assert!(check_i_json(b"1E400").is_err());
        assert!(check_i_json(b"18446744073709551617").is_err(), "past u64");
        assert!(check_i_json(b"1e20").is_err(), "integral, past 2^53");
        check_i_json(b"1.5e3").unwrap();
    }

    #[test]
    fn trailing_values_and_deep_nesting_are_refused() {
        assert!(check_i_json(b"{} {}").is_err());
        let deep = format!("{}{}", "[".repeat(200), "]".repeat(200));
        assert!(check_i_json(deep.as_bytes()).is_err());
        let fine = format!("{}{}", "[".repeat(100), "]".repeat(100));
        check_i_json(fine.as_bytes()).unwrap();
    }
}
