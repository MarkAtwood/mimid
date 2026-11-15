//! Localized display text (draft-atwood-jmap-updates-00 §4, the
//! `urn:ietf:params:jmap:i18n` capability): the `language` argument and
//! its RFC 4647 §3.4 Lookup.
//!
//! A Chat's `name` and `description` are its localizable properties (the
//! JMAP Chat applicability table, jmap-chat-spec bead qb21). They come
//! from the room's MIMI `RoomMetaData` (protocol-07 §7.6): `room_name` has
//! no language, and each `room_descriptions` entry has a language tag.
//! [`Localized`] maps them: the base values are the name and the first
//! description, `locale` is null because the name's language is unknown,
//! and each tagged description is a localization of `description`.

use std::collections::BTreeMap;

use serde_json::{Map, Value, json};

/// draft-atwood-jmap-updates-00 §3.
pub const I18N_CAPABILITY: &str = "urn:ietf:params:jmap:i18n";

/// Why a `language` argument was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LanguageError {
    /// The request did not name [`I18N_CAPABILITY`] in `using`.
    #[error("language needs urn:ietf:params:jmap:i18n in using")]
    NotUsing,
    /// Not null and not an array of language ranges.
    #[error("language must be null or an array of language ranges")]
    Malformed,
}

/// Reads a method call's `language` argument: `None` when absent or null.
///
/// # Errors
///
/// [`LanguageError::NotUsing`] for a `language` argument when `i18n` is
/// false (draft-atwood-jmap-updates-00 §3: an unknown argument), and
/// [`LanguageError::Malformed`] for anything but null or an array of RFC
/// 4647 §2.1 basic language ranges.
pub fn language_argument(
    args: &Map<String, Value>,
    i18n: bool,
) -> Result<Option<Vec<String>>, LanguageError> {
    let Some(value) = args.get("language") else {
        return Ok(None);
    };
    if !i18n {
        return Err(LanguageError::NotUsing);
    }
    if value.is_null() {
        return Ok(None);
    }
    let ranges: Vec<String> =
        serde_json::from_value(value.clone()).map_err(|_| LanguageError::Malformed)?;
    if ranges.iter().all(|range| is_basic_range(range)) {
        Ok(Some(ranges))
    } else {
        Err(LanguageError::Malformed)
    }
}

/// RFC 4647 §2.1: `language-range = (1*8ALPHA *("-" 1*8alphanum)) / "*"`.
fn is_basic_range(range: &str) -> bool {
    if range == "*" {
        return true;
    }
    let mut subtags = range.split('-');
    let first_ok = subtags
        .next()
        .is_some_and(|s| (1..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphabetic()));
    first_ok
        && subtags
            .all(|s| (1..=8).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// RFC 4647 §3.4 Lookup of `ranges` among `tags`, compared without regard
/// to case: the first tag that a range, or a range with subtags removed
/// from its end, equals. A `*` followed by other ranges is skipped; a
/// final `*`, or no match, gives `None`, the default.
pub fn lookup<'a>(
    ranges: &[String],
    tags: impl IntoIterator<Item = &'a str> + Clone,
) -> Option<&'a str> {
    for range in ranges {
        if range == "*" {
            continue;
        }
        let mut candidate = range.as_str();
        loop {
            if let Some(tag) = tags
                .clone()
                .into_iter()
                .find(|tag| tag.eq_ignore_ascii_case(candidate))
            {
                return Some(tag);
            }
            let Some(cut) = candidate.rfind('-') else {
                break;
            };
            candidate = &candidate[..cut];
            // RFC 4647 §3.4: a single-character subtag left at the end
            // (an extension or private-use singleton) goes with the cut.
            if let Some(cut) = candidate.rfind('-')
                && candidate.len() - cut == 2
            {
                candidate = &candidate[..cut];
            }
        }
    }
    None
}

/// A Chat's localizable display text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Localized {
    /// The base `name`.
    pub name: String,
    /// The base `description`: the first plain-text room description.
    pub description: Option<String>,
    /// Language tag to `description` in that language. RFC 5646 §2.1.1:
    /// tags are compared without regard to case; the first one of each
    /// case-insensitive spelling is kept.
    pub descriptions: BTreeMap<String, String>,
}

impl Localized {
    /// The display text of a room's (language tag, text) descriptions.
    /// An empty tag is a description of unknown language: it can be the
    /// base value but not a localization.
    pub fn new(name: String, descriptions: &[(String, String)]) -> Self {
        let mut by_tag = BTreeMap::new();
        for (tag, text) in descriptions {
            if tag.is_empty() || by_tag.keys().any(|k: &String| k.eq_ignore_ascii_case(tag)) {
                continue;
            }
            by_tag.insert(tag.clone(), text.clone());
        }
        Self {
            name,
            description: descriptions.first().map(|(_, text)| text.clone()),
            descriptions: by_tag,
        }
    }

    /// Writes `name` and `description` into `object`, and with `i18n`
    /// also `locale` and `localizations`
    /// (draft-atwood-jmap-updates-00 §4.1). With a `language` argument the
    /// object is the view in the language Lookup chooses, its `locale` that
    /// language (§4.2.1).
    pub fn write(&self, object: &mut Map<String, Value>, i18n: bool, language: Option<&[String]>) {
        object.insert("name".into(), json!(self.name));
        let chosen = language
            .and_then(|ranges| lookup(ranges, self.descriptions.keys().map(String::as_str)));
        let description = match chosen {
            Some(tag) => self.descriptions.get(tag).cloned(),
            None => self.description.clone(),
        };
        // The Chat type leaves an absent description out rather than null.
        match description {
            Some(description) => object.insert("description".into(), json!(description)),
            None => object.remove("description"),
        };
        if !i18n {
            return;
        }
        object.insert("locale".into(), json!(chosen));
        let localizations: Map<String, Value> = self
            .descriptions
            .iter()
            .map(|(tag, text)| (tag.clone(), json!({ "description": text })))
            .collect();
        object.insert(
            "localizations".into(),
            if localizations.is_empty() {
                Value::Null
            } else {
                Value::Object(localizations)
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ranges(list: &[&str]) -> Vec<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn lookup_truncates_ranges_and_never_extends_them() {
        let tags = ["de", "fr-CH", "zh-Hant"];
        let tags = tags.iter().copied();
        assert_eq!(lookup(&ranges(&["de-CH"]), tags.clone()), Some("de"));
        assert_eq!(lookup(&ranges(&["fr"]), tags.clone()), None);
        assert_eq!(lookup(&ranges(&["FR-ch"]), tags.clone()), Some("fr-CH"));
        assert_eq!(
            lookup(&ranges(&["zh-Hant-CN-x-private1"]), tags.clone()),
            Some("zh-Hant")
        );
        assert_eq!(lookup(&ranges(&["it", "de"]), tags.clone()), Some("de"));
        assert_eq!(lookup(&ranges(&["*", "de"]), tags.clone()), Some("de"));
        assert_eq!(lookup(&ranges(&["it", "*"]), tags), None);
    }

    #[test]
    fn the_language_argument_needs_the_capability_and_basic_ranges() {
        let args = |v: Value| json!({ "language": v }).as_object().unwrap().clone();
        assert_eq!(language_argument(&Map::new(), false), Ok(None));
        assert_eq!(
            language_argument(&args(json!(["de"])), false),
            Err(LanguageError::NotUsing)
        );
        assert_eq!(language_argument(&args(Value::Null), true), Ok(None));
        assert_eq!(
            language_argument(&args(json!(["de-CH", "*"])), true),
            Ok(Some(ranges(&["de-CH", "*"])))
        );
        for bad in [
            json!("de"),
            json!([1]),
            json!(["de_CH"]),
            json!(["toolongtag"]),
            json!([""]),
        ] {
            assert_eq!(
                language_argument(&args(bad.clone()), true),
                Err(LanguageError::Malformed),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_chat_view_in_one_language() {
        let text = Localized::new(
            "Lunch".into(),
            &[
                ("en".into(), "Where we eat".into()),
                ("de".into(), "Wo wir essen".into()),
                ("DE".into(), "ignored: same tag".into()),
                (String::new(), "no tag".into()),
            ],
        );
        let mut plain = Map::new();
        text.write(&mut plain, false, None);
        assert_eq!(
            Value::Object(plain),
            json!({"name": "Lunch", "description": "Where we eat"})
        );

        let mut stored = Map::new();
        text.write(&mut stored, true, None);
        assert_eq!(
            Value::Object(stored),
            json!({
                "name": "Lunch",
                "description": "Where we eat",
                "locale": null,
                "localizations": {"de": {"description": "Wo wir essen"}, "en": {"description": "Where we eat"}},
            })
        );

        let mut german = Map::new();
        text.write(&mut german, true, Some(&ranges(&["de-AT", "en"])));
        assert_eq!(german["description"], json!("Wo wir essen"));
        assert_eq!(german["locale"], json!("de"));

        let mut nothing = Map::new();
        text.write(&mut nothing, true, Some(&ranges(&["ja"])));
        assert_eq!(nothing["description"], json!("Where we eat"));
        assert_eq!(nothing["locale"], Value::Null);
    }
}
