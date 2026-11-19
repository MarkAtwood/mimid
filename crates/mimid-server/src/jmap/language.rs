//! A Chat's localized display text (draft-atwood-jmap-updates-00 §3, the
//! `urn:ietf:params:jmap:i18n` capability).
//!
//! A Chat's `name` and `description` are its localizable properties (the
//! JMAP Chat applicability table, jmap-chat-spec bead qb21). They come
//! from the room's MIMI `RoomMetaData` (protocol-07 §7.6): `room_name` has
//! no language, and each `room_descriptions` entry has a language tag.
//! [`Localized`] maps them to the stored object: the base values are the
//! name and the first description, `locale` is null because the name's
//! language is unknown, and each tagged description is a localization of
//! `description`.
//!
//! Everything else is crate-jmap's (decision mimid-1wgh.70): the `language`
//! argument, its gating on `using`, RFC 4647 §3.4 Lookup and the
//! single-language view are [`I18nProjection`], and `/query` and
//! `/queryChanges` use `handle_query_with_i18n` and
//! `handle_query_changes_with_i18n`.
//!
//! # Limitations
//!
//! Chat `name` is never localized: `RoomMetaData` has one untagged name.

use std::collections::BTreeMap;

use jmap_server::I18nProjection;
use jmap_types::i18n::{LanguageTag, LocalizableProperty};
use serde_json::{Map, Value, json};

/// The localizable properties of Chat (the JMAP Chat applicability
/// table, jmap-chat-spec bead qb21): `name` is a `String`, `description`
/// a `String|null`.
pub const CHAT_LOCALIZABLE: &[LocalizableProperty] = &[
    LocalizableProperty::new("name", false),
    LocalizableProperty::new("description", true),
];

/// A Chat's localizable display text.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Localized {
    /// The base `name`.
    pub name: String,
    /// The base `description`: the first plain-text room description.
    pub description: Option<String>,
    /// Language tag to `description` in that language, tags in RFC 5646
    /// §2.1.1 canonical case; the first description of each tag (compared
    /// without regard to case) is kept.
    pub descriptions: BTreeMap<LanguageTag, String>,
}

impl Localized {
    /// The display text of a room's (language tag, text) descriptions.
    /// A description whose tag is not a well-formed RFC 5646 language tag
    /// (as another provider may send) is of unknown language: it can be
    /// the base value but not a `localizations` key
    /// (draft-atwood-jmap-updates-00 §3.1).
    pub fn new(name: String, descriptions: &[(String, String)]) -> Self {
        let mut by_tag = BTreeMap::new();
        for (tag, text) in descriptions {
            if let Ok(tag) = LanguageTag::parse(tag) {
                by_tag.entry(tag).or_insert_with(|| text.clone());
            }
        }
        Self {
            name,
            description: descriptions.first().map(|(_, text)| text.clone()),
            descriptions: by_tag,
        }
    }

    /// Writes the stored `name`, `description`, `locale` and
    /// `localizations` into `object`, then lets `i18n` shape them for the
    /// request: removed without the capability, as stored with a null
    /// `language`, the single-language view otherwise
    /// (draft-atwood-jmap-updates-00 §3.2.1).
    pub fn write(&self, object: &mut Map<String, Value>, i18n: &I18nProjection) {
        object.insert("name".into(), json!(self.name));
        // The Chat type leaves an absent description out rather than null.
        match &self.description {
            Some(description) => object.insert("description".into(), json!(description)),
            None => object.remove("description"),
        };
        object.insert("locale".into(), Value::Null);
        let localizations: Map<String, Value> = self
            .descriptions
            .iter()
            .map(|(tag, text)| (tag.as_str().to_owned(), json!({ "description": text })))
            .collect();
        object.insert(
            "localizations".into(),
            if localizations.is_empty() {
                Value::Null
            } else {
                Value::Object(localizations)
            },
        );
        i18n.apply(object);
    }
}

#[cfg(test)]
mod tests {
    use super::super::projection::ChatRecord;
    use super::*;
    use jmap_server::I18nInfo;
    use jmap_types::i18n::JMAP_I18N_URI;

    fn projection(i18n: bool, language: Value) -> I18nProjection {
        let mut args = json!({ "language": language }).as_object().unwrap().clone();
        let using = if i18n {
            vec![JMAP_I18N_URI.to_owned()]
        } else {
            Vec::new()
        };
        I18nProjection::from_args::<ChatRecord>(&mut args, &using, Some(&I18nInfo::new())).unwrap()
    }

    #[test]
    fn a_chat_view_in_one_language() {
        let text = Localized::new(
            "Lunch".into(),
            &[
                ("en".into(), "Where we eat".into()),
                ("de".into(), "Wo wir essen".into()),
                ("DE".into(), "ignored: same tag".into()),
                ("en-us".into(), "Where we chow down".into()),
                (String::new(), "no tag".into()),
                ("de-1".into(), "ill-formed tag".into()),
            ],
        );
        let mut plain = Map::new();
        text.write(&mut plain, &projection(false, Value::Null));
        assert_eq!(
            Value::Object(plain),
            json!({"name": "Lunch", "description": "Where we eat"})
        );

        let mut stored = Map::new();
        text.write(&mut stored, &projection(true, Value::Null));
        assert_eq!(
            Value::Object(stored),
            json!({
                "name": "Lunch",
                "description": "Where we eat",
                "locale": null,
                "localizations": {
                    "de": {"description": "Wo wir essen"},
                    "en": {"description": "Where we eat"},
                    "en-US": {"description": "Where we chow down"},
                },
            })
        );

        // §3.2.1: the view's locale is the chosen tag and its
        // localizations null.
        let mut german = Map::new();
        text.write(&mut german, &projection(true, json!(["de-AT", "en"])));
        assert_eq!(
            Value::Object(german),
            json!({
                "name": "Lunch",
                "description": "Wo wir essen",
                "locale": "de",
                "localizations": null,
            })
        );

        // No range matches: the base values and the null locale.
        let mut nothing = Map::new();
        text.write(&mut nothing, &projection(true, json!(["ja", "*"])));
        assert_eq!(nothing["description"], json!("Where we eat"));
        assert_eq!(nothing["locale"], Value::Null);
    }

    #[test]
    fn a_room_without_descriptions_has_no_description() {
        let text = Localized::new("Lunch".into(), &[]);
        let mut view = Map::new();
        text.write(&mut view, &projection(true, json!(["de"])));
        assert_eq!(
            Value::Object(view),
            json!({"name": "Lunch", "locale": null, "localizations": null})
        );
    }
}
