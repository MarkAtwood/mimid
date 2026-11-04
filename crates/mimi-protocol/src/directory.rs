//! The directory document (protocol-07 §5.1).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::{self, SerializeMap};

use crate::UriTemplate;

/// The JSON keys of protocol-07 §5.1, in the order of the draft's example.
const KEYS: [&str; 10] = [
    "keyMaterial",
    "update",
    "notify",
    "submitMessage",
    "groupInfo",
    "requestConsent",
    "updateConsent",
    "identifierQuery",
    "reportAbuse",
    "proxyDownload",
];

/// The directory document served at `/.well-known/mimi-protocol-directory`
/// (protocol-07 §5.1): one URL template per endpoint.
///
/// Fields mirror the draft's JSON keys. Each is optional: §5.1 says the
/// document holds "URIs for each type of endpoint" but not what a provider
/// that does not offer an endpoint publishes, so an absent key means the
/// provider does not offer that endpoint (decision mimid-1wgh.5.75).
///
/// Each value is a [`UriTemplate`] whose `{name}` placeholders are literal
/// text, expanded by the client (decision mimid-1wgh.5.38). Placeholder names
/// are not checked: a mismatch is caught when [`UriTemplate::expand`] meets
/// an undefined variable (decision mimid-1wgh.5.42). URLs need not be `https` (decision mimid-1wgh.34).
///
/// Decoding with `serde_json` is strict: the document must be a JSON object,
/// every key may appear only once, every known key present needs a string
/// value that is a valid template, and nothing may follow the object. Members with other
/// keys are kept in [`Directory::unknown`] and serialized back unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    /// `keyMaterial` (§5.2).
    pub key_material: Option<UriTemplate>,
    /// `update` (§5.3).
    pub update: Option<UriTemplate>,
    /// `notify` (§5.5).
    pub notify: Option<UriTemplate>,
    /// `submitMessage` (§5.4).
    pub submit_message: Option<UriTemplate>,
    /// `groupInfo` (§5.6).
    pub group_info: Option<UriTemplate>,
    /// `requestConsent` (§5.7).
    pub request_consent: Option<UriTemplate>,
    /// `updateConsent` (§5.7).
    pub update_consent: Option<UriTemplate>,
    /// `identifierQuery` (§5.8).
    pub identifier_query: Option<UriTemplate>,
    /// `reportAbuse` (§5.9).
    pub report_abuse: Option<UriTemplate>,
    /// `proxyDownload` (§5.10.2).
    pub proxy_download: Option<UriTemplate>,
    /// Members whose keys §5.1 does not define, kept so they round-trip.
    /// Serializing fails if this holds one of the ten keys above.
    pub unknown: BTreeMap<String, serde_json::Value>,
}

impl Directory {
    /// The known members as `(key, template)` pairs, in [`KEYS`] order.
    fn known(&self) -> [(&'static str, Option<&UriTemplate>); 10] {
        [
            (KEYS[0], self.key_material.as_ref()),
            (KEYS[1], self.update.as_ref()),
            (KEYS[2], self.notify.as_ref()),
            (KEYS[3], self.submit_message.as_ref()),
            (KEYS[4], self.group_info.as_ref()),
            (KEYS[5], self.request_consent.as_ref()),
            (KEYS[6], self.update_consent.as_ref()),
            (KEYS[7], self.identifier_query.as_ref()),
            (KEYS[8], self.report_abuse.as_ref()),
            (KEYS[9], self.proxy_download.as_ref()),
        ]
    }
}

impl serde::Serialize for Directory {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if let Some(key) = self.unknown.keys().find(|k| KEYS.contains(&k.as_str())) {
            return Err(ser::Error::custom(format_args!(
                "unknown directory member uses the known key {key:?}"
            )));
        }
        let known = self.known();
        let present = known
            .iter()
            .filter(|(_, template)| template.is_some())
            .count();
        let mut map = serializer.serialize_map(Some(present + self.unknown.len()))?;
        for (key, template) in known {
            if let Some(template) = template {
                map.serialize_entry(key, template)?;
            }
        }
        for (key, value) in &self.unknown {
            map.serialize_entry(key, value)?;
        }
        map.end()
    }
}

impl<'de> serde::Deserialize<'de> for Directory {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_map(DirectoryVisitor)
    }
}

struct DirectoryVisitor;

impl<'de> Visitor<'de> for DirectoryVisitor {
    type Value = Directory;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a MIMI directory JSON object")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Directory, A::Error> {
        let mut known: [Option<UriTemplate>; 10] = Default::default();
        let mut unknown = BTreeMap::new();
        while let Some(key) = map.next_key::<String>()? {
            let duplicate = match KEYS.iter().position(|k| *k == key) {
                Some(i) => known[i].replace(map.next_value()?).is_some(),
                None => unknown.insert(key.clone(), map.next_value()?).is_some(),
            };
            if duplicate {
                return Err(de::Error::custom(format_args!(
                    "duplicate directory member {key:?}"
                )));
            }
        }
        let [
            key_material,
            update,
            notify,
            submit_message,
            group_info,
            request_consent,
            update_consent,
            identifier_query,
            report_abuse,
            proxy_download,
        ] = known;
        Ok(Directory {
            key_material,
            update,
            notify,
            submit_message,
            group_info,
            request_consent,
            update_consent,
            identifier_query,
            report_abuse,
            proxy_download,
            unknown,
        })
    }
}
