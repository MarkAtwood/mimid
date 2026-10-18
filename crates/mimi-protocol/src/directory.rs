//! The directory document (protocol-06 §5.1).

use std::collections::BTreeMap;
use std::fmt;

use serde::de::{self, MapAccess, Visitor};
use serde::ser::{self, SerializeMap};

use crate::UriTemplate;

/// The JSON keys of protocol-06 §5.1, in the order of the draft's example.
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
/// (protocol-06 §5.1): one URL template per endpoint.
///
/// Fields mirror the draft's JSON keys. All ten are required, since §5.1
/// says the document holds "URIs for each type of endpoint".
///
/// Each value is a [`UriTemplate`] whose `{name}` placeholders are literal
/// text, expanded by the client (decision mimid-1wgh.5.38). Placeholder names
/// are not checked: §5.1 writes `{targetUser}`/`{requesterUser}` for the
/// consent endpoints where §5.7 writes `{targetDomain}`/`{requesterDomain}`
/// (decision mimid-1wgh.5.16), and a mismatch is caught when
/// [`UriTemplate::expand`] meets an undefined variable (decision
/// mimid-1wgh.5.42). URLs need not be `https` (decision mimid-1wgh.34).
///
/// Decoding with `serde_json` is strict: the document must be a JSON object,
/// every key may appear only once, every known key needs a string value that
/// is a valid template, and nothing may follow the object. Members with other
/// keys are kept in [`Directory::unknown`] and serialized back unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Directory {
    /// `keyMaterial` (§5.2).
    pub key_material: UriTemplate,
    /// `update` (§5.3).
    pub update: UriTemplate,
    /// `notify` (§5.5).
    pub notify: UriTemplate,
    /// `submitMessage` (§5.4).
    pub submit_message: UriTemplate,
    /// `groupInfo` (§5.6).
    pub group_info: UriTemplate,
    /// `requestConsent` (§5.7).
    pub request_consent: UriTemplate,
    /// `updateConsent` (§5.7).
    pub update_consent: UriTemplate,
    /// `identifierQuery` (§5.8).
    pub identifier_query: UriTemplate,
    /// `reportAbuse` (§5.9).
    pub report_abuse: UriTemplate,
    /// `proxyDownload` (§5.10.2).
    pub proxy_download: UriTemplate,
    /// Members whose keys §5.1 does not define, kept so they round-trip.
    /// Serializing fails if this holds one of the ten keys above.
    pub unknown: BTreeMap<String, serde_json::Value>,
}

impl Directory {
    /// The known members as `(key, template)` pairs, in [`KEYS`] order.
    fn known(&self) -> [(&'static str, &UriTemplate); 10] {
        [
            (KEYS[0], &self.key_material),
            (KEYS[1], &self.update),
            (KEYS[2], &self.notify),
            (KEYS[3], &self.submit_message),
            (KEYS[4], &self.group_info),
            (KEYS[5], &self.request_consent),
            (KEYS[6], &self.update_consent),
            (KEYS[7], &self.identifier_query),
            (KEYS[8], &self.report_abuse),
            (KEYS[9], &self.proxy_download),
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
        let mut map = serializer.serialize_map(Some(KEYS.len() + self.unknown.len()))?;
        for (key, template) in self.known() {
            map.serialize_entry(key, template)?;
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
        let mut take = |i: usize| {
            known[i]
                .take()
                .ok_or_else(|| de::Error::missing_field(KEYS[i]))
        };
        Ok(Directory {
            key_material: take(0)?,
            update: take(1)?,
            notify: take(2)?,
            submit_message: take(3)?,
            group_info: take(4)?,
            request_consent: take(5)?,
            update_consent: take(6)?,
            identifier_query: take(7)?,
            report_abuse: take(8)?,
            proxy_download: take(9)?,
            unknown,
        })
    }
}
