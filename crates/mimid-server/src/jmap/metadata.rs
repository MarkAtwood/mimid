//! Chat `metadata` and `privateMetadata` (draft-ietf-jmap-metadata-05;
//! decision mimid-1wgh.63): what the account capability advertises, the
//! `/get` subselectors (§3.1) and the `/set` PatchObject paths (§3.2) of
//! the two properties.
//!
//! Chat is the only listed data type. Shared `metadata` is always `{}`:
//! every Chat here is bound to a room, whose shared state is MLS group
//! state (draft-atwood-jmap-chat-mimi-00 §Chat.roomId), so a write to it
//! is `forbidden` (decision mimid-1wgh.63 item 2). `privateMetadata`
//! takes any vendor (domain-name) namespace.
//!
//! # Limitations
//!
//! - No registered namespace is supported: the registry (§8.2) has none.
//! - The quota is per Chat ([`MAX_CHAT_PRIVATE_METADATA_LEN`]), not per
//!   account (§5).

use jmap_metadata_types::{DataTypeMetadataInfo, is_valid_namespace};
use serde_json::{Map, Value, json};

/// The `metadata` property (§2).
pub(crate) const METADATA: &str = "metadata";

/// The `privateMetadata` property (§2).
pub(crate) const PRIVATE_METADATA: &str = "privateMetadata";

/// `maxDepth` of a Chat namespace value (§1.2.1). INVENTED, NOT FROM SPEC:
/// the value (decision mimid-1wgh.63 item 1).
pub const MAX_CHAT_METADATA_DEPTH: u64 = 4;

/// The most octets of JSON a Chat's `privateMetadata` may take; a write
/// past it is `overQuota` (§3.2.1). INVENTED, NOT FROM SPEC: the value
/// (decision mimid-1wgh.63 item 3).
pub const MAX_CHAT_PRIVATE_METADATA_LEN: usize = 16_384;

/// The `dataTypes` entry for Chat (§1.2.1).
pub(crate) fn chat_info() -> DataTypeMetadataInfo {
    // DataTypeMetadataInfo is #[non_exhaustive]: built through serde
    // (AGENTS.md).
    serde_json::from_value(json!({
        "namespaces": [],
        "supportsVendorNamespaces": true,
        "supportsPrivate": true,
        "maxDepth": MAX_CHAT_METADATA_DEPTH,
    }))
    .expect("draft-ietf-jmap-metadata-05 §1.2.1 fields form a DataTypeMetadataInfo")
}

/// The property `key` of a `/get` `properties` entry or a `/set` key
/// belongs to: `metadata` or `privateMetadata`, if either.
pub(crate) fn root(key: &str) -> Option<&'static str> {
    let first = key.split('/').next().unwrap_or(key);
    [METADATA, PRIVATE_METADATA]
        .into_iter()
        .find(|root| *root == first)
}

/// Whether `entry` is a valid `/get` `properties` entry for the two
/// properties: the property itself, or `<property>/<namespace>` (§3.1).
/// `None` if `entry` is about neither property.
pub(crate) fn valid_selector(entry: &str) -> Option<bool> {
    root(entry)?;
    Some(match entry.split_once('/') {
        None => true,
        Some((_, namespace)) => !namespace.contains('/') && is_valid_namespace(namespace),
    })
}

/// `object` cut down to the metadata `properties` ask for (§3.1): a
/// property named whole is kept whole; otherwise its subselectors keep
/// the namespaces they name that hold data, and it is left out when none
/// is named.
pub(crate) fn select(object: &mut Map<String, Value>, properties: &[String]) {
    for root in [METADATA, PRIVATE_METADATA] {
        if properties.iter().any(|p| p == root) {
            continue;
        }
        let namespaces: Vec<&str> = properties
            .iter()
            .filter_map(|p| p.strip_prefix(root)?.strip_prefix('/'))
            .collect();
        if namespaces.is_empty() {
            object.remove(root);
            continue;
        }
        if let Some(Value::Object(map)) = object.get_mut(root) {
            map.retain(|namespace, _| namespaces.contains(&namespace.as_str()));
        }
    }
}

/// A PatchObject error, the SetError `invalidPatch` (RFC 8620 §5.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InvalidPatch(pub(crate) String);

/// The tokens of a PatchObject path below its property (RFC 6901 §4).
fn tokens(rest: &str) -> Result<Vec<String>, InvalidPatch> {
    rest.split('/')
        .map(|token| {
            let mut out = String::with_capacity(token.len());
            let mut chars = token.chars();
            while let Some(c) = chars.next() {
                if c != '~' {
                    out.push(c);
                    continue;
                }
                match chars.next() {
                    Some('0') => out.push('~'),
                    Some('1') => out.push('/'),
                    _ => {
                        return Err(InvalidPatch(format!(
                            "{rest:?} has an invalid ~ escape (RFC 6901 §3)"
                        )));
                    }
                }
            }
            Ok(out)
        })
        .collect()
}

/// The full path of a `/set` key as tokens, the property first.
fn key_path(key: &str) -> Result<Vec<String>, InvalidPatch> {
    match key.split_once('/') {
        None => Ok(vec![key.to_owned()]),
        Some((property, rest)) => {
            let mut path = vec![property.to_owned()];
            path.extend(tokens(rest)?);
            Ok(path)
        }
    }
}

/// The patch errors the request alone shows (§3.2: reported before rule
/// 1): a bad escape, an empty path token, or one path a prefix of
/// another (RFC 8620 §5.3).
pub(crate) fn check_patch_shape(patch: &Map<String, Value>) -> Result<(), InvalidPatch> {
    let paths = patch
        .keys()
        .map(|key| key_path(key))
        .collect::<Result<Vec<_>, _>>()?;
    if let Some(key) = patch
        .keys()
        .zip(&paths)
        .find(|(_, path)| path.iter().any(String::is_empty))
        .map(|(key, _)| key)
    {
        return Err(InvalidPatch(format!("{key:?} has an empty path token")));
    }
    for (i, a) in paths.iter().enumerate() {
        for b in &paths[i + 1..] {
            let shorter = a.len().min(b.len());
            if a[..shorter] == b[..shorter] {
                return Err(InvalidPatch(format!(
                    "{} and {} overlap (RFC 8620 §5.3)",
                    a.join("/"),
                    b.join("/")
                )));
            }
        }
    }
    Ok(())
}

/// Applies the `privateMetadata` keys of `patch` to `value`, the stored
/// `privateMetadata` (RFC 8620 §5.3; §3.2: null removes, the parent of
/// the target must exist, and no path goes through an array or a Binary
/// value).
///
/// # Errors
///
/// [`InvalidPatch`] for a path whose parent is missing or is not a plain
/// object.
pub(crate) fn apply(
    value: &mut Map<String, Value>,
    patch: &Map<String, Value>,
) -> Result<(), InvalidPatch> {
    for (key, new) in patch {
        let path = key_path(key)?;
        let Some((property, rest)) = path.split_first() else {
            continue;
        };
        if property != PRIVATE_METADATA {
            continue;
        }
        let Some((last, parents)) = rest.split_last() else {
            // §3.2: "In an update, null is equivalent to {}".
            *value = match new {
                Value::Null => Map::new(),
                Value::Object(map) => map.clone(),
                _ => return Err(InvalidPatch(format!("{key} must be an object"))),
            };
            continue;
        };
        let mut target = &mut *value;
        for token in parents {
            target = match target.get_mut(token) {
                Some(Value::Object(next))
                    if next.get("@type").and_then(Value::as_str) != Some("Binary") =>
                {
                    next
                }
                Some(_) => {
                    return Err(InvalidPatch(format!(
                        "{key} goes through a value that is not an object"
                    )));
                }
                None => return Err(InvalidPatch(format!("{key} has no parent"))),
            };
        }
        if new.is_null() {
            target.remove(last);
        } else {
            target.insert(last.clone(), new.clone());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(value: Value) -> Map<String, Value> {
        match value {
            Value::Object(map) => map,
            _ => panic!("not an object"),
        }
    }

    #[test]
    fn selectors_follow_section_3_1() {
        assert_eq!(valid_selector("privateMetadata"), Some(true));
        assert_eq!(valid_selector("metadata/acme.example.com"), Some(true));
        assert_eq!(valid_selector("privateMetadata/"), Some(false));
        assert_eq!(valid_selector("privateMetadata/a.example/key"), Some(false));
        assert_eq!(valid_selector("privateMetadata/Acme.Example"), Some(false));
        assert_eq!(valid_selector("roomId"), None);
        assert_eq!(valid_selector("privateMetadataX"), None);

        let full = map(json!({
            "id": "c",
            "metadata": {},
            "privateMetadata": {"a.example": {"x": 1}, "b.example": {"y": 2}},
        }));
        let mut object = full.clone();
        select(&mut object, &["privateMetadata/a.example".to_owned()]);
        assert_eq!(
            Value::Object(object),
            json!({"id": "c", "privateMetadata": {"a.example": {"x": 1}}})
        );
        // An explicit root supersedes its subselectors.
        let mut object = full.clone();
        select(
            &mut object,
            &[
                "privateMetadata".to_owned(),
                "privateMetadata/a.example".to_owned(),
            ],
        );
        assert_eq!(object.get("privateMetadata"), full.get("privateMetadata"));
        assert!(!object.contains_key("metadata"));
    }

    #[test]
    fn patch_paths_follow_rfc_8620_section_5_3() {
        let mut value = map(
            json!({"a.example": {"k": 1, "arr": [1], "bin": {"@type": "Binary", "base64": "AA=="}}}),
        );
        apply(
            &mut value,
            &map(json!({
                "privateMetadata/a.example/k": null,
                "privateMetadata/a.example/n~1m": true,
                "privateMetadata/b.example": {"accepted": true},
            })),
        )
        .unwrap();
        assert_eq!(
            Value::Object(value.clone()),
            json!({
                "a.example": {"n/m": true, "arr": [1], "bin": {"@type": "Binary", "base64": "AA=="}},
                "b.example": {"accepted": true},
            })
        );
        for bad in [
            "privateMetadata/c.example/k",
            "privateMetadata/a.example/arr/0",
            "privateMetadata/a.example/bin/base64",
        ] {
            assert!(
                apply(&mut value.clone(), &map(json!({bad: 1}))).is_err(),
                "{bad}"
            );
        }
        apply(&mut value, &map(json!({"privateMetadata": null}))).unwrap();
        assert!(value.is_empty());
    }

    #[test]
    fn overlapping_and_malformed_paths_are_invalid_patches() {
        for bad in [
            json!({"privateMetadata/a.example": {}, "privateMetadata/a.example/k": 1}),
            json!({"privateMetadata": {}, "privateMetadata/a.example": {}}),
            json!({"privateMetadata/a.example/~2": 1}),
            json!({"privateMetadata/a.example/": 1}),
        ] {
            assert!(check_patch_shape(&map(bad.clone())).is_err(), "{bad}");
        }
        assert!(
            check_patch_shape(&map(json!({
                "privateMetadata/a.example/k": 1,
                "privateMetadata/a.example/kk": 2,
            })))
            .is_ok()
        );
    }
}
