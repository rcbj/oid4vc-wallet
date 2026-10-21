//! Shipped message catalogs.
//!
//! `locales/catalogs.json` names the catalogs, and each
//! `locales/wallet/<tag>.json` is a flat map of keys to messages. A regional
//! file holds only the keys whose wording differs from its base. English is
//! the source, and a lookup that misses every catalog returns the key.

use std::collections::BTreeMap;

use crate::protocol::Json;

use super::matching::{parts_of, TagParts};

/// One row of `locales/catalogs.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogMeta {
    pub tag: String,
    pub name: String,
    pub english: String,
    pub status: String,
    pub base: Option<String>,
}

/// A locale the chooser offers, named in its own language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Offered {
    pub tag: String,
    pub name: String,
}

/// Every embedded catalog.
#[derive(Debug)]
pub struct CatalogSet {
    /// The `source` tag from the catalog index. The completeness test reads it.
    #[cfg(test)]
    pub source: String,
    pub catalogs: Vec<CatalogMeta>,
    pub offered: Vec<Offered>,
    pub parts: Vec<TagParts>,
    /// `(namespace, tag)` to the keys of that file. Keys omit the namespace.
    messages: BTreeMap<(String, String), BTreeMap<String, String>>,
}

mod embedded {
    include!(concat!(env!("OUT_DIR"), "/locales_gen.rs"));
}

impl CatalogSet {
    pub fn load() -> Self {
        let index = parse_json(embedded::INDEX_JSON, "locales/catalogs.json");
        let source = require_string(&index, "source", "locales/catalogs.json");
        assert!(
            source == "en",
            "locales/catalogs.json source is {source}, and this wallet's source is en"
        );
        let mut catalogs = Vec::new();
        for entry in require_array(&index, "catalogs", "locales/catalogs.json") {
            let tag = require_string(entry, "tag", "catalogs");
            catalogs.push(CatalogMeta {
                name: require_string(entry, "name", &tag),
                english: require_string(entry, "english", &tag),
                status: require_string(entry, "status", &tag),
                base: optional_string(entry, "base", &tag),
                tag,
            });
        }
        let mut offered = Vec::new();
        for entry in require_array(&index, "offered", "locales/catalogs.json") {
            offered.push(Offered {
                tag: require_string(entry, "tag", "offered"),
                name: require_string(entry, "name", "offered"),
            });
        }
        let mut messages = BTreeMap::new();
        for meta in &catalogs {
            let Some(text) = embedded::catalog_json("wallet", &meta.tag) else {
                panic!("missing embedded catalog locales/wallet/{}.json", meta.tag);
            };
            let value = parse_json(text, &format!("locales/wallet/{}.json", meta.tag));
            let members = value.as_object().unwrap_or_else(|| {
                panic!("locales/wallet/{}.json is not an object", meta.tag);
            });
            let mut map = BTreeMap::new();
            for (key, member) in members {
                let Some(message) = member.as_str() else {
                    panic!("locales/wallet/{}.json key {key} is not a string", meta.tag);
                };
                assert!(
                    super::format::placeholder_names(message).is_ok(),
                    "locales/wallet/{}.json key {key} is not a message this wallet can format",
                    meta.tag
                );
                map.insert(key.clone(), message.to_string());
            }
            messages.insert(("wallet".to_string(), meta.tag.clone()), map);
        }
        let parts = catalogs
            .iter()
            .map(|meta| {
                parts_of(&meta.tag)
                    .unwrap_or_else(|| panic!("catalog tag {} is not a tag", meta.tag))
            })
            .collect();
        Self {
            #[cfg(test)]
            source,
            catalogs,
            offered,
            parts,
            messages,
        }
    }

    /// The message for `namespace.key` in one catalog file, when that file has it.
    pub fn message(&self, namespace: &str, tag: &str, key: &str) -> Option<&str> {
        self.messages
            .get(&(namespace.to_string(), tag.to_string()))
            .and_then(|map| map.get(key).map(String::as_str))
    }

    #[cfg(test)]
    pub fn file_keys(&self, namespace: &str, tag: &str) -> Option<&BTreeMap<String, String>> {
        self.messages.get(&(namespace.to_string(), tag.to_string()))
    }
}

/// The first catalog in `chain` that has `namespace.key`.
pub fn find(set: &CatalogSet, chain: &[String], full_key: &str) -> Option<(String, String)> {
    let (namespace, key) = full_key.split_once('.')?;
    if namespace.is_empty() || key.is_empty() {
        return None;
    }
    for tag in chain {
        if let Some(message) = set.message(namespace, tag, key) {
            return Some((tag.clone(), message.to_string()));
        }
    }
    None
}

fn parse_json(text: &str, what: &str) -> Json {
    match Json::parse(text) {
        Ok(value) => value,
        Err(err) => panic!("{what} is not JSON at byte {}: {}", err.at, err.message),
    }
}

fn require_string(value: &Json, key: &str, what: &str) -> String {
    value
        .get(key)
        .and_then(Json::as_str)
        .filter(|text| !text.is_empty())
        .map_or_else(|| panic!("{what} is missing {key}"), str::to_string)
}

fn optional_string(value: &Json, key: &str, what: &str) -> Option<String> {
    match value.get(key) {
        None | Some(Json::Null) => None,
        Some(other) => Some(other.as_str().filter(|text| !text.is_empty()).map_or_else(
            || panic!("{what} has a {key} that is not a string"),
            str::to_string,
        )),
    }
}

fn require_array<'a>(value: &'a Json, key: &str, what: &str) -> &'a [Json] {
    value
        .get(key)
        .and_then(Json::as_array)
        .unwrap_or_else(|| panic!("{what} is missing {key}"))
}
