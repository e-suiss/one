//! Shared loaders for the federation, attention and model conformance tests: JSON vectors, schema-vector checks and a reader for the flat TOML tables (T-31).

use std::fmt::Debug;
use std::path::Path;

use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub(crate) fn conformance(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance")
        .join(rel)
}

pub(crate) fn vectors(rel: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(conformance(rel)).unwrap();
    serde_json::from_str(&text).unwrap()
}

pub(crate) fn decode<T: DeserializeOwned, E: Debug>(
    input: &Value,
    validate: fn(&T) -> Result<(), E>,
) -> Result<T, String> {
    let value: T = serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
    validate(&value).map_err(|e| format!("{e:?}"))?;
    Ok(value)
}

pub(crate) struct SchemaCount {
    pub(crate) valid: usize,
    pub(crate) invalid: usize,
}

pub(crate) fn check_schema_vectors<T: DeserializeOwned + Serialize, E: Debug>(
    rel: &str,
    validate: fn(&T) -> Result<(), E>,
) -> SchemaCount {
    let mut count = SchemaCount {
        valid: 0,
        invalid: 0,
    };
    let mut wrong = Vec::new();
    for v in vectors(rel) {
        let description = v["description"].as_str().unwrap().to_owned();
        let input = &v["input"];
        let result = decode::<T, E>(input, validate);
        if v["valid"].as_bool().unwrap() {
            count.valid += 1;
            match result {
                Ok(value) => {
                    let text = serde_json::to_string(&value).unwrap();
                    let back: Value = serde_json::from_str(&text).unwrap();
                    if &back != input {
                        wrong.push(format!("{description}: round trip gave {back}"));
                    }
                }
                Err(e) => wrong.push(format!("{description}: rejected ({e})")),
            }
        } else {
            count.invalid += 1;
            if result.is_ok() {
                wrong.push(format!("{description}: accepted"));
            }
        }
    }
    assert!(wrong.is_empty(), "{rel}:\n{}", wrong.join("\n"));
    count
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum TomlValue {
    Str(String),
    Bool(bool),
    Int(i64),
    List(Vec<String>),
}

pub(crate) type TomlRow = Vec<(String, TomlValue)>;

pub(crate) fn toml_value(raw: &str) -> TomlValue {
    let raw = raw.trim();
    if let Some(inner) = raw.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        return TomlValue::List(
            inner
                .split(',')
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(|s| s.trim_matches('"').to_owned())
                .collect(),
        );
    }
    if let Some(s) = raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return TomlValue::Str(s.to_owned());
    }
    match raw {
        "true" => TomlValue::Bool(true),
        "false" => TomlValue::Bool(false),
        _ => TomlValue::Int(raw.parse().unwrap()),
    }
}

pub(crate) fn toml_tables(rel: &str, table: &str) -> Vec<TomlRow> {
    let text = std::fs::read_to_string(conformance(rel)).unwrap();
    let header = format!("[[{table}]]");
    let mut rows: Vec<TomlRow> = Vec::new();
    let mut inside = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            inside = line == header;
            if inside {
                rows.push(Vec::new());
            }
            continue;
        }
        if !inside || line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line.split_once('=').unwrap();
        rows.last_mut()
            .unwrap()
            .push((key.trim().to_owned(), toml_value(value)));
    }
    rows
}

pub(crate) fn get<'a>(row: &'a TomlRow, key: &str) -> Option<&'a TomlValue> {
    row.iter().find(|(k, _)| k == key).map(|(_, v)| v)
}

pub(crate) fn get_str<'a>(row: &'a TomlRow, key: &str) -> Option<&'a str> {
    match get(row, key) {
        Some(TomlValue::Str(s)) => Some(s),
        _ => None,
    }
}

pub(crate) fn get_bool(row: &TomlRow, key: &str) -> Option<bool> {
    match get(row, key) {
        Some(TomlValue::Bool(b)) => Some(*b),
        _ => None,
    }
}
