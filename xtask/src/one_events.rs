//! `events-catalog`: the `AsyncAPI` catalog under `conformance/events/` is well formed, every `$ref` resolves, every message names an indexed event whose payload is an indexed JSON Schema, and every valid `CloudEvent` vector of a catalogued type carries a payload that validates; `asyncapi-breaking` compares the catalog and its payload schemas with a base commit (T-31, §17.10.5).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde_json::{Map, Value};
use yaml_rust2::{Yaml, YamlLoader};

use super::v;
use super::vectors::{self, Compiled, Index, SchemaVector};
use crate::Violation;

const DIR: &str = "conformance/events";
const DOC: &str = "conformance/events/asyncapi.yaml";
const SCHEMA_FORMAT: &str = "application/schema+json;version=draft-2020-12";
const CONTENT_TYPE: &str = "application/cloudevents+json";
const ENVELOPE_ID: &str = "https://suiss.app/schemas/one/events/cloudevent/v1.json";

fn to_json(yaml: &Yaml) -> Result<Value, String> {
    Ok(match yaml {
        Yaml::Null => Value::Null,
        Yaml::Boolean(b) => Value::Bool(*b),
        Yaml::Integer(i) => Value::from(*i),
        Yaml::Real(r) => r
            .parse::<f64>()
            .ok()
            .and_then(serde_json::Number::from_f64)
            .map(Value::Number)
            .ok_or_else(|| format!("unsupported number `{r}`"))?,
        Yaml::String(s) => Value::String(s.clone()),
        Yaml::Array(items) => Value::Array(items.iter().map(to_json).collect::<Result<_, _>>()?),
        Yaml::Hash(hash) => {
            let mut map = Map::new();
            for (k, val) in hash {
                let Yaml::String(key) = k else {
                    return Err(format!("mapping key {k:?} is not a string"));
                };
                if map.insert(key.clone(), to_json(val)?).is_some() {
                    return Err(format!("duplicate key `{key}`"));
                }
            }
            Value::Object(map)
        }
        Yaml::Alias(_) | Yaml::BadValue => return Err("aliases are not allowed".to_owned()),
    })
}

/// Parses a single-document YAML text into JSON.
pub(crate) fn parse_yaml(text: &str) -> Result<Value, String> {
    let docs = YamlLoader::load_from_str(text).map_err(|e| e.to_string())?;
    match docs.as_slice() {
        [doc] => to_json(doc),
        _ => Err(format!("expected one YAML document, found {}", docs.len())),
    }
}

/// `base` joined with a relative `reference`, with `.` and `..` resolved.
pub(crate) fn join(base: &str, reference: &str) -> Option<String> {
    let mut parts: Vec<&str> = base.split('/').filter(|p| !p.is_empty()).collect();
    for part in reference.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

fn pointer<'a>(doc: &'a Value, fragment: &str) -> Option<&'a Value> {
    doc.pointer(fragment.strip_prefix('#')?)
}

fn obj<'a>(doc: &'a Value, key: &str) -> Option<&'a Map<String, Value>> {
    doc.get(key).and_then(Value::as_object)
}

fn str_at<'a>(doc: &'a Value, path: &str) -> Option<&'a str> {
    doc.pointer(path).and_then(Value::as_str)
}

fn refs(value: &Value, at: &str, out: &mut Vec<(String, String)>) {
    match value {
        Value::Object(map) => {
            for (k, val) in map {
                if k == "$ref"
                    && let Some(r) = val.as_str()
                {
                    out.push((at.to_owned(), r.to_owned()));
                }
                refs(val, &format!("{at}/{k}"), out);
            }
        }
        Value::Array(items) => {
            for (i, item) in items.iter().enumerate() {
                refs(item, &format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

/// True for a `CloudEvent` `type` in the One namespace with a major version suffix.
pub(crate) fn is_event_type(kind: &str) -> bool {
    let Some(rest) = kind.strip_prefix("app.suiss.one.") else {
        return false;
    };
    let mut segments: Vec<&str> = rest.split('.').collect();
    let Some(version) = segments.pop().and_then(|s| s.strip_prefix('v')) else {
        return false;
    };
    let good_version = version.chars().all(|c| c.is_ascii_digit())
        && version.chars().next().is_some_and(|c| c != '0');
    good_version
        && !segments.is_empty()
        && segments.iter().all(|s| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
        })
}

/// A schema reference of a message payload or component schema.
fn schema_ref(entry: &Value) -> Option<&str> {
    str_at(entry, "/schema/$ref")
}

/// Structural rules over a parsed catalog; `file_exists` answers for repository-relative paths.
pub(crate) fn structure(doc: &Value, file_exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    if !str_at(doc, "/asyncapi").is_some_and(|s| s.starts_with("3.")) {
        out.push("`asyncapi` must be a 3.x version".to_owned());
    }
    if str_at(doc, "/info/title").is_none_or(str::is_empty) {
        out.push("`info.title` is missing".to_owned());
    }
    if str_at(doc, "/info/version").is_none_or(|s| s.split('.').count() != 3) {
        out.push("`info.version` must be `MAJOR.MINOR.PATCH`".to_owned());
    }
    if str_at(doc, "/defaultContentType") != Some(CONTENT_TYPE) {
        out.push(format!("`defaultContentType` must be `{CONTENT_TYPE}`"));
    }
    for key in ["channels", "operations"] {
        if obj(doc, key).is_none() {
            out.push(format!("`{key}` must be a mapping"));
        }
    }
    check_refs(doc, file_exists, &mut out);
    check_components(doc, &mut out);
    check_wiring(doc, &mut out);
    out
}

fn check_refs(doc: &Value, file_exists: &dyn Fn(&str) -> bool, out: &mut Vec<String>) {
    let mut found = Vec::new();
    refs(doc, "", &mut found);
    for (at, r) in &found {
        if r.starts_with('#') {
            if pointer(doc, r).is_none() {
                out.push(format!("{at}: `$ref` `{r}` does not resolve"));
            }
        } else if r.contains("://") || r.contains('#') {
            out.push(format!(
                "{at}: `$ref` `{r}` must be a local file or `#/` pointer"
            ));
        } else if !join(DIR, r).is_some_and(|p| file_exists(&p)) {
            out.push(format!("{at}: `$ref` `{r}` names no file"));
        }
    }
}

fn check_components(doc: &Value, out: &mut Vec<String>) {
    let components = doc.pointer("/components");
    for section in ["schemas", "messages"] {
        for (name, entry) in components
            .and_then(|c| obj(c, section))
            .into_iter()
            .flatten()
        {
            let payload = if section == "messages" {
                entry.get("payload").unwrap_or(&Value::Null)
            } else {
                entry
            };
            if str_at(payload, "/schemaFormat") != Some(SCHEMA_FORMAT)
                || schema_ref(payload).is_none_or(|r| r.starts_with('#'))
            {
                out.push(format!(
                    "components.{section}.{name}: needs `schemaFormat: {SCHEMA_FORMAT}` and a file `schema.$ref`"
                ));
            }
        }
    }
    let messages = components.and_then(|c| obj(c, "messages"));
    let mut names = BTreeSet::new();
    for (key, message) in messages.into_iter().flatten() {
        match message.get("name").and_then(Value::as_str) {
            Some(name) if is_event_type(name) => {
                if !names.insert(name) {
                    out.push(format!(
                        "components.messages.{key}: `name` `{name}` is repeated"
                    ));
                }
            }
            _ => out.push(format!(
                "components.messages.{key}: `name` must be a versioned `app.suiss.one.` event type"
            )),
        }
    }
}

fn check_wiring(doc: &Value, out: &mut Vec<String>) {
    let messages = doc
        .pointer("/components/messages")
        .and_then(Value::as_object);
    let mut used = BTreeSet::new();
    for (id, channel) in obj(doc, "channels").into_iter().flatten() {
        if str_at(channel, "/address").is_none_or(str::is_empty) {
            out.push(format!("channels.{id}: `address` is missing"));
        }
        let entries = obj(channel, "messages");
        if entries.is_none_or(Map::is_empty) {
            out.push(format!("channels.{id}: lists no messages"));
        }
        for (key, entry) in entries.into_iter().flatten() {
            match str_at(entry, "/$ref").and_then(|r| r.strip_prefix("#/components/messages/")) {
                Some(name) => {
                    used.insert(name.to_owned());
                }
                None => out.push(format!(
                    "channels.{id}.messages.{key}: must `$ref` a `#/components/messages/` entry"
                )),
            }
        }
    }
    for key in messages.into_iter().flatten().map(|(k, _)| k) {
        if !used.contains(key) {
            out.push(format!("components.messages.{key}: no channel carries it"));
        }
    }
    for (id, op) in obj(doc, "operations").into_iter().flatten() {
        if !matches!(str_at(op, "/action"), Some("send" | "receive")) {
            out.push(format!(
                "operations.{id}: `action` must be `send` or `receive`"
            ));
        }
        let Some(channel) = str_at(op, "/channel/$ref").and_then(|r| r.strip_prefix("#/channels/"))
        else {
            out.push(format!(
                "operations.{id}: must `$ref` a `#/channels/` entry"
            ));
            continue;
        };
        let listed = op.get("messages").and_then(Value::as_array);
        if listed.is_none_or(Vec::is_empty) {
            out.push(format!("operations.{id}: lists no messages"));
        }
        let prefix = format!("#/channels/{channel}/messages/");
        for r in listed.into_iter().flatten() {
            if !str_at(r, "/$ref").is_some_and(|r| r.starts_with(&prefix)) {
                out.push(format!(
                    "operations.{id}: every message must `$ref` a message of `{channel}`"
                ));
            }
        }
    }
}

/// Event type → payload schema reference, from `components.messages`.
pub(crate) fn payloads(doc: &Value) -> BTreeMap<String, String> {
    doc.pointer("/components/messages")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
        .filter_map(|(_, m)| {
            Some((
                m.get("name")?.as_str()?.to_owned(),
                m.get("payload").and_then(schema_ref)?.to_owned(),
            ))
        })
        .collect()
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let text = std::fs::read_to_string(root.join(DOC)).map_err(|e| format!("{DOC}: {e}"))?;
    let doc = parse_yaml(&text).map_err(|e| format!("{DOC}: {e}"))?;
    for message in structure(&doc, &|p| root.join(p).is_file()) {
        out.push(v("T-31", DOC, message));
    }
    let all = vectors::indexes(root)?;
    let mut ignored = Vec::new();
    let compiled = vectors::compile(root, &all, &mut ignored)?;
    let events = all
        .iter()
        .find(|(folder, _)| folder == "events")
        .map(|(_, index)| index);
    let empty = Index::default();
    let index = events.unwrap_or(&empty);
    let index_rel = format!("{DIR}/index.toml");
    let declared = payloads(&doc);
    let mut listed = BTreeMap::new();
    for event in &index.event {
        if listed
            .insert(event.kind.as_str(), event.schema.as_str())
            .is_some()
        {
            out.push(v(
                "T-31",
                index_rel.clone(),
                format!("event `{}` is repeated", event.kind),
            ));
        }
        if !compiled.by_id.contains_key(&event.schema) {
            out.push(v(
                "T-31",
                index_rel.clone(),
                format!(
                    "event `{}`: `{}` is no compiled schema",
                    event.kind, event.schema
                ),
            ));
        }
        let Some(reference) = declared.get(&event.kind) else {
            out.push(v(
                "T-31",
                index_rel.clone(),
                format!("event `{}` has no message in {DOC}", event.kind),
            ));
            continue;
        };
        let Some(path) = join(DIR, reference) else {
            continue;
        };
        if compiled.paths.get(&event.schema).is_none_or(|p| *p != path) {
            out.push(v(
                "T-31",
                DOC,
                format!(
                    "event `{}`: payload `{reference}` is not the indexed schema `{}`",
                    event.kind, event.schema
                ),
            ));
        }
    }
    for kind in declared.keys() {
        if !listed.contains_key(kind.as_str()) {
            out.push(v(
                "T-31",
                DOC,
                format!("message `{kind}` has no `[[event]]` in {index_rel}"),
            ));
        }
    }
    let envelope = compiled.by_id.get(ENVELOPE_ID);
    if envelope.is_none() {
        out.push(v(
            "T-31",
            index_rel.clone(),
            format!("`{ENVELOPE_ID}` is not compiled"),
        ));
    }
    for entry in index
        .vectors
        .iter()
        .filter(|e| e.kind == "schema" && e.schema.as_deref() == Some(ENVELOPE_ID))
    {
        let rel = format!("{DIR}/{}", entry.path);
        let parsed: Vec<SchemaVector> =
            serde_json::from_value(vectors::read_json(&root.join(&rel))?)
                .map_err(|e| format!("{rel}: {e}"))?;
        for (i, vector) in parsed.iter().enumerate().filter(|(_, x)| x.valid) {
            out.extend(
                payload_errors(&compiled, &listed, &vector.input)
                    .into_iter()
                    .map(|m| v("T-31", format!("{rel}#{i}"), m)),
            );
        }
    }
    Ok(out)
}

fn payload_errors(
    compiled: &Compiled,
    listed: &BTreeMap<&str, &str>,
    event: &Value,
) -> Vec<String> {
    let kind = event
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(schema) = listed.get(kind) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    if event.get("dataschema").and_then(Value::as_str) != Some(*schema) {
        out.push(format!("`{kind}` must carry `dataschema` `{schema}`"));
    }
    if let Some(index) = compiled.by_id.get(*schema) {
        let data = event.get("data").unwrap_or(&Value::Null);
        if let Err(e) = compiled.schemas.validate(data, *index) {
            out.push(format!("`{kind}` data does not match `{schema}`: {e}"));
        }
    }
    out
}

fn git_show(root: &Path, base: &str, path: &str) -> Result<String, String> {
    let output = Command::new("git")
        .args(["show", &format!("{base}:{path}")])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "{base}:{path}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|e| format!("{base}:{path}: {e}"))
}

fn types(schema: &Value) -> Option<BTreeSet<String>> {
    match schema.get("type")? {
        Value::String(s) => Some(BTreeSet::from([s.clone()])),
        Value::Array(items) => Some(
            items
                .iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect(),
        ),
        _ => None,
    }
}

fn strings(schema: &Value, key: &str) -> BTreeSet<String> {
    schema
        .get(key)
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|s| s.as_str().map(str::to_owned))
        .collect()
}

fn bound(schema: &Value, key: &str) -> Option<f64> {
    schema.get(key).and_then(Value::as_f64)
}

/// Breaking differences between two versions of one JSON Schema, by JSON pointer.
pub(crate) fn schema_breaks(base: &Value, head: &Value, at: &str, out: &mut Vec<String>) {
    let here = if at.is_empty() { "/" } else { at };
    if let Some(b) = types(base) {
        match types(head) {
            Some(h) if !b.is_subset(&h) => out.push(format!("{here}: `type` narrowed")),
            _ => {}
        }
    } else if types(head).is_some() {
        out.push(format!("{here}: `type` added"));
    }
    for key in ["$id", "$ref", "const", "pattern", "format"] {
        if head.get(key).is_some() && base.get(key) != head.get(key) {
            out.push(format!("{here}: `{key}` changed"));
        }
    }
    if let Some(h) = head.get("enum").and_then(Value::as_array) {
        let shrunk = base
            .get("enum")
            .and_then(Value::as_array)
            .is_none_or(|b| b.iter().any(|x| !h.contains(x)));
        if shrunk {
            out.push(format!("{here}: `enum` narrowed"));
        }
    }
    for (key, lower) in [
        ("minimum", true),
        ("exclusiveMinimum", true),
        ("minLength", true),
        ("minItems", true),
        ("minProperties", true),
        ("maximum", false),
        ("exclusiveMaximum", false),
        ("maxLength", false),
        ("maxItems", false),
        ("maxProperties", false),
    ] {
        if let Some(h) = bound(head, key) {
            let narrowed = bound(base, key).is_none_or(|b| if lower { h > b } else { h < b });
            if narrowed {
                out.push(format!("{here}: `{key}` narrowed"));
            }
        }
    }
    let base_required = strings(base, "required");
    let head_required = strings(head, "required");
    for name in base_required.difference(&head_required) {
        out.push(format!("{here}: `{name}` is no longer required"));
    }
    for name in head_required.difference(&base_required) {
        out.push(format!("{here}: `{name}` became required"));
    }
    let closed = |s: &Value| s.get("additionalProperties") == Some(&Value::Bool(false));
    if closed(head) && !closed(base) {
        out.push(format!("{here}: `additionalProperties` closed"));
    }
    let empty = Map::new();
    let head_props = obj(head, "properties").unwrap_or(&empty);
    for (name, b) in obj(base, "properties").unwrap_or(&empty) {
        match head_props.get(name) {
            Some(h) => schema_breaks(b, h, &format!("{at}/properties/{name}"), out),
            None => out.push(format!("{here}: property `{name}` removed")),
        }
    }
    for key in ["items", "additionalProperties"] {
        if let (Some(b @ Value::Object(_)), Some(h @ Value::Object(_))) =
            (base.get(key), head.get(key))
        {
            schema_breaks(b, h, &format!("{at}/{key}"), out);
        }
    }
    for key in ["$defs", "definitions"] {
        for (name, b) in obj(base, key).unwrap_or(&empty) {
            match obj(head, key).and_then(|h| h.get(name)) {
                Some(h) => schema_breaks(b, h, &format!("{at}/{key}/{name}"), out),
                None => out.push(format!("{here}: `{key}/{name}` removed")),
            }
        }
    }
}

/// Breaking differences between two catalogs; `load(side, path)` reads a payload schema.
pub(crate) fn catalog_breaks(
    base: &Value,
    head: &Value,
    load: &dyn Fn(bool, &str) -> Result<Value, String>,
) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    let empty = Map::new();
    let head_channels = obj(head, "channels").unwrap_or(&empty);
    for (id, b) in obj(base, "channels").unwrap_or(&empty) {
        let Some(h) = head_channels.get(id) else {
            out.push(format!("channel `{id}` removed"));
            continue;
        };
        if str_at(b, "/address") != str_at(h, "/address") {
            out.push(format!("channel `{id}`: address changed"));
        }
        let head_messages = obj(h, "messages").unwrap_or(&empty);
        for (key, entry) in obj(b, "messages").unwrap_or(&empty) {
            if head_messages.get(key) != Some(entry) {
                out.push(format!(
                    "channel `{id}`: message `{key}` removed or changed"
                ));
            }
        }
    }
    let head_ops = obj(head, "operations").unwrap_or(&empty);
    for (id, b) in obj(base, "operations").unwrap_or(&empty) {
        let Some(h) = head_ops.get(id) else {
            out.push(format!("operation `{id}` removed"));
            continue;
        };
        for key in ["/action", "/channel/$ref"] {
            if str_at(b, key) != str_at(h, key) {
                out.push(format!("operation `{id}`: `{key}` changed"));
            }
        }
        let listed = |op: &Value| -> BTreeSet<String> {
            op.get("messages")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|m| str_at(m, "/$ref").map(str::to_owned))
                .collect()
        };
        for gone in listed(b).difference(&listed(h)) {
            out.push(format!("operation `{id}`: message `{gone}` removed"));
        }
    }
    let base_payloads = payloads(base);
    let head_payloads = payloads(head);
    let mut pairs: Vec<(String, String, String)> = Vec::new();
    for (kind, b) in &base_payloads {
        match head_payloads.get(kind) {
            Some(h) => pairs.push((format!("message `{kind}`"), b.clone(), h.clone())),
            None => out.push(format!("message `{kind}` removed")),
        }
    }
    let head_schemas = head
        .pointer("/components/schemas")
        .and_then(Value::as_object);
    for (name, b) in base
        .pointer("/components/schemas")
        .and_then(Value::as_object)
        .into_iter()
        .flatten()
    {
        let h = head_schemas.and_then(|s| s.get(name)).and_then(schema_ref);
        match (schema_ref(b), h) {
            (Some(b), Some(h)) => {
                pairs.push((format!("schema `{name}`"), b.to_owned(), h.to_owned()));
            }
            _ => out.push(format!("schema `{name}` removed")),
        }
    }
    for (label, b, h) in pairs {
        let mut found = Vec::new();
        schema_breaks(&load(false, &b)?, &load(true, &h)?, "", &mut found);
        out.extend(found.into_iter().map(|f| format!("{label}: {f}")));
    }
    Ok(out)
}

pub(crate) fn breaking(root: &Path, base: &str) -> Result<(), String> {
    let base_doc =
        parse_yaml(&git_show(root, base, DOC)?).map_err(|e| format!("{base}:{DOC}: {e}"))?;
    let text = std::fs::read_to_string(root.join(DOC)).map_err(|e| format!("{DOC}: {e}"))?;
    let head_doc = parse_yaml(&text).map_err(|e| format!("{DOC}: {e}"))?;
    let load = |head: bool, reference: &str| -> Result<Value, String> {
        let path =
            join(DIR, reference).ok_or_else(|| format!("`{reference}` leaves the repository"))?;
        let text = if head {
            std::fs::read_to_string(root.join(&path)).map_err(|e| format!("{path}: {e}"))?
        } else {
            git_show(root, base, &path)?
        };
        serde_json::from_str(&text).map_err(|e| format!("{path}: {e}"))
    };
    let found = catalog_breaks(&base_doc, &head_doc, &load)?;
    if found.is_empty() {
        println!("ok    no breaking change in {DOC} since {base}");
        return Ok(());
    }
    Err(format!(
        "breaking changes in {DOC} since {base} (T-31: only with a new major version):\n  {}",
        found.join("\n  ")
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const CATALOG: &str = "asyncapi: 3.0.0\ninfo:\n  title: t\n  version: 1.0.0\ndefaultContentType: application/cloudevents+json\nchannels:\n  task:\n    address: one.task\n    messages:\n      changed:\n        $ref: '#/components/messages/TaskChanged'\noperations:\n  publishTask:\n    action: send\n    channel:\n      $ref: '#/channels/task'\n    messages:\n      - $ref: '#/channels/task/messages/changed'\ncomponents:\n  messages:\n    TaskChanged:\n      name: app.suiss.one.task.state_changed.v1\n      payload:\n        schemaFormat: application/schema+json;version=draft-2020-12\n        schema:\n          $ref: ./task.json\n";

    #[test]
    fn t_31_a_well_formed_catalog_passes() {
        let doc = parse_yaml(CATALOG).unwrap();
        let errors = structure(&doc, &|p| p == "conformance/events/task.json");
        assert!(errors.is_empty(), "{errors:?}");
        assert_eq!(
            payloads(&doc).get("app.suiss.one.task.state_changed.v1"),
            Some(&"./task.json".to_owned())
        );
    }

    #[test]
    fn t_31_dangling_references_and_orphan_messages_fail() {
        let text = CATALOG
            .replace(
                "'#/channels/task/messages/changed'",
                "'#/channels/task/messages/gone'",
            )
            .replace(
                "$ref: '#/components/messages/TaskChanged'",
                "$ref: '#/components/messages/Other'",
            );
        let errors = structure(&parse_yaml(&text).unwrap(), &|_| false);
        assert!(errors.iter().any(|e| e.contains("does not resolve")));
        assert!(errors.iter().any(|e| e.contains("names no file")));
        assert!(errors.iter().any(|e| e.contains("no channel carries it")));
    }

    #[test]
    fn t_31_event_types_are_versioned_and_namespaced() {
        assert!(is_event_type("app.suiss.one.task.state_changed.v1"));
        assert!(!is_event_type("app.suiss.one.task"));
        assert!(!is_event_type("app.suiss.one.task.v0"));
        assert!(!is_event_type("com.example.thing.v1"));
    }

    #[test]
    fn t_31_narrowing_a_payload_is_breaking() {
        let base = json!({
            "type": "object",
            "required": ["id", "state"],
            "properties": {
                "id": { "type": "string" },
                "state": { "enum": ["open", "done"] },
                "note": { "type": ["string", "null"], "maxLength": 100 }
            }
        });
        let head = json!({
            "type": "object",
            "required": ["id"],
            "additionalProperties": false,
            "properties": {
                "id": { "type": "string" },
                "state": { "enum": ["open"] },
                "note": { "type": "string", "maxLength": 50 }
            }
        });
        let mut out = Vec::new();
        schema_breaks(&base, &head, "", &mut out);
        for needle in [
            "`state` is no longer required",
            "/properties/state: `enum` narrowed",
            "/properties/note: `type` narrowed",
            "/properties/note: `maxLength` narrowed",
            "`additionalProperties` closed",
        ] {
            assert!(out.iter().any(|o| o.contains(needle)), "{needle}: {out:?}");
        }
        let mut none = Vec::new();
        schema_breaks(&base, &base, "", &mut none);
        assert!(none.is_empty(), "{none:?}");
    }

    #[test]
    fn t_31_widening_a_payload_is_not_breaking() {
        let base = json!({ "type": "object", "properties": { "a": { "type": "string", "maxLength": 5 } } });
        let head = json!({ "type": "object", "properties": { "a": { "type": ["string", "null"], "maxLength": 9 }, "b": { "type": "integer" } } });
        let mut out = Vec::new();
        schema_breaks(&base, &head, "", &mut out);
        assert!(out.is_empty(), "{out:?}");
    }

    #[test]
    fn t_31_removed_channels_and_messages_are_breaking() {
        let base = parse_yaml(CATALOG).unwrap();
        let head = parse_yaml(
            "asyncapi: 3.0.0\ninfo:\n  title: t\n  version: 2.0.0\nchannels: {}\noperations: {}\n",
        )
        .unwrap();
        let load = |_: bool, _: &str| -> Result<Value, String> { Ok(json!({})) };
        let out = catalog_breaks(&base, &head, &load).unwrap();
        assert!(out.iter().any(|o| o == "channel `task` removed"));
        assert!(out.iter().any(|o| o == "operation `publishTask` removed"));
        assert!(
            out.iter()
                .any(|o| o == "message `app.suiss.one.task.state_changed.v1` removed")
        );
        assert_eq!(
            catalog_breaks(&base, &base, &load).unwrap(),
            Vec::<String>::new()
        );
    }

    #[test]
    fn t_31_relative_references_resolve_inside_the_repository() {
        assert_eq!(
            join(DIR, "./a.json").as_deref(),
            Some("conformance/events/a.json")
        );
        assert_eq!(
            join(DIR, "../task/b.json").as_deref(),
            Some("conformance/task/b.json")
        );
        assert_eq!(join("a", "../../x"), None);
    }
}
