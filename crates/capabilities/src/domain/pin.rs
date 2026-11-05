//! Tool pins (CP-21, SEC-24 (3), SEC-31 (9), E-35): at approval a tool's name, description, input and output schema, annotations and permission declaration are pinned as the SHA-256 of their JCS form under `tool-pin/v1`; any change stops the tool until the user approves it again, and annotations such as `readOnlyHint` are untrusted content that never stand in for the registry's Access class.

use std::collections::BTreeMap;

use one_proto::ontology::JsonValue;
use one_proto::task::common::Sha256Digest;
use one_provenance::intent::jcs::sha256_digest;

/// The pin version.
pub const VERSION: &str = "tool-pin/v1";

/// What a server says about one tool.
#[derive(Debug, Clone, PartialEq)]
pub struct Tool {
    /// The tool name.
    pub name: String,
    /// Its description.
    pub description: String,
    /// Its input schema.
    pub input_schema: JsonValue,
    /// Its output schema, if any.
    pub output_schema: Option<JsonValue>,
    /// Its annotations, if any.
    pub annotations: Option<JsonValue>,
    /// The permissions its package declares.
    pub declaration: JsonValue,
}

/// Whether the tool still matches its approval.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Pinned {
    /// Unchanged: it may be called.
    Same,
    /// Changed, or never pinnable: it is not called until the user approves it again.
    Changed,
}

fn entry(map: &mut BTreeMap<String, JsonValue>, key: &str, value: JsonValue) {
    map.insert(String::from(key), value);
}

/// The pin of `tool`; `None` when it cannot be put in JCS form.
#[must_use]
pub fn pin(tool: &Tool) -> Option<Sha256Digest> {
    let mut map = BTreeMap::new();
    entry(&mut map, "v", JsonValue::String(String::from(VERSION)));
    entry(&mut map, "name", JsonValue::String(tool.name.clone()));
    entry(
        &mut map,
        "description",
        JsonValue::String(tool.description.clone()),
    );
    entry(&mut map, "input_schema", tool.input_schema.clone());
    entry(
        &mut map,
        "output_schema",
        tool.output_schema.clone().unwrap_or(JsonValue::Null),
    );
    entry(
        &mut map,
        "annotations",
        tool.annotations.clone().unwrap_or(JsonValue::Null),
    );
    entry(&mut map, "declaration", tool.declaration.clone());
    sha256_digest(&JsonValue::Object(map))
}

/// Checks `tool` against the pin the user approved.
#[must_use]
pub fn check(approved: &Sha256Digest, tool: &Tool) -> Pinned {
    if pin(tool).as_ref() == Some(approved) {
        Pinned::Same
    } else {
        Pinned::Changed
    }
}
