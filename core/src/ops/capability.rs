//! Capability operations: name and version parsing and version negotiation (CP-15, OO-9).

use one_proto::capability::{
    CapabilityName, CapabilityVersion, Declaration, NameKind, negotiate as kept,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{object, parse, wire};
use crate::CoreError;

pub(super) fn parse_name(input: Value) -> Result<Value, CoreError> {
    let text: String = parse(input, "name")?;
    Ok(match CapabilityName::parse(&text) {
        Ok(name) => {
            let mut m = Map::new();
            m.insert("valid".to_owned(), Value::Bool(true));
            let kind = match name.kind() {
                NameKind::Suiss => "suiss",
                NameKind::ThirdParty => "third_party",
            };
            m.insert("kind".to_owned(), Value::from(kind));
            m.insert(
                "segments".to_owned(),
                Value::Array(name.segments().map(Value::from).collect()),
            );
            if let Some(category) = name.category() {
                m.insert("category".to_owned(), Value::from(category));
            }
            Value::Object(m)
        }
        Err(e) => object([
            ("valid", Value::Bool(false)),
            ("error", Value::from(e.code())),
        ]),
    })
}

pub(super) fn parse_version(input: Value) -> Result<Value, CoreError> {
    let text: String = parse(input, "version")?;
    Ok(object([(
        "valid",
        Value::Bool(CapabilityVersion::parse(&text).is_ok()),
    )]))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NegotiateInput {
    local: Vec<Value>,
    remote: Vec<Value>,
}

fn offer(side: Vec<Value>) -> Vec<Declaration> {
    side.into_iter()
        .filter_map(|d| serde_json::from_value(d).ok())
        .collect()
}

pub(super) fn negotiate(input: Value) -> Result<Value, CoreError> {
    let input: NegotiateInput = parse(input, "local or remote")?;
    wire(&kept(&offer(input.local), &offer(input.remote)))
}
