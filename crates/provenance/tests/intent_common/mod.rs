//! Loading the `conformance/intent` vectors, the fixture input schema registry and a `boon` input schema validator.

#![allow(clippy::unwrap_used, reason = "T-38")]
#![allow(dead_code, unreachable_pub, reason = "T-38")]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use one_proto::capability::{CapabilityName, CapabilityRef, CapabilityVersion};
use one_proto::ontology::JsonValue;
use one_provenance::intent::{InputSchemaValidator, PinnedSchema, jcs};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub fn path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/intent")
        .join(rel)
}

pub fn read(rel: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(path(rel)).unwrap()).unwrap()
}

pub fn vectors(rel: &str) -> Vec<Value> {
    let items = read(rel).as_array().unwrap().clone();
    assert!(!items.is_empty(), "{rel} has no vectors");
    items
}

pub fn description(v: &Value) -> &str {
    v["description"].as_str().unwrap()
}

pub fn json(v: &Value) -> JsonValue {
    serde_json::from_value(v.clone()).unwrap()
}

pub fn fixture() -> PinnedSchema {
    PinnedSchema::new(json(&read("fixtures/message-send-input.v1.json"))).unwrap()
}

pub fn fixture_capability() -> CapabilityRef {
    CapabilityRef {
        name: CapabilityName::parse("app.suiss.fixture.message.send").unwrap(),
        version: CapabilityVersion::parse("2026-10-01").unwrap(),
    }
}

pub fn registry() -> BTreeMap<CapabilityRef, PinnedSchema> {
    BTreeMap::from([(fixture_capability(), fixture())])
}

pub struct Boon;

impl InputSchemaValidator for Boon {
    fn conforms(&self, schema: &PinnedSchema, input: &JsonValue) -> bool {
        let id = schema.id().as_str();
        let mut compiler = boon::Compiler::new();
        compiler.enable_format_assertions();
        compiler
            .add_resource(id, serde_json::to_value(schema.document()).unwrap())
            .unwrap();
        let mut schemas = boon::Schemas::new();
        let index = compiler.compile(id, &mut schemas).unwrap();
        schemas
            .validate(&serde_json::to_value(input).unwrap(), index)
            .is_ok()
    }
}

pub fn round_trips<T: Serialize + DeserializeOwned>(input: &Value) -> Result<T, String> {
    let parsed: T = serde_json::from_value(input.clone()).map_err(|e| e.to_string())?;
    let back = serde_json::to_value(&parsed).unwrap();
    assert_eq!(&back, input);
    assert_eq!(
        jcs::canonicalize(&json(&back)).unwrap(),
        jcs::canonicalize(&json(input)).unwrap()
    );
    let again: T = serde_json::from_value(back).unwrap();
    assert_eq!(
        serde_json::to_string(&again).unwrap(),
        serde_json::to_string(&parsed).unwrap()
    );
    Ok(parsed)
}
