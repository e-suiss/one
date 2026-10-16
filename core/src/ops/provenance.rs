//! Provenance operations: join, transform, open and the Access mapping of a label (SEC-14, T-36 (1, 3, 4, 5)).

use one_provenance::{AccessMapping, Label, LabelKind, Labelled, Opened, Transform};
use serde::Deserialize;
use serde_json::Value;

use super::{object, parse, wire};
use crate::CoreError;

fn label(entry: Value) -> Result<Label, CoreError> {
    let Value::Object(mut m) = entry else {
        return Err(CoreError::InvalidInput("label"));
    };
    if m.insert("value".to_owned(), Value::from(0)).is_some() {
        return Err(CoreError::InvalidInput("label"));
    }
    let opened: Opened<u8> = parse(Value::Object(m), "label")?;
    if !opened.conforms() {
        return Err(CoreError::InvalidInput("label"));
    }
    Ok(opened.labelled().label())
}

fn labels(inputs: Vec<Value>) -> Result<Vec<Label>, CoreError> {
    inputs.into_iter().map(label).collect()
}

fn label_wire(label: &Label) -> Result<Value, CoreError> {
    let derived = Labelled::derive(Transform::Combine, [label], ())
        .ok_or(CoreError::InvalidInput("label"))?;
    let mut v = wire(&derived)?;
    if let Value::Object(m) = &mut v {
        m.remove("value");
    }
    Ok(v)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JoinInput {
    inputs: Vec<Value>,
}

pub(super) fn join(input: Value) -> Result<Value, CoreError> {
    let input: JoinInput = parse(input, "inputs")?;
    let joined =
        Label::join_all(&labels(input.inputs)?).ok_or(CoreError::InvalidInput("inputs"))?;
    label_wire(&joined)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "snake_case")]
enum TransformName {
    Summarise,
    Translate,
    QuarantineExtract,
    NormaliseText,
    MemoryWrite,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TransformInput {
    transform: TransformName,
    inputs: Vec<Value>,
}

pub(super) fn transform(input: Value) -> Result<Value, CoreError> {
    let input: TransformInput = parse(input, "transform")?;
    let t = match input.transform {
        TransformName::Summarise => Transform::Summarise,
        TransformName::Translate => Transform::Translate,
        TransformName::QuarantineExtract => Transform::QuarantineExtract,
        TransformName::NormaliseText => Transform::NormaliseText,
        TransformName::MemoryWrite => Transform::MemoryWrite,
    };
    let derived = t
        .label(&labels(input.inputs)?)
        .ok_or(CoreError::InvalidInput("inputs"))?;
    label_wire(&derived)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenInput {
    encoded: Value,
}

pub(super) fn open(input: Value) -> Result<Value, CoreError> {
    let input: OpenInput = parse(input, "encoded")?;
    let opened: Opened<Value> = parse(input.encoded, "encoded")?;
    let labelled = opened.labelled();
    let mut out = label_wire(&labelled.label())?;
    if let Value::Object(m) = &mut out {
        m.insert(
            "access_provenance".to_owned(),
            wire(&labelled.access_provenance())?,
        );
        m.insert("conforms".to_owned(), Value::Bool(opened.conforms()));
        m.insert("value".to_owned(), labelled.expose().clone());
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MapInput {
    label: LabelKind,
}

pub(super) fn access_mapping(input: Value) -> Result<Value, CoreError> {
    let input: MapInput = parse(input, "label")?;
    Ok(object([(
        "provenance",
        wire(&AccessMapping::of(input.label).provenance())?,
    )]))
}
