//! Interaction operations: kind resolution, the projection decision for one surface target and response processing (X-12, X-13, X-22, C-7, C-26).

use one_interaction::common::Timestamp;
use one_interaction::projection::live_update_chip;
use one_interaction::{
    Interaction, InteractionResponse, Kind, KindRegistry, ProjectionOutcome, ResponseOutcome,
    ResponseProcessor, SurfaceClass, SurfaceTarget, project as projection, validate_interaction,
    validate_response,
};
use serde::Deserialize;
use serde_json::{Map, Value};

use super::{object, parse, wire};
use crate::CoreError;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ResolveInput {
    registry: KindRegistry,
    kind: Kind,
}

pub(super) fn resolve_kind(input: Value) -> Result<Value, CoreError> {
    let input: ResolveInput = parse(input, "registry or kind")?;
    Ok(match input.registry.resolve(&input.kind) {
        Ok(core) => object([("valid", Value::Bool(true)), ("core_kind", wire(&core)?)]),
        Err(e) => object([("valid", Value::Bool(false)), ("error", wire(&e)?)]),
    })
}

fn invalid(error: &'static str) -> Value {
    object([("valid", Value::Bool(false)), ("error", Value::from(error))])
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectInput {
    registry: KindRegistry,
    interaction: Interaction,
    surface_class: SurfaceClass,
    target: SurfaceTarget,
    declared_targets: Vec<SurfaceTarget>,
}

pub(super) fn project(input: Value) -> Result<Value, CoreError> {
    let input: ProjectInput = parse(input, "projection input")?;
    let i = &input.interaction;
    if let Err(e) = validate_interaction(i) {
        return Ok(invalid(e.0));
    }
    let kind = match input.registry.resolve(&i.kind) {
        Ok(kind) => kind,
        Err(e) => {
            return Ok(object([
                ("valid", Value::Bool(false)),
                ("error", wire(&e)?),
            ]));
        }
    };
    let p = projection(
        i,
        kind,
        input.surface_class,
        input.target,
        &input.declared_targets,
    );
    let mut out = wire(&p)?;
    if let Value::Object(m) = &mut out {
        m.insert("valid".to_owned(), Value::Bool(true));
        if input.target == SurfaceTarget::LiveUpdate && p.projection == ProjectionOutcome::Full {
            let max = input
                .target
                .budget()
                .chip_max_chars
                .and_then(|n| usize::try_from(n).ok())
                .unwrap_or(0);
            m.insert(
                "chip".to_owned(),
                live_update_chip(i, max).map_or(Value::Null, Value::from),
            );
        }
    }
    Ok(out)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessingState {
    now: Timestamp,
    signature_valid: bool,
    current_version: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProcessInput {
    interaction: Interaction,
    state: ProcessingState,
    responses: Vec<InteractionResponse>,
}

pub(super) fn process_responses(input: Value) -> Result<Value, CoreError> {
    let input: ProcessInput = parse(input, "processing input")?;
    let i = &input.interaction;
    if let Err(e) = validate_interaction(i) {
        return Ok(invalid(e.0));
    }
    if let Some(e) = input
        .responses
        .iter()
        .find_map(|r| validate_response(r).err())
    {
        return Ok(invalid(e.0));
    }
    let mut processor = ResponseProcessor::new(i, input.state.current_version);
    let mut results = Vec::with_capacity(input.responses.len());
    let mut outcomes = Vec::with_capacity(input.responses.len());
    let mut approvals = 0_u64;
    for r in &input.responses {
        let processed = processor.process(r, &input.state.now, input.state.signature_valid);
        if processed.outcome == ResponseOutcome::Accepted && processed.aas.is_some() {
            approvals = approvals.saturating_add(1);
        }
        outcomes.push(wire(&processed.outcome)?);
        results.push(wire(&processed)?);
    }
    let mut m = Map::new();
    m.insert("valid".to_owned(), Value::Bool(true));
    m.insert("outcomes".to_owned(), Value::Array(outcomes));
    m.insert("approvals_created".to_owned(), Value::from(approvals));
    m.insert("results".to_owned(), Value::Array(results));
    Ok(Value::Object(m))
}
