//! Instruction counts of projecting a typical Interaction on every target of each surface class; a rise over 5 % is reported (T-45 (1, 3), X-13).

#![allow(missing_docs, reason = "T-45")]
#![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "T-45")]

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use one_interaction::surface::ClassRow;
use one_interaction::{Interaction, Projection, SurfaceClass, SurfaceTarget, project};
use serde_json::Value;

fn typical(kind: &str) -> Interaction {
    let all: Vec<Value> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/interaction/vectors/fixtures.json"
    )))
    .unwrap();
    let raw = all
        .iter()
        .map(|v| &v["input"])
        .find(|i| i["kind"] == kind)
        .unwrap();
    serde_json::from_value(raw.clone()).unwrap()
}

fn case(kind: &str, class: SurfaceClass) -> (Interaction, SurfaceClass) {
    (typical(kind), class)
}

#[library_benchmark]
#[bench::approval_phone(setup = case, args = ("approval", SurfaceClass::Phone))]
#[bench::approval_desktop(setup = case, args = ("approval", SurfaceClass::Desktop))]
#[bench::approval_watch(setup = case, args = ("approval", SurfaceClass::Watch))]
#[bench::approval_voice_car(setup = case, args = ("approval", SurfaceClass::VoiceCar))]
#[bench::approval_voice_glasses(setup = case, args = ("approval", SurfaceClass::VoiceGlasses))]
#[bench::progress_phone(setup = case, args = ("progress", SurfaceClass::Phone))]
#[bench::choice_watch(setup = case, args = ("choice", SurfaceClass::Watch))]
fn per_class(input: (Interaction, SurfaceClass)) -> Vec<Projection> {
    let (i, class) = input;
    let kind = i.kind.declared_core();
    SurfaceTarget::ALL
        .iter()
        .filter(|t| class.has_target(**t))
        .map(|t| black_box(project(black_box(&i), kind, class, *t, &SurfaceTarget::ALL)))
        .collect()
}

library_benchmark_group!(name = projection, benchmarks = per_class);

main!(library_benchmark_groups = projection);
