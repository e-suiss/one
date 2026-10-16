//! Instruction counts of capability negotiation over 50 names, `trust/v1` and the memory text view; a rise over 5 % is reported (T-45 (1, 3), CP-15, M-13, M-6).

#![allow(missing_docs, reason = "T-45")]
#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-45"
)]

use std::hint::black_box;

use gungraun::{library_benchmark, library_benchmark_group, main};
use one_proto::capability::{
    CapabilityName, CapabilityRef, CapabilityVersion, Declaration, Extends, negotiate,
};
use one_proto::memory::text_view::{TextView, TextViewError, TextViewRequest, render};
use one_proto::memory::trust::{TrustError, TrustInput, trust_v1};
use serde_json::{Value, json};

fn declarations(n: usize, versions: &[&str]) -> Vec<Declaration> {
    let name = |i: usize| CapabilityName::parse(&format!("app.suiss.bench.cap{i}")).unwrap();
    (0..n)
        .map(|i| Declaration {
            name: name(i),
            versions: versions
                .iter()
                .map(|v| CapabilityVersion::parse(v).unwrap())
                .collect(),
            extends: (i % 5 == 4).then(|| Extends::one(name(i - 1))),
        })
        .collect()
}

fn sides(n: usize) -> (Vec<Declaration>, Vec<Declaration>) {
    let local = declarations(n, &["2026-01-01", "2026-06-01"]);
    let mut remote = declarations(n, &["2026-09-01", "2026-06-01"]);
    remote.reverse();
    (local, remote)
}

#[library_benchmark]
#[bench::names_50(setup = sides, args = (50))]
fn negotiation(sides: (Vec<Declaration>, Vec<Declaration>)) -> Vec<CapabilityRef> {
    black_box(negotiate(black_box(&sides.0), black_box(&sides.1)))
}

fn trust_input(confirmed: bool, contradicting: u32) -> TrustInput {
    serde_json::from_value(json!({
        "source_kind": "connected_source",
        "observation_count": 12,
        "supporting_count": 9,
        "last_observed_at": "2026-04-01T08:10:00.250Z",
        "user_confirmed_at": confirmed.then_some("2026-02-01T00:00:00Z"),
        "contradicting_count": contradicting,
        "as_of": "2026-10-16T00:00:00Z",
    }))
    .unwrap()
}

#[library_benchmark]
#[bench::plain(setup = trust_input, args = (false, 0))]
#[bench::confirmed_contradicted(setup = trust_input, args = (true, 3))]
fn trust(input: TrustInput) -> Result<f64, TrustError> {
    black_box(trust_v1(black_box(&input)))
}

fn text_view_request(n: usize) -> TextViewRequest {
    let all: Vec<Value> = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../conformance/memory/vectors/text-view.json"
    )))
    .unwrap();
    let pool: Vec<Value> = all
        .iter()
        .filter(|v| v["expected"].get("error").is_none())
        .flat_map(|v| v["input"]["entries"].as_array().unwrap().clone())
        .collect();
    let entries: Vec<Value> = pool.iter().cycle().take(n).cloned().collect();
    serde_json::from_value(json!({ "entries": entries })).unwrap()
}

#[library_benchmark]
#[benches::entries(args = [8, 64], setup = text_view_request)]
fn text_view(request: TextViewRequest) -> Result<TextView, TextViewError> {
    black_box(render(black_box(&request.entries)))
}

library_benchmark_group!(name = records, benchmarks = [negotiation, trust, text_view]);

main!(library_benchmark_groups = records);
