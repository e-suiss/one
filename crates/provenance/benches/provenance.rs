//! Instruction counts of the label join over N labels and of a label-carrying transform; a rise over 5 % fails the run (T-45 (1, 3), SEC-14 (1)).

#![allow(missing_docs, reason = "T-45")]

use std::hint::black_box;

use gungraun::{
    Callgrind, EventKind, LibraryBenchmarkConfig, library_benchmark, library_benchmark_group, main,
};
use one_provenance::{Label, LabelKind, Transform, TrustedLabel};

fn mixed(n: usize) -> Vec<Label> {
    let pool: Vec<Label> = LabelKind::ALL.iter().filter_map(|k| k.single()).collect();
    pool.iter().cycle().take(n).cloned().collect()
}

fn trusted(n: usize) -> Vec<Label> {
    TrustedLabel::ALL
        .iter()
        .rev()
        .cycle()
        .take(n)
        .map(|t| Label::Trusted(*t))
        .collect()
}

#[library_benchmark]
#[benches::mixed(args = [8, 64, 512], setup = mixed)]
#[benches::trusted(args = [8, 64, 512], setup = trusted)]
fn join_all(labels: Vec<Label>) -> Option<Label> {
    black_box(Label::join_all(black_box(&labels)))
}

#[library_benchmark]
#[benches::mixed(args = [8, 64, 512], setup = mixed)]
fn memory_write(labels: Vec<Label>) -> Option<Label> {
    black_box(Transform::MemoryWrite.label(black_box(&labels)))
}

library_benchmark_group!(name = join, benchmarks = [join_all, memory_write]);

main!(
    config = LibraryBenchmarkConfig::default()
        .tool(Callgrind::default().soft_limits([(EventKind::Ir, 5.0)])),
    library_benchmark_groups = join
);
