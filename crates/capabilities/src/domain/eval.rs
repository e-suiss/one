//! The capability evaluation gate `capability-eval/v1` (CP-19, A-24, C-17): only real task cases count, never a vendor's benchmark; at least [`MIN_CASES`] of them with [`MIN_PER_LANGUAGE`] in each of Turkish and English, and at least [`PASS_PERCENT`] percent passed; the data-access and surface declarations must be verified, and a reversibility that was not verified is recorded as irreversible; a capability whose last pass is older than [`MAX_AGE_SECS`] counts as not working.

use one_proto::capability::{EvaluationResult, ExampleLang, Verified, effective_reversibility};
use one_proto::interaction_types::Reversibility;

/// The gate version.
pub const VERSION: &str = "capability-eval/v1";
/// The fewest real cases.
pub const MIN_CASES: usize = 20;
/// The fewest real cases in each language.
pub const MIN_PER_LANGUAGE: usize = 5;
/// The share of real cases that must pass, in percent.
pub const PASS_PERCENT: usize = 95;
/// How long a pass holds: 30 days.
pub const MAX_AGE_SECS: u64 = 2_592_000;

/// One evaluation case.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Case {
    /// Its language.
    pub lang: ExampleLang,
    /// A real task, not a vendor's benchmark.
    pub real: bool,
    /// Whether it passed.
    pub passed: bool,
}

/// Why the gate failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// Fewer than [`MIN_CASES`] real cases.
    TooFewCases,
    /// Fewer than [`MIN_PER_LANGUAGE`] real cases in a language.
    LanguageShort(ExampleLang),
    /// Fewer than [`PASS_PERCENT`] percent passed.
    PassRate,
    /// The data-access declaration was not verified.
    DataAccessUnverified,
    /// The surface declaration was not verified.
    SurfaceUnverified,
}

/// The gate's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// The result.
    pub result: EvaluationResult,
    /// Every reason it failed, in check order.
    pub why: Vec<Why>,
    /// The reversibility the registry records.
    pub reversibility: Reversibility,
}

/// Runs the gate over `cases` with the declarations `verified` and the `declared` reversibility.
#[must_use]
pub fn evaluate(cases: &[Case], verified: Verified, declared: Reversibility) -> Verdict {
    let real: Vec<&Case> = cases.iter().filter(|c| c.real).collect();
    let mut why = Vec::new();
    if real.len() < MIN_CASES {
        why.push(Why::TooFewCases);
    }
    for lang in [ExampleLang::Tr, ExampleLang::En] {
        if real.iter().filter(|c| c.lang == lang).count() < MIN_PER_LANGUAGE {
            why.push(Why::LanguageShort(lang));
        }
    }
    let passed = real.iter().filter(|c| c.passed).count();
    let enough = passed
        .checked_mul(100)
        .zip(real.len().checked_mul(PASS_PERCENT))
        .is_some_and(|(p, need)| p >= need);
    if !enough {
        why.push(Why::PassRate);
    }
    if !verified.data_access {
        why.push(Why::DataAccessUnverified);
    }
    if !verified.surface {
        why.push(Why::SurfaceUnverified);
    }
    Verdict {
        result: if why.is_empty() {
            EvaluationResult::Pass
        } else {
            EvaluationResult::Fail
        },
        why,
        reversibility: effective_reversibility(Some(declared), verified.reversibility),
    }
}
