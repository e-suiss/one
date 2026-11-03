//! The second-stage difficulty heuristic `difficulty/v1` (MF-21, T-10): the probability that the small model suffices, from the needed capabilities, the tool count, the plan depth, the expected output length and the task kind, until a learned estimator passes the release gate.

use one_proto::memory::trust::round6;
use one_proto::model::request::{ModelRequest, RequiredCapability};

/// The estimator version a routing record names.
pub const ESTIMATOR_VERSION: &str = "difficulty-v1";
/// The small model is chosen at or above this estimate.
pub const SMALL_MIN: f64 = 0.5;
/// The short-answer fallback needs at least this estimate.
pub const SHORT_ANSWER_MIN: f64 = 0.35;

const BASE: f64 = 0.85;
const PLANNING_PENALTY: f64 = 0.3;
const LONG_CONTEXT_PENALTY: f64 = 0.2;
const TOOL_PENALTY: f64 = 0.05;
const TOOL_PENALTY_CAP: f64 = 0.2;
const DEPTH_PENALTY: f64 = 0.1;
const DEPTH_PENALTY_CAP: f64 = 0.3;
const LONG_OUTPUT_TOKENS: u64 = 800;
const VERY_LONG_OUTPUT_TOKENS: u64 = 2000;
const MEDIUM_OUTPUT_PENALTY: f64 = 0.15;
const LONG_OUTPUT_PENALTY: f64 = 0.3;
const SMALL_KIND_BONUS: f64 = 0.1;
const LARGE_KIND_PENALTY: f64 = 0.25;
const SMALL_KINDS: [&str; 7] = [
    "intent",
    "classify",
    "short_answer",
    "memory_extraction",
    "consolidation",
    "summary",
    "short_message",
];
const LARGE_KINDS: [&str; 4] = ["planning", "long_text", "browser_step", "orchestration"];

/// The signals the heuristic reads from a request.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Signals {
    /// The capabilities include multi-step planning.
    pub planning: bool,
    /// The capabilities include long context.
    pub long_context: bool,
    /// The tool count hint, else the number of offered tools.
    pub tools: u64,
    /// The plan depth hint.
    pub plan_depth: Option<u64>,
    /// The expected output tokens hint.
    pub expected_output_tokens: Option<u64>,
    /// The task kind hint.
    pub task_kind: Option<String>,
}

impl Signals {
    /// Reads the signals of `request`.
    #[must_use]
    pub fn of(request: &ModelRequest) -> Self {
        let hints = request.hints.as_ref();
        let offered = request
            .tools
            .as_ref()
            .map_or(0, |t| u64::try_from(t.len()).unwrap_or(u64::MAX));
        Self {
            planning: request
                .capabilities
                .contains(&RequiredCapability::MultiStepPlanning),
            long_context: request
                .capabilities
                .contains(&RequiredCapability::LongContext),
            tools: hints.and_then(|h| h.tool_count).unwrap_or(offered),
            plan_depth: hints.and_then(|h| h.plan_depth),
            expected_output_tokens: hints.and_then(|h| h.expected_output_tokens),
            task_kind: hints
                .and_then(|h| h.task_kind.as_ref())
                .map(|k| k.as_str().to_owned()),
        }
    }
}

#[allow(
    clippy::cast_precision_loss,
    reason = "counts are capped far below 2^52 before the cast"
)]
fn steps(count: u64) -> f64 {
    count.min(1000) as f64
}

/// The probability in `0..=1` that the small model suffices, rounded to six decimals.
#[must_use]
pub fn small_sufficient(s: &Signals) -> f64 {
    let mut p = BASE;
    if s.planning {
        p -= PLANNING_PENALTY;
    }
    if s.long_context {
        p -= LONG_CONTEXT_PENALTY;
    }
    p -= TOOL_PENALTY_CAP.min(TOOL_PENALTY * steps(s.tools.saturating_sub(1)));
    if let Some(depth) = s.plan_depth {
        p -= DEPTH_PENALTY_CAP.min(DEPTH_PENALTY * steps(depth.saturating_sub(1)));
    }
    if let Some(out) = s.expected_output_tokens {
        if out > VERY_LONG_OUTPUT_TOKENS {
            p -= LONG_OUTPUT_PENALTY;
        } else if out > LONG_OUTPUT_TOKENS {
            p -= MEDIUM_OUTPUT_PENALTY;
        }
    }
    if let Some(kind) = s.task_kind.as_deref() {
        if SMALL_KINDS.contains(&kind) {
            p += SMALL_KIND_BONUS;
        } else if LARGE_KINDS.contains(&kind) {
            p -= LARGE_KIND_PENALTY;
        }
    }
    round6(p.clamp(0.0, 1.0))
}

/// Whether the estimate `p` picks the small model.
#[must_use]
pub fn small_enough(p: f64) -> bool {
    p >= SMALL_MIN
}

/// Whether the small model may give a labelled short answer when no large model is left (MF-23).
#[must_use]
pub fn short_answer_allowed(s: &Signals, p: f64) -> bool {
    p >= SHORT_ANSWER_MIN && !s.planning
}
