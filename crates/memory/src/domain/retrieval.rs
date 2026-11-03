//! The fixed retrieval pipeline (M-30, M-11, M-32, M-34): life area with the General area, then status and the "use only for" restriction, then the policy gate, then the opinion filter, then hybrid search, ranking, the smallest subset and the marked data block, in that order with no step skipped; a record that does not hold at the query time is kept and marked, never dropped; an opinion reaches the model only when the user asks for their own view, for style or for a suggestion, and a query of unknown kind counts as factual.

use one_proto::ProjectId;
use one_proto::data_class::LifeArea;
use one_proto::memory::fields::{CoreContentType, EpistemicState, LiveStatus};
use one_proto::memory::record::LiveMemoryRecord;
use one_proto::ontology::time::Instant;

/// One step of the pipeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Step {
    /// Life area.
    Area,
    /// Status and the usage restriction.
    Status,
    /// The policy gate of the shared restriction engine.
    Policy,
    /// The opinion filter.
    Opinion,
    /// Lexical and dense search together.
    Search,
    /// Ranking.
    Rank,
    /// The smallest subset.
    Subset,
    /// The marked data block.
    Present,
}

/// The order every retrieval runs in.
pub const ORDER: [Step; 8] = [
    Step::Area,
    Step::Status,
    Step::Policy,
    Step::Opinion,
    Step::Search,
    Step::Rank,
    Step::Subset,
    Step::Present,
];

/// What the user asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum QueryKind {
    /// A factual question, or a question of unknown kind.
    Factual,
    /// The user's own view.
    OwnOpinion,
    /// Style or tone.
    Style,
    /// A suggestion.
    Suggestion,
}

/// One retrieval.
#[derive(Clone, PartialEq)]
pub struct Query {
    /// The query text.
    pub text: String,
    /// The life area it is in.
    pub area: Option<LifeArea>,
    /// The user project it is in.
    pub project: Option<ProjectId>,
    /// What the user asked for.
    pub kind: QueryKind,
    /// The time the records must hold at.
    pub valid_at: Instant,
    /// Whether personalisation is off for this answer (M-34).
    pub unpersonalised: bool,
}

impl core::fmt::Debug for Query {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Query")
            .field("area", &self.area)
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

/// Whether an opinion may reach the model for `kind` (M-32).
#[must_use]
pub const fn opinion_allowed(kind: QueryKind) -> bool {
    !matches!(kind, QueryKind::Factual)
}

/// Step 1: the record is in the query's life area or in the General area, or the query names none.
#[must_use]
pub fn in_area(record: &LiveMemoryRecord, query: &Query) -> bool {
    let areas = &record.header.domain.areas;
    query
        .area
        .is_none_or(|a| areas.contains(&a) || areas.contains(&LifeArea::General))
}

/// Step 2: active, not invalidated and allowed by its "use only for" restriction; validity at the query time is marked on the entry, not filtered.
#[must_use]
pub fn usable(record: &LiveMemoryRecord, query: &Query) -> bool {
    record.status == LiveStatus::Active
        && record.epistemic_state != EpistemicState::Invalidated
        && within_restriction(record, query)
}

/// Whether the query is inside every area and project list the record's usage restriction names; a restricted record never serves a query that names no area or project it allows.
#[must_use]
pub fn within_restriction(record: &LiveMemoryRecord, query: &Query) -> bool {
    record.usage_restriction.as_ref().is_none_or(|r| {
        (r.areas.is_empty() || query.area.is_some_and(|a| r.areas.contains(&a)))
            && (r.projects.is_empty() || query.project.is_some_and(|p| r.projects.contains(&p)))
    })
}

/// Whether the record holds at `at`.
#[must_use]
pub fn holds_at(record: &LiveMemoryRecord, at: Instant) -> bool {
    record.valid_from <= at && record.valid_to.is_none_or(|t| at < t)
}

/// Step 4: not an opinion, or an opinion the query may see.
#[must_use]
pub fn passes_opinion_filter(record: &LiveMemoryRecord, query: &Query) -> bool {
    record.content_type.core() != CoreContentType::Opinion || opinion_allowed(query.kind)
}
