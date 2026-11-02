//! Ranking and the smallest subset (M-30 steps 6 and 7, M-20, M-31, `conformance/memory/rank-v1.toml`): a score from hybrid relevance, trust, decayed priority and the query's life area; the model sees at most twelve records scoring 0.35 or more, and a record contradicting a kept one always travels with it.

use std::collections::BTreeMap;

use one_proto::memory::trust::round6;

const LEXICAL_SHARE: f64 = 0.5;
const RELEVANCE_WEIGHT: f64 = 0.55;
const TRUST_WEIGHT: f64 = 0.2;
const PRIORITY_WEIGHT: f64 = 0.15;
const AREA_WEIGHT: f64 = 0.1;

/// The lowest score kept.
pub const MIN_SCORE: f64 = 0.35;

/// The most records kept before contradicting ones are added.
pub const MAX_RECORDS: usize = 12;

/// One eligible record after hybrid search.
#[derive(Debug, Clone, PartialEq)]
pub struct Ranked<K> {
    /// The record.
    pub id: K,
    /// Lexical score in `0..=1`.
    pub lexical: f64,
    /// Dense similarity in `0..=1`.
    pub similarity: f64,
    /// Trust in `0..=1`.
    pub trust: f64,
    /// Decayed priority in `0..=1`.
    pub priority: f64,
    /// Whether it is in the query's life area.
    pub in_area: bool,
    /// The records it contradicts.
    pub contradicts: Vec<K>,
}

/// The score of one record, rounded to six decimals.
#[must_use]
pub fn score<K>(r: &Ranked<K>) -> f64 {
    let relevance = LEXICAL_SHARE * r.lexical + (1.0 - LEXICAL_SHARE) * r.similarity;
    let area = if r.in_area { 1.0 } else { 0.0 };
    round6(
        RELEVANCE_WEIGHT * relevance
            + TRUST_WEIGHT * r.trust
            + PRIORITY_WEIGHT * r.priority
            + AREA_WEIGHT * area,
    )
}

/// The records the model sees, in order.
#[must_use]
pub fn smallest_subset<K: Ord + Clone>(records: &[Ranked<K>]) -> Vec<K> {
    let mut scored: Vec<(f64, &Ranked<K>)> = records.iter().map(|r| (score(r), r)).collect();
    scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
    let mut kept: Vec<K> = scored
        .iter()
        .filter(|(s, _)| *s >= MIN_SCORE)
        .take(MAX_RECORDS)
        .map(|(_, r)| r.id.clone())
        .collect();
    let by_id: BTreeMap<&K, &Ranked<K>> = records.iter().map(|r| (&r.id, r)).collect();
    let mut i = 0;
    while let Some(id) = kept.get(i).cloned() {
        if let Some(r) = by_id.get(&id) {
            for other in &r.contradicts {
                if by_id.contains_key(other) && !kept.contains(other) {
                    kept.push(other.clone());
                }
            }
        }
        i = i.saturating_add(1);
    }
    kept
}
