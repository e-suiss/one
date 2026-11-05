//! The planner's candidates (CP-17, CP-18, C-17): the registry entries that work now and fall inside the current authority are the only names handed to retrieval, and the best few of them are the only definitions handed to the model; a failed search yields no candidates, never the whole list.

use one_proto::capability::{CapabilityDefinition, CapabilityName};
use one_proto::ontology::Instant;

use crate::domain::registry::Entry;
use crate::domain::select::{Authority, candidates, eligible};
use crate::ports::{Search, SearchError};

/// The definitions the planner gets for `request` at `now`.
///
/// # Errors
/// [`SearchError`] from retrieval.
pub async fn planner_candidates<S: Search>(
    entries: &[Entry],
    authority: &Authority,
    search: &mut S,
    request: &str,
    now: Instant,
) -> Result<Vec<CapabilityDefinition>, SearchError> {
    let allowed = eligible(entries, authority, now);
    if allowed.is_empty() {
        return Ok(Vec::new());
    }
    let names: Vec<CapabilityName> = allowed.iter().map(|e| e.definition.name.clone()).collect();
    let scores = search.scores(request, &names).await?;
    Ok(candidates(&allowed, &scores)
        .into_iter()
        .map(|e| e.definition.clone())
        .collect())
}
