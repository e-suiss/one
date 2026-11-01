//! Rebuild-diff (OP-1 (2), OP-18): inside the TEE a derived structure rebuilt from the canonical records is compared with the live one entry by entry, each entry an id, the source versions it was built from and the SHA-256 of its plaintext; any difference raises the sev-1 alarm, which carries counts only, and the rebuild replaces the live structure, never the reverse.

use std::collections::BTreeMap;

/// One entry of a derived structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// The derived row's id.
    pub id: [u8; 16],
    /// The source rows and versions it was built from, in any order.
    pub sources: Sources,
    /// The SHA-256 of its plaintext.
    pub digest: [u8; 32],
}

/// How a live structure differs from its rebuild; counts only, so it may leave the TEE.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Diff {
    /// Entries the rebuild has and the live structure lacks.
    pub missing: u64,
    /// Entries the live structure has and the rebuild does not, such as a derivative of a forgotten source.
    pub extra: u64,
    /// Entries in both whose sources or plaintext differ.
    pub changed: u64,
}

impl Diff {
    /// Whether the sev-1 alarm is raised.
    #[must_use]
    pub const fn alarm(&self) -> bool {
        self.missing > 0 || self.extra > 0 || self.changed > 0
    }
}

type Sources = Vec<([u8; 16], u32)>;

fn index(entries: &[Entry]) -> BTreeMap<[u8; 16], (Sources, [u8; 32])> {
    entries
        .iter()
        .map(|e| {
            let mut sources = e.sources.clone();
            sources.sort_unstable();
            sources.dedup();
            (e.id, (sources, e.digest))
        })
        .collect()
}

/// Compares `live` with `rebuilt`; an id listed twice counts once, with its last entry.
#[must_use]
pub fn diff(live: &[Entry], rebuilt: &[Entry]) -> Diff {
    let live = index(live);
    let rebuilt = index(rebuilt);
    let mut out = Diff::default();
    for (id, entry) in &rebuilt {
        match live.get(id) {
            None => out.missing = out.missing.saturating_add(1),
            Some(l) if l != entry => out.changed = out.changed.saturating_add(1),
            Some(_) => {}
        }
    }
    let extra = live.keys().filter(|id| !rebuilt.contains_key(*id)).count();
    out.extra = u64::try_from(extra).unwrap_or(u64::MAX);
    out
}
