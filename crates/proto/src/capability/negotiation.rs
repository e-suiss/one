//! Capability negotiation by intersection: same name on both sides, same `extends`, the highest common version, then extensions pruned until every kept name reaches a kept parent (CP-15).

use alloc::vec::Vec;

use super::name::{CapabilityName, CapabilityRef, CapabilityVersion, Extends, NameKind};
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

fn check_declaration(value: &Declaration) -> Result<(), ContractViolation> {
    require(
        !value.versions.is_empty() && unique(&value.versions),
        "declaration versions",
    )?;
    if value.name.kind() == NameKind::ThirdParty {
        require(
            value.extends.is_some(),
            "a third-party name extends a parent",
        )?;
    }
    Ok(())
}

crate::task::common::checked_record!(
    /// One side's offer of a capability during negotiation.
    #[derive(Eq)]
    pub struct Declaration via DeclarationWire = "DeclarationWire", check check_declaration {
        /// The name.
        pub name: CapabilityName,
        /// The versions offered.
        pub versions: Vec<CapabilityVersion>,
        /// The parents.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pub extends: Option<Extends>,
    }
);

fn same_extends(a: Option<&Extends>, b: Option<&Extends>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.same_set(y),
        _ => false,
    }
}

/// Negotiates two offers; a name declared twice on one side counts once, by its first declaration.
#[must_use]
pub fn negotiate(local: &[Declaration], remote: &[Declaration]) -> Vec<CapabilityRef> {
    let first = |side: &[Declaration], name: &CapabilityName| {
        side.iter().find(|d| &d.name == name).cloned()
    };
    let mut candidates: Vec<(Declaration, CapabilityVersion)> = Vec::new();
    for (i, mine) in local.iter().enumerate() {
        if local.iter().take(i).any(|d| d.name == mine.name) {
            continue;
        }
        let Some(theirs) = first(remote, &mine.name) else {
            continue;
        };
        if !same_extends(mine.extends.as_ref(), theirs.extends.as_ref()) {
            continue;
        }
        let best = mine
            .versions
            .iter()
            .filter(|v| theirs.versions.contains(v))
            .max()
            .cloned();
        if let Some(version) = best {
            candidates.push((mine.clone(), version));
        }
    }
    let mut grounded: Vec<bool> = candidates
        .iter()
        .map(|(d, _)| d.extends.is_none())
        .collect();
    loop {
        let mut changed = false;
        for (i, (decl, _)) in candidates.iter().enumerate() {
            if grounded.get(i).copied().unwrap_or(true) {
                continue;
            }
            let Some(extends) = decl.extends.as_ref() else {
                continue;
            };
            let reaches = extends.parents().iter().any(|p| {
                candidates
                    .iter()
                    .zip(grounded.iter())
                    .any(|((c, _), g)| *g && &c.name == p)
            });
            if reaches && let Some(flag) = grounded.get_mut(i) {
                *flag = true;
                changed = true;
            }
        }
        if !changed {
            break;
        }
    }
    let mut kept: Vec<CapabilityRef> = candidates
        .into_iter()
        .zip(grounded)
        .filter(|(_, g)| *g)
        .map(|((d, version), _)| CapabilityRef {
            name: d.name,
            version,
        })
        .collect();
    kept.sort_by(|a, b| a.name.as_str().cmp(b.name.as_str()));
    kept
}
