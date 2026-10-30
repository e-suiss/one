//! The client side of the 2-of-3 PIN vault: registration on three realms of separate hosts and operators, a recovery plan from the reachable realms, the version the threshold agrees on, guess accounting across realms and shred with its open copies (PV-12, PV-14, PV-15).

use std::collections::{BTreeMap, BTreeSet};

use one_proto::recovery::{RealmName, RecoveryStatus, VAULT_REALMS, VAULT_THRESHOLD};

use super::recovery::GuessLimit;

/// Where one realm runs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmSite {
    /// The realm.
    pub realm: RealmName,
    /// The host pool.
    pub host: String,
    /// The operator.
    pub operator: String,
}

/// Why a vault registration is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RegisterRefusal {
    /// Not exactly three distinct realms.
    RealmCount,
    /// Two realms share a host or an operator.
    SharedSite,
    /// The threshold is not 2.
    Threshold,
}

/// The realms a registration writes to: all three, each on its own host and operator.
///
/// # Errors
/// The [`RegisterRefusal`] that applies.
pub fn register(sites: &[RealmSite], threshold: u8) -> Result<Vec<RealmName>, RegisterRefusal> {
    if threshold != VAULT_THRESHOLD {
        return Err(RegisterRefusal::Threshold);
    }
    let realms: BTreeSet<&RealmName> = sites.iter().map(|s| &s.realm).collect();
    if sites.len() != VAULT_REALMS || realms.len() != VAULT_REALMS {
        return Err(RegisterRefusal::RealmCount);
    }
    let hosts: BTreeSet<&str> = sites.iter().map(|s| s.host.as_str()).collect();
    let operators: BTreeSet<&str> = sites.iter().map(|s| s.operator.as_str()).collect();
    if hosts.len() != VAULT_REALMS || operators.len() != VAULT_REALMS {
        return Err(RegisterRefusal::SharedSite);
    }
    Ok(sites.iter().map(|s| s.realm.clone()).collect())
}

/// How a recovery proceeds.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryPlan {
    /// Contact `contact` reachable realms; re-register on a replacement when a realm is lost.
    Proceed {
        /// The realms to contact, as many as the threshold.
        contact: Vec<RealmName>,
        /// Whether the vault is re-registered after recovery.
        reregister: bool,
    },
    /// Fewer realms than the threshold answer: nothing is sent, so no guess is counted.
    Unavailable,
}

/// The plan for the registered realms when `reachable` answer.
#[must_use]
pub fn plan_recovery(registered: &[RealmName], reachable: &[RealmName]) -> RecoveryPlan {
    let live: Vec<RealmName> = registered
        .iter()
        .filter(|r| reachable.contains(r))
        .cloned()
        .collect();
    let threshold = usize::from(VAULT_THRESHOLD);
    if live.len() < threshold {
        return RecoveryPlan::Unavailable;
    }
    RecoveryPlan::Proceed {
        reregister: live.len() < registered.len(),
        contact: live.into_iter().take(threshold).collect(),
    }
}

/// The record version held by at least the threshold of realms, with those realms; minority records are ignored.
#[must_use]
pub fn agreed_version<V: Ord + Clone>(versions: &[(RealmName, V)]) -> Option<(V, Vec<RealmName>)> {
    let mut by_version: BTreeMap<&V, Vec<RealmName>> = BTreeMap::new();
    for (realm, version) in versions {
        by_version.entry(version).or_default().push(realm.clone());
    }
    by_version
        .into_iter()
        .find(|(_, realms)| realms.len() >= usize::from(VAULT_THRESHOLD))
        .map(|(v, realms)| (v.clone(), realms))
}

/// Guesses used per realm; the effective count is the lowest remaining.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealmGuesses {
    limit: GuessLimit,
    used: BTreeMap<RealmName, u8>,
}

/// What follows a failed guess.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AfterFailure {
    /// Realms that delete their record: every realm once one reaches the limit.
    pub deleted: Vec<RealmName>,
}

/// What exhaustion of the guess limit does beyond deleting the records (PV-13, PV-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Exhaustion {
    /// The Access recovery method's new status.
    pub access_method: RecoveryStatus,
    /// The user is shown the paths that remain.
    pub show_remaining_paths: bool,
}

/// The effects of an exhausted vault.
pub const EXHAUSTION: Exhaustion = Exhaustion {
    access_method: RecoveryStatus::Unusable,
    show_remaining_paths: true,
};

impl RealmGuesses {
    /// Counters for `realms`, starting from `used`.
    #[must_use]
    pub fn new(limit: GuessLimit, used: impl IntoIterator<Item = (RealmName, u8)>) -> Self {
        Self {
            limit,
            used: used.into_iter().collect(),
        }
    }

    /// The guesses used on `realm`.
    #[must_use]
    pub fn used(&self, realm: &RealmName) -> u8 {
        self.used.get(realm).copied().unwrap_or(0)
    }

    /// The guesses left: the lowest remaining over all realms.
    #[must_use]
    pub fn remaining(&self) -> u8 {
        let most = self.used.values().copied().max().unwrap_or(0);
        self.limit.get().saturating_sub(most)
    }

    /// Counts one failed guess on each realm it reached.
    pub fn fail(&mut self, reached: &[RealmName]) -> AfterFailure {
        for realm in reached {
            if let Some(used) = self.used.get_mut(realm) {
                *used = used.saturating_add(1);
            }
        }
        let limit = self.limit.get();
        let deleted = if self.used.values().any(|u| *u >= limit) {
            self.used.keys().cloned().collect()
        } else {
            Vec::new()
        };
        AfterFailure { deleted }
    }
}

/// A copy a shred could not reach, kept open in the erasure log (PV-15).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpenCopy {
    /// The holder kind, `vault_realm`.
    pub holder: &'static str,
    /// The realm.
    pub realm: RealmName,
}

/// The result of shredding the vault record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shred {
    /// The realms that deleted their record.
    pub deleted: Vec<RealmName>,
    /// The erasure log scope, `recovery_vault`.
    pub scope: &'static str,
    /// The realms still holding a copy.
    pub open_copies: Vec<OpenCopy>,
}

/// Shreds the record on every reachable realm and keeps the rest open in the erasure log.
#[must_use]
pub fn shred(registered: &[RealmName], reachable: &[RealmName]) -> Shred {
    let (deleted, open): (Vec<RealmName>, Vec<RealmName>) = registered
        .iter()
        .cloned()
        .partition(|r| reachable.contains(r));
    Shred {
        deleted,
        scope: "recovery_vault",
        open_copies: open
            .into_iter()
            .map(|realm| OpenCopy {
                holder: "vault_realm",
                realm,
            })
            .collect(),
    }
}
