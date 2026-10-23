//! Permanent forgetting: only the user, with explicit confirmation (trusted surface and strong authentication for an area or all memory), shreds the record keys of the scope and every derivative, episodes used only by it and device caches, retrains the personal adapter and leaves a skeleton (M-25, A-11 (4), PV-65).

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::data_class::{LifeArea, RetentionClass};
use crate::id::{DeviceId, EpisodeId, MemoryRecordId};
use crate::ontology::episode::SkeletonRetention;
use crate::ontology::tags::Forgotten;
use crate::ontology::time::Instant;

crate::const_tag!(
    /// `verb: "forget_permanently"`.
    ForgetPermanently,
    "forget_permanently"
);

/// What to forget.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgetScope {
    /// One record.
    Record(MemoryRecordId),
    /// Every record of a life area.
    Area(LifeArea),
    /// All memory; the value is `true`.
    All(bool),
}

/// Who asked.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Initiator {
    /// The user.
    User,
    /// One on its own.
    One,
    /// A behaviour rule.
    BehaviourRule,
    /// A trigger.
    Trigger,
}

/// How the user confirmed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Confirmation {
    /// An in-app confirmation; enough for one record.
    InApp,
    /// The Access trusted surface with strong authentication.
    AccessTrustedSurfaceStrongAuth,
}

/// A record the request may touch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopedRecord {
    /// Its retention class.
    pub retention_class: RetentionClass,
    /// Its life areas.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub areas: Vec<LifeArea>,
}

/// The name of a derivative that is not a memory record (`summary:1`, `vec:2`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct DerivativeName(pub String);

/// A derivative: a memory record such as a consolidated fact, or another artefact.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum DerivativeId {
    /// A memory record.
    Record(MemoryRecordId),
    /// Another artefact.
    Other(DerivativeName),
}

/// The kind of a derivative.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DerivativeKind {
    /// A summary.
    Summary,
    /// A consolidated fact.
    ConsolidatedFact,
    /// A text view.
    TextView,
    /// An embedding.
    Embedding,
}

/// A derivative and the records it was made from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Derivative {
    /// The derivative.
    pub id: DerivativeId,
    /// Its kind.
    pub kind: DerivativeKind,
    /// Its source records.
    pub sources: Vec<MemoryRecordId>,
}

/// An Episode and the records that use it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpisodeUse {
    /// The Episode.
    pub id: EpisodeId,
    /// Records using it.
    pub used_by: Vec<MemoryRecordId>,
}

/// A device's state in Access.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    /// Connected.
    Online,
    /// Not connected.
    Offline,
    /// Removed in Access; its local key is invalid.
    RemovedInAccess,
}

/// A device holding a cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCache {
    /// The device.
    pub id: DeviceId,
    /// Its state.
    pub state: DeviceState,
}

/// The records the personal adapter was trained on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterLineage {
    /// Training records.
    pub trained_on: Vec<MemoryRecordId>,
}

/// A permanent forget request with everything it may reach.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetRequest {
    /// `forget_permanently`.
    pub verb: ForgetPermanently,
    /// What to forget.
    pub scope: ForgetScope,
    /// Who asked.
    pub initiator: Initiator,
    /// How the user confirmed, or `null`.
    pub confirmation: Option<Confirmation>,
    /// Records by identifier.
    pub records: BTreeMap<MemoryRecordId, ScopedRecord>,
    /// Derivatives.
    pub derivatives: Vec<Derivative>,
    /// Episodes.
    pub episodes: Vec<EpisodeUse>,
    /// Devices.
    pub devices: Vec<DeviceCache>,
    /// The personal adapter's lineage.
    #[serde(default)]
    pub adapter: Option<AdapterLineage>,
    /// The time, given explicitly.
    pub at: Instant,
}

/// Why a forget request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForgetError {
    /// Only the user can forget permanently.
    UserOnly,
    /// No explicit confirmation.
    ConfirmationRequired,
    /// An area or all memory needs the trusted surface and strong authentication.
    TrustedSurfaceStrongAuthRequired,
}

/// What happens to a device cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheErasure {
    /// Shredded now.
    Shredded,
    /// Shredded when the device connects.
    PendingUntilConnected,
    /// The device key is invalid in Access.
    KeyInvalid,
}

/// Whether the erasure log is still waiting for a device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureLog {
    /// Waiting for an offline device.
    Open,
    /// Done.
    Closed,
}

/// The notice shown to the user, in both languages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserNotice {
    /// Turkish.
    pub tr: String,
    /// English.
    pub en: String,
    /// Devices still to be erased.
    pub pending_devices: Vec<DeviceId>,
}

/// The Turkish notice text.
pub const NOTICE_TR: &str =
    "Bu bilgi kal\u{131}c\u{131} olarak unutuldu: okunamaz h\u{e2}le getirildi.";
/// The English notice text.
pub const NOTICE_EN: &str = "This was permanently forgotten: it has been made unreadable.";

crate::const_tag!(
    /// `old_version: "shredded_after_retrain"`.
    ShreddedAfterRetrain,
    "shredded_after_retrain"
);
crate::const_tag!(
    /// `fallback: "general_model"`.
    GeneralModel,
    "general_model"
);

/// What happens to a personal adapter trained on a forgotten record: one fact cannot be removed from weights.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterPlan {
    /// Retrain from the remaining memory.
    pub retrain_from_remaining_memory: bool,
    /// The old version is shredded after retraining.
    pub old_version: ShreddedAfterRetrain,
    /// The old version is never used meanwhile.
    pub use_old_until_retrained: bool,
    /// The general model serves meanwhile.
    pub fallback: GeneralModel,
}

/// The skeleton a forgotten record leaves.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkeletonSummary {
    /// The record.
    pub id: MemoryRecordId,
    /// `forgotten`.
    pub status: Forgotten,
    /// When.
    pub deleted_at: Instant,
    /// Retention class.
    pub retention_class: SkeletonRetention,
}

/// The effects of an accepted forget request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ForgetEffects {
    /// Record keys shredded: the scope and derived records.
    pub shredded_record_keys: Vec<MemoryRecordId>,
    /// Derivatives made unreadable.
    pub unreadable_derivatives: Vec<DerivativeId>,
    /// Derivatives untouched.
    pub kept_derivatives: Vec<DerivativeId>,
    /// Episodes used only by forgotten records.
    pub shredded_episodes: Vec<EpisodeId>,
    /// Episodes still used by another record.
    pub kept_episodes: Vec<EpisodeId>,
    /// Whether the person × class key was shredded.
    pub class_dek_shredded: bool,
    /// The skeleton of a single forgotten record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub skeleton: Option<SkeletonSummary>,
    /// Device caches.
    pub device_caches: BTreeMap<DeviceId, CacheErasure>,
    /// Erasure log state.
    pub erasure_log: ErasureLog,
    /// User notice.
    pub user_notice: UserNotice,
    /// Personal adapter plan, when it was trained on a forgotten record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub adapter: Option<AdapterPlan>,
}

/// The decision on a forget request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ForgetDecision {
    /// Forgotten.
    Forgotten(Box<ForgetEffects>),
    /// Refused.
    Rejected {
        /// Why.
        error: ForgetError,
    },
}

const fn skeleton_retention(class: RetentionClass) -> SkeletonRetention {
    match class {
        RetentionClass::OneSensitive => SkeletonRetention::OneSensitive,
        _ => SkeletonRetention::OneMemory,
    }
}

fn authorise(request: &ForgetRequest) -> Result<(), ForgetError> {
    if request.initiator != Initiator::User {
        return Err(ForgetError::UserOnly);
    }
    let confirmation = request
        .confirmation
        .ok_or(ForgetError::ConfirmationRequired)?;
    let broad = !matches!(request.scope, ForgetScope::Record(_));
    if broad && confirmation != Confirmation::AccessTrustedSurfaceStrongAuth {
        return Err(ForgetError::TrustedSurfaceStrongAuthRequired);
    }
    Ok(())
}

fn scope_records(request: &ForgetRequest) -> Vec<MemoryRecordId> {
    match request.scope {
        ForgetScope::Record(id) => alloc::vec![id],
        ForgetScope::Area(area) => request
            .records
            .iter()
            .filter(|(_, r)| r.areas.contains(&area))
            .map(|(id, _)| *id)
            .collect(),
        ForgetScope::All(_) => request.records.keys().copied().collect(),
    }
}

fn propagate(derivatives: &[Derivative], forgotten: &mut Vec<MemoryRecordId>) -> BTreeSet<usize> {
    let mut gone: BTreeSet<MemoryRecordId> = forgotten.iter().copied().collect();
    let mut unreadable: BTreeSet<usize> = BTreeSet::new();
    let mut grew = true;
    while grew {
        grew = false;
        for (i, d) in derivatives.iter().enumerate() {
            if unreadable.contains(&i) || !d.sources.iter().any(|s| gone.contains(s)) {
                continue;
            }
            unreadable.insert(i);
            grew = true;
            if let DerivativeId::Record(id) = d.id
                && gone.insert(id)
            {
                forgotten.push(id);
            }
        }
    }
    unreadable
}

fn devices(request: &ForgetRequest) -> (BTreeMap<DeviceId, CacheErasure>, Vec<DeviceId>) {
    let mut caches = BTreeMap::new();
    let mut pending = Vec::new();
    for d in &request.devices {
        let erasure = match d.state {
            DeviceState::Online => CacheErasure::Shredded,
            DeviceState::Offline => {
                pending.push(d.id);
                CacheErasure::PendingUntilConnected
            }
            DeviceState::RemovedInAccess => CacheErasure::KeyInvalid,
        };
        caches.insert(d.id, erasure);
    }
    (caches, pending)
}

/// Decides a permanent forget request and lists every effect (M-25).
#[must_use]
pub fn forget(request: &ForgetRequest) -> ForgetDecision {
    if let Err(error) = authorise(request) {
        return ForgetDecision::Rejected { error };
    }
    let mut forgotten = scope_records(request);
    let unreadable = propagate(&request.derivatives, &mut forgotten);
    let gone: BTreeSet<MemoryRecordId> = forgotten.iter().copied().collect();
    let (mut unreadable_derivatives, mut kept_derivatives) = (Vec::new(), Vec::new());
    for (i, d) in request.derivatives.iter().enumerate() {
        if unreadable.contains(&i) {
            unreadable_derivatives.push(d.id.clone());
        } else {
            kept_derivatives.push(d.id.clone());
        }
    }
    let (mut shredded_episodes, mut kept_episodes) = (Vec::new(), Vec::new());
    for e in &request.episodes {
        if !e.used_by.is_empty() && e.used_by.iter().all(|r| gone.contains(r)) {
            shredded_episodes.push(e.id);
        } else {
            kept_episodes.push(e.id);
        }
    }
    let (device_caches, pending_devices) = devices(request);
    let skeleton = match request.scope {
        ForgetScope::Record(id) => Some(SkeletonSummary {
            id,
            status: Forgotten,
            deleted_at: request.at,
            retention_class: request
                .records
                .get(&id)
                .map_or(SkeletonRetention::OneMemory, |r| {
                    skeleton_retention(r.retention_class)
                }),
        }),
        ForgetScope::Area(_) | ForgetScope::All(_) => None,
    };
    let adapter = request
        .adapter
        .as_ref()
        .filter(|a| a.trained_on.iter().any(|r| gone.contains(r)))
        .map(|_| AdapterPlan {
            retrain_from_remaining_memory: true,
            old_version: ShreddedAfterRetrain,
            use_old_until_retrained: false,
            fallback: GeneralModel,
        });
    ForgetDecision::Forgotten(Box::new(ForgetEffects {
        shredded_record_keys: forgotten,
        unreadable_derivatives,
        kept_derivatives,
        shredded_episodes,
        kept_episodes,
        class_dek_shredded: matches!(request.scope, ForgetScope::All(true)),
        skeleton,
        device_caches,
        erasure_log: if pending_devices.is_empty() {
            ErasureLog::Closed
        } else {
            ErasureLog::Open
        },
        user_notice: UserNotice {
            tr: String::from(NOTICE_TR),
            en: String::from(NOTICE_EN),
            pending_devices,
        },
        adapter,
    }))
}

/// Sync and key unwrap for a reconnecting device.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// Allowed.
    Allowed,
    /// Refused.
    Refused,
}

/// The outcome of a reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReconnectOutcome {
    /// Accepted; pending erasures run first.
    Accepted,
    /// Rejected.
    Rejected,
}

/// What a reconnecting device may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconnectDecision {
    /// Outcome.
    pub outcome: ReconnectOutcome,
    /// Sync.
    pub sync: Permission,
    /// Key unwrap.
    pub key_unwrap: Permission,
}

/// A device removed in Access gets neither sync nor key unwrap when it reconnects (M-25).
#[must_use]
pub const fn device_reconnect(state: DeviceState) -> ReconnectDecision {
    match state {
        DeviceState::RemovedInAccess => ReconnectDecision {
            outcome: ReconnectOutcome::Rejected,
            sync: Permission::Refused,
            key_unwrap: Permission::Refused,
        },
        DeviceState::Online | DeviceState::Offline => ReconnectDecision {
            outcome: ReconnectOutcome::Accepted,
            sync: Permission::Allowed,
            key_unwrap: Permission::Allowed,
        },
    }
}
