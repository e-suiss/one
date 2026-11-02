//! The memory component's use cases (M-6, M-15, M-24, M-25, M-30, M-39): remember, confirm, show, correct, stop or resume using, permanently forget, retrieve and export; every change is a new sealed version written through the vault in the caller's transaction, and nothing is edited in place or deleted.

use std::collections::{BTreeMap, BTreeSet};
use std::num::NonZeroU32;

use one_proto::data_class::RetentionClass;
use one_proto::memory::export::{
    ExcludedSection, ExportDocument, ExportFormat, Generator, MemorySection, PersonalityExport,
    ProfileExport, SCHEMA_VERSION,
};
use one_proto::memory::fields::{EpistemicState, Layer, LiveStatus, TimeKind};
use one_proto::memory::forget::{
    Confirmation, EpisodeUse, ForgetDecision, ForgetEffects, ForgetError, ForgetPermanently,
    ForgetRequest, ForgetScope, Initiator, ScopedRecord, forget as decide_forget,
};
use one_proto::memory::ops::{MemoryError, check_write};
use one_proto::memory::record::{LiveMemoryRecord, MemoryRecord, MemorySkeleton};
use one_proto::memory::text_view::{TextView, TextViewEntry, TextViewError, render};
use one_proto::memory::trust::round6;
use one_proto::ontology::episode::{Episode, EpisodeSkeleton, SkeletonRetention};
use one_proto::ontology::reference::PartyRef;
use one_proto::ontology::tags::{EpisodeType, Forgotten, MemoryRecordType};
use one_proto::ontology::time::Instant;
use one_proto::ontology::validate::{ContractViolation, UnknownFields};
use one_proto::{EpisodeId, MemoryRecordId};

use crate::domain::classes::trust_class;
use crate::domain::decay::{DecayInput, priority};
use crate::domain::rank::{Ranked, smallest_subset};
use crate::domain::retrieval::{Query, in_area, passes_opinion_filter, usable};
use crate::domain::write::{Moment, Session, WriteError, WritePath, admit, default_expected_end};
use crate::ports::{Forgot, Policy, Projections, Row, Search, SearchError, Vault, VaultError};

/// Why a use case failed.
#[derive(Debug, thiserror::Error)]
pub enum MemoryAppError {
    /// The write is not admitted.
    #[error(transparent)]
    Write(#[from] WriteError),
    /// The record breaks a contract rule.
    #[error("contract: {0}")]
    Contract(ContractViolation),
    /// A record operation was refused.
    #[error("memory operation refused: {0:?}")]
    Memory(MemoryError),
    /// Permanent forgetting was refused.
    #[error("forgetting refused: {0:?}")]
    Forget(ForgetError),
    /// A legal hold covers the record; nothing changed.
    #[error("held")]
    Held,
    /// No live record by that identifier.
    #[error("no such record")]
    NotFound,
    /// The change does not apply to the record's current state.
    #[error("the record is not in a state this change applies to")]
    State,
    /// The vault failed.
    #[error(transparent)]
    Vault(#[from] VaultError),
    /// A stored body did not decode.
    #[error("stored record does not decode")]
    Decode,
    /// Search failed.
    #[error(transparent)]
    Search(#[from] SearchError),
    /// The view refused a record.
    #[error("view: {0:?}")]
    View(TextViewError),
}

fn decode(row: &Row) -> Result<Option<LiveMemoryRecord>, MemoryAppError> {
    row.body
        .as_deref()
        .map(|b| serde_json::from_slice(b).map_err(|_| MemoryAppError::Decode))
        .transpose()
}

fn encode(record: &LiveMemoryRecord) -> Result<Vec<u8>, MemoryAppError> {
    record.validate().map_err(MemoryAppError::Contract)?;
    serde_json::to_vec(record).map_err(|_| MemoryAppError::Decode)
}

/// Remembers `record` along `path`; the write path sets its lifecycle and epistemic state and the server sets its time and version.
///
/// # Errors
/// [`MemoryAppError`].
pub async fn remember<V: Vault>(
    vault: &mut V,
    now: Instant,
    mut record: LiveMemoryRecord,
    path: WritePath,
    moment: Moment,
    session: Session,
) -> Result<MemoryRecordId, MemoryAppError> {
    let admitted = admit(
        session,
        moment,
        path,
        record.layer,
        record.header.data_class.is_sensitive(),
    )?;
    record.status = admitted.status;
    record.epistemic_state = admitted.epistemic_state;
    record.supersedes = None;
    record.superseded_at = None;
    record.header.version = NonZeroU32::MIN;
    record.header.recorded_at = now;
    record.header.deleted_at = None;
    if record.time_kind == TimeKind::Current && record.expected_end.is_none() {
        record.expected_end = Some(default_expected_end(&record.valid_from));
    }
    check_write(&record.source_episodes, None).map_err(MemoryAppError::Memory)?;
    if !vault.episodes_exist(&record.source_episodes).await? {
        return Err(MemoryAppError::Memory(MemoryError::UnknownSourceEpisode));
    }
    let body = encode(&record)?;
    vault
        .put_first(record.id, record.header.retention_class, &body)
        .await?;
    Ok(record.id)
}

/// Writes episode `episode`, which records cite as their source (M-6).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn record_episode<V: Vault>(
    vault: &mut V,
    episode: &Episode,
) -> Result<EpisodeId, MemoryAppError> {
    let Episode::Live(live) = episode else {
        return Err(MemoryAppError::State);
    };
    live.validate().map_err(MemoryAppError::Contract)?;
    let body = serde_json::to_vec(episode).map_err(|_| MemoryAppError::Decode)?;
    vault
        .put_episode(live.id, live.header.retention_class, &body)
        .await?;
    Ok(live.id)
}

async fn head<V: Vault>(
    vault: &mut V,
    id: MemoryRecordId,
) -> Result<LiveMemoryRecord, MemoryAppError> {
    let rows = vault.rows().await?;
    let row = rows
        .iter()
        .find(|r| r.id == id)
        .ok_or(MemoryAppError::NotFound)?;
    if !row.head {
        return Err(MemoryAppError::NotFound);
    }
    decode(row)?.ok_or(MemoryAppError::NotFound)
}

async fn next_version<V: Vault>(
    vault: &mut V,
    now: Instant,
    old: &LiveMemoryRecord,
    mut next: LiveMemoryRecord,
) -> Result<MemoryRecordId, MemoryAppError> {
    if next.id == old.id || next.header.retention_class != old.header.retention_class {
        return Err(MemoryAppError::State);
    }
    next.supersedes = Some(old.id);
    next.header.version = old.header.version.saturating_add(1);
    next.header.recorded_at = now;
    next.header.deleted_at = None;
    let body = encode(&next)?;
    vault.put_next(next.id, old.id, &body).await?;
    Ok(next.id)
}

/// Confirms candidate `id` as `new_id`: active, verified and confirmed now (M-8, M-15).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn confirm<V: Vault>(
    vault: &mut V,
    now: Instant,
    id: MemoryRecordId,
    new_id: MemoryRecordId,
) -> Result<MemoryRecordId, MemoryAppError> {
    let old = head(vault, id).await?;
    if old.status != LiveStatus::Candidate {
        return Err(MemoryAppError::State);
    }
    let mut next = old.clone();
    next.id = new_id;
    next.status = LiveStatus::Active;
    next.epistemic_state = EpistemicState::Verified;
    next.evidence.user_confirmed_at = Some(now);
    next_version(vault, now, &old, next).await
}

/// Corrects `id` with `replacement`: the replacement is the new, stated head and the old version stays in the chain as superseded (M-24, C-20).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn correct<V: Vault>(
    vault: &mut V,
    now: Instant,
    id: MemoryRecordId,
    mut replacement: LiveMemoryRecord,
) -> Result<MemoryRecordId, MemoryAppError> {
    let old = head(vault, id).await?;
    replacement.status = LiveStatus::Active;
    replacement.epistemic_state = EpistemicState::Stated;
    replacement.superseded_at = None;
    next_version(vault, now, &old, replacement).await
}

/// Whether a record is used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Use {
    /// Stop using it: out of retrieval, context and training, and reversible (M-24).
    Suppress,
    /// Use it again.
    Resume,
}

/// Stops or resumes using `id` as `new_id`.
///
/// # Errors
/// [`MemoryAppError`].
pub async fn set_use<V: Vault>(
    vault: &mut V,
    now: Instant,
    id: MemoryRecordId,
    new_id: MemoryRecordId,
    change: Use,
) -> Result<MemoryRecordId, MemoryAppError> {
    let old = head(vault, id).await?;
    let (from, to) = match change {
        Use::Suppress => (LiveStatus::Active, LiveStatus::Suppressed),
        Use::Resume => (LiveStatus::Suppressed, LiveStatus::Active),
    };
    if old.status != from {
        return Err(MemoryAppError::State);
    }
    let mut next = old.clone();
    next.id = new_id;
    next.status = to;
    next_version(vault, now, &old, next).await
}

/// Permanently forgets `id`, asked by `initiator` with `confirmation`: only the user, with explicit confirmation, and the chain's key and the keys of every derivative and every episode used only by it are destroyed; a legal hold changes nothing (M-25, OP-30 (1)).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn forget<V: Vault>(
    vault: &mut V,
    now: Instant,
    id: MemoryRecordId,
    initiator: Initiator,
    confirmation: Option<Confirmation>,
) -> Result<ForgetEffects, MemoryAppError> {
    let rows = vault.rows().await?;
    let mut records = BTreeMap::new();
    let mut uses: BTreeMap<EpisodeId, Vec<MemoryRecordId>> = BTreeMap::new();
    for row in rows.iter().filter(|r| r.head) {
        if let Some(r) = decode(row)? {
            for e in &r.source_episodes {
                uses.entry(*e).or_default().push(r.id);
            }
            records.insert(
                r.id,
                ScopedRecord {
                    retention_class: r.header.retention_class,
                    areas: r.header.domain.areas.clone(),
                },
            );
        }
    }
    if !records.contains_key(&id) {
        return Err(MemoryAppError::NotFound);
    }
    let request = ForgetRequest {
        verb: ForgetPermanently,
        scope: ForgetScope::Record(id),
        initiator,
        confirmation,
        records,
        derivatives: Vec::new(),
        episodes: uses
            .into_iter()
            .map(|(id, used_by)| EpisodeUse { id, used_by })
            .collect(),
        devices: Vec::new(),
        adapter: None,
        at: now,
    };
    let effects = match decide_forget(&request) {
        ForgetDecision::Rejected { error } => return Err(MemoryAppError::Forget(error)),
        ForgetDecision::Forgotten(effects) => *effects,
    };
    for record in &effects.shredded_record_keys {
        match vault.forget(*record).await? {
            Forgot::Done => {}
            Forgot::Held => return Err(MemoryAppError::Held),
            Forgot::Missing => return Err(MemoryAppError::NotFound),
        }
    }
    for episode in &effects.shredded_episodes {
        if vault.forget_episode(*episode).await? == Forgot::Held {
            return Err(MemoryAppError::Held);
        }
    }
    Ok(effects)
}

fn skeleton(owner: &PartyRef, row: &Row) -> MemoryRecord {
    MemoryRecord::Forgotten(MemorySkeleton {
        concept: MemoryRecordType,
        id: row.id,
        owner: owner.clone(),
        version: NonZeroU32::new(row.version).unwrap_or(NonZeroU32::MIN),
        status: Forgotten,
        recorded_at: row.recorded_at,
        deleted_at: row.deleted_at.unwrap_or(row.recorded_at),
        retention_class: if row.class == RetentionClass::OneSensitive {
            SkeletonRetention::OneSensitive
        } else {
            SkeletonRetention::OneMemory
        },
        unknown: UnknownFields::new(),
    })
}

/// The head of every chain, forgotten ones as skeletons, as the user sees them (M-6, M-25).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn records<V: Vault>(
    vault: &mut V,
    owner: &PartyRef,
) -> Result<Vec<MemoryRecord>, MemoryAppError> {
    let rows = vault.rows().await?;
    let superseded: BTreeSet<MemoryRecordId> = rows.iter().filter_map(|r| r.supersedes).collect();
    rows.iter()
        .filter(|r| !superseded.contains(&r.id))
        .map(|r| {
            Ok(match decode(r)? {
                Some(live) => MemoryRecord::Live(Box::new(live)),
                None => skeleton(owner, r),
            })
        })
        .collect()
}

fn entry(record: &LiveMemoryRecord, at: Instant) -> TextViewEntry {
    TextViewEntry {
        trust_class: trust_class(
            record.source_kind,
            record.evidence.user_confirmed_at.is_some(),
            record.trust.value,
        ),
        currently_valid: record.valid_from <= at && record.valid_to.is_none_or(|t| at < t),
        record: MemoryRecord::Live(Box::new(record.clone())),
    }
}

fn shown(record: &LiveMemoryRecord) -> bool {
    record.status == LiveStatus::Active && record.epistemic_state != EpistemicState::Invalidated
}

/// The `<memory-data version="1">` view of every active, valid head at `at` (M-6, M-14).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn view<V: Vault>(
    vault: &mut V,
    owner: &PartyRef,
    at: Instant,
) -> Result<TextView, MemoryAppError> {
    let entries: Vec<TextViewEntry> = records(vault, owner)
        .await?
        .iter()
        .filter_map(MemoryRecord::live)
        .filter(|r| shown(r))
        .map(|r| entry(r, at))
        .collect();
    render(&entries).map_err(MemoryAppError::View)
}

/// Retrieves the smallest subset for `query` through the eight fixed steps and renders it as the data block the model sees; with personalisation off nothing is retrieved (M-30, M-31, M-34).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn retrieve<V: Vault, P: Policy, S: Search>(
    vault: &mut V,
    policy: &P,
    search: &mut S,
    owner: &PartyRef,
    query: &Query,
) -> Result<TextView, MemoryAppError> {
    if query.unpersonalised {
        return render(&[]).map_err(MemoryAppError::View);
    }
    let all = records(vault, owner).await?;
    let eligible: Vec<&LiveMemoryRecord> = all
        .iter()
        .filter_map(MemoryRecord::live)
        .filter(|r| in_area(r, query))
        .filter(|r| usable(r, query))
        .filter(|r| policy.allows(r, query))
        .filter(|r| passes_opinion_filter(r, query))
        .collect();
    let ids: Vec<MemoryRecordId> = eligible.iter().map(|r| r.id).collect();
    let hits = search.search(query, &ids).await?;
    let by_id: BTreeMap<MemoryRecordId, &LiveMemoryRecord> =
        eligible.iter().map(|r| (r.id, *r)).collect();
    let mut ranked = Vec::new();
    for hit in hits {
        let Some(record) = by_id.get(&hit.id) else {
            continue;
        };
        let decayed = priority(&DecayInput {
            time_kind: record.time_kind,
            as_of: query.valid_at,
            last_used_at: record.evidence.last_observed_at,
            use_count: 0,
            last_confirmed_at: record.evidence.user_confirmed_at,
        })
        .unwrap_or(0.0);
        ranked.push(Ranked {
            id: hit.id,
            lexical: round6(hit.lexical.clamp(0.0, 1.0)),
            similarity: round6(hit.similarity.clamp(0.0, 1.0)),
            trust: record.trust.value,
            priority: decayed,
            in_area: query
                .area
                .is_some_and(|a| record.header.domain.areas.contains(&a)),
            contradicts: record.evidence.contradicting_records.clone(),
        });
    }
    let entries: Vec<TextViewEntry> = smallest_subset(&ranked)
        .iter()
        .filter_map(|id| by_id.get(id))
        .map(|r| entry(r, query.valid_at))
        .collect();
    render(&entries).map_err(MemoryAppError::View)
}

/// What an export produced.
#[derive(Debug, Clone, PartialEq)]
pub enum Export {
    /// The whole package.
    Ready(Box<ExportDocument>),
    /// Access could not be read; the export job waits and no partial package is made (M-39).
    Waiting,
}

fn section(
    owner: &PartyRef,
    rows: &[Row],
    episodes: &[crate::ports::EpisodeRow],
    sensitive: bool,
) -> Result<MemorySection, MemoryAppError> {
    let wanted = |class: RetentionClass| (class == RetentionClass::OneSensitive) == sensitive;
    let records = rows
        .iter()
        .filter(|r| wanted(r.class))
        .map(|r| {
            Ok(match decode(r)? {
                Some(live) => MemoryRecord::Live(Box::new(live)),
                None => skeleton(owner, r),
            })
        })
        .collect::<Result<_, MemoryAppError>>()?;
    let episodes = episodes
        .iter()
        .filter(|e| wanted(e.class))
        .map(|e| match &e.body {
            Some(b) => serde_json::from_slice(b).map_err(|_| MemoryAppError::Decode),
            None => Ok(Episode::Forgotten(EpisodeSkeleton {
                concept: EpisodeType,
                id: e.id,
                owner: owner.clone(),
                version: NonZeroU32::MIN,
                status: Forgotten,
                recorded_at: e.recorded_at,
                deleted_at: e.deleted_at.unwrap_or(e.recorded_at),
                retention_class: if sensitive {
                    SkeletonRetention::OneSensitive
                } else {
                    SkeletonRetention::OneMemory
                },
                unknown: UnknownFields::new(),
            })),
        })
        .collect::<Result<_, _>>()?;
    Ok(MemorySection {
        records,
        relationship_edges: Vec::new(),
        episodes,
    })
}

/// The full export package at `now`: every version of every record and episode, forgotten ones as skeletons, the sensitive section unless left out, the behaviour rules, the Access projections and the text view; it waits while Access cannot be read (M-39, M-40, M-41, INV-27).
///
/// # Errors
/// [`MemoryAppError`].
pub async fn export<V: Vault, A: Projections>(
    vault: &mut V,
    access: &mut A,
    owner: &PartyRef,
    now: Instant,
    include_sensitive: bool,
    generator: Generator,
) -> Result<Export, MemoryAppError> {
    let Some((grants, connections)) = access.read(now).await else {
        return Ok(Export::Waiting);
    };
    let rows = vault.rows().await?;
    let episodes = vault.episodes().await?;
    let memory = section(owner, &rows, &episodes, false)?;
    let sensitive = include_sensitive
        .then(|| section(owner, &rows, &episodes, true))
        .transpose()?;
    let heads = records(vault, owner).await?;
    let rules = heads
        .iter()
        .filter_map(MemoryRecord::live)
        .filter(|r| r.layer == Layer::BehaviourRule && shown(r))
        .map(|r| r.id)
        .collect();
    let text_view = view(vault, owner, now).await?.text;
    let document = ExportDocument {
        format: ExportFormat,
        schema_version: SCHEMA_VERSION,
        exported_at: now,
        owner: owner.clone(),
        generator,
        retention_class: if include_sensitive {
            SkeletonRetention::OneSensitive
        } else {
            SkeletonRetention::OneMemory
        },
        memory,
        sensitive,
        excluded_sections: if include_sensitive {
            Vec::new()
        } else {
            vec![ExcludedSection::Sensitive]
        },
        personality: PersonalityExport {
            profile: ProfileExport {
                name: None,
                form_of_address: None,
                style: None,
                values: Vec::new(),
            },
            rules,
        },
        grants,
        connections,
        tasks: Vec::new(),
        adapter: None,
        text_view,
    };
    document.validate().map_err(MemoryAppError::Contract)?;
    Ok(Export::Ready(Box::new(document)))
}
