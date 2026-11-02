//! The memory component's ports (T-27 (2)): the vault that keeps rows sealed and versioned, the policy gate of the shared restriction engine, the hybrid search that runs in the TEE and the Access projections an export needs.

use std::future::Future;

use one_proto::data_class::RetentionClass;
use one_proto::memory::export::AccessProjection;
use one_proto::memory::record::LiveMemoryRecord;
use one_proto::ontology::time::Instant;
use one_proto::{EpisodeId, MemoryRecordId};

use crate::domain::retrieval::Query;

/// One memory row as the vault opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct Row {
    /// The row's record identifier.
    pub id: MemoryRecordId,
    /// Its version in the chain.
    pub version: u32,
    /// The row it supersedes.
    pub supersedes: Option<MemoryRecordId>,
    /// Whether it is the head of its chain.
    pub head: bool,
    /// Its retention class.
    pub class: RetentionClass,
    /// The opened body, or `None` once forgotten.
    pub body: Option<Vec<u8>>,
    /// Transaction time.
    pub recorded_at: Instant,
    /// When it was forgotten.
    pub deleted_at: Option<Instant>,
}

impl core::fmt::Debug for Row {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Row")
            .field("id", &self.id)
            .field("version", &self.version)
            .field("head", &self.head)
            .finish_non_exhaustive()
    }
}

/// One episode as the vault opens it.
#[derive(Clone, PartialEq, Eq)]
pub struct EpisodeRow {
    /// The episode.
    pub id: EpisodeId,
    /// Its retention class.
    pub class: RetentionClass,
    /// The opened body, or `None` once forgotten.
    pub body: Option<Vec<u8>>,
    /// Transaction time.
    pub recorded_at: Instant,
    /// When it was forgotten.
    pub deleted_at: Option<Instant>,
}

impl core::fmt::Debug for EpisodeRow {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("EpisodeRow")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// What permanent forgetting did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Forgot {
    /// The keys are destroyed.
    Done,
    /// A legal hold covers the class; nothing changed.
    Held,
    /// No such row.
    Missing,
}

/// Why the vault failed.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    /// The store failed.
    #[error(transparent)]
    Store(#[from] one_store::StoreError),
    /// A key could not be made, wrapped or unwrapped.
    #[error("key layer")]
    Key,
    /// A row did not open under its key.
    #[error("sealed row did not open")]
    Open,
    /// The row named is not the live head of its chain.
    #[error("not the head of its chain")]
    NotHead,
}

/// Sealed, versioned memory storage; every call is part of the caller's transaction.
pub trait Vault {
    /// Writes an episode.
    fn put_episode(
        &mut self,
        id: EpisodeId,
        class: RetentionClass,
        body: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>>;

    /// Whether every episode in `ids` exists and is not forgotten.
    fn episodes_exist(
        &mut self,
        ids: &[EpisodeId],
    ) -> impl Future<Output = Result<bool, VaultError>>;

    /// Writes version 1 of a new chain under a new record key.
    fn put_first(
        &mut self,
        id: MemoryRecordId,
        class: RetentionClass,
        body: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>>;

    /// Writes the next version after the head `supersedes`, under the chain's record key.
    fn put_next(
        &mut self,
        id: MemoryRecordId,
        supersedes: MemoryRecordId,
        body: &[u8],
    ) -> impl Future<Output = Result<(), VaultError>>;

    /// Every memory row, oldest first.
    fn rows(&mut self) -> impl Future<Output = Result<Vec<Row>, VaultError>>;

    /// Every episode, oldest first.
    fn episodes(&mut self) -> impl Future<Output = Result<Vec<EpisodeRow>, VaultError>>;

    /// Destroys the record key of `id`'s chain and of every row derived from it.
    fn forget(&mut self, id: MemoryRecordId) -> impl Future<Output = Result<Forgot, VaultError>>;

    /// Destroys the record key of episode `id`.
    fn forget_episode(&mut self, id: EpisodeId)
    -> impl Future<Output = Result<Forgot, VaultError>>;
}

/// The policy gate (M-30 step 3, Access E43): the shared restriction engine decides whether a record may serve this query.
pub trait Policy {
    /// Whether `record` may serve `query`.
    fn allows(&self, record: &LiveMemoryRecord, query: &Query) -> bool;
}

/// One search hit.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Hit {
    /// The record.
    pub id: MemoryRecordId,
    /// Lexical score in `0..=1`.
    pub lexical: f64,
    /// Dense similarity in `0..=1`.
    pub similarity: f64,
}

/// Why the search failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum SearchError {
    /// The index is not loaded or the TEE is not attested.
    #[error("search unavailable")]
    Unavailable,
}

/// Hybrid search inside the TEE over the eligible records only (M-30 step 5, OP-5).
pub trait Search {
    /// Lexical and dense scores of `eligible` for `query`.
    fn search(
        &mut self,
        query: &Query,
        eligible: &[MemoryRecordId],
    ) -> impl Future<Output = Result<Vec<Hit>, SearchError>>;
}

/// The Access E65 projections an export carries; `None` while Access cannot be read, and the export waits.
pub trait Projections {
    /// The grants and the connections, read at `at`.
    fn read(
        &mut self,
        at: Instant,
    ) -> impl Future<Output = Option<(AccessProjection, AccessProjection)>>;
}
