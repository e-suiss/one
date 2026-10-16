//! Offline work against a server-authoritative memory: the server version replaces the device cache, offline remembers and corrections queue as episodes and run against the server head on reconnect, devices never push merged records or set `recorded_at`, and device-only classes never leave the device (M-36, M-37).

use alloc::vec::Vec;
use core::num::NonZeroU32;

use serde::{Deserialize, Serialize};

use super::fields::{EpistemicState, LiveStatus};
use crate::data_class::{DataClass, SensitiveClass};
use crate::id::MemoryRecordId;

/// A record at a version.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRef {
    /// The record.
    pub id: MemoryRecordId,
    /// Its version.
    pub version: NonZeroU32,
}

/// A device's cached copy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CachedVersion {
    /// The record.
    pub id: MemoryRecordId,
    /// Its version.
    pub version: NonZeroU32,
    /// Changed on the device since the last sync.
    #[serde(default)]
    pub locally_modified: bool,
}

/// Resolves a cache conflict: the server version always wins and replaces the cache.
#[must_use]
pub const fn resolve_cache(server: VersionRef, _cache: CachedVersion) -> VersionRef {
    server
}

/// The kind of an offline entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueuedKind {
    /// "Remember this".
    ExplicitRemember,
    /// A conversation turn.
    ConversationTurn,
}

/// An entry queued on a device while offline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueuedEntry {
    /// Its kind.
    pub kind: QueuedKind,
    /// Always `true`: the Episode records the device.
    pub queued_on_device: bool,
}

/// Queues an offline utterance as an episode entry; the device never writes a record.
#[must_use]
pub const fn queue_offline(kind: QueuedKind) -> QueuedEntry {
    QueuedEntry {
        kind,
        queued_on_device: true,
    }
}

crate::const_tag!(
    /// `"record"`: the server creates the record.
    ServerCreatesRecord,
    "record"
);
crate::const_tag!(
    /// `"server_time"`: `recorded_at` comes from the server clock.
    ServerTime,
    "server_time"
);
crate::const_tag!(
    /// `"ignored"`: a device-supplied value is dropped.
    Ignored,
    "ignored"
);

/// What the server does with a queued remember on reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RememberOnReconnect {
    /// The server creates the record.
    pub server_creates: ServerCreatesRecord,
    /// With server time.
    pub recorded_at: ServerTime,
    /// `stated`.
    pub epistemic_state: EpistemicState,
    /// `active`.
    pub status: LiveStatus,
    /// The result returns to the device.
    pub reflected_to_device: bool,
}

/// The reconnect effect of a queued explicit remember.
#[must_use]
pub const fn remember_on_reconnect() -> RememberOnReconnect {
    RememberOnReconnect {
        server_creates: ServerCreatesRecord,
        recorded_at: ServerTime,
        epistemic_state: EpistemicState::Stated,
        status: LiveStatus::Active,
        reflected_to_device: true,
    }
}

/// The server write of an offline correction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorrectionWrite {
    /// One past the server head.
    pub version: NonZeroU32,
    /// The corrected record.
    pub supersedes: MemoryRecordId,
}

/// An offline correction replayed on reconnect.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineCorrection {
    /// The new version.
    pub server_writes: CorrectionWrite,
    /// The head it invalidates.
    pub invalidated: VersionRef,
}

/// Replays an offline correction against the server head, whatever version the device saw.
#[must_use]
pub fn replay_correction(_device_saw: VersionRef, server_head: VersionRef) -> OfflineCorrection {
    OfflineCorrection {
        server_writes: CorrectionWrite {
            version: server_head.version.saturating_add(1),
            supersedes: server_head.id,
        },
        invalidated: server_head,
    }
}

/// What a device tries to push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushKind {
    /// A memory record.
    MemoryRecord,
    /// An episode.
    Episode,
}

/// Why a device push was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SyncError {
    /// The server is authoritative; devices never merge records.
    ServerAuthoritative,
}

/// An accepted device push.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcceptedPush {
    /// `recorded_at` is the server's.
    pub recorded_at: ServerTime,
    /// The device's value.
    pub device_value: Ignored,
}

/// Accepts episode pushes with server time and refuses record pushes.
///
/// # Errors
/// [`SyncError::ServerAuthoritative`] for a memory record.
pub const fn accept_push(kind: PushKind) -> Result<AcceptedPush, SyncError> {
    match kind {
        PushKind::MemoryRecord => Err(SyncError::ServerAuthoritative),
        PushKind::Episode => Ok(AcceptedPush {
            recorded_at: ServerTime,
            device_value: Ignored,
        }),
    }
}

/// Where a record may go.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CloudPlacement {
    /// Uploaded to the cloud.
    pub uploaded: bool,
    /// Included in cloud backup.
    pub cloud_backup: bool,
}

/// A record in a device-only class never syncs or backs up to the cloud (M-37).
#[must_use]
pub fn cloud_placement(data_class: &DataClass, device_only: &[SensitiveClass]) -> CloudPlacement {
    let local = data_class
        .sensitive()
        .iter()
        .any(|c| device_only.contains(c));
    CloudPlacement {
        uploaded: !local,
        cloud_backup: !local,
    }
}

crate::const_tag!(
    /// `"sqlite"`.
    Sqlite,
    "sqlite"
);
crate::const_tag!(
    /// `"device_key"`.
    DeviceKey,
    "device_key"
);

/// The device cache: an encrypted, non-canonical subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCachePolicy {
    /// Store.
    pub store: Sqlite,
    /// Encryption key.
    pub encrypted_with: DeviceKey,
    /// Never canonical.
    pub canonical: bool,
}

/// The device cache policy.
pub const DEVICE_CACHE: DeviceCachePolicy = DeviceCachePolicy {
    store: Sqlite,
    encrypted_with: DeviceKey,
    canonical: false,
};

/// The device queue for one offline utterance.
#[must_use]
pub fn device_queue(kind: QueuedKind) -> Vec<QueuedEntry> {
    alloc::vec![queue_offline(kind)]
}
