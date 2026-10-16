//! One-to-One typed messages, offer versions and expiry (OO-15, OO-16).

pub mod handle;
pub mod message;
pub mod relay;
pub mod rules;
pub mod task;
pub mod wire;

pub use handle::{
    HandleClaims, OpenedHandle, ProtectedHeader, ReplyBinding, SpentEntry, SpentHandles,
    VerifiedHandle, verify_handle,
};
pub use message::{Body, Contact, Envelope, InReplyTo, Message, Note, NoteDisplay, TypedContent};
pub use rules::{
    Chain, ChainEntry, Incoming, KIND_TABLE, ReceiptTime, Selection, SenderRole, WorkOperation,
    WorkResult, WorkState, check_chain, check_expiry_window, check_timely, expire_unanswered,
    select_operation,
};
pub use task::{AgentExtension, Task, TaskState};
pub use wire::{Did, Digest, EXTENSION_URI, Kind, Party, Refusal, SchemaVersion, Uuid7};
