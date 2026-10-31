//! Receiver rules of a typed message: the (kind, sender role, Work state) selector of exactly one Work operation, offer version and reply rules of the chain, and expiry judged on Relay enqueue or receiver receipt time, at most 7 days and inclusive at the expiry instant (OO-15, OO-16, OO-20).

use super::message::{Body, Message, Role};
use super::task::TaskState;
use super::wire::{Digest, Kind, Refusal, Uuid7};
use crate::capability::CapabilityRef;
use crate::ontology::Instant;

/// The sender's role in the Work commitment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SenderRole {
    /// The party that asks (opened the chain).
    Creditor,
    /// The party asked to promise.
    DebtorCandidate,
}

impl From<Role> for SenderRole {
    fn from(role: Role) -> Self {
        match role {
            Role::RoleUser => Self::Creditor,
            Role::RoleAgent => Self::DebtorCandidate,
        }
    }
}

/// The Work state of the chain as the selector sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkState {
    /// No Work commitment yet.
    None,
    /// Requested.
    Requested,
    /// Countered by the debtor candidate.
    Countered,
    /// An information wait addressed to the recipient is open.
    InformationWaitOpen,
    /// Promised.
    Promised,
    /// Declined.
    Declined,
    /// Expired.
    Expired,
}

/// A Work operation a message selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkOperation {
    /// `request`.
    Request,
    /// `counter`.
    Counter,
    /// `promise`.
    Promise,
    /// `accept-counter`.
    AcceptCounter,
    /// `decline`.
    Decline,
    /// Open an Epistemic information wait.
    OpenInformationWait,
    /// A claim satisfying the information wait.
    Claim,
    /// `expire`, written by the Work service party.
    Expire,
}

/// The Work state after the operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkResult {
    /// No Work commitment.
    None,
    /// Requested.
    Requested,
    /// Countered.
    Countered,
    /// Promised.
    Promised,
    /// Declined.
    Declined,
    /// Expired.
    Expired,
    /// The information wait is satisfied.
    InformationWaitSatisfied,
}

/// The role a selector row accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RoleSelector {
    /// Only this role.
    Is(SenderRole),
    /// Any role.
    Any,
    /// The addressee of the open query; bound by the handle.
    QueryAddressee,
}

/// The Work state a selector row accepts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum StateSelector {
    /// Only this state.
    Is(WorkState),
    /// Any open state: none, requested or countered.
    AnyOpen,
}

/// The result a selector row yields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResultSelector {
    /// This result.
    Is(WorkResult),
    /// The state is unchanged.
    Unchanged,
}

/// A row of the kind table (`a2a-mapping.toml` `[[kind]]`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct KindRow {
    /// The message kind.
    pub kind: Kind,
    /// The sender role.
    pub sender_role: RoleSelector,
    /// The Work state.
    pub work_state: StateSelector,
    /// The selected operation.
    pub work_operation: WorkOperation,
    /// The result.
    pub work_result: ResultSelector,
    /// The task state after it; `None` keeps the previous state.
    pub task_state_after: Option<TaskState>,
}

/// The kind table (OO-15); the creditor's rejection of a counter has no row.
pub const KIND_TABLE: &[KindRow] = &[
    KindRow {
        kind: Kind::Offer,
        sender_role: RoleSelector::Is(SenderRole::Creditor),
        work_state: StateSelector::Is(WorkState::None),
        work_operation: WorkOperation::Request,
        work_result: ResultSelector::Is(WorkResult::Requested),
        task_state_after: Some(TaskState::InputRequired),
    },
    KindRow {
        kind: Kind::CounterOffer,
        sender_role: RoleSelector::Is(SenderRole::DebtorCandidate),
        work_state: StateSelector::Is(WorkState::Requested),
        work_operation: WorkOperation::Counter,
        work_result: ResultSelector::Is(WorkResult::Countered),
        task_state_after: Some(TaskState::InputRequired),
    },
    KindRow {
        kind: Kind::CounterOffer,
        sender_role: RoleSelector::Is(SenderRole::Creditor),
        work_state: StateSelector::Is(WorkState::Countered),
        work_operation: WorkOperation::Counter,
        work_result: ResultSelector::Is(WorkResult::Requested),
        task_state_after: Some(TaskState::InputRequired),
    },
    KindRow {
        kind: Kind::Commitment,
        sender_role: RoleSelector::Is(SenderRole::DebtorCandidate),
        work_state: StateSelector::Is(WorkState::Requested),
        work_operation: WorkOperation::Promise,
        work_result: ResultSelector::Is(WorkResult::Promised),
        task_state_after: Some(TaskState::Completed),
    },
    KindRow {
        kind: Kind::Commitment,
        sender_role: RoleSelector::Is(SenderRole::Creditor),
        work_state: StateSelector::Is(WorkState::Countered),
        work_operation: WorkOperation::AcceptCounter,
        work_result: ResultSelector::Is(WorkResult::Promised),
        task_state_after: Some(TaskState::Completed),
    },
    KindRow {
        kind: Kind::Rejection,
        sender_role: RoleSelector::Is(SenderRole::DebtorCandidate),
        work_state: StateSelector::Is(WorkState::Requested),
        work_operation: WorkOperation::Decline,
        work_result: ResultSelector::Is(WorkResult::Declined),
        task_state_after: Some(TaskState::Rejected),
    },
    KindRow {
        kind: Kind::Query,
        sender_role: RoleSelector::Any,
        work_state: StateSelector::AnyOpen,
        work_operation: WorkOperation::OpenInformationWait,
        work_result: ResultSelector::Unchanged,
        task_state_after: Some(TaskState::InputRequired),
    },
    KindRow {
        kind: Kind::Answer,
        sender_role: RoleSelector::QueryAddressee,
        work_state: StateSelector::Is(WorkState::InformationWaitOpen),
        work_operation: WorkOperation::Claim,
        work_result: ResultSelector::Is(WorkResult::InformationWaitSatisfied),
        task_state_after: None,
    },
];

/// The Work operation a message selects.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Selection {
    /// The operation.
    pub work_operation: WorkOperation,
    /// The Work state after it.
    pub work_result: WorkResult,
    /// The task state after it; `None` keeps the previous state.
    pub task_state_after: Option<TaskState>,
}

impl KindRow {
    fn matches(self, kind: Kind, role: SenderRole, state: WorkState) -> bool {
        let role_ok = match self.sender_role {
            RoleSelector::Is(r) => r == role,
            RoleSelector::Any | RoleSelector::QueryAddressee => true,
        };
        let state_ok = match self.work_state {
            StateSelector::Is(s) => s == state,
            StateSelector::AnyOpen => {
                matches!(
                    state,
                    WorkState::None | WorkState::Requested | WorkState::Countered
                )
            }
        };
        self.kind == kind && role_ok && state_ok
    }
}

const fn unchanged(state: WorkState) -> Option<WorkResult> {
    match state {
        WorkState::None => Some(WorkResult::None),
        WorkState::Requested => Some(WorkResult::Requested),
        WorkState::Countered => Some(WorkResult::Countered),
        WorkState::Promised => Some(WorkResult::Promised),
        WorkState::Declined => Some(WorkResult::Declined),
        WorkState::Expired => Some(WorkResult::Expired),
        WorkState::InformationWaitOpen => None,
    }
}

/// Selects the single Work operation for a message; no match writes nothing and is refused (OO-15).
///
/// # Errors
/// [`Refusal::OfferExpired`] on an expired chain, [`Refusal::OperationNotPermitted`] when no row or more than one row matches.
pub fn select_operation(
    kind: Kind,
    role: SenderRole,
    state: WorkState,
) -> Result<Selection, Refusal> {
    if state == WorkState::Expired {
        return Err(Refusal::OfferExpired);
    }
    let mut rows = KIND_TABLE.iter().filter(|r| r.matches(kind, role, state));
    let (Some(row), None) = (rows.next(), rows.next()) else {
        return Err(Refusal::OperationNotPermitted);
    };
    let work_result = match row.work_result {
        ResultSelector::Is(result) => result,
        ResultSelector::Unchanged => unchanged(state).ok_or(Refusal::OperationNotPermitted)?,
    };
    Ok(Selection {
        work_operation: row.work_operation,
        work_result,
        task_state_after: row.task_state_after,
    })
}

/// A message already in the chain.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChainEntry {
    /// The kind.
    pub kind: Kind,
    /// The offer version.
    pub offer_version: u32,
    /// Its digest.
    pub digest: Digest,
    /// The capability its body names.
    pub capability: Option<CapabilityRef>,
}

/// The chain a message joins.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Chain<'a> {
    /// The chain's correlation identifier; `None` before the first message.
    pub correlation_id: Option<&'a Uuid7>,
    /// The messages so far, oldest first.
    pub entries: &'a [ChainEntry],
}

/// The reply reference of an incoming message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReplyRef<'a> {
    /// The answered version.
    pub offer_version: u32,
    /// The answered digest.
    pub digest: &'a Digest,
}

/// The chain-relevant members of an incoming message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Incoming<'a> {
    /// The envelope kind.
    pub kind: Kind,
    /// The body kind.
    pub body_kind: Kind,
    /// The envelope offer version.
    pub offer_version: u32,
    /// The A2A `contextId`.
    pub context_id: &'a Uuid7,
    /// The envelope correlation identifier.
    pub correlation_id: &'a Uuid7,
    /// The reply reference.
    pub in_reply_to: Option<ReplyRef<'a>>,
    /// The capability its body names.
    pub capability: Option<&'a CapabilityRef>,
}

impl<'a> Incoming<'a> {
    /// The chain-relevant members of a message.
    #[must_use]
    pub fn of(message: &'a Message) -> Self {
        let envelope = message.envelope();
        let body: &Body = message.body();
        Self {
            kind: envelope.kind,
            body_kind: body.kind(),
            offer_version: envelope.offer_version,
            context_id: &message.context_id,
            correlation_id: &envelope.correlation_id,
            in_reply_to: envelope.in_reply_to.as_ref().map(|r| ReplyRef {
                offer_version: r.offer_version,
                digest: &r.digest,
            }),
            capability: body.capability(),
        }
    }
}

fn answered<'c>(chain: &'c [ChainEntry], kinds: &[Kind]) -> Result<&'c ChainEntry, Refusal> {
    chain
        .iter()
        .rev()
        .find(|e| kinds.contains(&e.kind))
        .ok_or(Refusal::OperationNotPermitted)
}

fn reply<'m>(next: &Incoming<'m>) -> Result<ReplyRef<'m>, Refusal> {
    next.in_reply_to.ok_or(Refusal::SchemaInvalid)
}

/// Checks a message against its chain: correlation, body kind, offer version monotonicity, reply version and digest, and an unchanged capability (OO-15, OO-16).
///
/// # Errors
/// Returns the refusal for the first broken rule.
pub fn check_chain(chain: &Chain<'_>, next: &Incoming<'_>) -> Result<(), Refusal> {
    if next.context_id != next.correlation_id
        || chain
            .correlation_id
            .is_some_and(|c| c != next.correlation_id)
    {
        return Err(Refusal::CorrelationMismatch);
    }
    if next.body_kind != next.kind {
        return Err(Refusal::KindMismatch);
    }
    let entries = chain.entries;
    let current = entries.iter().map(|e| e.offer_version).max().unwrap_or(0);
    match next.kind {
        Kind::Offer => {
            if !entries.is_empty() {
                return Err(Refusal::OperationNotPermitted);
            }
            if next.offer_version != 1 {
                return Err(Refusal::VersionNotMonotonic);
            }
        }
        Kind::CounterOffer => {
            let open = answered(entries, &[Kind::Offer, Kind::CounterOffer])?;
            let r = reply(next)?;
            if Some(next.offer_version) != open.offer_version.checked_add(1) {
                return Err(Refusal::VersionNotMonotonic);
            }
            if r.offer_version != open.offer_version {
                return Err(Refusal::ReplyVersionMismatch);
            }
            if r.digest != &open.digest {
                return Err(Refusal::DigestMismatch);
            }
            if next.capability != open.capability.as_ref() {
                return Err(Refusal::KindMismatch);
            }
        }
        Kind::Commitment | Kind::Rejection => {
            let open = answered(entries, &[Kind::Offer, Kind::CounterOffer])?;
            let r = reply(next)?;
            if r.offer_version != open.offer_version || next.offer_version != open.offer_version {
                return Err(Refusal::ReplyVersionMismatch);
            }
            if r.digest != &open.digest {
                return Err(Refusal::DigestMismatch);
            }
        }
        Kind::Query => {
            if next.offer_version != current {
                return Err(Refusal::VersionNotMonotonic);
            }
        }
        Kind::Answer => {
            let query = answered(entries, &[Kind::Query])?;
            let r = reply(next)?;
            if r.offer_version != query.offer_version || next.offer_version != query.offer_version {
                return Err(Refusal::ReplyVersionMismatch);
            }
            if r.digest != &query.digest {
                return Err(Refusal::DigestMismatch);
            }
        }
    }
    Ok(())
}

/// The longest a message stays answerable: 7 days (OO-16).
pub const MAX_MESSAGE_LIFETIME_SECONDS: i64 = 604_800;

/// Checks that the expiry is after the send time and at most 7 days after it (OO-16).
///
/// # Errors
/// [`Refusal::ExpiryInvalid`] otherwise.
pub fn check_expiry_window(sent_at: &Instant, expires_at: &Instant) -> Result<(), Refusal> {
    let lifetime = expires_at.unix_secs().checked_sub(sent_at.unix_secs());
    let longest_ok = lifetime.is_some_and(|s| {
        s < MAX_MESSAGE_LIFETIME_SECONDS
            || (s == MAX_MESSAGE_LIFETIME_SECONDS
                && expires_at.subsec_nanos() <= sent_at.subsec_nanos())
    });
    if expires_at > sent_at && longest_ok {
        Ok(())
    } else {
        Err(Refusal::ExpiryInvalid)
    }
}

/// The time a reply's timeliness is judged on; the sender's `sentAt` claim is never used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReceiptTime<'a> {
    /// The Relay mailbox enqueue time.
    RelayEnqueued(&'a Instant),
    /// The receiver's receipt time for direct A2A with an organisation agent.
    DirectReceipt(&'a Instant),
}

impl ReceiptTime<'_> {
    /// The instant.
    #[must_use]
    pub const fn instant(&self) -> &Instant {
        match self {
            Self::RelayEnqueued(t) | Self::DirectReceipt(t) => t,
        }
    }
}

/// Checks that a reply arrived no later than the answered message's expiry; arriving exactly at it is on time (OO-16).
///
/// # Errors
/// [`Refusal::OfferExpired`] when it arrived later.
pub fn check_timely(
    answered_expires_at: &Instant,
    receipt: ReceiptTime<'_>,
) -> Result<(), Refusal> {
    if receipt.instant() <= answered_expires_at {
        Ok(())
    } else {
        Err(Refusal::OfferExpired)
    }
}

/// Who writes a Work operation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum WorkAuthor {
    /// The Work service party.
    WorkService,
}

/// The record of an offer or counter-offer that expired unanswered: neither acceptance nor rejection (OO-16, OO-20).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Expiry {
    /// `expire`.
    pub work_operation: WorkOperation,
    /// The Work service party.
    pub work_author: WorkAuthor,
    /// `expired`.
    pub work_result: WorkResult,
    /// Never acceptance.
    pub counts_as_acceptance: bool,
    /// Never rejection.
    pub counts_as_rejection: bool,
    /// `TASK_STATE_CANCELED`.
    pub task_state: TaskState,
}

/// The expiry record once `now` has passed the expiry without a reply; `None` while the message is still answerable.
#[must_use]
pub fn expire_unanswered(expires_at: &Instant, now: &Instant) -> Option<Expiry> {
    (now > expires_at).then_some(Expiry {
        work_operation: WorkOperation::Expire,
        work_author: WorkAuthor::WorkService,
        work_result: WorkResult::Expired,
        counts_as_acceptance: false,
        counts_as_rejection: false,
        task_state: TaskState::Canceled,
    })
}
