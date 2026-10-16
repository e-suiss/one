//! Response processing: identity, nonce, replay, version, expiry, action and surface ceiling checks, and the mapping of an accepted approval to the Approval Act Statement fields One supplies (X-16, X-19, X-21, X-22, X-30, C-26, A-29, A-30, AT-12).

use one_proto::ontology::OpaqueId;
use serde::Serialize;

use crate::budget::ProjectionOutcome;
use crate::common::Timestamp;
use crate::interaction::Interaction;
use crate::kind::Effect;
use crate::projection::approval_within_ceiling;
use crate::response::{InteractionResponse, Presence};
use one_proto::interaction_types::SurfaceClass;

/// The result of one response.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseOutcome {
    /// Accepted; the first valid answer.
    Accepted,
    /// The same signed payload again; the first result is returned.
    ReplaySameResult,
    /// Another payload with an already answered nonce.
    RejectedAlreadyAnswered,
    /// The nonce is not the Interaction's answer nonce.
    RejectedNonceMismatch,
    /// The Interaction expired; silence is not approval.
    RejectedExpired,
    /// The action is not in the Interaction's actions.
    RejectedUnknownAction,
    /// The device signature did not verify.
    RejectedBadSignature,
    /// The answer is for an older version.
    RejectedStaleVersion,
    /// The answer is for a version that does not exist.
    RejectedUnknownVersion,
    /// The answer is for another Interaction.
    RejectedWrongInteraction,
    /// The responder is not the owner.
    RejectedForeignResponder,
    /// An approval below the surface ceiling or the required evidence; the request waits.
    NotAContribution,
}

/// The fixed order of the response checks; the first failing check decides (`projection/approval-act-statement.toml`).
pub const CHECK_ORDER: [&str; 10] = [
    "signature",
    "interaction",
    "owner",
    "nonce",
    "replay",
    "action",
    "stop",
    "version",
    "expiry",
    "ceiling_and_evidence",
];

/// Access request state after a response that is not a contribution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum AccessState {
    /// The request still needs the user's action.
    #[serde(rename = "REQUIRE_ACTION")]
    RequireAction,
}

/// Effect of an accepted stop on the task (X-30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskEffect {
    /// The task moves to stopping.
    Stopping,
}

/// Pending item state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PendingState {
    /// Expired; the work stopped (X-21 (4)).
    Expired,
}

/// Other copies of the Interaction on other surfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OtherCopies {
    /// They close.
    Closed,
}

/// Contribution class of an approval act.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ContributionClass {
    /// Approve.
    Approve,
}

/// Act of the statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Act {
    /// A contribution.
    Contribution,
}

/// Capacity of the approver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum Capacity {
    /// The user's own capacity.
    #[serde(rename = "OWN")]
    Own,
}

/// The Approval Act Statement fields One supplies; Access computes the digests and the rest (`projection/approval-act-statement.toml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ApprovalAct {
    /// `contribution`.
    pub act: Act,
    /// The responder's Instance.
    pub approver: OpaqueId,
    /// `OWN`.
    pub capacity: Capacity,
    /// `approve`.
    pub contribution_class: ContributionClass,
    /// The response time.
    pub issued_at: Timestamp,
    /// The answering surface class.
    pub surface: SurfaceClass,
}

/// What processing one response produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Processed {
    /// Outcome.
    pub outcome: ResponseOutcome,
    /// The accepted action's effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effect: Option<Effect>,
    /// A new approval contribution.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aas: Option<ApprovalAct>,
    /// Other copies.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_copies: Option<OtherCopies>,
    /// Access request state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access: Option<AccessState>,
    /// What the surface shows instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub projection: Option<ProjectionOutcome>,
    /// Task effect.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskEffect>,
    /// Pending item state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pending: Option<PendingState>,
}

impl Processed {
    const fn only(outcome: ResponseOutcome) -> Self {
        Self {
            outcome,
            effect: None,
            aas: None,
            other_copies: None,
            access: None,
            projection: None,
            task: None,
            pending: None,
        }
    }

    fn waits(projection: Option<ProjectionOutcome>) -> Self {
        Self {
            access: Some(AccessState::RequireAction),
            projection,
            ..Self::only(ResponseOutcome::NotAContribution)
        }
    }
}

/// True if the evidence is a deliberate human act strong enough for the Interaction on this class (X-18, X-19).
fn evidence_suffices(i: &Interaction, r: &InteractionResponse) -> bool {
    let e = &r.evidence;
    let gesture = match r.surface_class {
        SurfaceClass::Watch => matches!(e.presence_gesture, Presence::Hold | Presence::TwoStep),
        SurfaceClass::VoiceCar | SurfaceClass::VoiceGlasses => {
            matches!(e.presence_gesture, Presence::Voice | Presence::Tap)
        }
        SurfaceClass::Phone | SurfaceClass::Desktop => e.presence_gesture != Presence::None,
    };
    gesture && e.authentication >= i.min_assurance.authentication
}

/// Processes the responses to one Interaction in arrival order; the first valid answer wins (X-21 (3), X-22).
#[derive(Debug, Clone)]
pub struct ResponseProcessor<'a> {
    interaction: &'a Interaction,
    current_version: u32,
    first: Option<(InteractionResponse, Processed)>,
}

impl<'a> ResponseProcessor<'a> {
    /// A processor for the given Interaction whose latest version is `current_version`.
    #[must_use]
    pub const fn new(interaction: &'a Interaction, current_version: u32) -> Self {
        Self {
            interaction,
            current_version,
            first: None,
        }
    }

    /// The first accepted response and its result.
    #[must_use]
    pub const fn first(&self) -> Option<&(InteractionResponse, Processed)> {
        self.first.as_ref()
    }

    /// Processes one response at `now`. `signature_verified` is the result of verifying the detached `COSE_Sign1` over the deterministic CBOR payload with the device key Access bound to `signature.kid`.
    pub fn process(
        &mut self,
        r: &InteractionResponse,
        now: &Timestamp,
        signature_verified: bool,
    ) -> Processed {
        let result = self.decide(r, now, signature_verified);
        if result.outcome == ResponseOutcome::Accepted && self.first.is_none() {
            self.first = Some((r.clone(), result.clone()));
        }
        result
    }

    fn decide(
        &self,
        r: &InteractionResponse,
        now: &Timestamp,
        signature_verified: bool,
    ) -> Processed {
        let i = self.interaction;
        // X-22, C-26, Access E49 (3)
        if !signature_verified {
            return Processed::only(ResponseOutcome::RejectedBadSignature);
        }
        if r.interaction_id != i.id {
            return Processed::only(ResponseOutcome::RejectedWrongInteraction);
        }
        if r.responder.party != i.owner {
            return Processed::only(ResponseOutcome::RejectedForeignResponder);
        }
        if r.nonce != i.answer_nonce {
            return Processed::only(ResponseOutcome::RejectedNonceMismatch);
        }
        if let Some((first, result)) = &self.first {
            return if first.same_payload(r) {
                Processed {
                    outcome: ResponseOutcome::ReplaySameResult,
                    ..result.clone()
                }
            } else {
                Processed::only(ResponseOutcome::RejectedAlreadyAnswered)
            };
        }
        let Some(action) = i.action(&r.action) else {
            return Processed::only(ResponseOutcome::RejectedUnknownAction);
        };
        // X-30, INV-32
        if action.effect == Effect::Stop {
            return Processed {
                effect: Some(Effect::Stop),
                other_copies: Some(OtherCopies::Closed),
                task: Some(TaskEffect::Stopping),
                ..Processed::only(ResponseOutcome::Accepted)
            };
        }
        if r.interaction_version < self.current_version {
            return Processed::only(ResponseOutcome::RejectedStaleVersion);
        }
        if r.interaction_version > self.current_version {
            return Processed::only(ResponseOutcome::RejectedUnknownVersion);
        }
        // X-21 (4), AT-12
        if *now > i.expires_at || r.responded_at > i.expires_at {
            return Processed {
                pending: Some(PendingState::Expired),
                ..Processed::only(ResponseOutcome::RejectedExpired)
            };
        }
        let mut accepted = Processed {
            effect: Some(action.effect),
            other_copies: Some(OtherCopies::Closed),
            ..Processed::only(ResponseOutcome::Accepted)
        };
        if action.effect == Effect::Approve {
            // X-19, A-28
            if !approval_within_ceiling(i, r.surface_class) {
                return Processed::waits(Some(ProjectionOutcome::Redirect));
            }
            if !evidence_suffices(i, r) {
                return Processed::waits(None);
            }
            // A-29
            accepted.aas = Some(ApprovalAct {
                act: Act::Contribution,
                approver: r.responder.instance.id.clone(),
                capacity: Capacity::Own,
                contribution_class: ContributionClass::Approve,
                issued_at: r.responded_at,
                surface: r.surface_class,
            });
        }
        accepted
    }
}
