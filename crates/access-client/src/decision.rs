//! The decision of L1-ADP-10 as One acts on it: only a 200 whose `decision` is `true`, whose `outcome` is `allow` and which names its Exercise outside `check` mode is an [`Decision::Allow`]; every other status, a contradictory body or one that does not parse is [`Decision::NoAllow`], never an allow (L1-ADP-3, A-2, E-14, SEC-1).

use access_kernel::combinator::Mode;
use access_kernel::json::b64url_decode;
use serde_json::Value;
use suiss_crypto::digest::Digest;

/// What Access decided, typed for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Access allowed the Exercise.
    Allow {
        /// The `ExerciseID`, for `commit` and `continue`; `None` only in `check`.
        exercise: Option<Digest>,
        /// Whether the decision is advisory (`check`): never a promise.
        advisory: bool,
        /// The opaque reference to the decision record.
        basis_ref: Option<String>,
        /// The head the answer was given at.
        consistency_token: Option<String>,
    },
    /// Access denied it; terminal for this nonce.
    Deny {
        /// The blockers Access disclosed, as received.
        blockers: Vec<Value>,
    },
    /// Access needs more before it decides; the same nonce is sent again with the missing proofs (L1-ADP-12).
    RequireAction {
        /// The blockers Access disclosed, as received.
        blockers: Vec<Value>,
        /// The unmet requirements Access disclosed, as received.
        unmet: Vec<Value>,
    },
    /// No decision that allows anything: another status, an unreachable Access or a body that does not hold together.
    NoAllow(NoAllow),
}

/// Why a response is no allow without being a deny.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NoAllow {
    /// A status other than 200, with the RFC 9457 `code` when the body names one.
    Status(u16, Option<String>),
    /// The body is not JSON, or its members contradict each other.
    Malformed,
    /// Access could not be reached.
    Unreachable,
}

impl Decision {
    /// Whether the caller may go on: an allow outside `check` mode.
    #[must_use]
    pub const fn allows(&self) -> bool {
        matches!(
            self,
            Self::Allow {
                exercise: Some(_),
                advisory: false,
                ..
            }
        )
    }
}

fn list(context: &Value, name: &str) -> Vec<Value> {
    context
        .get(name)
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

fn text(context: &Value, name: &str) -> Option<String> {
    context.get(name).and_then(Value::as_str).map(str::to_owned)
}

fn exercise(context: &Value) -> Result<Option<Digest>, NoAllow> {
    match context.get("exercise") {
        None => Ok(None),
        Some(v) => {
            let bytes = v
                .as_str()
                .and_then(|s| b64url_decode(s).ok())
                .ok_or(NoAllow::Malformed)?;
            let hash: [u8; 32] = bytes.try_into().map_err(|_| NoAllow::Malformed)?;
            Ok(Some(Digest(hash)))
        }
    }
}

fn parse(mode: Mode, body: &[u8]) -> Result<Decision, NoAllow> {
    let v: Value = serde_json::from_slice(body).map_err(|_| NoAllow::Malformed)?;
    let decision = v
        .get("decision")
        .and_then(Value::as_bool)
        .ok_or(NoAllow::Malformed)?;
    let context = v.get("context").ok_or(NoAllow::Malformed)?;
    let outcome = context
        .get("outcome")
        .and_then(Value::as_str)
        .ok_or(NoAllow::Malformed)?;
    let advisory = context
        .get("advisory")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if advisory != (mode == Mode::Check) {
        return Err(NoAllow::Malformed);
    }
    match (outcome, decision) {
        ("allow", true) => {
            let exercise = exercise(context)?;
            if (mode == Mode::Check) == exercise.is_some() {
                return Err(NoAllow::Malformed);
            }
            Ok(Decision::Allow {
                exercise,
                advisory,
                basis_ref: text(context, "basis_ref"),
                consistency_token: text(context, "consistency_token"),
            })
        }
        ("deny", false) => Ok(Decision::Deny {
            blockers: list(context, "blockers"),
        }),
        ("require_action", false) => Ok(Decision::RequireAction {
            blockers: list(context, "blockers"),
            unmet: list(context, "unmet"),
        }),
        _ => Err(NoAllow::Malformed),
    }
}

/// The decision for a response with `status` and `body` to a request in `mode`.
#[must_use]
pub fn decide(mode: Mode, status: u16, body: &[u8]) -> Decision {
    if status != 200 {
        let code = serde_json::from_slice::<Value>(body)
            .ok()
            .and_then(|v| v.get("code").and_then(Value::as_str).map(str::to_owned));
        return Decision::NoAllow(NoAllow::Status(status, code));
    }
    parse(mode, body).unwrap_or_else(Decision::NoAllow)
}
