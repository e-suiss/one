//! The evaluation request of L1-ADP-5 to L1-ADP-8: the `AuthZEN` carriers mirror the intent's action and first resource, and every Access member travels in `context` with binaries in unpadded base64url (L1-ADP-6); the intent digest is never sent, Access computes it (L1-ADP-8).

use std::collections::BTreeMap;

use access_kernel::combinator::{Capacity, Mode};
use access_kernel::intent::{ContextRefs, IntentEnvelope, ParamValue};
use access_kernel::json::b64url_encode;
use access_kernel::meta::ExerciseBasis;
use access_kernel::model::{EqValue, Id, PurposeRef, ResourceRef, Window};
use serde_json::{Map, Value, json};
use suiss_crypto::digest::Digest;

/// The evaluation endpoint path (L1-ADP-1).
pub const EVALUATION_PATH: &str = "/access/v1/evaluation";

/// The shortest nonce Access takes (L1-ADP-7).
pub const NONCE_MIN: usize = 16;

/// The longest nonce Access takes (L1-ADP-7).
pub const NONCE_MAX: usize = 64;

/// Why a request was not built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdpError {
    /// The nonce is not 16 to 64 bytes.
    Nonce,
    /// The intent has no resource.
    NoResource,
    /// A `continue` request has no Exercise, or another mode has one.
    Exercise,
}

/// One evaluation request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation<'a> {
    /// The `DomainID` addressed.
    pub domain: Digest,
    /// The mode.
    pub mode: Mode,
    /// The request nonce, 16 to 64 bytes, never reused for another intent.
    pub nonce: &'a [u8],
    /// The Actor Intent Statement, exactly as signed; `None` is an anonymous actor.
    pub ais: Option<&'a [u8]>,
    /// The declared basis.
    pub basis: ExerciseBasis,
    /// The declared capacity.
    pub capacity: Capacity,
    /// The intent.
    pub intent: &'a IntentEnvelope,
    /// The Exercise continued, for `continue`.
    pub exercise: Option<Digest>,
}

/// The wire word of a mode.
#[must_use]
pub const fn mode_word(mode: Mode) -> &'static str {
    match mode {
        Mode::Commit => "commit",
        Mode::Continue => "continue",
        Mode::Check => "check",
    }
}

fn b64(bytes: &[u8]) -> Value {
    Value::String(b64url_encode(bytes))
}

fn id(id: &Id) -> Value {
    b64(&id.0)
}

fn digest(d: &Digest) -> Value {
    b64(&d.0)
}

fn window(w: &Window) -> Value {
    json!({ "from": w.from, "until": w.until })
}

fn resource(r: &ResourceRef) -> Value {
    json!({ "namespace": r.namespace, "path": r.path, "incarnation": r.incarnation })
}

fn purpose(p: &PurposeRef) -> Value {
    match p {
        PurposeRef::Code(c) => json!({ "code": c }),
        PurposeRef::Work(d) => json!({ "work": digest(d) }),
        PurposeRef::Aim(d) => json!({ "aim": digest(d) }),
    }
}

fn eq(v: &EqValue) -> Value {
    match v {
        EqValue::Text(t) => json!(t),
        EqValue::Bytes(b) => json!({ "bytes": b64(b) }),
        EqValue::Int(n) => json!(n),
        EqValue::Bool(b) => json!(b),
    }
}

fn param(v: &ParamValue) -> Value {
    match v {
        ParamValue::Enum(e) => json!({ "enum": e }),
        ParamValue::Eq(e) => json!({ "eq": eq(e) }),
        ParamValue::Amount { value, unit } => {
            json!({ "amount": { "value": value, "unit": unit } })
        }
        ParamValue::Count(n) => json!({ "count": n }),
        ParamValue::Interval(w) => json!({ "interval": window(w) }),
        ParamValue::Resource(r) => json!({ "resource": resource(r) }),
        ParamValue::Subject(s) => json!({ "subject": id(s) }),
        ParamValue::Purpose(p) => json!({ "purpose": purpose(p) }),
        ParamValue::Flag(b) => json!({ "flag": b }),
    }
}

fn refs(c: &ContextRefs) -> Value {
    let mut out = Map::new();
    for (name, value) in [
        ("work", &c.work),
        ("commitment", &c.commitment),
        ("step", &c.step),
        ("upstream_exercise", &c.upstream_exercise),
    ] {
        if let Some(d) = value {
            out.insert(name.to_owned(), digest(d));
        }
    }
    Value::Object(out)
}

/// The intent object of L1-ADP-8; empty optional members are left out.
#[must_use]
pub fn intent_json(intent: &IntentEnvelope) -> Value {
    let mut out = Map::new();
    let a = &intent.action;
    out.insert(
        "action".to_owned(),
        json!({ "namespace": a.namespace, "name": a.name, "major": a.major, "schema": digest(&a.schema) }),
    );
    out.insert(
        "resources".to_owned(),
        Value::Array(intent.resources.iter().map(resource).collect()),
    );
    if !intent.params.is_empty() {
        let params: Map<String, Value> = intent
            .params
            .iter()
            .map(|(k, v)| (k.clone(), param(v)))
            .collect();
        out.insert("params".to_owned(), Value::Object(params));
    }
    if !intent.opaque.is_empty() {
        let opaque: BTreeMap<&String, Value> =
            intent.opaque.iter().map(|(k, v)| (k, digest(v))).collect();
        out.insert("opaque".to_owned(), json!(opaque));
    }
    if let Some(r) = &intent.recipient {
        out.insert("recipient".to_owned(), id(r));
    }
    if let Some(p) = &intent.purpose {
        out.insert("purpose".to_owned(), purpose(p));
    }
    if intent.context != ContextRefs::default() {
        out.insert("context".to_owned(), refs(&intent.context));
    }
    out.insert("validity".to_owned(), window(&intent.validity));
    Value::Object(out)
}

/// The JSON form of a basis.
#[must_use]
pub fn basis_json(basis: &ExerciseBasis) -> Value {
    match basis {
        ExerciseBasis::Anchor(a) => json!({ "anchor": id(a) }),
        ExerciseBasis::Public(g) => json!({ "public": id(g) }),
        ExerciseBasis::Holding(h) => json!({
            "holding": { "grant": id(&h.grant), "holder": id(&h.holder), "since": h.since }
        }),
    }
}

/// The JSON form of a capacity.
#[must_use]
pub fn capacity_json(capacity: &Capacity) -> Value {
    match capacity {
        Capacity::Own => json!("own"),
        Capacity::For(p) => json!({ "for": id(p) }),
    }
}

impl Evaluation<'_> {
    /// The request body.
    ///
    /// # Errors
    /// [`AdpError`] for a nonce outside 16 to 64 bytes, an intent without a resource, or an Exercise that does not match the mode.
    pub fn to_json(&self) -> Result<Value, AdpError> {
        if !(NONCE_MIN..=NONCE_MAX).contains(&self.nonce.len()) {
            return Err(AdpError::Nonce);
        }
        let first = self.intent.resources.first().ok_or(AdpError::NoResource)?;
        if (self.mode == Mode::Continue) != self.exercise.is_some() {
            return Err(AdpError::Exercise);
        }
        let mut context = Map::new();
        context.insert("domain".to_owned(), digest(&self.domain));
        context.insert("mode".to_owned(), json!(mode_word(self.mode)));
        context.insert("nonce".to_owned(), b64(self.nonce));
        if let Some(ais) = self.ais {
            context.insert("ais".to_owned(), b64(ais));
        }
        context.insert("basis".to_owned(), basis_json(&self.basis));
        context.insert("capacity".to_owned(), capacity_json(&self.capacity));
        context.insert("intent".to_owned(), intent_json(self.intent));
        if let Some(e) = &self.exercise {
            context.insert("exercise".to_owned(), digest(e));
        }
        Ok(json!({
            "subject": { "type": "access_actor", "id": "-" },
            "action": { "name": self.intent.action.name },
            "resource": { "type": first.namespace, "id": first.path.join("/") },
            "context": Value::Object(context),
        }))
    }
}
