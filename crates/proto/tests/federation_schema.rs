//! Every One Federation schema vector against the typed wire forms: valid inputs round-trip through serde unchanged, invalid inputs are rejected (OO-3, OO-4, OO-5, OO-15, OO-16, OO-17).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::unnecessary_wraps,
    reason = "T-38"
)]

#[allow(dead_code, reason = "T-38")]
#[path = "federation_support/mod.rs"]
mod support;

use one_proto::federation::message::Contact;
use one_proto::federation::wire::HandleCompact;
use one_proto::federation::{
    AgentExtension, Body, Envelope, HandleClaims, Message, Note, ProtectedHeader, Task,
};
use one_proto::ontology::validate::ContractViolation;
use support::check_schema_vectors;

fn none<T>(_: &T) -> Result<(), ContractViolation> {
    Ok(())
}

#[test]
fn oo_4_message_schema_vectors() {
    let n = check_schema_vectors::<Message, _>(
        "open/federation/vectors/schema/message.json",
        Message::validate,
    );
    assert_eq!((n.valid, n.invalid), (6, 12));
}

#[test]
fn oo_16_envelope_schema_vectors() {
    let n = check_schema_vectors::<Envelope, _>(
        "open/federation/vectors/schema/envelope.json",
        Envelope::validate,
    );
    assert_eq!((n.valid, n.invalid), (5, 30));
}

#[test]
fn oo_15_body_schema_vectors() {
    let n =
        check_schema_vectors::<Body, _>("open/federation/vectors/schema/body.json", Body::validate);
    assert_eq!((n.valid, n.invalid), (8, 11));
}

#[test]
fn oo_17_note_schema_vectors() {
    let n = check_schema_vectors::<Note, _>("open/federation/vectors/schema/note.json", none);
    assert_eq!((n.valid, n.invalid), (1, 7));
}

#[test]
fn oo_31_contact_schema_vectors() {
    let n = check_schema_vectors::<Contact, _>(
        "open/federation/vectors/schema/contact.json",
        Contact::validate,
    );
    assert_eq!((n.valid, n.invalid), (3, 5));
}

#[test]
fn oo_5_handle_schema_vectors() {
    let n = check_schema_vectors::<HandleCompact, _>(
        "open/federation/vectors/schema/handle.json",
        none,
    );
    assert_eq!((n.valid, n.invalid), (1, 2));
}

#[test]
fn oo_5_handle_claims_schema_vectors() {
    let n = check_schema_vectors::<HandleClaims, _>(
        "open/federation/vectors/schema/handle-claims.json",
        none,
    );
    assert_eq!((n.valid, n.invalid), (1, 6));
}

#[test]
fn oo_5_handle_protected_header_schema_vectors() {
    let n = check_schema_vectors::<ProtectedHeader, _>(
        "open/federation/vectors/schema/handle-protected-header.json",
        none,
    );
    assert_eq!((n.valid, n.invalid), (1, 3));
}

#[test]
fn oo_4_task_schema_vectors() {
    let n =
        check_schema_vectors::<Task, _>("open/federation/vectors/schema/task.json", Task::validate);
    assert_eq!((n.valid, n.invalid), (7, 8));
}

#[test]
fn oo_4_agent_extension_schema_vectors() {
    let n = check_schema_vectors::<AgentExtension, _>(
        "open/federation/vectors/schema/agent-extension.json",
        AgentExtension::validate,
    );
    assert_eq!((n.valid, n.invalid), (1, 4));
}
