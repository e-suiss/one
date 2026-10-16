//! One Federation behaviour vectors: kind → Work operation selection, offer versions, expiry, notes, handles and the Relay no-content check (OO-5, OO-7, OO-15, OO-16, OO-17, OO-20).

#![allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

#[allow(dead_code, reason = "T-38")]
#[path = "federation_support/mod.rs"]
mod support;

use one_proto::capability::CapabilityRef;
use one_proto::federation::handle::SpentEntry;
use one_proto::federation::message::{NoteLabel, NoteText, note_to_field};
use one_proto::federation::relay::{
    DELIVERY_CLASSES, MAILBOX_ALLOWED_FIELDS, PUSH_ALLOWED_FIELDS, canary_found, first_disallowed,
};
use one_proto::federation::rules::{
    ReplyRef, ResultSelector, RoleSelector, StateSelector, WorkAuthor,
};
use one_proto::federation::wire::LangTag;
use one_proto::federation::{
    Chain, ChainEntry, Digest, HandleClaims, Incoming, KIND_TABLE, Kind, Message, Note,
    OpenedHandle, Party, ProtectedHeader, ReceiptTime, Refusal, ReplyBinding, SenderRole, Uuid7,
    WorkOperation, WorkResult, WorkState, check_chain, check_expiry_window, check_timely,
    expire_unanswered, select_operation, verify_handle,
};
use one_proto::ontology::Instant;
use serde_json::{Value, json};
use support::{TomlValue, conformance, get_str, toml_tables, toml_value, vectors};

fn from<T: serde::de::DeserializeOwned>(v: &Value) -> T {
    serde_json::from_value(v.clone()).unwrap()
}

fn wire<T: serde::Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

fn ts(v: &Value) -> Instant {
    Instant::parse(v.as_str().unwrap()).unwrap()
}

fn role(s: &str) -> SenderRole {
    match s {
        "creditor" => SenderRole::Creditor,
        "debtor-candidate" => SenderRole::DebtorCandidate,
        other => panic!("{other}"),
    }
}

fn state(s: &str) -> WorkState {
    match s {
        "none" => WorkState::None,
        "requested" => WorkState::Requested,
        "countered" => WorkState::Countered,
        "information-wait-open" => WorkState::InformationWaitOpen,
        "promised" => WorkState::Promised,
        "declined" => WorkState::Declined,
        "expired" => WorkState::Expired,
        other => panic!("{other}"),
    }
}

fn operation_name(op: WorkOperation) -> &'static str {
    match op {
        WorkOperation::Request => "request",
        WorkOperation::Counter => "counter",
        WorkOperation::Promise => "promise",
        WorkOperation::AcceptCounter => "accept-counter",
        WorkOperation::Decline => "decline",
        WorkOperation::OpenInformationWait => "open-information-wait",
        WorkOperation::Claim => "claim",
        WorkOperation::Expire => "expire",
    }
}

fn result_name(result: WorkResult) -> &'static str {
    match result {
        WorkResult::None => "none",
        WorkResult::Requested => "requested",
        WorkResult::Countered => "countered",
        WorkResult::Promised => "promised",
        WorkResult::Declined => "declined",
        WorkResult::Expired => "expired",
        WorkResult::InformationWaitSatisfied => "information-wait-satisfied",
    }
}

fn refusal(v: &Value) -> Refusal {
    from(v)
}

const ALL_KINDS: [Kind; 6] = [
    Kind::Offer,
    Kind::CounterOffer,
    Kind::Commitment,
    Kind::Rejection,
    Kind::Query,
    Kind::Answer,
];
const ALL_STATES: [WorkState; 7] = [
    WorkState::None,
    WorkState::Requested,
    WorkState::Countered,
    WorkState::InformationWaitOpen,
    WorkState::Promised,
    WorkState::Declined,
    WorkState::Expired,
];

#[test]
fn oo_15_kind_mapping_vectors() {
    let all = vectors("federation/vectors/kind-mapping.json");
    for v in &all {
        let i = &v["input"];
        let e = &v["expected"];
        let what = v["description"].as_str().unwrap();
        if i.get("table").is_some() {
            assert_eq!(e["maxOperationsPerSelector"], 1);
            for kind in ALL_KINDS {
                for r in [SenderRole::Creditor, SenderRole::DebtorCandidate] {
                    for s in ALL_STATES {
                        let rows = KIND_TABLE
                            .iter()
                            .filter(|row| {
                                row.kind == kind
                                    && match row.sender_role {
                                        RoleSelector::Is(x) => x == r,
                                        _ => true,
                                    }
                                    && match row.work_state {
                                        StateSelector::Is(x) => x == s,
                                        StateSelector::AnyOpen => matches!(
                                            s,
                                            WorkState::None
                                                | WorkState::Requested
                                                | WorkState::Countered
                                        ),
                                    }
                            })
                            .count();
                        assert!(rows <= 1, "{kind:?} {r:?} {s:?}");
                        assert_eq!(
                            select_operation(kind, r, s).is_ok(),
                            rows == 1 && s != WorkState::Expired
                        );
                    }
                }
            }
            continue;
        }
        let got = select_operation(
            from(&i["kind"]),
            role(i["senderRole"].as_str().unwrap()),
            state(i["workState"].as_str().unwrap()),
        );
        if e["accept"].as_bool().unwrap() {
            let s = got.unwrap();
            assert_eq!(
                operation_name(s.work_operation),
                e["workOperation"],
                "{what}"
            );
            assert_eq!(result_name(s.work_result), e["workResult"], "{what}");
        } else {
            assert_eq!(got, Err(refusal(&e["refusal"])), "{what}");
            assert!(e["workOperation"].is_null());
        }
    }
    assert_eq!(all.len(), 21);
}

#[test]
fn oo_15_kind_table_matches_a2a_mapping_toml() {
    let rows = toml_tables("federation/a2a-mapping.toml", "kind");
    assert_eq!(rows.len(), KIND_TABLE.len());
    for (row, k) in rows.iter().zip(KIND_TABLE) {
        assert_eq!(wire(&k.kind), json!(get_str(row, "kind").unwrap()));
        let sender = match get_str(row, "sender_role").unwrap() {
            "any" => RoleSelector::Any,
            "addressee of the query" => RoleSelector::QueryAddressee,
            other => RoleSelector::Is(role(other)),
        };
        assert_eq!(sender, k.sender_role);
        let work_state = match get_str(row, "work_state").unwrap() {
            "any open" => StateSelector::AnyOpen,
            "open information wait" => StateSelector::Is(WorkState::InformationWaitOpen),
            other => StateSelector::Is(state(other)),
        };
        assert_eq!(work_state, k.work_state);
        let op = match get_str(row, "work_operation").unwrap() {
            "open information wait" => WorkOperation::OpenInformationWait,
            "claim satisfying the information wait" => WorkOperation::Claim,
            other => [
                WorkOperation::Request,
                WorkOperation::Counter,
                WorkOperation::Promise,
                WorkOperation::AcceptCounter,
                WorkOperation::Decline,
            ]
            .into_iter()
            .find(|o| operation_name(*o) == other)
            .unwrap(),
        };
        assert_eq!(op, k.work_operation);
        let result = get_str(row, "work_result").unwrap();
        let want = if result.starts_with("unchanged; Epistemic") {
            ResultSelector::Unchanged
        } else if result == "unchanged; wait satisfied" {
            ResultSelector::Is(WorkResult::InformationWaitSatisfied)
        } else {
            ResultSelector::Is(
                [
                    WorkResult::Requested,
                    WorkResult::Countered,
                    WorkResult::Promised,
                    WorkResult::Declined,
                ]
                .into_iter()
                .find(|r| result_name(*r) == result)
                .unwrap(),
            )
        };
        assert_eq!(want, k.work_result);
        let task = get_str(row, "task_state_after").unwrap();
        match k.task_state_after {
            Some(t) => assert_eq!(wire(&t), json!(task)),
            None => assert_eq!(task, "previous state of the Task"),
        }
    }
    let expiry = toml_tables("federation/a2a-mapping.toml", "expiry");
    let e = expire_unanswered(
        &Instant::parse("2026-11-05T10:00:00Z").unwrap(),
        &Instant::parse("2026-11-05T10:00:01Z").unwrap(),
    )
    .unwrap();
    assert_eq!(
        get_str(&expiry[0], "work_result"),
        Some(result_name(e.work_result))
    );
    assert_eq!(
        get_str(&expiry[0], "task_state_after").map(|t| json!(t)),
        Some(wire(&e.task_state))
    );
    assert!(
        get_str(&expiry[0], "work_operation")
            .unwrap()
            .starts_with("expire")
    );
}

const D0: &str = "sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const C0: &str = "019a5a3c-8e00-7a00-8a00-000000000001";

fn cap0() -> CapabilityRef {
    from(&json!({"name": "app.suiss.calendar.event.propose", "version": "2026-10-12"}))
}

fn opt_digest(v: &Value, key: &str) -> Digest {
    Digest::parse(v.get(key).and_then(Value::as_str).unwrap_or(D0)).unwrap()
}

fn offers(kind: Kind) -> bool {
    matches!(kind, Kind::Offer | Kind::CounterOffer)
}

#[test]
fn oo_16_offer_version_vectors() {
    let all = vectors("federation/vectors/offer-version.json");
    for v in &all {
        let what = v["description"].as_str().unwrap();
        let i = &v["input"];
        let chain_json = i["chain"].as_array().unwrap();
        let entries: Vec<ChainEntry> = chain_json
            .iter()
            .map(|c| {
                let kind: Kind = from(&c["kind"]);
                ChainEntry {
                    kind,
                    offer_version: u32::try_from(c["offerVersion"].as_u64().unwrap()).unwrap(),
                    digest: opt_digest(c, "digest"),
                    capability: c
                        .get("capability")
                        .map(from)
                        .or_else(|| offers(kind).then(cap0)),
                }
            })
            .collect();
        let chain_cid = chain_json.first().map(|c| {
            Uuid7::parse(c.get("correlationId").and_then(Value::as_str).unwrap_or(C0)).unwrap()
        });
        let n = &i["next"];
        let kind: Kind = from(&n["kind"]);
        let cid =
            Uuid7::parse(n.get("correlationId").and_then(Value::as_str).unwrap_or(C0)).unwrap();
        let context = n.get("contextId").map_or_else(
            || cid.clone(),
            |c| Uuid7::parse(c.as_str().unwrap()).unwrap(),
        );
        let reply_digest = opt_digest(n, "inReplyToDigest");
        let capability = n
            .get("capability")
            .map(from)
            .or_else(|| offers(kind).then(cap0));
        let next = Incoming {
            kind,
            body_kind: n.get("bodyKind").map_or(kind, from),
            offer_version: u32::try_from(n["offerVersion"].as_u64().unwrap()).unwrap(),
            context_id: &context,
            correlation_id: &cid,
            in_reply_to: n.get("inReplyToVersion").map(|r| ReplyRef {
                offer_version: u32::try_from(r.as_u64().unwrap()).unwrap(),
                digest: &reply_digest,
            }),
            capability: capability.as_ref(),
        };
        let chain = Chain {
            correlation_id: chain_cid.as_ref(),
            entries: &entries,
        };
        let got = check_chain(&chain, &next);
        let e = &v["expected"];
        if e["accept"].as_bool().unwrap() {
            assert_eq!(got, Ok(()), "{what}");
        } else {
            assert_eq!(got, Err(refusal(&e["refusal"])), "{what}");
        }
    }
    assert_eq!(all.len(), 18);
}

#[test]
fn oo_16_expiry_vectors() {
    let all = vectors("federation/vectors/expiry.json");
    for v in &all {
        let what = v["description"].as_str().unwrap();
        let i = &v["input"];
        let e = &v["expected"];
        if let Some(message) = i.get("message") {
            let got = check_expiry_window(&ts(&message["sentAt"]), &ts(&message["expiresAt"]));
            if e["accept"].as_bool().unwrap() {
                assert_eq!(got, Ok(()), "{what}");
            } else {
                assert_eq!(got, Err(refusal(&e["refusal"])), "{what}");
            }
            continue;
        }
        let expires = ts(i
            .get("offerExpiresAt")
            .or_else(|| i.get("queryExpiresAt"))
            .unwrap());
        if i["reply"].is_null() {
            let x = expire_unanswered(&expires, &ts(&i["now"])).unwrap();
            assert_eq!(operation_name(x.work_operation), e["workOperation"]);
            assert_eq!(x.work_author, WorkAuthor::WorkService);
            assert_eq!(e["workAuthor"], "work-service");
            assert_eq!(result_name(x.work_result), e["workResult"]);
            assert_eq!(json!(x.counts_as_acceptance), e["countsAsAcceptance"]);
            assert_eq!(json!(x.counts_as_rejection), e["countsAsRejection"]);
            assert_eq!(wire(&x.task_state), e["taskState"]);
            assert!(expire_unanswered(&expires, &expires).is_none());
            continue;
        }
        let at;
        let receipt = if let Some(t) = i.get("relayEnqueuedAt") {
            at = ts(t);
            ReceiptTime::RelayEnqueued(&at)
        } else {
            at = ts(&i["receivedAt"]);
            ReceiptTime::DirectReceipt(&at)
        };
        let got = check_timely(&expires, receipt);
        if e["accept"].as_bool().unwrap() {
            assert_eq!(got, Ok(()), "{what}");
            let s = select_operation(
                from(&i["reply"]["kind"]),
                SenderRole::DebtorCandidate,
                WorkState::Requested,
            )
            .unwrap();
            assert_eq!(
                operation_name(s.work_operation),
                e["workOperation"],
                "{what}"
            );
        } else {
            assert_eq!(got, Err(refusal(&e["refusal"])), "{what}");
            assert!(e["workOperation"].is_null());
        }
    }
    assert_eq!(all.len(), 12);
}

fn work_state_for(message: &Message) -> WorkState {
    if message.envelope().offer_version == 0 {
        WorkState::None
    } else {
        WorkState::Requested
    }
}

#[test]
fn oo_17_note_vectors() {
    let all = vectors("federation/vectors/note.json");
    for v in &all {
        let what = v["description"].as_str().unwrap();
        let i = &v["input"];
        let e = &v["expected"];
        if i.get("operation").is_some() {
            assert_eq!(i["operation"], "note-to-field");
            let note = Note::new(
                NoteText::parse(i["note"].as_str().unwrap()).unwrap(),
                LangTag::parse("en").unwrap(),
            );
            let field = i["targetField"].as_str().unwrap();
            assert_eq!(
                note_to_field(&note, field).map(|_| ()),
                Err(refusal(&e["refusal"])),
                "{what}"
            );
            continue;
        }
        let parsed = serde_json::from_value::<Message>(i["message"].clone());
        let Ok(message) = parsed else {
            assert_eq!(e["refusal"], "schema-invalid", "{what}");
            assert_eq!(e["accept"], false);
            assert!(e["workOperation"].is_null());
            continue;
        };
        message.check_consistency().unwrap();
        let note = message.note().unwrap();
        let note_text = i["message"]["parts"][1]["text"].as_str().unwrap();
        let typed = serde_json::to_string(&message.typed_content()).unwrap();
        assert!(!typed.contains(note_text), "{what}");
        if let Some(op) = e.get("workOperation") {
            let s = select_operation(
                message.envelope().kind,
                SenderRole::from(message.role),
                work_state_for(&message),
            )
            .unwrap();
            assert_eq!(operation_name(s.work_operation), op, "{what}");
        }
        if let Some(fields) = e.get("typedFields") {
            assert_eq!(&wire(message.body().fields().unwrap()), fields, "{what}");
        }
        for key in ["noteInWork", "noteToPlanner", "noteToFields"] {
            if let Some(flag) = e.get(key) {
                assert_eq!(flag, false, "{what}");
            }
        }
        if let Some(n) = e.get("automaticActionsFromNote") {
            assert_eq!(n, 0);
        }
        let display = note.display();
        if e.get("noteDisplay").is_some() {
            assert_eq!(e["noteDisplay"], "counterparty-note-unrendered");
            assert_eq!(display.label(), NoteLabel::CounterpartyNoteUnrendered);
        }
        if let Some(text) = e.get("noteDisplayedText") {
            assert_eq!(display.to_string(), text.as_str().unwrap(), "{what}");
            assert_eq!(json!(display.rendered()), e["rendered"]);
        }
        if let Some(trust) = e.get("noteTrust") {
            assert_eq!(&wire(&note.trust()), trust);
            assert_eq!(&wire(&note.access_provenance()), &e["noteProvenance"]);
        }
        if let Some(accept) = e.get("accept") {
            assert_eq!(accept, true);
        }
    }
    assert_eq!(all.len(), 7);
}

const MISSING_HANDLE_VECTOR: &str = "Reply without the handle echoed";

#[test]
fn oo_5_handle_vectors() {
    let all = vectors("federation/vectors/handle.json");
    for v in &all {
        let what = v["description"].as_str().unwrap();
        let i = &v["input"];
        let c = &i["context"];
        let e = &v["expected"];
        let header = serde_json::from_value::<ProtectedHeader>(i["protectedHeader"].clone()).ok();
        let claims = (!i["claims"].is_null()).then(|| from::<HandleClaims>(&i["claims"]));
        let compact = (what != MISSING_HANDLE_VECTOR).then(|| i["compact"].as_str().unwrap());
        let opened = OpenedHandle {
            compact,
            header: header.as_ref(),
            aead_verified: i["aeadVerifies"].as_bool().unwrap(),
            claims: claims.as_ref(),
        };
        let sender: Party = from(&c["replySender"]);
        let recipient: Party = from(&c["replyRecipient"]);
        let cid: Uuid7 = from(&c["correlationId"]);
        let digest: Digest = from(&c["inReplyToDigest"]);
        let binding = ReplyBinding {
            reply_sender: &sender,
            reply_recipient: &recipient,
            correlation_id: &cid,
            in_reply_to_version: u32::try_from(c["inReplyToVersion"].as_u64().unwrap()).unwrap(),
            in_reply_to_digest: &digest,
            suspended_expires_at: c.get("suspendedExpiresAt").map(|x| x.as_u64().unwrap()),
            now: c["now"].as_u64().unwrap(),
        };
        let mut spent: Vec<Uuid7> = from(&c["spent"]);
        let downstream = c
            .get("downstreamRefusal")
            .map_or(Ok(()), |r| Err(refusal(r)));
        let got =
            verify_handle(&opened, &binding, spent.as_slice()).and_then(|h| h.consume(downstream));
        if e["accept"].as_bool().unwrap() {
            let SpentEntry { jti, keep_until } = got.unwrap();
            assert_eq!(keep_until, claims.as_ref().unwrap().exp);
            spent.push(jti);
        } else {
            assert_eq!(got, Err(refusal(&e["refusal"])), "{what}");
        }
        if let Some(after) = e.get("spentAfter") {
            assert_eq!(wire(&spent), *after, "{what}");
        }
    }
    assert_eq!(all.len(), 20);
}

fn table_section(rel: &str, section: &str) -> Vec<(String, TomlValue)> {
    let text = std::fs::read_to_string(conformance(rel)).unwrap();
    let header = format!("[{section}]");
    let mut inside = false;
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == header;
            continue;
        }
        if inside && let Some((k, v)) = line.split_once('=') {
            out.push((k.trim().to_owned(), toml_value(v)));
        }
    }
    out
}

fn flatten(values: &[(String, TomlValue)]) -> Vec<String> {
    values
        .iter()
        .flat_map(|(_, v)| match v {
            TomlValue::Str(s) => vec![s.clone()],
            TomlValue::List(l) => l.clone(),
            other => panic!("{other:?}"),
        })
        .collect()
}

#[test]
fn oo_7_relay_no_content_vectors() {
    let rel = "federation/relay-no-content.toml";
    let mut mailbox = flatten(&table_section(rel, "allowed_fields"));
    let mut ours: Vec<String> = MAILBOX_ALLOWED_FIELDS
        .iter()
        .map(|s| (*s).to_owned())
        .collect();
    mailbox.sort();
    ours.sort();
    assert_eq!(mailbox, ours);
    assert_eq!(flatten(&table_section(rel, "push")), PUSH_ALLOWED_FIELDS);
    let classes = table_section(rel, "delivery_class");
    assert_eq!(
        classes
            .iter()
            .find(|(k, _)| k == "values")
            .map(|(_, v)| v.clone()),
        Some(TomlValue::List(
            DELIVERY_CLASSES.iter().map(|s| (*s).to_owned()).collect()
        ))
    );
    let all = vectors("federation/vectors/relay-no-content.json");
    for v in &all {
        let what = v["description"].as_str().unwrap();
        let i = &v["input"];
        let e = &v["expected"];
        let text = format!(
            "line with {} inside",
            i["canary"].as_str().unwrap_or_default()
        );
        let found = if let Some(push) = i.get("push") {
            first_disallowed(
                push.as_object().unwrap().keys().map(String::as_str),
                PUSH_ALLOWED_FIELDS,
            )
        } else if let Some(canary) = i.get("canary") {
            let canary = canary.as_str().unwrap();
            let exports: Vec<(&str, &str)> = i["foundIn"]
                .as_array()
                .unwrap()
                .iter()
                .map(|l| (l.as_str().unwrap(), text.as_str()))
                .collect();
            assert_eq!(canary_found(canary, [("relay.metrics", "clean")]), None);
            canary_found(canary, exports)
        } else {
            let record = i.get("record").or_else(|| i.get("event")).unwrap();
            if let Some(class) = record.get("deliveryClass") {
                assert!(DELIVERY_CLASSES.contains(&class.as_str().unwrap()));
            }
            first_disallowed(
                record.as_object().unwrap().keys().map(String::as_str),
                MAILBOX_ALLOWED_FIELDS,
            )
        };
        assert_eq!(found.is_some(), e["violation"].as_bool().unwrap(), "{what}");
        if let Some(field) = e.get("field") {
            assert_eq!(found, field.as_str(), "{what}");
        }
    }
    assert_eq!(all.len(), 10);
}

#[test]
fn oo_17_note_has_no_path_into_typed_content() {
    let all = vectors("federation/vectors/note.json");
    let message: Message = from(&all[1]["input"]["message"]);
    let typed = wire(&message.typed_content());
    assert_eq!(
        typed["body"]["fields"]["start"],
        "2026-11-05T20:30:00+03:00"
    );
    assert!(typed.get("note").is_none());
    assert_eq!(
        format!("{:?}", message.note().unwrap()),
        "Note([untrusted])"
    );
}
