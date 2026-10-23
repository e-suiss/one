//! The A2A v1.0.1 conformance checklist `conformance/federation/a2a-conformance.toml`, row by row, against the federation schemas, vectors and the A2A projection types (OO-3, OO-4, OO-29).

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

use std::collections::BTreeSet;

use one_proto::federation::message::Role;
use one_proto::federation::rules::{Chain, check_chain};
use one_proto::federation::task::Phase;
use one_proto::federation::wire::ExtensionUri;
use one_proto::federation::{
    AgentExtension, EXTENSION_URI, Envelope, Incoming, KIND_TABLE, Kind, Message, Refusal, Task,
    TaskState, Uuid7,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use support::{TomlRow, TomlValue, conformance, get, get_str, toml_tables, toml_value, vectors};

const CHECKLIST: &str = "federation/a2a-conformance.toml";
const MAPPING: &str = "federation/a2a-mapping.toml";
const MESSAGES: &str = "federation/vectors/schema/message.json";
const TASKS: &str = "federation/vectors/schema/task.json";
const AGENT_EXTENSIONS: &str = "federation/vectors/schema/agent-extension.json";
const ENVELOPES: &str = "federation/vectors/schema/envelope.json";
const OFFER_VERSIONS: &str = "federation/vectors/offer-version.json";

fn section(rel: &str, name: &str) -> Vec<(String, TomlValue)> {
    let text = std::fs::read_to_string(conformance(rel)).unwrap();
    let header = format!("[{name}]");
    let mut inside = false;
    let mut out = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.starts_with('[') {
            inside = line == header;
            continue;
        }
        if inside
            && !line.starts_with('#')
            && let Some((k, v)) = line.split_once('=')
        {
            out.push((k.trim().to_owned(), toml_value(v)));
        }
    }
    assert!(!out.is_empty(), "{rel} [{name}]");
    out
}

fn value<'a>(rows: &'a [(String, TomlValue)], key: &str) -> &'a TomlValue {
    rows.iter()
        .find(|(k, _)| k == key)
        .map_or_else(|| panic!("{key}"), |(_, v)| v)
}

fn text<'a>(rows: &'a [(String, TomlValue)], key: &str) -> &'a str {
    match value(rows, key) {
        TomlValue::Str(s) => s,
        other => panic!("{key}: {other:?}"),
    }
}

struct Run {
    consulted: BTreeSet<String>,
}

impl Run {
    fn vectors(&mut self, rel: &str) -> Vec<Value> {
        let local = rel.strip_prefix("federation/").unwrap();
        self.consulted.insert(local.to_owned());
        vectors(rel)
    }

    fn valid(&mut self, rel: &str) -> Vec<Value> {
        self.vectors(rel)
            .into_iter()
            .filter(|v| v["valid"] == json!(true))
            .map(|v| v["input"].clone())
            .collect()
    }

    fn invalid(&mut self, rel: &str, description: &str) -> Value {
        self.vectors(rel)
            .into_iter()
            .find(|v| v["valid"] == json!(false) && v["description"] == json!(description))
            .unwrap_or_else(|| panic!("{rel}: {description}"))["input"]
            .clone()
    }
}

fn wire<T: Serialize>(v: &T) -> Value {
    serde_json::to_value(v).unwrap()
}

fn typed<T: DeserializeOwned>(v: &Value) -> Result<T, String> {
    serde_json::from_value(v.clone()).map_err(|e| e.to_string())
}

fn message(v: &Value) -> Result<Message, String> {
    let m: Message = typed(v)?;
    m.validate().map_err(|e| format!("{e:?}"))?;
    Ok(m)
}

fn task(v: &Value) -> Result<Task, String> {
    let t: Task = typed(v)?;
    t.validate().map_err(|e| format!("{e:?}"))?;
    Ok(t)
}

fn agent_extension(v: &Value) -> Result<AgentExtension, String> {
    let a: AgentExtension = typed(v)?;
    a.validate().map_err(|e| format!("{e:?}"))?;
    Ok(a)
}

fn only_extension_key(metadata: &Value) -> &Value {
    let object = metadata.as_object().unwrap();
    assert_eq!(object.len(), 1, "{metadata}");
    &object[EXTENSION_URI]
}

fn camel_keys(v: &Value, path: &str, wrong: &mut Vec<String>) {
    match v {
        Value::Object(members) => {
            for (k, child) in members {
                let camel = k == EXTENSION_URI
                    || (k.starts_with(|c: char| c.is_ascii_lowercase())
                        && k.chars().all(|c| c.is_ascii_alphanumeric()));
                if !camel {
                    wrong.push(format!("{path}.{k}"));
                }
                if k != "fields" {
                    camel_keys(child, &format!("{path}.{k}"), wrong);
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|i| camel_keys(i, path, wrong)),
        _ => {}
    }
}

fn mapping_states() -> Vec<TomlRow> {
    toml_tables(MAPPING, "state")
}

fn a2a_1(run: &mut Run) {
    let target = section(CHECKLIST, "target");
    let extension = section(MAPPING, "extension");
    assert_eq!(text(&target, "specification"), "A2A Protocol Specification");
    assert_eq!(text(&target, "version"), "1.0.1");
    let header = text(&target, "protocol_version_header");
    assert_eq!(header, "1.0");
    assert_eq!(text(&extension, "a2a_version"), header);
    assert!(text(&target, "version").starts_with(&format!("{header}.")));
    assert!(text(&extension, "a2a_reference").contains("v1.0.1"));
    let old = run.invalid(TASKS, "A2A v0.3 lower-case state name");
    assert!(task(&old).is_err());
}

fn a2a_2(_: &mut Run) {
    let target = section(CHECKLIST, "target");
    let extension = section(MAPPING, "extension");
    assert_eq!(text(&target, "binding"), "HTTP+JSON");
    assert_eq!(text(&extension, "binding"), text(&target, "binding"));
    assert_eq!(text(&extension, "media_type"), "application/a2a+json");
}

fn a2a_3(run: &mut Run) {
    let mut wrong = Vec::new();
    for input in run.valid(MESSAGES) {
        let m = message(&input).unwrap();
        let out = wire(&m);
        camel_keys(&out, "message", &mut wrong);
        assert!(["ROLE_USER", "ROLE_AGENT"].contains(&out["role"].as_str().unwrap()));
    }
    for input in run.valid(TASKS) {
        let out = wire(&task(&input).unwrap());
        camel_keys(&out, "task", &mut wrong);
        assert!(
            out["status"]["state"]
                .as_str()
                .unwrap()
                .starts_with("TASK_STATE_")
        );
    }
    assert!(wrong.is_empty(), "{}", wrong.join("\n"));
    assert_eq!(wire(&Role::RoleUser), json!("ROLE_USER"));
    assert_eq!(wire(&Role::RoleAgent), json!("ROLE_AGENT"));
    assert_eq!(
        wire(&TaskState::InputRequired),
        json!("TASK_STATE_INPUT_REQUIRED")
    );
    assert!(message(&run.invalid(MESSAGES, "Role is not a ProtoJSON enum name")).is_err());
    assert!(task(&run.invalid(TASKS, "A2A v0.3 lower-case state name")).is_err());
    let mut snake = run.valid(MESSAGES).remove(0);
    let id = snake.as_object_mut().unwrap().remove("messageId").unwrap();
    snake["message_id"] = id;
    assert!(message(&snake).is_err());
}

fn a2a_4(run: &mut Run) {
    let extension = section(MAPPING, "extension");
    assert_eq!(text(&extension, "uri"), EXTENSION_URI);
    assert_eq!(value(&extension, "required"), &TomlValue::Bool(true));
    assert_eq!(text(&extension, "extension_type"), "profile");
    let card_row = toml_tables(MAPPING, "object")
        .into_iter()
        .find(|o| get_str(o, "a2a") == Some("AgentCard.capabilities.extensions[]"))
        .unwrap();
    assert_eq!(
        get_str(&card_row, "schema"),
        Some("schemas/agent-extension.v1.json")
    );
    let schema: Value = serde_json::from_str(
        &std::fs::read_to_string(conformance("federation/schemas/agent-extension.v1.json"))
            .unwrap(),
    )
    .unwrap();
    let mut schema_params: Vec<&String> = schema["properties"]["params"]["properties"]
        .as_object()
        .unwrap()
        .keys()
        .collect();
    schema_params.sort();
    let declarations = run.valid(AGENT_EXTENSIONS);
    assert_ne!(declarations.len(), 0);
    for input in declarations {
        let declared = agent_extension(&input).unwrap();
        assert_eq!(declared.uri, ExtensionUri::OneFederationV1);
        let out = wire(&declared);
        assert_eq!(out["uri"], json!(EXTENSION_URI));
        assert_eq!(out["required"], json!(true));
        let mut params: Vec<&String> = out["params"].as_object().unwrap().keys().collect();
        params.sort();
        assert_eq!(params, schema_params);
        let kinds: Vec<Kind> = declared.params.kinds.clone();
        for row in KIND_TABLE {
            assert!(kinds.contains(&row.kind), "{:?}", row.kind);
        }
    }
    assert!(
        agent_extension(&run.invalid(AGENT_EXTENSIONS, "Extension declared as optional")).is_err()
    );
}

fn a2a_5(run: &mut Run) {
    let missing = run.invalid(MESSAGES, "Extension URI missing from Message.extensions");
    assert!(message(&missing).is_err());
    let mut empty = run.valid(MESSAGES).remove(0);
    empty["extensions"] = json!([]);
    assert!(message(&empty).is_err());
    let mut absent = run.valid(MESSAGES).remove(0);
    absent.as_object_mut().unwrap().remove("extensions");
    assert!(message(&absent).is_err());
    assert_eq!(
        wire(&Refusal::ExtensionNotActivated),
        json!("extension-not-activated")
    );
    let extension = section(MAPPING, "extension");
    let activation = text(&extension, "activation");
    assert!(activation.contains("A2A-Extensions"));
    assert!(activation.contains("ExtensionSupportRequiredError"));
}

fn a2a_6(run: &mut Run) {
    let other = run.invalid(MESSAGES, "Different extension version URI");
    assert!(message(&other).is_err());
    assert!(agent_extension(&run.invalid(AGENT_EXTENSIONS, "Wrong extension URI")).is_err());
    for uri in [
        "https://suiss.app/a2a/one-federation/v2",
        "https://suiss.app/a2a/one-federation/v0",
        "https://suiss.app/a2a/one-federation",
        "https://suiss.app/a2a/one-federation/v1/",
    ] {
        assert!(typed::<ExtensionUri>(&json!(uri)).is_err(), "{uri}");
        let mut m = run.valid(MESSAGES).remove(0);
        m["extensions"] = json!([uri]);
        assert!(message(&m).is_err(), "{uri}");
        let mut keyed = run.valid(MESSAGES).remove(0);
        let ext = keyed["metadata"]
            .as_object_mut()
            .unwrap()
            .remove(EXTENSION_URI)
            .unwrap();
        keyed["metadata"][uri] = ext;
        assert!(message(&keyed).is_err(), "{uri}");
    }
    assert!(typed::<ExtensionUri>(&json!(EXTENSION_URI)).is_ok());
}

fn a2a_7(run: &mut Run) {
    for input in run.valid(MESSAGES) {
        let out = wire(&message(&input).unwrap());
        assert_eq!(out["extensions"], json!([EXTENSION_URI]));
        assert!(only_extension_key(&out["metadata"]).is_object());
        for part in out["parts"].as_array().unwrap() {
            assert!(only_extension_key(&part["metadata"]).is_object());
        }
    }
    let mut artifacts = 0;
    for input in run.valid(TASKS) {
        let out = wire(&task(&input).unwrap());
        assert!(only_extension_key(&out["metadata"]).is_object());
        for artifact in out["artifacts"].as_array().into_iter().flatten() {
            artifacts += 1;
            assert_eq!(artifact["extensions"], json!([EXTENSION_URI]));
            for part in artifact["parts"].as_array().unwrap() {
                assert_eq!(
                    only_extension_key(&part["metadata"]),
                    &json!({ "part": "commitment" })
                );
            }
        }
    }
    assert!(artifacts > 0);
    assert!(
        message(&run.invalid(MESSAGES, "Extension object missing from Message.metadata")).is_err()
    );
    assert!(message(&run.invalid(MESSAGES, "Unknown member in Message.metadata")).is_err());
    let mut artifact_task = run
        .valid(TASKS)
        .into_iter()
        .find(|t| t.get("artifacts").is_some())
        .unwrap();
    artifact_task["artifacts"][0]["extensions"] = json!([]);
    assert!(task(&artifact_task).is_err());
}

fn a2a_8(run: &mut Run) {
    let mut parts = 0;
    for input in run.valid(MESSAGES) {
        let out = wire(&message(&input).unwrap());
        for part in out["parts"].as_array().unwrap() {
            parts += 1;
            let has = |k: &str| part.get(k).is_some();
            assert!(has("text") ^ has("data"), "{part}");
            assert!(!has("url") && !has("raw") && !has("file"), "{part}");
        }
    }
    assert!(parts > 0);
    assert!(message(&run.invalid(MESSAGES, "File part (url) is not allowed")).is_err());
    let base = run.valid(MESSAGES).remove(0);
    let mut both = base.clone();
    both["parts"][0]["text"] = json!("free text");
    assert!(message(&both).is_err());
    let mut raw = base.clone();
    raw["parts"][0]["raw"] = json!("aGVsbG8");
    assert!(message(&raw).is_err());
    let mut neither = base;
    neither["parts"][0].as_object_mut().unwrap().remove("data");
    assert!(message(&neither).is_err());
}

fn a2a_9(run: &mut Run) {
    let mut ids = BTreeSet::new();
    for input in run.valid(MESSAGES) {
        let m = message(&input).unwrap();
        assert!(
            ids.insert(m.message_id.as_str().to_owned()),
            "{}",
            m.message_id.as_str()
        );
        assert_eq!(m.check_consistency(), Ok(()));
        assert_eq!(&m.context_id, &m.envelope().correlation_id);
        let mut moved = input.clone();
        moved["contextId"] = json!("019a5a3c-8e00-7a00-8a00-000000000998");
        let moved = message(&moved).unwrap();
        assert_eq!(moved.check_consistency(), Err(Refusal::CorrelationMismatch));
        let chain = Chain {
            correlation_id: None,
            entries: &[],
        };
        assert_eq!(
            check_chain(&chain, &Incoming::of(&moved)),
            Err(Refusal::CorrelationMismatch)
        );
    }
    let mut not_v7 = run.valid(MESSAGES).remove(0);
    not_v7["messageId"] = json!("019a5a3c-8e00-4a00-8a00-000000000001");
    assert!(message(&not_v7).is_err());
    assert!(Uuid7::parse("019a5a3c-8e00-7a00-8a00-000000000001").is_ok());
    let mismatches: Vec<Value> = run
        .vectors(OFFER_VERSIONS)
        .into_iter()
        .filter(|v| {
            let n = &v["input"]["next"];
            n.get("contextId").is_some() || n.get("correlationId").is_some()
        })
        .collect();
    assert!(mismatches.len() >= 2);
    for v in &mismatches {
        assert_eq!(
            v["expected"]["refusal"],
            json!("correlation-mismatch"),
            "{v}"
        );
    }
}

fn a2a_10(run: &mut Run) {
    let states = mapping_states();
    assert_eq!(states.len(), 8);
    let mut seen = BTreeSet::new();
    for row in &states {
        let name = get_str(row, "a2a").unwrap();
        let state: TaskState = typed(&json!(name)).unwrap();
        assert!(seen.insert(name), "{name}");
        assert_eq!(
            wire(&state.phase()),
            json!(get_str(row, "phase").unwrap()),
            "{name}"
        );
    }
    let waits: Vec<&str> = states
        .iter()
        .filter(|r| get_str(r, "phase").unwrap().starts_with("awaiting-"))
        .map(|r| get_str(r, "a2a").unwrap())
        .collect();
    assert_eq!(
        waits,
        ["TASK_STATE_INPUT_REQUIRED", "TASK_STATE_AUTH_REQUIRED"]
    );
    assert_eq!(
        TaskState::InputRequired.phase(),
        Phase::AwaitingCounterparty
    );
    assert_eq!(TaskState::AuthRequired.phase(), Phase::AwaitingPrincipal);
    for input in run.valid(TASKS) {
        let t = task(&input).unwrap();
        assert_eq!(t.metadata.extension.phase, t.status.state.phase());
    }
    for d in [
        "input-required mapped to the principal wait",
        "auth-required mapped to the counterparty wait",
    ] {
        assert!(task(&run.invalid(TASKS, d)).is_err(), "{d}");
    }
    for row in KIND_TABLE {
        if let Some(state) = row.task_state_after {
            assert!(seen.contains(wire(&state).as_str().unwrap()), "{state:?}");
        }
    }
}

fn a2a_11(_: &mut Run) {
    let target = section(CHECKLIST, "target");
    assert_eq!(text(&target, "binding"), "HTTP+JSON");
    assert!(
        text(&section(MAPPING, "extension"), "a2a_reference").contains(" 11,"),
        "the HTTP+JSON binding section is cited"
    );
}

fn a2a_12(run: &mut Run) {
    for input in run.valid(MESSAGES) {
        let m = message(&input).unwrap();
        let envelope = wire(m.envelope());
        for party in ["sender", "recipient"] {
            for id in ["person", "agent"] {
                assert!(
                    envelope[party][id]
                        .as_str()
                        .unwrap()
                        .starts_with("did:web:"),
                    "{party}.{id}"
                );
            }
        }
        assert!(envelope["authority"]["ref"].is_string());
        assert!(envelope["authority"]["digest"].is_string());
    }
    for d in [
        "Mandatory field sender missing",
        "Mandatory field recipient missing",
        "Mandatory field authority missing",
        "Sender without agent identity",
        "Sender without person identity",
        "Recipient without agent identity",
        "Authority reference without digest",
    ] {
        let input = run.invalid(ENVELOPES, d);
        assert!(
            typed::<Envelope>(&input)
                .and_then(|e| e.validate().map_err(|e| format!("{e:?}")))
                .is_err(),
            "{d}"
        );
    }
    let card = run.valid(AGENT_EXTENSIONS).remove(0);
    for (key, at) in [
        ("person", None),
        ("agent", None),
        ("authority", Some("params")),
    ] {
        let mut with_identity = card.clone();
        match at {
            Some(inner) => with_identity[inner][key] = json!("did:web:bob.one.suiss.app"),
            None => with_identity[key] = json!("did:web:bob.one.suiss.app"),
        }
        assert!(agent_extension(&with_identity).is_err(), "{key}");
    }
    assert_eq!(wire(&Refusal::IdentityMismatch), json!("identity-mismatch"));
    assert_eq!(wire(&Refusal::AuthorityInvalid), json!("authority-invalid"));
}

fn a2a_13(_: &mut Run) {
    let extension = section(MAPPING, "extension");
    let person = text(&extension, "person_to_person_carriage");
    assert!(person.contains("HTTP+JSON") && person.contains("MLS"));
    assert!(text(&extension, "organization_carriage").contains("over TLS"));
}

fn assertion(id: &str) -> Option<fn(&mut Run)> {
    Some(match id {
        "A2A-1" => a2a_1,
        "A2A-2" => a2a_2,
        "A2A-3" => a2a_3,
        "A2A-4" => a2a_4,
        "A2A-5" => a2a_5,
        "A2A-6" => a2a_6,
        "A2A-7" => a2a_7,
        "A2A-8" => a2a_8,
        "A2A-9" => a2a_9,
        "A2A-10" => a2a_10,
        "A2A-11" => a2a_11,
        "A2A-12" => a2a_12,
        "A2A-13" => a2a_13,
        _ => return None,
    })
}

#[test]
fn oo_4_every_a2a_checklist_row_has_an_assertion() {
    let rows = toml_tables(CHECKLIST, "check");
    let mut ids = BTreeSet::new();
    let mut missing = Vec::new();
    for row in &rows {
        let id = get_str(row, "id").unwrap();
        assert!(ids.insert(id), "{id} listed twice");
        let rules = match get(row, "rules") {
            Some(TomlValue::List(r)) => r,
            other => panic!("{id}: {other:?}"),
        };
        assert!(rules.iter().any(|r| r == "OO-4"), "{id}");
        let Some(check) = assertion(id) else {
            missing.push(id);
            continue;
        };
        let mut run = Run {
            consulted: BTreeSet::new(),
        };
        check(&mut run);
        if let Some(TomlValue::List(listed)) = get(row, "vectors") {
            for rel in listed {
                assert!(
                    conformance(&format!("federation/{rel}")).is_file(),
                    "{id}: {rel}"
                );
                assert!(run.consulted.contains(rel), "{id} does not run {rel}");
            }
        }
    }
    assert!(missing.is_empty(), "rows without an assertion: {missing:?}");
    assert_eq!(rows.len(), 13);
    for id in ["A2A-0", "A2A-14"] {
        assert!(assertion(id).is_none());
    }
}
