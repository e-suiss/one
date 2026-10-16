//! Every relevant behaviour vector of `conformance/` through the one-core facade: checks each output against the vector and writes the case file (operation, input bytes, output bytes) that the WASM, Swift and Kotlin bindings must reproduce byte for byte (T-38 (2)).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use std::collections::BTreeMap;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

struct Case {
    name: String,
    op: &'static str,
    input: Vec<u8>,
    output: Vec<u8>,
}

#[derive(Default)]
struct Run {
    cases: Vec<Case>,
    per_file: BTreeMap<&'static str, usize>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("..")
}

fn load(rel: &str) -> Vec<Value> {
    let text = std::fs::read_to_string(root().join("conformance").join(rel)).unwrap();
    match serde_json::from_str(&text).unwrap() {
        Value::Array(items) => items,
        other => panic!("{rel}: not an array: {other}"),
    }
}

fn subset(expected: &Value, actual: &Value) -> bool {
    match (expected, actual) {
        (Value::Object(e), Value::Object(a)) => e
            .iter()
            .all(|(k, v)| a.get(k).is_some_and(|x| subset(v, x))),
        _ => expected == actual,
    }
}

impl Run {
    fn case(&mut self, file: &'static str, name: String, op: &'static str, input: &Value) -> Value {
        let input = one_core::canonical::to_vec(input);
        let output = one_core::invoke(op, &input);
        assert_eq!(
            one_core::call(op, &input).ok(),
            serde_json::from_slice::<Value>(&output)
                .unwrap()
                .get("ok")
                .map(one_core::canonical::to_vec),
            "{name}: call and invoke disagree"
        );
        *self.per_file.entry(file).or_default() += 1;
        let value = serde_json::from_slice(&output).unwrap();
        self.cases.push(Case {
            name,
            op,
            input,
            output,
        });
        value
    }

    fn vectors(
        &mut self,
        file: &'static str,
        count: usize,
        mut each: impl FnMut(&mut Self, String, &Value),
    ) {
        let all = load(file);
        assert_eq!(all.len(), count, "{file}");
        for (n, v) in all.iter().enumerate() {
            each(self, format!("{file}#{n}"), v);
        }
    }
}

fn without_op(input: &Value) -> Value {
    let mut v = input.clone();
    v.as_object_mut().unwrap().remove("op");
    v
}

fn provenance(run: &mut Run) {
    run.vectors("provenance/vectors/join.json", 18, |run, name, v| {
        let out = run.case(
            "provenance/vectors/join.json",
            name.clone(),
            "provenance.join",
            &without_op(&v["input"]),
        );
        assert_eq!(out["ok"], v["expected"], "{name}");
    });
    run.vectors("provenance/vectors/transform.json", 14, |run, name, v| {
        let op = v["input"]["op"].as_str().unwrap();
        if op == "serialise_roundtrip" {
            return;
        }
        let input = json!({"transform": op, "inputs": v["input"]["inputs"]});
        let out = run.case(
            "provenance/vectors/transform.json",
            name.clone(),
            "provenance.transform",
            &input,
        );
        assert_eq!(out["ok"], v["expected"], "{name}");
    });
    run.vectors("provenance/vectors/open.json", 14, |run, name, v| {
        let out = run.case(
            "provenance/vectors/open.json",
            name.clone(),
            "provenance.open",
            &without_op(&v["input"]),
        );
        assert!(subset(&v["expected"], &out["ok"]), "{name}: {out}");
        let encoded = &v["input"]["encoded"];
        assert_eq!(
            &out["ok"]["value"],
            encoded.get("value").unwrap_or(encoded),
            "{name}"
        );
    });
    run.vectors(
        "provenance/vectors/access-mapping.json",
        19,
        |run, name, v| {
            let out = run.case(
                "provenance/vectors/access-mapping.json",
                name.clone(),
                "provenance.access_mapping",
                &without_op(&v["input"]),
            );
            assert_eq!(out["ok"], v["expected"], "{name}");
        },
    );
}

fn task(run: &mut Run) {
    run.vectors("task/vectors/state-derivation.json", 50, |run, name, v| {
        let out = run.case(
            "task/vectors/state-derivation.json",
            name.clone(),
            "task.derive",
            &v["input"],
        );
        let mut expected = v["expected"].clone();
        if let Some(r) = expected.get_mut("rejected").and_then(Value::as_object_mut) {
            r.retain(|_, x| !x.is_null());
        }
        assert!(subset(&expected, &out["ok"]), "{name}: {out}");
    });
    run.vectors("task/vectors/projection.json", 14, |run, name, v| {
        let out = run.case(
            "task/vectors/projection.json",
            name.clone(),
            "task.project",
            &v["input"],
        );
        assert_eq!(out["ok"], v["expected"], "{name}");
    });
}

fn merged(out: &Value) -> Value {
    let mut m = Map::new();
    for r in out["results"].as_array().unwrap() {
        for (k, value) in r.as_object().unwrap() {
            if k != "outcome" {
                m.entry(k.clone()).or_insert_with(|| value.clone());
            }
        }
    }
    for k in ["valid", "outcomes", "approvals_created"] {
        m.insert(k.to_owned(), out[k].clone());
    }
    Value::Object(m)
}

fn interaction(run: &mut Run) {
    run.vectors(
        "interaction/vectors/kind-resolution.json",
        5,
        |run, name, v| {
            let out = run.case(
                "interaction/vectors/kind-resolution.json",
                name.clone(),
                "interaction.resolve_kind",
                &v["input"],
            );
            assert_eq!(out["ok"], v["expected"], "{name}");
        },
    );
    run.vectors("interaction/vectors/budgets.json", 26, |run, name, v| {
        let out = run.case(
            "interaction/vectors/budgets.json",
            name.clone(),
            "interaction.project",
            &v["input"],
        );
        assert!(subset(&v["expected"], &out["ok"]), "{name}: {out}");
    });
    run.vectors(
        "interaction/vectors/response-processing.json",
        13,
        |run, name, v| {
            let out = run.case(
                "interaction/vectors/response-processing.json",
                name.clone(),
                "interaction.process_responses",
                &v["input"],
            );
            assert!(subset(&v["expected"], &merged(&out["ok"])), "{name}: {out}");
        },
    );
}

fn capability(run: &mut Run) {
    run.vectors("capability/vectors/name.json", 26, |run, name, v| {
        let expected = &v["expected"];
        if expected["kind"] == "version" {
            let out = run.case(
                "capability/vectors/name.json",
                name.clone(),
                "capability.parse_version",
                &v["input"],
            );
            assert_eq!(out["ok"], json!({"valid": expected["valid"]}), "{name}");
            return;
        }
        let out = run.case(
            "capability/vectors/name.json",
            name.clone(),
            "capability.parse_name",
            &v["input"],
        );
        assert!(subset(expected, &out["ok"]), "{name}: {out}");
        assert_eq!(
            out["ok"].get("category"),
            expected.get("category"),
            "{name}"
        );
    });
    run.vectors("capability/vectors/negotiation.json", 12, |run, name, v| {
        let out = run.case(
            "capability/vectors/negotiation.json",
            name.clone(),
            "capability.negotiate",
            &v["input"],
        );
        assert_eq!(out["ok"], v["expected"], "{name}");
    });
}

fn memory(run: &mut Run) {
    run.vectors("memory/vectors/trust-v1.json", 26, |run, name, v| {
        if let Some(cases) = v["input"]["cases"].as_array() {
            let values: Vec<Value> = cases
                .iter()
                .enumerate()
                .map(|(n, c)| {
                    run.case(
                        "memory/vectors/trust-v1.json",
                        format!("{name}.{n}"),
                        "memory.trust_v1",
                        c,
                    )["ok"]["trust"]
                        .clone()
                })
                .collect();
            assert_eq!(Value::Array(values), v["expected"]["values"], "{name}");
            return;
        }
        let out = run.case(
            "memory/vectors/trust-v1.json",
            name.clone(),
            "memory.trust_v1",
            &v["input"],
        );
        assert_eq!(out["ok"], v["expected"], "{name}");
    });
    run.vectors("memory/vectors/text-view.json", 10, |run, name, v| {
        let out = run.case(
            "memory/vectors/text-view.json",
            name.clone(),
            "memory.text_view",
            &v["input"],
        );
        assert_eq!(out["ok"], v["expected"], "{name}");
    });
}

fn attention(run: &mut Run) {
    run.vectors(
        "attention/vectors/decision-head.json",
        17,
        |run, name, v| {
            let out = run.case(
                "attention/vectors/decision-head.json",
                name.clone(),
                "attention.decide",
                &v["input"],
            );
            assert_eq!(out["ok"], v["expected"], "{name}");
        },
    );
    run.vectors(
        "attention/vectors/relay-mapping.json",
        14,
        |run, name, v| {
            let out = run.case(
                "attention/vectors/relay-mapping.json",
                name.clone(),
                "attention.relay_mapping",
                &v["input"],
            );
            assert_eq!(out["ok"], v["expected"], "{name}");
        },
    );
}

fn errors(run: &mut Run) {
    let file = "facade";
    for (name, op, input, code) in [
        (
            "unknown_operation",
            "task.unknown",
            b"{}".to_vec(),
            "unknown_operation",
        ),
        ("invalid_json", "task.derive", b"[".to_vec(), "invalid_json"),
        (
            "invalid_input",
            "provenance.join",
            b"{\"inputs\":3}".to_vec(),
            "invalid_input",
        ),
    ] {
        let output = one_core::invoke(op, &input);
        let v: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(v["error"]["code"], code, "{name}");
        assert_eq!(
            one_core::call(op, &input).err().map(|e| e.code()),
            Some(code)
        );
        *run.per_file.entry(file).or_default() += 1;
        run.cases.push(Case {
            name: format!("{file}#{name}"),
            op,
            input,
            output,
        });
    }
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for (i, shift) in [18, 12, 6, 0].into_iter().enumerate() {
            if i <= chunk.len() {
                out.push(char::from(
                    ALPHABET[usize::try_from((n >> shift) & 63).unwrap()],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fn text(bytes: &[u8]) -> Value {
    Value::String(String::from_utf8(bytes.to_vec()).unwrap())
}

#[test]
fn t_38_every_behaviour_vector_runs_through_the_facade_and_is_recorded() {
    let mut run = Run::default();
    provenance(&mut run);
    task(&mut run);
    interaction(&mut run);
    capability(&mut run);
    memory(&mut run);
    attention(&mut run);
    errors(&mut run);
    let operations: Vec<&str> = run.cases.iter().map(|c| c.op).collect();
    for op in one_core::operations() {
        assert!(operations.contains(&op), "{op} has no differential case");
    }
    let cases: Vec<Value> = run
        .cases
        .iter()
        .map(|c| {
            json!({
                "name": c.name,
                "op": c.op,
                "input": text(&c.input),
                "output": text(&c.output),
            })
        })
        .collect();
    let file = json!({
        "version": 1,
        "operations": one_core::operations(),
        "per_file": run.per_file,
        "cases": cases,
    });
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(
        dir.join("one-core-differential.json"),
        one_core::canonical::to_vec(&file),
    )
    .unwrap();
    let mut tsv = String::new();
    for c in &run.cases {
        let _ = writeln!(
            tsv,
            "{}\t{}\t{}\t{}",
            c.name,
            c.op,
            base64(&c.input),
            base64(&c.output)
        );
    }
    std::fs::write(dir.join("one-core-differential.tsv"), tsv).unwrap();
    assert_eq!(base64(b"Ma"), "TWE=");
    assert_eq!(base64(b"Man"), "TWFu");
    assert_eq!(base64(b"M"), "TQ==");
    assert_eq!(run.cases.len(), 282);
}

#[test]
fn t_29_operation_names_round_trip() {
    for op in one_core::Operation::ALL {
        assert_eq!(one_core::Operation::parse(op.as_str()), Some(op));
    }
    assert_eq!(one_core::Operation::parse("provenance"), None);
}
