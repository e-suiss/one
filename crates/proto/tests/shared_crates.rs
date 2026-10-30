//! The shared Suiss crates bound from crates.io at their published API: deterministic CBOR and RFC 9162 digests, the ledger Merkle frontier and the forbid-only restriction profile (T-26 (3), Access OP-76).

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "T-38"
)]

use suiss_crypto::dcbor::{Limits, Value, decode, encode};
use suiss_crypto::digest::{leaf_hash, root};
use suiss_ledger::merkle::Frontier;
use suiss_restriction::{Denial, Engine, Outcome, RequestJson};

const LEAVES: [&str; 8] = [
    "",
    "00",
    "10",
    "2021",
    "3031",
    "40414243",
    "5051525354555657",
    "606162636465666768696a6b6c6d6e6f",
];

const ROOT_3: &str = "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77";
const ROOT_8: &str = "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328";

fn bytes(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(core::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}

#[test]
fn t_26_dcbor_encodes_rfc_8949_map_canonically() {
    let map = Value::Map(vec![
        (Value::Unsigned(3), Value::Unsigned(4)),
        (Value::Unsigned(1), Value::Unsigned(2)),
    ]);
    let encoded = encode(&map, Limits::CEILING).unwrap();
    assert_eq!(encoded, bytes("a201020304"));
    assert!(decode(&bytes("a203040102"), Limits::CEILING).is_err());
}

#[test]
fn t_26_digest_root_matches_rfc_9162_vector() {
    let leaves: Vec<Vec<u8>> = LEAVES.iter().map(|l| bytes(l)).collect();
    let refs: Vec<&[u8]> = leaves.iter().map(Vec::as_slice).collect();
    assert_eq!(root(&refs[..3]).to_vec(), bytes(ROOT_3));
    assert_eq!(root(&refs).to_vec(), bytes(ROOT_8));
}

#[test]
fn t_26_ledger_frontier_appends_to_the_vector_root() {
    let mut frontier = Frontier::default();
    for (i, leaf) in LEAVES.iter().enumerate() {
        if i == 3 {
            assert_eq!(frontier.root().to_vec(), bytes(ROOT_3));
        }
        frontier.push(leaf_hash(&bytes(leaf))).unwrap();
    }
    assert_eq!(frontier.size(), 8);
    assert_eq!(frontier.nodes().len(), 1);
    assert_eq!(frontier.root().to_vec(), bytes(ROOT_8));
}

#[test]
fn t_26_restriction_profile_forbids_only() {
    let schema = r"
entity Actor { tenant: String };
entity Resource { tenant: String };
action read appliesTo { principal: [Actor], resource: [Resource] };
";
    let source = r#"@id("cross-tenant") forbid(principal, action, resource) when { principal.tenant != resource.tenant };"#;
    let engine = Engine::compile(schema, source, suiss_restriction::Limits::default()).unwrap();
    assert!(
        Engine::compile(
            schema,
            r#"@id("p") permit(principal, action, resource);"#,
            suiss_restriction::Limits::default()
        )
        .is_err()
    );
    let evaluate = |resource_tenant: &str| {
        let entities = format!(
            r#"[{{"uid":{{"type":"Actor","id":"a1"}},"attrs":{{"tenant":"t1"}},"parents":[]}},
                {{"uid":{{"type":"Resource","id":"r1"}},"attrs":{{"tenant":"{resource_tenant}"}},"parents":[]}}]"#
        );
        engine
            .evaluate(&RequestJson {
                principal: r#"Actor::"a1""#,
                action: r#"Action::"read""#,
                resource: r#"Resource::"r1""#,
                context: "{}",
                entities: &entities,
            })
            .unwrap()
    };
    assert_eq!(evaluate("t1"), Outcome::NoObjection);
    assert_eq!(
        evaluate("t2"),
        Outcome::Deny(Denial::Forbid {
            policies: vec!["cross-tenant".to_owned()],
            undisclosed: false,
        })
    );
}
