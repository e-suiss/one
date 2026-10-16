//! The model request, response, registry, routing and embedding types against `conformance/model/` (MF-6, MF-22, MF-55).

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

use one_proto::model::response::Outcome;
use one_proto::model::routing::{Fallback, GateResult};
use one_proto::model::{
    EmbeddingVector, ErrorCode, ModelRequest, ModelResponse, Registry, RegistryEntry, RoutingRecord,
};
use serde_json::json;
use support::{check_schema_vectors, vectors};

#[test]
fn mf_6_request_schema_vectors() {
    let n = check_schema_vectors::<ModelRequest, _>(
        "model/vectors/request.json",
        ModelRequest::validate,
    );
    assert_eq!((n.valid, n.invalid), (3, 15));
}

#[test]
fn mf_6_response_schema_vectors() {
    let n = check_schema_vectors::<ModelResponse, _>(
        "model/vectors/response.json",
        ModelResponse::validate,
    );
    assert_eq!((n.valid, n.invalid), (6, 10));
}

#[test]
fn mf_6_error_set_is_closed_and_responses_split_into_output_or_error() {
    for v in vectors("model/vectors/response.json") {
        if !v["valid"].as_bool().unwrap() {
            continue;
        }
        let response: ModelResponse = serde_json::from_value(v["input"].clone()).unwrap();
        match response.result().unwrap() {
            Ok((model, _)) => assert_eq!(response.outcome, Outcome::Ok, "{model:?}"),
            Err(error) => assert!(matches!(
                error.code,
                ErrorCode::RateLimited
                    | ErrorCode::Refusal
                    | ErrorCode::ContextSizeExceeded
                    | ErrorCode::Unavailable
            )),
        }
    }
    assert!(serde_json::from_value::<ErrorCode>(json!("timeout")).is_err());
}

#[test]
fn mf_55_registry_entry_schema_vectors() {
    let n = check_schema_vectors::<RegistryEntry, _>(
        "model/vectors/registry-entry.json",
        RegistryEntry::validate,
    );
    assert_eq!((n.valid, n.invalid), (4, 22));
}

#[test]
fn mf_55_released_entry_needs_signature_and_passed_gate() {
    let all = vectors("model/vectors/registry-entry.json");
    let released: RegistryEntry = serde_json::from_value(all[0]["input"].clone()).unwrap();
    assert!(released.is_releasable());
    let mut unsigned = released.clone();
    unsigned.signature = Some(" ".to_owned());
    assert!(!unsigned.is_releasable());
    assert!(unsigned.validate().is_err());
    let mut ungated = released.clone();
    ungated.evaluation.gate = one_proto::model::registry::Gate::Failed;
    assert!(ungated.validate().is_err());
    let registry = Registry {
        model: Some(vec![released, ungated]),
    };
    assert_eq!(registry.releasable().count(), 1);
}

#[test]
fn mf_22_routing_record_schema_vectors() {
    let n = check_schema_vectors::<RoutingRecord, _>(
        "model/vectors/routing-record.json",
        RoutingRecord::validate,
    );
    assert_eq!((n.valid, n.invalid), (4, 17));
}

#[test]
fn mf_22_routing_record_splits_into_memory_and_provider_trace_parts() {
    let all = vectors("model/vectors/routing-record.json");
    let record: RoutingRecord = serde_json::from_value(all[0]["input"].clone()).unwrap();
    let (memory, trace) = record.split();
    let memory = serde_json::to_value(&memory).unwrap();
    let trace = serde_json::to_value(&trace).unwrap();
    assert_eq!(memory["retention_class"], "one_memory");
    assert_eq!(trace["retention_class"], "one_provider_trace");
    assert!(memory.get("hops").is_none());
    assert!(trace.get("gate").is_none());
    let waiting: RoutingRecord = all
        .iter()
        .filter(|v| v["valid"].as_bool().unwrap())
        .map(|v| serde_json::from_value::<RoutingRecord>(v["input"].clone()).unwrap())
        .find(|r| r.memory_part.gate.result == GateResult::WaitingNoModel)
        .unwrap();
    assert_eq!(waiting.memory_part.fallback, Fallback::Wait);
    assert_eq!(waiting.provider_trace_part.hops.len(), 0);
}

#[test]
fn mf_55_embedding_vector_schema_vectors() {
    let n = check_schema_vectors::<EmbeddingVector, _>(
        "model/vectors/embedding-vector.json",
        EmbeddingVector::validate,
    );
    assert_eq!((n.valid, n.invalid), (1, 3));
}

#[test]
fn mf_55_vectors_of_different_embedding_models_never_mix() {
    let all = vectors("model/vectors/embedding-vector.json");
    let a: EmbeddingVector = serde_json::from_value(all[0]["input"].clone()).unwrap();
    assert!(a.same_space(&a));
    let mut b = all[0]["input"].clone();
    b["embedding_model"]["model_version_id"] = json!("mdl_01m4ezb900f9at0tvpg669f8nd");
    let b: EmbeddingVector = serde_json::from_value(b).unwrap();
    assert!(!a.same_space(&b));
    let mut short = a.clone();
    short.values.pop();
    assert!(short.validate().is_err());
}
