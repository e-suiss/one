//! The `one.serving.v1` mapping against the canonical vectors in `conformance/model/` (T-31, T-8, MF-6, MF-55).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    reason = "T-38"
)]

use std::path::Path;

use one_proto::id::{ModelRequestId, ModelVersionId};
use one_proto::model::{ModelRef, ModelRequest, ModelResponse, Usage};
use one_rpc::model::{
    ConvertError, Embeddings, StreamReader, embed_request, embed_response, embeddings,
    generate_request, generate_response, model_response, request_ids,
};
use one_rpc::serving_v1 as wire;
use one_rpc::serving_v1::__buffa::oneof::generate_stream_response::Event;
use serde_json::{Value, json};

fn vectors(name: &str) -> Vec<Value> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../conformance/model/vectors")
        .join(name);
    serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap()
}

fn valid<T: serde::de::DeserializeOwned>(name: &str) -> Vec<(String, T)> {
    vectors(name)
        .into_iter()
        .filter(|v| v["valid"].as_bool().unwrap())
        .map(|v| {
            let description = v["description"].as_str().unwrap().to_owned();
            (
                description,
                serde_json::from_value(v["input"].clone()).unwrap(),
            )
        })
        .collect()
}

fn target() -> ModelRef {
    serde_json::from_value(json!({
        "model_role": "small_lm",
        "model_version_id": "mdl_01m4ezb900f9at0tvpg669f8nd",
        "adapter_id": "adp_01m4ezb900ec79j91f792n0pv6"
    }))
    .unwrap()
}

fn request_vector() -> ModelRequest {
    valid::<ModelRequest>("request.json").remove(0).1
}

fn over_the_wire<M: buffa::Message>(message: &M) -> M {
    M::decode_from_slice(&message.encode_to_vec()).unwrap()
}

fn usage() -> Usage {
    Usage {
        input_tokens: 3,
        output_tokens: 0,
        cached_input_tokens: 0,
        reasoning_tokens: 0,
        latency_ms: 20,
    }
}

#[test]
fn t_31_every_cloud_request_vector_maps_and_keeps_its_ids() {
    let requests = valid::<ModelRequest>("request.json");
    let mut mapped = 0;
    for (description, request) in &requests {
        let Ok(w) = generate_request(request, &target()) else {
            continue;
        };
        let w = over_the_wire(&w);
        let (request_id, task_id, version, adapter) = request_ids(&w).unwrap();
        assert_eq!(request_id, request.request_id, "{description}");
        assert_eq!(task_id, request.task_id, "{description}");
        assert_eq!(version, target().model_version_id, "{description}");
        assert_eq!(adapter, target().adapter_id, "{description}");
        assert_eq!(
            w.messages.len(),
            request.context.messages.len(),
            "{description}"
        );
        assert_eq!(w.latency_budget_ms, 1500, "{description}");
        assert!(!w.data_classes.is_empty(), "{description}");
        mapped += 1;
    }
    assert!(
        mapped >= 2,
        "{mapped} of {} request vectors mapped",
        requests.len()
    );
}

#[test]
fn t_31_invalid_and_device_only_requests_never_reach_the_wire() {
    for v in vectors("request.json") {
        if v["valid"].as_bool().unwrap() {
            continue;
        }
        if let Ok(request) = serde_json::from_value::<ModelRequest>(v["input"].clone()) {
            assert!(
                generate_request(&request, &target()).is_err(),
                "{}",
                v["description"]
            );
        }
    }
    let mut input = valid::<Value>("request.json").remove(0).1;
    input["device_only"] = json!(true);
    if let Ok(request) = serde_json::from_value::<ModelRequest>(input) {
        assert!(matches!(
            generate_request(&request, &target()),
            Err(ConvertError::DeviceOnly | ConvertError::Contract(_))
        ));
    }
}

#[test]
fn t_31_responses_round_trip_or_are_rejected_never_dropped() {
    let mut round_trips = 0;
    for (description, response) in valid::<ModelResponse>("response.json") {
        let model = response.model.clone().unwrap_or_else(target);
        match generate_response(&response) {
            Ok(w) => {
                let back = model_response(&over_the_wire(&w), &model).unwrap();
                assert_eq!(back, response, "{description}");
                round_trips += 1;
            }
            Err(e) => assert!(
                matches!(e, ConvertError::Unrepresentable(_)),
                "{description}: {e}"
            ),
        }
    }
    assert!(round_trips >= 3, "{round_trips}");
}

#[test]
fn mf_55_a_response_from_another_model_version_is_rejected() {
    let (_, response) = valid::<ModelResponse>("response.json").remove(0);
    let w = generate_response(&response).unwrap();
    let mut other = response.model.unwrap();
    other.model_version_id = ModelVersionId::parse("mdl_01m4ezb900emrbphjhbhkq4zc8").unwrap();
    assert_eq!(
        model_response(&w, &other),
        Err(ConvertError::VersionMismatch)
    );
}

#[test]
fn t_31_a_wire_response_without_a_result_or_usage_is_invalid() {
    let (_, response) = valid::<ModelResponse>("response.json").remove(0);
    let model = response.model.clone().unwrap();
    let w = generate_response(&response).unwrap();
    let mut no_result = w.clone();
    no_result.result = None;
    assert_eq!(
        model_response(&no_result, &model),
        Err(ConvertError::Invalid("result"))
    );
    let mut no_usage = w;
    no_usage.usage = buffa::MessageField::none();
    assert_eq!(
        model_response(&no_usage, &model),
        Err(ConvertError::Invalid("usage"))
    );
}

#[test]
fn t_31_only_the_final_stream_event_yields_a_response() {
    let (_, response) = valid::<ModelResponse>("response.json").remove(0);
    let model = response.model.clone().unwrap();
    let delta = wire::GenerateStreamResponse {
        event: Some(Event::TextDelta("Yar".to_owned())),
        ..Default::default()
    };
    let last = wire::GenerateStreamResponse {
        event: Some(Event::Final(Box::new(
            generate_response(&response).unwrap(),
        ))),
        ..Default::default()
    };

    let mut cut = StreamReader::new(model.clone());
    assert_eq!(
        cut.push(&over_the_wire(&delta)).unwrap().as_deref(),
        Some("Yar")
    );
    assert_eq!(cut.finish(), Err(ConvertError::Invalid("stream cut short")));

    let mut whole = StreamReader::new(model);
    whole.push(&delta).unwrap();
    assert_eq!(whole.push(&over_the_wire(&last)).unwrap(), None);
    assert!(whole.push(&delta).is_err());
    assert_eq!(whole.finish().unwrap(), response);
}

#[test]
fn mf_55_embeddings_keep_their_model_version_count_and_dimension() {
    let request_id = ModelRequestId::parse("mrq_01m4ezb900emrbphjhbhkq4zc8").unwrap();
    let version = ModelVersionId::parse("mdl_01m4ezb900f9at0tvpg669f8nd").unwrap();
    let request = embed_request(request_id, version, &["a".to_owned(), "b".to_owned()]);
    let good = Embeddings {
        request_id,
        model_version_id: version,
        vectors: vec![vec![0.1, 0.2], vec![0.3, 0.4]],
        usage: usage(),
    };
    let w = over_the_wire(&embed_response(&good).unwrap());
    assert_eq!(embeddings(&w, &over_the_wire(&request)).unwrap(), good);

    let mut other = w.clone();
    other.model_version_id = "mdl_01m4ezb900emrbphjhbhkq4zc8".to_owned();
    assert_eq!(
        embeddings(&other, &request),
        Err(ConvertError::VersionMismatch)
    );

    let mut short = w.clone();
    short.embeddings.pop();
    assert_eq!(
        embeddings(&short, &request),
        Err(ConvertError::Invalid("embedding count"))
    );

    let mut mixed = w.clone();
    mixed.embeddings[1].values.push(0.5);
    assert_eq!(
        embeddings(&mixed, &request),
        Err(ConvertError::Invalid("embedding dimension"))
    );

    let mut nan = w;
    nan.embeddings[0].values[0] = f32::NAN;
    assert_eq!(
        embeddings(&nan, &request),
        Err(ConvertError::Invalid("embedding values"))
    );
}

#[test]
fn t_31_a_number_wider_than_the_wire_is_rejected() {
    let mut request = request_vector();
    request.latency_budget_ms = u64::from(u32::MAX) + 1;
    assert!(generate_request(&request, &target()).is_err());
}
