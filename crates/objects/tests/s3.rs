//! Against a real S3-compatible store (T-32 (9)): ciphertext round-trips, an object id is written once and a missing object is reported as missing. The store comes from `ONE_TEST_S3_*`, as CI and `just deps` provide it.

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use one_objects::{Objects, ObjectsError, Settings};
use one_proto::ObjectId;
use one_proto::id::uuid_v7;

fn var(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("object store tests need {name}"))
}

fn objects() -> Objects {
    let endpoint = var("ONE_TEST_S3_ENDPOINT");
    let bucket = var("ONE_TEST_S3_BUCKET");
    let access_key = var("ONE_TEST_S3_ACCESS_KEY");
    let secret_key = var("ONE_TEST_S3_SECRET_KEY");
    Objects::s3(&Settings {
        allow_http: endpoint.starts_with("http://"),
        endpoint: &endpoint,
        bucket: &bucket,
        region: "us-east-1",
        access_key: &access_key,
        secret_key: &secret_key,
    })
    .unwrap()
}

fn fresh_id(tag: u8) -> ObjectId {
    let pid = std::process::id().to_be_bytes();
    let random = [tag, pid[0], pid[1], pid[2], pid[3], 0, 0, 0, 0, tag];
    ObjectId::from_bytes(uuid_v7(1_791_504_000_000, random)).unwrap()
}

#[tokio::test]
async fn t_5_ciphertext_round_trips() {
    let store = objects();
    let id = fresh_id(1);
    store.put("party:a", id, vec![7; 4096]).await.unwrap();
    assert_eq!(store.get("party:a", id).await.unwrap(), vec![7; 4096]);
    assert!(matches!(
        store.get("party:b", id).await,
        Err(ObjectsError::Missing)
    ));
}

#[tokio::test]
async fn op_6_an_object_is_never_overwritten() {
    let store = objects();
    let id = fresh_id(2);
    store.put("party:a", id, vec![1]).await.unwrap();
    assert!(matches!(
        store.put("party:a", id, vec![2]).await,
        Err(ObjectsError::Exists)
    ));
    assert_eq!(store.get("party:a", id).await.unwrap(), vec![1]);
}
