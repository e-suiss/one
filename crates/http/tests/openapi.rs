//! The committed OpenAPI document equals the one generated from code; `just gen` rewrites it (T-31).

#![allow(clippy::unwrap_used, reason = "T-38")]

use std::path::Path;

const COMMITTED: &str = "../../conformance/openapi/one.v1.json";

#[test]
fn t_31_openapi_matches_the_committed_document() {
    let generated = one_http::openapi::document().unwrap();
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(COMMITTED);
    if std::env::var_os("ONE_UPDATE_OPENAPI").is_some() {
        std::fs::write(&path, &generated).unwrap();
    }
    let committed = std::fs::read_to_string(&path).unwrap_or_default();
    assert!(
        committed == generated,
        "conformance/openapi/one.v1.json is stale; run `just gen`"
    );
}
