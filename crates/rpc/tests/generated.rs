//! The committed generated code equals what `conformance/rpc` generates; `just gen` rewrites it (T-31, T-42 (6)).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "T-38")]

use std::path::{Path, PathBuf};

use buffa_codegen::generated::descriptor::FileDescriptorSet;
use connectrpc_codegen::codegen::{Options, generate_files};

const PROTO: &str = "one/serving/v1/serving.proto";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn generate() -> Vec<(String, String)> {
    let includes = root().join("conformance/rpc");
    let mut compiler = protox::Compiler::new([&includes]).unwrap();
    compiler.include_imports(true).include_source_info(true);
    compiler.open_file(PROTO).unwrap();
    let bytes = compiler.encode_file_descriptor_set();
    let fds = buffa_codegen::tooling_decode_options()
        .unwrap()
        .decode_from_slice::<FileDescriptorSet>(&bytes)
        .unwrap();
    let mut options = Options::default();
    options.buffa.generate_json = false;
    options.buffa.file_per_package = true;
    generate_files(&fds.file, &[PROTO.to_owned()], &options)
        .unwrap()
        .into_iter()
        .map(|f| (f.name, f.content))
        .collect()
}

#[test]
fn t_31_generated_code_matches_the_committed_files() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/gen");
    for (name, content) in generate() {
        let path = dir.join(&name);
        if std::env::var_os("ONE_UPDATE_RPC").is_some() {
            std::fs::write(&path, &content).unwrap();
        }
        let committed = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(
            committed == content,
            "crates/rpc/src/gen/{name} is stale; run `just gen`"
        );
    }
}
