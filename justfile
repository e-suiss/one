# T-42 (6)

set shell := ["bash", "-euo", "pipefail", "-c"]

core_targets := "aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android wasm32-unknown-unknown"
no_std_target := "thumbv7em-none-eabihf"
npm_packages := "packages/config packages/i18n packages/api-client packages/core"
compose := "docker compose -f deploy/compose/compose.yaml"
dev_db_password := "local-only-not-a-secret"
uv := "uvx --from uv==0.12.22 uv"

default:
    @just --list

check: fmt-check lint rules deny ml-check web-check

test:
    cargo nextest run --workspace --locked --no-tests=pass
    cargo test --workspace --locked --doc
    cd ml && {{uv}} run --locked pytest -q
    just differential-wasm

fmt:
    cargo fmt --all

fmt-check:
    cargo fmt --all -- --check

lint:
    cargo clippy --workspace --all-targets --locked -- -D warnings

rules:
    cargo fetch --locked
    cargo xtask check

deny:
    cargo deny --locked check

vet:
    cargo vet --locked

audit:
    cargo audit

semgrep:
    semgrep scan --config .semgrep/ --error --metrics=off

secrets:
    gitleaks git --redact --no-banner --exit-code 1 --config .gitleaks.toml .

commits base head:
    cargo xtask commits {{base}} {{head}}

coverage:
    cargo xtask coverage

catalog:
    cargo xtask catalog

cross:
    for t in {{core_targets}}; do cargo build --locked -p one-core --target "$t"; done
    for c in one-proto one-provenance one-interaction one-runtime; do cargo build --locked -p "$c" --target {{no_std_target}}; done

ml-check:
    cd ml && {{uv}} sync --locked --quiet
    cd ml && {{uv}} run --locked ruff format --check .
    cd ml && {{uv}} run --locked ruff check .
    cd ml && {{uv}} run --locked mypy
    cd ml && {{uv}} run --locked python -m one_ml.guard

ml-audit:
    cd ml && {{uv}} run --locked pip-audit --skip-editable

web-install:
    for p in {{npm_packages}}; do (cd "$p" && npm ci); done

web-check:
    for p in {{npm_packages}}; do (cd "$p" && npm run --if-present lint && npm run --if-present typecheck && npm run --if-present format:check && npm run --if-present check && npm test --if-present); done

web-audit:
    for p in {{npm_packages}}; do (cd "$p" && npm audit --audit-level=high); done

deps:
    {{compose}} up --detach --wait
    @echo "PostgreSQL     postgres://one_app@127.0.0.1:${ONE_DEV_PG_PORT:-5433}/one"
    @echo "Object store   http://127.0.0.1:${ONE_DEV_S3_PORT:-8334}  bucket one-dev"
    @echo "Grafana        http://127.0.0.1:${ONE_DEV_GRAFANA_PORT:-3301}"
    @echo "Jaeger         http://127.0.0.1:${ONE_DEV_JAEGER_UI_PORT:-16687}   Prometheus http://127.0.0.1:${ONE_DEV_PROMETHEUS_PORT:-9091}"
    @echo "OTLP           127.0.0.1:${ONE_DEV_OTLP_GRPC_PORT:-4327} (gRPC), 127.0.0.1:${ONE_DEV_OTLP_HTTP_PORT:-4328} (HTTP)"

siblings:
    {{compose}} -f deploy/compose/siblings.yaml up --detach --wait
    @echo "Access         http://127.0.0.1:${ONE_DEV_ACCESS_PORT:-8180}/healthz"
    @echo "Relay          http://127.0.0.1:${ONE_DEV_RELAY_PORT:-8200}/readyz"
    @echo "Work           127.0.0.1:${ONE_DEV_WORK_PORT:-8190}"

dev:
    cargo xtask dev-preflight
    just deps
    just siblings

dev-model:
    {{compose}} --profile model up --detach --wait model embedding

dev-down:
    {{compose}} --profile model down

dev-status:
    {{compose}} ps

db-reset:
    {{compose}} rm --stop --force postgres
    docker volume rm --force one-dev_pgdata
    {{compose}} up --detach --wait postgres

psql:
    {{compose}} exec -e PGPASSWORD={{dev_db_password}} postgres psql -h 127.0.0.1 -U one_app -d one

serve:
    cargo run --locked -p one-server

gen:
    ONE_UPDATE_OPENAPI=1 cargo test --locked -q -p one-http --test openapi
    ONE_UPDATE_RPC=1 cargo test --locked -q -p one-rpc --test generated
    just bindings

bindings:
    cargo build --locked -q -p one-core-uniffi
    for l in swift kotlin; do rm -rf "core/bindings/uniffi/generated/$l"; cargo run --locked -q -p one-uniffi-bindgen -- generate "target/debug/libone_core_uniffi.$([[ "$(uname)" == Darwin ]] && echo dylib || echo so)" --no-format -c core/bindings/uniffi/bindgen.toml -l "$l" -o "core/bindings/uniffi/generated/$l"; done

differential-cases:
    cargo test --locked -q -p one-core --test differential

differential-wasm: differential-cases
    cd packages/core && npm run -s build:wasm && npm run -s test:differential

differential-swift: differential-cases
    cargo build --locked -q -p one-core-uniffi
    swiftc -O -module-name OneCore -I core/bindings/uniffi/generated/swift -Xcc -fmodule-map-file=core/bindings/uniffi/generated/swift/OneCoreFFI.modulemap core/bindings/uniffi/generated/swift/OneCore.swift core/bindings/uniffi/tests/swift/main.swift target/debug/libone_core_uniffi.a -o target/tmp/one-core-swift
    target/tmp/one-core-swift target/tmp/one-core-differential.tsv

differential-kotlin jna kotlin_stdlib: differential-cases
    cargo build --locked -q -p one-core-uniffi
    kotlinc core/bindings/uniffi/generated/kotlin/app/suiss/one/core/one_core.kt core/bindings/uniffi/tests/kotlin/Differential.kt -cp {{jna}} -d target/tmp/one-core-kotlin.jar
    java -Djna.library.path=target/debug -cp "target/tmp/one-core-kotlin.jar:{{jna}}:{{kotlin_stdlib}}" app.suiss.one.core.differential.DifferentialKt target/tmp/one-core-differential.tsv

eval set="evals/tr_en/set.toml" model="" out="runs":
    cd ml && {{uv}} run --locked python -m one_ml.evals run --set {{set}} --model "{{model}}" --code-version "$(git rev-parse HEAD)" --out {{out}}

bench *args:
    cargo bench --locked --workspace -- {{args}}

load addr="127.0.0.1:8091" rate="200" seconds="10":
    cargo run --locked --release -p one-load -- --addr {{addr}} --path /livez --rate {{rate}} --seconds {{seconds}}

profile *args:
    samply record {{args}}

pull ref="main":
    docker pull "ghcr.io/e-suiss/one:{{ref}}"

image tag="one-server:local":
    docker build -f deploy/docker/Dockerfile -t {{tag}} .

release-build target:
    rm -rf target/vendor && mkdir -p target
    cargo vendor --locked --versioned-dirs target/vendor > target/vendor-config.toml
    RUSTFLAGS="--remap-path-prefix={{justfile_directory()}}=/one --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo" \
      cargo auditable build --locked --offline --config "{{justfile_directory()}}/target/vendor-config.toml" --release -p one-server --target {{target}}

sbom target binary out:
    mkdir -p {{out}}
    cargo cyclonedx --manifest-path bins/one-server/Cargo.toml --format json --spec-version 1.5 --target {{target}}
    find bins crates xtask -name '*.cdx.json' -not -path '*/target/*' -exec mv {} {{out}}/ \;
    syft scan "file:{{binary}}" -o "spdx-json={{out}}/one-server.spdx.json"

changelog:
    git cliff --output CHANGELOG.md
