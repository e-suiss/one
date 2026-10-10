# T-42 (6)

set shell := ["bash", "-euo", "pipefail", "-c"]

core_targets := "aarch64-apple-ios aarch64-apple-ios-sim aarch64-linux-android x86_64-linux-android wasm32-unknown-unknown"
no_std_target := "thumbv7em-none-eabihf"
npm_packages := "packages/config packages/i18n packages/api-client"
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

dev:
    cargo xtask dev-preflight
    just deps

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
    @echo "nothing is generated yet: OpenAPI, AsyncAPI, Protobuf, sqlx metadata, UniFFI, WASM and the TypeScript client come with their Stage 1 contracts"

eval set="evals/tr_en/set.toml" model="" out="runs":
    cd ml && {{uv}} run --locked python -m one_ml.evals run --set {{set}} --model "{{model}}" --code-version "$(git rev-parse HEAD)" --out {{out}}

bench *args:
    cargo bench --locked --workspace -- {{args}}

load addr="127.0.0.1:8091" rate="200" seconds="10":
    cargo run --locked --release -p one-load -- --addr {{addr}} --path /livez --rate {{rate}} --seconds {{seconds}}

profile *args:
    samply record {{args}}

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
