#!/usr/bin/env bash
# T-32 (1)
set -euo pipefail

out="$1"
: "${DATABASE_URL:?a superuser URL whose last path segment names the compile database}"
base="${DATABASE_URL%/*}"
db="${DATABASE_URL##*/}"
psql -X -q -v ON_ERROR_STOP=1 "$base/postgres" -c "DROP DATABASE IF EXISTS $db" -c "CREATE DATABASE $db"
psql -X -q -v ON_ERROR_STOP=1 "$base/postgres" -f crates/store/bootstrap/roles.sql
psql -X -q -v ON_ERROR_STOP=1 "$DATABASE_URL" -f crates/store/bootstrap/database.sql
for f in crates/store/migrations/*.sql; do
    if head -1 "$f" | grep -qx -- '-- no-transaction'; then
        psql -X -q -v ON_ERROR_STOP=1 "$DATABASE_URL" -f "$f"
    else
        psql -X -q -v ON_ERROR_STOP=1 --single-transaction "$DATABASE_URL" -f "$f"
    fi
done
rm -rf "$out"
mkdir -p "$out"
touch crates/store/src/*.rs crates/store/tests/*.rs
SQLX_OFFLINE=false SQLX_OFFLINE_DIR="$out" cargo check --locked -p one-store --all-targets --features testing
diff -r .sqlx "$out"
