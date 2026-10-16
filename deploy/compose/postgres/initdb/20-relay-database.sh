#!/usr/bin/env bash
# T-42 (1)
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v password="$RELAY_DB_PASSWORD" <<'SQL'
CREATE ROLE relay LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'password';
CREATE DATABASE relay OWNER relay;
REVOKE ALL ON DATABASE relay FROM PUBLIC;
SQL
