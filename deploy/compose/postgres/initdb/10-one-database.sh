#!/usr/bin/env bash
# T-32 (3, 6, 8)
set -euo pipefail

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres -f /one-bootstrap/roles.sql

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres \
    -v db="$ONE_DB_NAME" \
    -v migrate_password="$ONE_MIGRATE_PASSWORD" \
    -v app_password="$ONE_APP_PASSWORD" \
    -v queue_password="$ONE_QUEUE_PASSWORD" <<'SQL'
CREATE ROLE one_migrate LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'migrate_password' IN ROLE one_owner;
CREATE ROLE one_api LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'app_password' IN ROLE one_app;
CREATE ROLE one_worker LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS
    PASSWORD :'queue_password' IN ROLE one_queue;

CREATE DATABASE :"db";
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO one_migrate, one_api, one_worker;
GRANT CREATE ON DATABASE :"db" TO one_owner;
SQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$ONE_DB_NAME" -f /one-bootstrap/database.sql
