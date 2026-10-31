//! Schema safety read from the catalog of a migrated database, so every future table is covered without being listed here: forced row-level security, the owner scope prefix, the table owner, no physical delete, pinned search paths, valid indexes, the closed plain-column list and the erasure scope list (T-32 (3, 4, 6, 8), OP-4 (2), OP-7 (3)).

#![allow(clippy::unwrap_used, clippy::panic, reason = "T-38")]

use one_store::testing::fresh;
use serde::Deserialize;
use sqlx::{Connection, PgConnection, Row};

const PLAIN_COLUMNS: &str = include_str!("../../../conformance/store/plain-columns.toml");
const ERASURE_SCOPE: &str = include_str!("../../../conformance/store/erasure-scope.toml");

#[derive(Deserialize)]
struct List {
    encrypted_type: String,
    column: Vec<Listed>,
    encrypted_only: Vec<Named>,
}

#[derive(Deserialize)]
struct Listed {
    name: String,
    sql_type: String,
}

#[derive(Deserialize)]
struct Named {
    name: String,
}

#[derive(Deserialize)]
struct Scope {
    key: Vec<Named>,
    table: Vec<ScopedTable>,
}

#[derive(Deserialize)]
struct ScopedTable {
    name: String,
    personal: bool,
    key: Option<String>,
}

async fn admin() -> PgConnection {
    let db = fresh().await.unwrap();
    PgConnection::connect_with(&db.admin).await.unwrap()
}

async fn strings(c: &mut PgConnection, sql: &'static str) -> Vec<String> {
    sqlx::query(sql)
        .fetch_all(c)
        .await
        .unwrap()
        .iter()
        .map(|r| r.get::<String, _>(0))
        .collect()
}

#[tokio::test]
async fn t_32_every_table_forces_row_level_security_with_a_restrictive_owner_policy() {
    let mut c = admin().await;
    let bad = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'one' AND c.relkind IN ('r', 'p')
            AND (NOT c.relrowsecurity OR NOT c.relforcerowsecurity
                 OR NOT EXISTS (SELECT FROM pg_policy p WHERE p.polrelid = c.oid AND NOT p.polpermissive
                                  AND p.polname = 'owner_scope'))",
    )
    .await;
    assert!(bad.is_empty(), "{bad:?}");
}

#[tokio::test]
async fn t_32_keys_and_foreign_keys_start_with_the_owner() {
    let mut c = admin().await;
    let bad = strings(
        &mut c,
        "SELECT c.relname::text || ' ' || con.conname::text
           FROM pg_constraint con
           JOIN pg_class c ON c.oid = con.conrelid
           JOIN pg_namespace n ON n.oid = c.relnamespace
           JOIN pg_attribute a ON a.attrelid = con.conrelid AND a.attnum = con.conkey[1]
          WHERE n.nspname = 'one' AND con.contype IN ('p', 'f', 'u') AND a.attname <> 'owner'
         UNION ALL
         SELECT t.relname::text || ' ' || i.relname::text
           FROM pg_index x
           JOIN pg_class i ON i.oid = x.indexrelid
           JOIN pg_class t ON t.oid = x.indrelid
           JOIN pg_namespace n ON n.oid = t.relnamespace
           LEFT JOIN pg_attribute a ON a.attrelid = x.indrelid AND a.attnum = x.indkey[0]
          WHERE n.nspname = 'one' AND x.indisunique AND coalesce(a.attname::text, '') <> 'owner'",
    )
    .await;
    assert!(bad.is_empty(), "{bad:?}");
}

#[tokio::test]
async fn t_32_the_owner_role_owns_everything_and_no_role_bypasses_rls() {
    let mut c = admin().await;
    let owners = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'one' AND pg_get_userbyid(c.relowner) <> 'one_owner'
         UNION ALL
         SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'one' AND pg_get_userbyid(p.proowner) <> 'one_owner'",
    )
    .await;
    assert!(owners.is_empty(), "{owners:?}");
    let bypass = strings(
        &mut c,
        "SELECT rolname::text FROM pg_roles
          WHERE rolname LIKE 'one\\_%' AND (rolbypassrls OR rolsuper OR rolcreaterole OR rolcreatedb)",
    )
    .await;
    assert!(bypass.is_empty(), "{bypass:?}");
}

#[tokio::test]
async fn op_6_no_role_but_the_owner_may_delete_or_truncate() {
    let mut c = admin().await;
    let grants = strings(
        &mut c,
        "SELECT table_name::text || ' ' || grantee::text || ' ' || privilege_type::text
           FROM information_schema.role_table_grants
          WHERE table_schema = 'one' AND grantee <> 'one_owner'
            AND privilege_type IN ('DELETE', 'TRUNCATE')",
    )
    .await;
    assert!(grants.is_empty(), "{grants:?}");
    let whole_row_updates = strings(
        &mut c,
        "SELECT table_name::text || ' ' || grantee::text
           FROM information_schema.role_table_grants
          WHERE table_schema = 'one' AND grantee <> 'one_owner' AND privilege_type = 'UPDATE'",
    )
    .await;
    assert!(whole_row_updates.is_empty(), "{whole_row_updates:?}");
}

#[tokio::test]
async fn t_32_functions_pin_their_search_path_and_indexes_are_valid() {
    let mut c = admin().await;
    let unpinned = strings(
        &mut c,
        "SELECT p.proname::text FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'one'
            AND NOT EXISTS (SELECT FROM unnest(coalesce(p.proconfig, '{}')) s WHERE s LIKE 'search\\_path=%')",
    )
    .await;
    assert!(unpinned.is_empty(), "{unpinned:?}");
    let invalid = strings(
        &mut c,
        "SELECT i.relname::text FROM pg_index x
           JOIN pg_class i ON i.oid = x.indexrelid
           JOIN pg_namespace n ON n.oid = i.relnamespace
          WHERE n.nspname = 'one' AND NOT (x.indisvalid AND x.indisready)",
    )
    .await;
    assert!(invalid.is_empty(), "{invalid:?}");
    let unlogged = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'one' AND c.relpersistence = 'u'",
    )
    .await;
    assert!(unlogged.is_empty(), "{unlogged:?}");
}

#[tokio::test]
async fn t_32_columns_are_on_the_plain_list_or_encrypted_bytes() {
    let list: List = toml::from_str(PLAIN_COLUMNS).unwrap();
    let mut c = admin().await;
    let rows = sqlx::query(
        "SELECT table_name::text, column_name::text,
                CASE data_type WHEN 'timestamp with time zone' THEN 'timestamptz' ELSE data_type::text END
           FROM information_schema.columns
          WHERE table_schema = 'one'",
    )
    .fetch_all(&mut c)
    .await
    .unwrap();
    assert!(!rows.is_empty());
    let mut bad = Vec::new();
    for r in &rows {
        let (table, column, ty): (String, String, String) = (r.get(0), r.get(1), r.get(2));
        let ok = if list.encrypted_only.iter().any(|n| n.name == column) {
            false
        } else if let Some(listed) = list.column.iter().find(|l| l.name == column) {
            listed.sql_type == ty
        } else {
            ty == list.encrypted_type
        };
        if !ok {
            bad.push(format!("{table}.{column} {ty}"));
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
}

#[tokio::test]
async fn op_7_every_table_is_on_the_erasure_scope_list() {
    let scope: Scope = toml::from_str(ERASURE_SCOPE).unwrap();
    let mut c = admin().await;
    let tables = strings(
        &mut c,
        "SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
          WHERE n.nspname = 'one' AND c.relkind IN ('r', 'p') ORDER BY 1",
    )
    .await;
    let encrypted = strings(
        &mut c,
        "SELECT DISTINCT table_name::text FROM information_schema.columns
          WHERE table_schema = 'one' AND data_type = 'bytea'",
    )
    .await;
    let mut bad = Vec::new();
    for t in &tables {
        match scope.table.iter().find(|s| &s.name == t) {
            None => bad.push(format!("{t} is not on the list")),
            Some(s) if s.personal => {
                if !s
                    .key
                    .as_ref()
                    .is_some_and(|k| scope.key.iter().any(|n| &n.name == k))
                {
                    bad.push(format!("{t} names no known key"));
                }
            }
            Some(_) if encrypted.contains(t) => {
                bad.push(format!("{t} holds encrypted bytes but is not personal"));
            }
            Some(_) => {}
        }
    }
    for s in &scope.table {
        if !tables.contains(&s.name) {
            bad.push(format!("{} is listed but missing", s.name));
        }
    }
    assert!(bad.is_empty(), "{bad:?}");
}
