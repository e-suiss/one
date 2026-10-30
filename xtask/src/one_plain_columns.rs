//! `plain-columns`: every column the migrations create is either on the closed plain list of `conformance/store/plain-columns.toml` with its listed type and value `CHECK`, or encrypted `bytea`; an encrypted-only name is never a column (T-32 (4, 8), OP-4 (2), OP-5, PV-6).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde::Deserialize;

use super::migrations::DIR;
use super::v;
use crate::Violation;
use crate::rules::files::read;

pub(crate) const LIST: &str = "conformance/store/plain-columns.toml";

#[derive(Debug, Deserialize)]
pub(crate) struct List {
    pub(crate) encrypted_type: String,
    #[serde(default)]
    pub(crate) column: Vec<Listed>,
    #[serde(default)]
    pub(crate) encrypted_only: Vec<Named>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Listed {
    pub(crate) name: String,
    pub(crate) sql_type: String,
    #[serde(default)]
    pub(crate) values: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct Named {
    pub(crate) name: String,
}

/// Why a column is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reason {
    UnlistedPlainColumn,
    EncryptedOnly,
    ListedType,
    ListedValues,
}

impl Reason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::UnlistedPlainColumn => "unlisted_plain_column",
            Self::EncryptedOnly => "encrypted_only",
            Self::ListedType => "listed_type",
            Self::ListedValues => "listed_values",
        }
    }

    const fn message(self) -> &'static str {
        match self {
            Self::UnlistedPlainColumn => {
                "not on the plain-column list: an encrypted column is bytea (T-32 (4))"
            }
            Self::EncryptedOnly => "lives inside the ciphertext and is never a column (OP-4 (2))",
            Self::ListedType => "a listed column has exactly its listed SQL type (T-32 (4))",
            Self::ListedValues => {
                "a listed column with values needs a CHECK over those values only (OP-4 (2))"
            }
        }
    }
}

/// Judges one column: `Ok(true)` for a listed plain column, `Ok(false)` for an encrypted one.
pub(crate) fn judge(
    list: &List,
    column: &str,
    sql_type: &str,
    check: Option<&[String]>,
) -> Result<bool, Reason> {
    if list.encrypted_only.iter().any(|n| n.name == column) {
        return Err(Reason::EncryptedOnly);
    }
    let Some(listed) = list.column.iter().find(|c| c.name == column) else {
        return if sql_type == list.encrypted_type {
            Ok(false)
        } else {
            Err(Reason::UnlistedPlainColumn)
        };
    };
    if listed.sql_type != sql_type {
        return Err(Reason::ListedType);
    }
    if let Some(values) = &listed.values {
        let ok = check.is_some_and(|c| !c.is_empty() && c.iter().all(|x| values.contains(x)));
        if !ok {
            return Err(Reason::ListedValues);
        }
    }
    Ok(true)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Token {
    Word(String),
    Quoted(String),
    Text(String),
    Punct(char),
}

fn tokens(sql: &str) -> Vec<Token> {
    let mut out = Vec::new();
    let chars: Vec<char> = sql.chars().collect();
    let mut i = 0_usize;
    let at = |i: usize| chars.get(i).copied();
    while let Some(c) = at(i) {
        if c == '-' && at(i.saturating_add(1)) == Some('-') {
            while at(i).is_some_and(|c| c != '\n') {
                i = i.saturating_add(1);
            }
        } else if c == '/' && at(i.saturating_add(1)) == Some('*') {
            i = i.saturating_add(2);
            while at(i).is_some() && !(at(i) == Some('*') && at(i.saturating_add(1)) == Some('/')) {
                i = i.saturating_add(1);
            }
            i = i.saturating_add(2);
        } else if c == '\'' || c == '"' {
            let mut s = String::new();
            i = i.saturating_add(1);
            while let Some(d) = at(i) {
                if d == c {
                    if at(i.saturating_add(1)) == Some(c) {
                        s.push(c);
                        i = i.saturating_add(2);
                        continue;
                    }
                    break;
                }
                s.push(d);
                i = i.saturating_add(1);
            }
            i = i.saturating_add(1);
            out.push(if c == '"' {
                Token::Quoted(s)
            } else {
                Token::Text(s)
            });
        } else if c.is_alphanumeric() || c == '_' {
            let mut s = String::new();
            while let Some(d) = at(i).filter(|d| d.is_alphanumeric() || *d == '_' || *d == '$') {
                s.push(d.to_ascii_lowercase());
                i = i.saturating_add(1);
            }
            out.push(Token::Word(s));
        } else {
            if !c.is_whitespace() {
                out.push(Token::Punct(c));
            }
            i = i.saturating_add(1);
        }
    }
    out
}

fn word(t: Option<&Token>) -> Option<&str> {
    match t {
        Some(Token::Word(w)) => Some(w),
        _ => None,
    }
}

fn ident(t: Option<&Token>) -> Option<String> {
    match t {
        Some(Token::Word(w) | Token::Quoted(w)) => Some(w.clone()),
        _ => None,
    }
}

/// Splits on commas outside parentheses and brackets.
fn split_top(tokens: &[Token]) -> Vec<&[Token]> {
    let mut out = Vec::new();
    let mut depth = 0_i32;
    let mut start = 0;
    for (i, t) in tokens.iter().enumerate() {
        match t {
            Token::Punct('(' | '[') => depth = depth.saturating_add(1),
            Token::Punct(')' | ']') => depth = depth.saturating_sub(1),
            Token::Punct(',') if depth == 0 => {
                out.push(tokens.get(start..i).unwrap_or_default());
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    out.push(tokens.get(start..).unwrap_or_default());
    out.into_iter().filter(|s| !s.is_empty()).collect()
}

/// The tokens inside the parenthesis that opens at `open`, and the index after it.
fn group(tokens: &[Token], open: usize) -> Option<(&[Token], usize)> {
    if tokens.get(open) != Some(&Token::Punct('(')) {
        return None;
    }
    let mut depth = 0_i32;
    for (i, t) in tokens.iter().enumerate().skip(open) {
        match t {
            Token::Punct('(') => depth = depth.saturating_add(1),
            Token::Punct(')') => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some((tokens.get(open.saturating_add(1)..i)?, i.saturating_add(1)));
                }
            }
            _ => {}
        }
    }
    None
}

const COLUMN_STOP: &[&str] = &[
    "not",
    "null",
    "default",
    "primary",
    "references",
    "check",
    "unique",
    "constraint",
    "generated",
    "collate",
];

const TABLE_CONSTRAINT: &[&str] = &[
    "constraint",
    "primary",
    "foreign",
    "unique",
    "check",
    "exclude",
    "like",
];

fn normalize_type(parts: &[String]) -> String {
    let joined = parts
        .join(" ")
        .replace(" (", "(")
        .replace("( ", "(")
        .replace(" )", ")");
    let joined = joined
        .replace(" [", "[")
        .replace("[ ", "[")
        .replace(" ]", "]");
    match joined.as_str() {
        "timestamp with time zone" => "timestamptz".to_owned(),
        "timestamp" | "timestamp without time zone" => "timestamp".to_owned(),
        "int" | "int4" => "integer".to_owned(),
        "int8" => "bigint".to_owned(),
        "int2" => "smallint".to_owned(),
        "bool" => "boolean".to_owned(),
        _ => joined,
    }
}

fn render(tokens: &[Token]) -> Vec<String> {
    tokens
        .iter()
        .map(|t| match t {
            Token::Word(w) | Token::Quoted(w) | Token::Text(w) => w.clone(),
            Token::Punct(c) => c.to_string(),
        })
        .collect()
}

/// `(column, values)` of every `CHECK (column IN ('a', ...))` in `tokens`.
fn checks(tokens: &[Token]) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    for (i, t) in tokens.iter().enumerate() {
        if word(Some(t)) != Some("check") {
            continue;
        }
        let Some((inner, _)) = group(tokens, i.saturating_add(1)) else {
            continue;
        };
        let (Some(col), Some("in")) = (ident(inner.first()), word(inner.get(1))) else {
            continue;
        };
        let Some((list, _)) = group(inner, 2) else {
            continue;
        };
        let values = list
            .iter()
            .filter_map(|t| match t {
                Token::Text(s) => Some(s.clone()),
                _ => None,
            })
            .collect();
        out.push((col, values));
    }
    out
}

/// A column definition: name, normalized type and the values of its inline `CHECK`.
fn column_def(def: &[Token]) -> Option<(String, String, Option<Vec<String>>)> {
    let name = ident(def.first())?;
    let mut parts = Vec::new();
    let mut end = def.len();
    for (i, t) in def.iter().enumerate().skip(1) {
        if word(Some(t)).is_some_and(|w| COLUMN_STOP.contains(&w)) {
            end = i;
            break;
        }
    }
    parts.extend(render(def.get(1..end).unwrap_or_default()));
    let check = checks(def.get(end..).unwrap_or_default())
        .into_iter()
        .find(|(c, _)| *c == name)
        .map(|(_, v)| v);
    Some((name, normalize_type(&parts), check))
}

/// One column the migrations create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Column {
    pub(crate) table: String,
    pub(crate) name: String,
    pub(crate) sql_type: String,
    pub(crate) check: Option<Vec<String>>,
}

fn skip_words(tokens: &[Token], mut i: usize, words: &[&str]) -> usize {
    while word(tokens.get(i)).is_some_and(|w| words.contains(&w)) {
        i = i.saturating_add(1);
    }
    i
}

fn table_name(tokens: &[Token], i: usize) -> Option<(String, usize)> {
    let mut name = ident(tokens.get(i))?;
    let mut next = i.saturating_add(1);
    if tokens.get(next) == Some(&Token::Punct('.')) {
        name = ident(tokens.get(next.saturating_add(1)))?;
        next = next.saturating_add(2);
    }
    Some((name, next))
}

fn add_check(columns: &mut [Column], table: &str, col: &str, values: Vec<String>) {
    if let Some(c) = columns
        .iter_mut()
        .find(|c| c.table == table && c.name == col)
    {
        c.check = Some(values);
    }
}

/// The columns created by a migration file, in order, with table-level `CHECK`s attached.
pub(crate) fn columns(sql: &str, out: &mut Vec<Column>) {
    let all = tokens(sql);
    for stmt in all.split(|t| *t == Token::Punct(';')) {
        match (word(stmt.first()), word(stmt.get(1))) {
            (Some("create"), _) => {
                let mut i = skip_words(stmt, 1, &["unlogged", "temporary", "temp"]);
                if word(stmt.get(i)) != Some("table") {
                    continue;
                }
                i = skip_words(stmt, i.saturating_add(1), &["if", "not", "exists"]);
                let Some((table, next)) = table_name(stmt, i) else {
                    continue;
                };
                let Some((body, _)) = group(stmt, next) else {
                    continue;
                };
                let mut table_checks = Vec::new();
                for def in split_top(body) {
                    if word(def.first()).is_some_and(|w| TABLE_CONSTRAINT.contains(&w)) {
                        table_checks.extend(checks(def));
                    } else if let Some((name, sql_type, check)) = column_def(def) {
                        out.push(Column {
                            table: table.clone(),
                            name,
                            sql_type,
                            check,
                        });
                    }
                }
                for (col, values) in table_checks {
                    add_check(out, &table, &col, values);
                }
            }
            (Some("alter"), Some("table")) => {
                let i = skip_words(stmt, 2, &["if", "exists", "only"]);
                let Some((table, next)) = table_name(stmt, i) else {
                    continue;
                };
                for action in split_top(stmt.get(next..).unwrap_or_default()) {
                    if word(action.first()) != Some("add") {
                        continue;
                    }
                    let j = skip_words(action, 1, &["column", "if", "not", "exists"]);
                    if word(action.get(1)) == Some("constraint")
                        || word(action.get(1)) == Some("check")
                    {
                        for (col, values) in checks(action) {
                            add_check(out, &table, &col, values);
                        }
                    } else if let Some((name, sql_type, check)) =
                        column_def(action.get(j..).unwrap_or_default())
                    {
                        out.push(Column {
                            table: table.clone(),
                            name,
                            sql_type,
                            check,
                        });
                    }
                }
            }
            _ => {}
        }
    }
}

/// Violations of the migrated columns against the list.
pub(crate) fn findings(list: &List, columns: &[Column]) -> Vec<(Column, Reason)> {
    columns
        .iter()
        .filter_map(|c| {
            judge(list, &c.name, &c.sql_type, c.check.as_deref())
                .err()
                .map(|r| (c.clone(), r))
        })
        .collect()
}

pub(crate) fn load_list(root: &Path) -> Result<List, String> {
    toml::from_str(&read(&root.join(LIST))?).map_err(|e| format!("{LIST}: {e}"))
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let list = load_list(root)?;
    let names: BTreeSet<&str> = list.column.iter().map(|c| c.name.as_str()).collect();
    let mut out = Vec::new();
    if names.len() != list.column.len() {
        out.push(v("T-32", LIST, "a column is listed twice".to_owned()));
    }
    for n in &list.encrypted_only {
        if names.contains(n.name.as_str()) {
            out.push(v(
                "OP-4",
                LIST,
                format!("`{}` is both plain and encrypted-only", n.name),
            ));
        }
    }
    let dir = root.join(DIR);
    if !dir.is_dir() {
        return Ok(out);
    }
    let mut files: Vec<String> = std::fs::read_dir(&dir)
        .map_err(|e| format!("{DIR}: {e}"))?
        .filter_map(Result::ok)
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| {
            Path::new(n)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("sql"))
        })
        .collect();
    files.sort();
    let mut by_file: BTreeMap<String, Vec<Column>> = BTreeMap::new();
    let mut all = Vec::new();
    for name in files {
        let rel = format!("{DIR}/{name}");
        let before = all.len();
        columns(&read(&root.join(&rel))?, &mut all);
        by_file.insert(rel, all.get(before..).unwrap_or_default().to_vec());
    }
    for (column, reason) in findings(&list, &all) {
        let file = by_file
            .iter()
            .find(|(_, cols)| {
                cols.iter()
                    .any(|c| c.table == column.table && c.name == column.name)
            })
            .map_or(DIR, |(f, _)| f.as_str());
        out.push(v(
            "T-32",
            file,
            format!(
                "`{}.{}` ({}): {}: {}",
                column.table,
                column.name,
                column.sql_type,
                reason.as_str(),
                reason.message()
            ),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn list() -> List {
        load_list(&crate::workspace_root()).unwrap()
    }

    fn cols(sql: &str) -> Vec<Column> {
        let mut out = Vec::new();
        columns(sql, &mut out);
        out
    }

    fn reasons(sql: &str) -> Vec<(String, &'static str)> {
        findings(&list(), &cols(sql))
            .into_iter()
            .map(|(c, r)| (c.name, r.as_str()))
            .collect()
    }

    fn strings(v: &serde_json::Value) -> Vec<String> {
        v.as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_owned())
            .collect()
    }

    #[test]
    fn t_32_plain_column_vectors() {
        let path = crate::workspace_root().join("conformance/store/vectors/plain-columns.json");
        let vectors: Vec<serde_json::Value> =
            serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
        let list = list();
        let mut seen = 0;
        for v in vectors {
            seen += 1;
            let d = v["description"].as_str().unwrap();
            let input = &v["input"];
            let expected = &v["expected"];
            if let Some(migrated) = input["migrated_columns"].as_array() {
                let columns: Vec<Column> = migrated
                    .iter()
                    .map(|c| Column {
                        table: c[0].as_str().unwrap().to_owned(),
                        name: c[1].as_str().unwrap().to_owned(),
                        sql_type: c[2].as_str().unwrap().to_owned(),
                        check: None,
                    })
                    .collect();
                let got: Vec<serde_json::Value> = findings(&list, &columns)
                    .into_iter()
                    .map(|(c, r)| serde_json::json!([c.table, c.name, r.as_str()]))
                    .collect();
                assert_eq!(
                    got,
                    expected["violations"].as_array().unwrap().clone(),
                    "{d}"
                );
                assert!(!expected["accepted"].as_bool().unwrap());
                continue;
            }
            if input["generate"] == "sec-30" {
                assert_eq!(
                    list.column.len() as u64,
                    expected["rows"].as_u64().unwrap(),
                    "{d}"
                );
                continue;
            }
            let check = input.get("check").map(strings);
            let got = judge(
                &list,
                input["column"].as_str().unwrap(),
                input["sql_type"].as_str().unwrap(),
                check.as_deref(),
            );
            if expected["accepted"].as_bool().unwrap() {
                let plain = got.unwrap();
                if let Some(p) = expected["plain"].as_bool() {
                    assert_eq!(plain, p, "{d}");
                }
            } else {
                assert_eq!(got.unwrap_err().as_str(), expected["reason"], "{d}");
            }
        }
        assert_eq!(seen, 15);
    }

    #[test]
    fn t_32_create_table_columns_and_checks_are_read() {
        let sql = "-- memory\nCREATE TABLE IF NOT EXISTS one.memory_record (\n  owner text NOT NULL,\n  id uuid NOT NULL,\n  recorded_at timestamp with time zone NOT NULL DEFAULT now(),\n  status text NOT NULL CHECK (status IN ('active', 'superseded', 'deleted')),\n  retention_class text NOT NULL,\n  statement_ct bytea NOT NULL,\n  version int4 NOT NULL,\n  PRIMARY KEY (owner, id),\n  CONSTRAINT rc CHECK (retention_class IN ('one_memory', 'one_sensitive'))\n);";
        let got = cols(sql);
        let summary: Vec<(&str, &str, Option<usize>)> = got
            .iter()
            .map(|c| {
                (
                    c.name.as_str(),
                    c.sql_type.as_str(),
                    c.check.as_ref().map(Vec::len),
                )
            })
            .collect();
        assert_eq!(
            summary,
            [
                ("owner", "text", None),
                ("id", "uuid", None),
                ("recorded_at", "timestamptz", None),
                ("status", "text", Some(3)),
                ("retention_class", "text", Some(2)),
                ("statement_ct", "bytea", None),
                ("version", "integer", None),
            ]
        );
        assert!(got.iter().all(|c| c.table == "memory_record"));
        assert_eq!(reasons(sql), []);
    }

    #[test]
    fn t_32_unlisted_plain_and_encrypted_only_columns_are_rejected() {
        let sql = "CREATE TABLE memory_record (owner text, note text, trust_ct jsonb, domain bytea, data_class text[], version text, status text);";
        assert_eq!(
            reasons(sql),
            [
                ("note".to_owned(), "unlisted_plain_column"),
                ("trust_ct".to_owned(), "unlisted_plain_column"),
                ("domain".to_owned(), "encrypted_only"),
                ("data_class".to_owned(), "encrypted_only"),
                ("version".to_owned(), "listed_type"),
                ("status".to_owned(), "listed_values"),
            ]
        );
    }

    #[test]
    fn t_32_alter_table_add_column_is_checked() {
        let sql = "CREATE TABLE job (job_id uuid, owner text);\nALTER TABLE ONLY job ADD COLUMN IF NOT EXISTS job_kind text, ADD COLUMN body_ct bytea;\nALTER TABLE job ADD CONSTRAINT jk CHECK (job_kind IN ('consolidation', 'analytics'));\nALTER TABLE job ADD COLUMN \"provenance\" bytea;";
        let got = cols(sql);
        assert_eq!(got.len(), 5);
        assert_eq!(
            reasons(sql),
            [
                ("job_kind".to_owned(), "listed_values"),
                ("provenance".to_owned(), "encrypted_only"),
            ]
        );
        let ok = "CREATE TABLE job (job_id uuid, owner text);\nALTER TABLE job ADD COLUMN job_kind text CHECK (job_kind IN ('export'));";
        assert_eq!(reasons(ok), []);
    }

    #[test]
    fn t_32_comments_and_strings_do_not_create_columns() {
        let sql = "/* CREATE TABLE x (note text); */\n-- ALTER TABLE x ADD COLUMN note text;\nCOMMENT ON TABLE job IS 'CREATE TABLE y (note text)';";
        assert_eq!(cols(sql), []);
    }

    #[test]
    fn t_32_the_repository_passes() {
        assert!(check(&crate::workspace_root()).unwrap().is_empty());
    }
}
