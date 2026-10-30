//! `migrations`: forward-only, one expand or contract step per file, committed files never change, and no locking index, table rewrite or one-step rename (T-32 (7), §18 OP-27).

use std::path::Path;
use std::process::Command;

use super::{read_opt, v};
use crate::Violation;
use crate::rules::files::read;

pub(crate) const DIR: &str = "crates/store/migrations";
const LOCK: &str = "crates/store/migrations/lock.toml";

/// Problems with a migration file name: `NNNN_slug.expand.sql` or `NNNN_slug.contract.sql`.
pub(crate) fn name_problem(name: &str) -> Option<String> {
    if name.contains(".down.") || name.contains("_down.") {
        return Some("down migrations are not allowed; migrations are forward-only".to_owned());
    }
    let Some(stem) = name.strip_suffix(".sql") else {
        return Some("migration files end in .sql".to_owned());
    };
    let (base, phase) = stem.rsplit_once('.').unwrap_or((stem, ""));
    if !matches!(phase, "expand" | "contract") {
        return Some("name must end in .expand.sql or .contract.sql".to_owned());
    }
    let (number, slug) = base.split_once('_').unwrap_or(("", ""));
    let ok = number.len() == 4
        && number.chars().all(|c| c.is_ascii_digit())
        && !slug.is_empty()
        && slug
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
    (!ok).then(|| "name must be NNNN_lower_snake.(expand|contract).sql".to_owned())
}

/// Statements that lock or rewrite a table in one step.
pub(crate) fn sql_problems(sql: &str) -> Vec<String> {
    let upper: String = sql
        .lines()
        .map(|l| l.split("--").next().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_uppercase();
    let words: Vec<&str> = upper
        .split(|c: char| !(c.is_ascii_alphanumeric() || c == '_'))
        .filter(|w| !w.is_empty())
        .collect();
    let mut out = Vec::new();
    for (i, w) in words.iter().enumerate() {
        let next = |k: usize| words.get(i.saturating_add(k)).copied().unwrap_or("");
        if *w == "CREATE" && (next(1) == "INDEX" || (next(1) == "UNIQUE" && next(2) == "INDEX")) {
            let after = if next(1) == "UNIQUE" {
                next(3)
            } else {
                next(2)
            };
            if after != "CONCURRENTLY" {
                out.push("CREATE INDEX without CONCURRENTLY locks the table".to_owned());
            }
        }
        if *w == "RENAME" {
            out.push(
                "rename in one step breaks running code; add, copy, then drop in later steps"
                    .to_owned(),
            );
        }
        if *w == "ALTER" && next(1) == "COLUMN" && (next(3) == "TYPE" || next(4) == "TYPE") {
            out.push("changing a column type rewrites the table".to_owned());
        }
        if *w == "SET" && next(1) == "NOT" && next(2) == "NULL" {
            out.push(
                "SET NOT NULL scans under an exclusive lock; use a validated CHECK constraint"
                    .to_owned(),
            );
        }
    }
    out
}

fn blob_id(root: &Path, rel: &str) -> Result<String, String> {
    let output = Command::new("git")
        .args(["hash-object", rel])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git hash-object: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let dir = root.join(DIR);
    if !dir.is_dir() {
        return Ok(Vec::new());
    }
    let lock: toml::Table = match read_opt(root, LOCK)? {
        Some(text) => text.parse().map_err(|e| format!("{LOCK}: {e}"))?,
        None => toml::Table::new(),
    };
    let mut out = Vec::new();
    let mut names = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{DIR}: {e}"))? {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name == "lock.toml" {
            continue;
        }
        let rel = format!("{DIR}/{name}");
        if let Some(problem) = name_problem(&name) {
            out.push(v("T-32", rel.clone(), problem));
        }
        for problem in sql_problems(&read(&root.join(&rel))?) {
            out.push(v("T-32", rel.clone(), problem));
        }
        let id = blob_id(root, &rel)?;
        match lock.get(&name).and_then(toml::Value::as_str) {
            None => out.push(v(
                "T-32",
                LOCK,
                format!("`{name}` is not locked; add `\"{name}\" = \"{id}\"`"),
            )),
            Some(locked) if locked != id => out.push(v(
                "T-32",
                rel.clone(),
                "a committed migration never changes; write a new one".to_owned(),
            )),
            Some(_) => {}
        }
        names.push(name);
    }
    for key in lock.keys().filter(|k| !names.contains(k)) {
        out.push(v("T-32", LOCK, format!("`{key}` is locked but missing")));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_32_migration_names_are_forward_only_and_phased() {
        assert!(name_problem("0001_records.expand.sql").is_none());
        assert!(name_problem("0001_records.down.sql").is_some());
        assert!(name_problem("0001_records.sql").is_some());
        assert!(name_problem("1_Records.expand.sql").is_some());
    }

    #[test]
    fn t_32_locking_and_rewriting_statements_are_rejected() {
        assert_eq!(
            sql_problems("CREATE INDEX CONCURRENTLY i ON t (a);").len(),
            0
        );
        assert_eq!(sql_problems("CREATE UNIQUE INDEX i ON t (a);").len(), 1);
        assert_eq!(sql_problems("ALTER TABLE t RENAME COLUMN a TO b;").len(), 1);
        assert_eq!(
            sql_problems("ALTER TABLE t ALTER COLUMN a TYPE bigint;").len(),
            1
        );
        assert_eq!(
            sql_problems("ALTER TABLE t ALTER COLUMN a SET NOT NULL;").len(),
            1
        );
        assert_eq!(sql_problems("-- RENAME later\nSELECT 1;").len(), 0);
    }
}
