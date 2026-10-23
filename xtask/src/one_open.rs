//! `open-sync`: `conformance/open.lock` pins the `e-suiss/one-open` commit whose schemas and vectors One carries; offline every mapped copy exists, and with `XTASK_ONLINE=1` every copy is byte-equal to the file at the pinned commit (T-26 (2), T-31).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

use super::v;
use crate::Violation;

const LOCK: &str = "conformance/open.lock";
const REPOSITORY: &str = "https://github.com/e-suiss/one-open";
const CACHE: &str = "target/xtask-open-sync";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Lock {
    pub(crate) repository: String,
    pub(crate) commit: String,
    pub(crate) files: BTreeMap<String, String>,
}

fn online() -> bool {
    std::env::var("XTASK_ONLINE").is_ok_and(|v| v == "1")
}

fn clean(path: &str) -> bool {
    !path.is_empty()
        && !path.starts_with('/')
        && !path.contains('\\')
        && path
            .split('/')
            .all(|p| !p.is_empty() && p != "." && p != "..")
}

/// Rules on the lock file alone; `file_exists` answers for repository-relative paths.
pub(crate) fn well_formed(lock: &Lock, file_exists: &dyn Fn(&str) -> bool) -> Vec<String> {
    let mut out = Vec::new();
    if lock.repository != REPOSITORY {
        out.push(format!("`repository` must be `{REPOSITORY}`"));
    }
    if lock.commit.len() != 40
        || !lock
            .commit
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    {
        out.push("`commit` must be a full lowercase commit SHA".to_owned());
    }
    if lock.files.is_empty() {
        out.push("`files` maps nothing".to_owned());
    }
    let mut targets = BTreeSet::new();
    for (open, one) in &lock.files {
        if !clean(open) {
            out.push(format!("`{open}` is not a clean relative path"));
        }
        if !clean(one) || !one.starts_with("conformance/") {
            out.push(format!("`{one}` must be a clean path under conformance/"));
        } else if !file_exists(one) {
            out.push(format!("`{one}` does not exist"));
        }
        if !targets.insert(one.as_str()) {
            out.push(format!("`{one}` is the copy of more than one file"));
        }
    }
    out
}

fn git(dir: &Path, args: &[&str]) -> Result<Vec<u8>, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if output.status.success() {
        Ok(output.stdout)
    } else {
        Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn fetch(root: &Path, lock: &Lock) -> Result<std::path::PathBuf, String> {
    let dir = root.join(CACHE);
    if !dir.join(".git").is_dir() {
        std::fs::create_dir_all(&dir).map_err(|e| format!("{CACHE}: {e}"))?;
        git(&dir, &["init", "--quiet"])?;
    }
    let object = format!("{}^{{commit}}", lock.commit);
    if git(&dir, &["cat-file", "-e", &object]).is_err() {
        git(
            &dir,
            &[
                "fetch",
                "--quiet",
                "--depth",
                "1",
                "--no-tags",
                &lock.repository,
                &lock.commit,
            ],
        )?;
    }
    Ok(dir)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = std::fs::read_to_string(root.join(LOCK)).map_err(|e| format!("{LOCK}: {e}"))?;
    let lock: Lock = toml::from_str(&text).map_err(|e| format!("{LOCK}: {e}"))?;
    let mut out: Vec<Violation> = well_formed(&lock, &|p| root.join(p).is_file())
        .into_iter()
        .map(|m| v("T-26", LOCK, m))
        .collect();
    if !out.is_empty() || !online() {
        return Ok(out);
    }
    let dir = fetch(root, &lock)?;
    for (open, one) in &lock.files {
        let Ok(upstream) = git(
            &dir,
            &["cat-file", "blob", &format!("{}:{open}", lock.commit)],
        ) else {
            out.push(v(
                "T-26",
                LOCK,
                format!("`{open}` is not in one-open at {}", lock.commit),
            ));
            continue;
        };
        let local = std::fs::read(root.join(one)).map_err(|e| format!("{one}: {e}"))?;
        if local != upstream {
            out.push(v(
                "T-26",
                one.clone(),
                format!(
                    "differs from one-open `{open}` at {}; change one-open first, then move the pin",
                    lock.commit
                ),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lock(files: &[(&str, &str)]) -> Lock {
        Lock {
            repository: REPOSITORY.to_owned(),
            commit: "090216d73cf2d8e1c5fa944006721a6b78d8f2f0".to_owned(),
            files: files
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect(),
        }
    }

    #[test]
    fn t_26_a_pinned_lock_with_existing_copies_passes() {
        let l = lock(&[(
            "capability/name.schema.json",
            "conformance/capability/name.schema.json",
        )]);
        assert_eq!(well_formed(&l, &|_| true), Vec::<String>::new());
    }

    #[test]
    fn t_26_short_sha_escaping_paths_and_shared_copies_fail() {
        let mut l = lock(&[
            ("../x", "conformance/a.json"),
            ("b.json", "conformance/a.json"),
            ("c.json", "crates/c.json"),
        ]);
        l.commit = "090216d".to_owned();
        let errors = well_formed(&l, &|_| false);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("full lowercase commit SHA"))
        );
        assert!(errors.iter().any(|e| e.contains("`../x` is not a clean")));
        assert!(errors.iter().any(|e| e.contains("more than one file")));
        assert!(errors.iter().any(|e| e.contains("under conformance/")));
        assert!(errors.iter().any(|e| e.contains("does not exist")));
    }
}
