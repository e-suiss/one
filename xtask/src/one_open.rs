//! `open-submodule`: `conformance/open` is the `e-suiss/one-open` submodule, initialized at the commit its gitlink pins, and no file elsewhere under `conformance/` is a copy of one of its files (T-26 (2), T-31).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use super::v;
use crate::Violation;

const SUBMODULE: &str = "conformance/open";
const REPOSITORY: &str = "https://github.com/e-suiss/one-open";

fn git(dir: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(dir)
        .env("GIT_TERMINAL_PROMPT", "0")
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        Err(format!(
            "git {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

/// The commit a `git ls-files --stage` line pins when it is the gitlink of [`SUBMODULE`].
pub(crate) fn gitlink(stage: &str) -> Option<&str> {
    let line = stage
        .lines()
        .find(|l| l.ends_with(&format!("\t{SUBMODULE}")))?;
    let mut fields = line.split_whitespace();
    (fields.next()? == "160000").then_some(())?;
    let commit = fields.next()?;
    (commit.len() == 40 && commit.chars().all(|c| c.is_ascii_hexdigit())).then_some(commit)
}

/// Rules on `.gitmodules` alone.
pub(crate) fn declared(gitmodules: &str) -> Vec<String> {
    let mut path = false;
    let mut url = false;
    let mut out = Vec::new();
    for section in gitmodules.split('[').skip(1) {
        let field = |key: &str| {
            section.lines().find_map(|l| {
                let (k, value) = l.split_once('=')?;
                (k.trim() == key).then(|| value.trim().to_owned())
            })
        };
        if field("path").as_deref() == Some(SUBMODULE) {
            path = true;
            url = field("url").as_deref() == Some(REPOSITORY);
        } else if let Some(other) = field("path") {
            out.push(format!("`{other}` is not a known submodule"));
        }
    }
    if !path {
        out.push(format!("`{SUBMODULE}` is not declared"));
    } else if !url {
        out.push(format!("`{SUBMODULE}` must point at `{REPOSITORY}`"));
    }
    out
}

fn lines(text: &str) -> impl Iterator<Item = &str> {
    text.lines().filter(|l| !l.is_empty())
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let gitmodules = std::fs::read_to_string(root.join(".gitmodules")).unwrap_or_default();
    let mut out: Vec<Violation> = declared(&gitmodules)
        .into_iter()
        .map(|m| v("T-26", ".gitmodules", m))
        .collect();
    let stage = git(root, &["ls-files", "--stage", "--", SUBMODULE])?;
    let Some(pinned) = gitlink(&stage) else {
        out.push(v(
            "T-26",
            SUBMODULE,
            "is not a submodule gitlink".to_owned(),
        ));
        return Ok(out);
    };
    let dir = root.join(SUBMODULE);
    let head = if dir.join(".git").exists() {
        git(&dir, &["rev-parse", "HEAD"]).ok()
    } else {
        None
    };
    let Some(head) = head else {
        out.push(v(
            "T-26",
            SUBMODULE,
            "is not initialized; run `git submodule update --init`".to_owned(),
        ));
        return Ok(out);
    };
    if head.trim() != pinned {
        out.push(v(
            "T-26",
            SUBMODULE,
            format!(
                "is checked out at {} but pinned at {pinned}; run `git submodule update`",
                head.trim()
            ),
        ));
    }
    let mut open: BTreeMap<u64, Vec<(String, Vec<u8>)>> = BTreeMap::new();
    for rel in lines(&git(&dir, &["ls-files"])?) {
        let path = dir.join(rel);
        if !path.is_file() {
            continue;
        }
        let bytes = std::fs::read(&path).map_err(|e| format!("{}: {e}", path.display()))?;
        open.entry(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .or_default()
            .push((rel.to_owned(), bytes));
    }
    let ours = git(
        root,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "conformance",
        ],
    )?;
    for rel in lines(&ours) {
        if rel == SUBMODULE || rel.starts_with(&format!("{SUBMODULE}/")) {
            continue;
        }
        let path = root.join(rel);
        let Ok(meta) = std::fs::metadata(&path) else {
            continue;
        };
        let Some(same_size) = open.get(&meta.len()) else {
            continue;
        };
        let bytes = std::fs::read(&path).map_err(|e| format!("{rel}: {e}"))?;
        if let Some((copy_of, _)) = same_size.iter().find(|(_, b)| *b == bytes) {
            out.push(v(
                "T-26",
                rel,
                format!("is a copy of one-open `{copy_of}`; refer to `{SUBMODULE}/{copy_of}`"),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_26_the_gitlink_pins_a_full_commit() {
        let sha = "e7c00ec0ffc47f1e7ed5591396609fcbb90a3000";
        assert_eq!(
            gitlink(&format!("160000 {sha} 0\tconformance/open\n")),
            Some(sha)
        );
        assert_eq!(
            gitlink(&format!("100644 {sha} 0\tconformance/open\n")),
            None
        );
        assert_eq!(gitlink("160000 e7c00ec 0\tconformance/open\n"), None);
        assert_eq!(gitlink(""), None);
    }

    #[test]
    fn t_26_only_the_one_open_submodule_is_declared() {
        let good = "[submodule \"conformance/open\"]\n\tpath = conformance/open\n\turl = https://github.com/e-suiss/one-open\n";
        assert_eq!(declared(good), Vec::<String>::new());
        assert!(declared("")[0].contains("is not declared"));
        let fork = good.replace("e-suiss/one-open", "someone/one-open");
        assert!(declared(&fork)[0].contains("must point at"));
        let extra = format!("{good}[submodule \"x\"]\n\tpath = x\n\turl = https://example.com/x\n");
        assert!(declared(&extra)[0].contains("`x` is not a known submodule"));
    }
}
