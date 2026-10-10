//! `cargo xtask commits BASE HEAD`: every commit has a Conventional Commits subject, and a commit touching a security-sensitive path carries the `Security-Sensitive: yes` trailer with `Threat:` and `Privacy:` lines (T-44 (1, 3), T-49).

use std::path::Path;
use std::process::Command;

const TYPES: &[&str] = &[
    "feat", "fix", "docs", "style", "refactor", "perf", "test", "build", "ci", "chore", "revert",
];

pub(crate) const SENSITIVE: &[&str] = &[
    "crates/keys/",
    "crates/tee/",
    "core/src/crypto/",
    "crates/memory/",
    "crates/provenance/",
    "crates/router/",
    "crates/federation/",
    "serving/",
    "ml/train/",
    "ml/datasets/",
    "crates/store/",
    "conformance/data-inventory.toml",
    "crates/telemetry/src/fields.rs",
    "conformance/platform/",
    ".github/workflows/release.yml",
    "deploy/compat.toml",
];

fn sensitive(file: &str) -> bool {
    SENSITIVE.iter().any(|p| file.starts_with(p))
        || file.ends_with("AndroidManifest.xml")
        || file.ends_with(".entitlements")
        || file.ends_with("Info.plist")
        || file.ends_with("PrivacyInfo.xcprivacy")
}

/// Problems with one commit given its message and changed files.
pub(crate) fn problems(message: &str, files: &[String], shared_crate_change: bool) -> Vec<String> {
    let mut out = Vec::new();
    let subject = message.lines().next().unwrap_or_default();
    let (head, summary) = subject.split_once(": ").unwrap_or(("", ""));
    let kind = head
        .trim_end_matches('!')
        .split('(')
        .next()
        .unwrap_or_default();
    let scope_ok = !head.contains('(') || head.trim_end_matches('!').ends_with(')');
    if !TYPES.contains(&kind) || !scope_ok || summary.trim().is_empty() {
        out.push(format!("subject `{subject}` is not a Conventional Commit"));
    }
    if files.iter().any(|f| sensitive(f)) || shared_crate_change {
        let lines: Vec<&str> = message.lines().map(str::trim).collect();
        if !lines.contains(&"Security-Sensitive: yes") {
            out.push("touches a security-sensitive path: add `Security-Sensitive: yes`".to_owned());
        }
        for label in ["Threat:", "Privacy:"] {
            if !lines
                .iter()
                .any(|l| l.starts_with(label) && l.len() > label.len().saturating_add(1))
            {
                out.push(format!(
                    "touches a security-sensitive path: add a `{label}` line"
                ));
            }
        }
    }
    out
}

fn git(root: &Path, args: &[&str]) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(root)
        .output()
        .map_err(|e| format!("git: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

pub(crate) fn check_range(root: &Path, base: &str, head: &str) -> Result<(), String> {
    let range = format!("{base}..{head}");
    let mut failed = Vec::new();
    for sha in git(root, &["rev-list", "--reverse", &range])?.lines() {
        let message = git(root, &["log", "-1", "--format=%B", sha])?;
        let files: Vec<String> = git(
            root,
            &[
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                "--root",
                sha,
            ],
        )?
        .lines()
        .map(str::to_owned)
        .collect();
        let shared = files.iter().any(|f| f == "Cargo.toml")
            && git(root, &["show", "--format=", sha, "--", "Cargo.toml"])?
                .lines()
                .any(|l| (l.starts_with('+') || l.starts_with('-')) && l.contains("esuiss-"));
        for p in problems(&message, &files, shared) {
            failed.push(format!("{}: {p}", sha.get(..12).unwrap_or(sha)));
        }
    }
    if failed.is_empty() {
        Ok(())
    } else {
        Err(failed.join("\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_44_subject_must_be_conventional() {
        assert_eq!(problems("feat(http): add readiness", &[], false).len(), 0);
        assert_eq!(problems("fix!: drop field", &[], false).len(), 0);
        assert_eq!(problems("Add stuff", &[], false).len(), 1);
    }

    #[test]
    fn t_44_sensitive_path_needs_trailer_and_assessment() {
        let files = vec!["crates/telemetry/src/fields.rs".to_owned()];
        assert_eq!(
            problems("feat(telemetry): add field", &files, false).len(),
            3
        );
        let ok = "feat(telemetry): add field\n\nThreat: a new counter carries no content.\nPrivacy: no personal data.\n\nSecurity-Sensitive: yes\n";
        assert_eq!(problems(ok, &files, false).len(), 0);
        assert_eq!(problems("build: bump", &[], true).len(), 3);
    }
}
