//! Text scans over the repository's own configuration: images pinned by digest from allowed sources (T-39) and no automatic test retries (T-38 (11)).

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Check, Violation};

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "image-sources",
            run: image_sources,
        },
        Check {
            name: "no-flaky-retries",
            run: no_flaky_retries,
        },
    ]
}

/// Tracked and not-ignored files, relative to the root; `docs/` is excluded by `.git/info/exclude`.
pub(crate) fn repo_files(root: &Path) -> Result<Vec<String>, String> {
    let output = Command::new("git")
        .args(["ls-files", "--cached", "--others", "--exclude-standard"])
        .current_dir(root)
        .output()
        .map_err(|e| format!("git ls-files: {e}"))?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter(|f| root.join(f).is_file())
        .map(str::to_owned)
        .collect())
}

fn read(root: &Path, file: &str) -> String {
    std::fs::read_to_string(root.join(file)).unwrap_or_default()
}

fn violation(rule: &'static str, file: &str, line: usize, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(format!("{file}:{}", line.saturating_add(1))),
        message,
    }
}

fn is_config(file: &str) -> bool {
    let name = Path::new(file)
        .file_name()
        .map(|n| n.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    name.starts_with("dockerfile")
        || name == "justfile"
        || [".toml", ".yml", ".yaml", ".sh", ".json"]
            .iter()
            .any(|ext| name.ends_with(ext))
}

/// Third-party image catalogs that T-39 rules out.
const IMAGE_CATALOGS: &[&str] = &["bitnami/", "bitnamilegacy/", "bitnamicharts/"];

/// Prefix of images that `just dev` builds locally from Dockerfiles in this repository.
const LOCAL_IMAGE_PREFIX: &str = "one-dev/";

/// Returns the image reference on a `FROM` / `image:` line, if any.
fn image_reference(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let rest = trimmed
        .strip_prefix("FROM ")
        .or_else(|| trimmed.strip_prefix("from "))
        .or_else(|| trimmed.strip_prefix("image:"))
        .or_else(|| trimmed.strip_prefix("- image:"))?;
    let reference = rest
        .split_whitespace()
        .find(|part| !part.starts_with("--"))?
        .trim_matches(|c| c == '"' || c == '\'');
    Some(reference)
}

fn image_findings(text: &str, is_dockerfile: bool) -> Vec<(usize, String)> {
    let mut stages: Vec<String> = Vec::new();
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let Some(reference) = image_reference(line) else {
            continue;
        };
        if is_dockerfile && let Some((_, alias)) = line.to_ascii_lowercase().split_once(" as ") {
            stages.push(alias.trim().to_owned());
        }
        let lower = reference.to_ascii_lowercase();
        if lower == "scratch"
            || stages.contains(&lower)
            || lower.starts_with('$')
            || lower.starts_with(LOCAL_IMAGE_PREFIX)
        {
            continue;
        }
        if IMAGE_CATALOGS.iter().any(|c| lower.contains(c)) {
            found.push((
                n,
                format!("`{reference}`: no third-party image catalogs (T-39)"),
            ));
        } else if !reference.contains("@sha256:") {
            found.push((n, format!("`{reference}` is not pinned by digest (T-39)")));
        }
    }
    found
}

fn image_sources(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let name = Path::new(&file)
            .file_name()
            .map(|n| n.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let is_dockerfile = name.starts_with("dockerfile");
        let in_scope = is_dockerfile
            || (file.starts_with("deploy/")
                && Path::new(&name)
                    .extension()
                    .is_some_and(|e| e == "yaml" || e == "yml"))
            || file.starts_with(".github/");
        if !in_scope {
            continue;
        }
        for (n, message) in image_findings(&read(root, &file), is_dockerfile) {
            out.push(violation("T-39", &file, n, message));
        }
    }
    Ok(out)
}

fn retry_findings(file: &str, text: &str) -> Vec<(usize, String)> {
    let mut found = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let compact: String = line.chars().filter(|c| !c.is_whitespace()).collect();
        let lower = compact.to_ascii_lowercase();
        let nonzero_setting = lower
            .strip_prefix("retries=")
            .is_some_and(|value| value.trim_start_matches('"') != "0" && !value.starts_with('0'));
        let nonzero_flag = lower
            .split("--retries")
            .nth(1)
            .is_some_and(|value| !value.trim_start_matches('=').starts_with('0'));
        let retry_action =
            file.starts_with(".github/") && lower.contains("uses:") && lower.contains("retry");
        if nonzero_setting || nonzero_flag || retry_action {
            found.push((
                n,
                "flaky tests are quarantined, never retried until green (T-38 (11))".to_owned(),
            ));
        }
    }
    found
}

fn no_flaky_retries(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)?.iter().filter(|f| is_config(f)) {
        for (n, message) in retry_findings(file, &read(root, file)) {
            out.push(violation("T-38", file, n, message));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_39_bitnami_image_is_rejected() {
        let found = image_findings("    image: bitnami/postgresql@sha256:abc", false);
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn t_39_unpinned_image_is_rejected_but_build_stage_is_not() {
        let dockerfile = "FROM rust:1.99@sha256:abc AS build\nFROM build AS chef\nFROM gcr.io/distroless/cc:nonroot\n";
        let found = image_findings(dockerfile, true);
        assert_eq!(found.len(), 1);
        assert!(found[0].1.contains("distroless"));
    }

    #[test]
    fn t_38_nonzero_retries_are_rejected() {
        assert_eq!(
            retry_findings(".config/nextest.toml", "retries = 2").len(),
            1
        );
        assert_eq!(
            retry_findings(".config/nextest.toml", "retries = 0").len(),
            0
        );
        assert_eq!(
            retry_findings("justfile", "cargo nextest run --retries 3").len(),
            1
        );
        assert_eq!(
            retry_findings(".github/workflows/ci.yml", "uses: nick-fields/retry@abc").len(),
            1
        );
    }
}
