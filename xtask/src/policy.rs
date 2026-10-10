//! Project policy checks: proprietary licence (T-3), no ADR folder (T-43), component layers (T-27 (1)), no JavaScript at the root (T-53) and no external-contribution files (T-44 (2)).

use std::path::{Path, PathBuf};

use crate::rules::files::{rel, walk};
use crate::{Check, Violation};

#[path = "policy_scan.rs"]
pub(crate) mod scan;

pub(crate) fn checks() -> Vec<Check> {
    let mut all = vec![
        Check {
            name: "license",
            run: license,
        },
        Check {
            name: "no-adr-folder",
            run: no_adr_folder,
        },
        Check {
            name: "component-layers",
            run: component_layers,
        },
        Check {
            name: "no-root-javascript",
            run: no_root_javascript,
        },
        Check {
            name: "no-contribution-files",
            run: no_contribution_files,
        },
        Check {
            name: "review-checklist",
            run: review_checklist,
        },
    ];
    all.extend(scan::checks());
    all
}

const LICENSE_ID: &str = "LicenseRef-Suiss-Proprietary";

const COMPONENTS: &[&str] = &[
    "sync",
    "task",
    "memory",
    "router",
    "capabilities",
    "attention",
    "federation",
    "jobs",
];

fn v(rule: &'static str, path: &str, message: String) -> Violation {
    Violation {
        rule,
        path: PathBuf::from(path),
        message,
    }
}

fn license(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    let mut out = Vec::new();
    for pkg in md.members() {
        let manifest = std::fs::read_to_string(&pkg.manifest_path)
            .map_err(|e| format!("{}: {e}", pkg.manifest_path.display()))?;
        let table: toml::Table = manifest
            .parse()
            .map_err(|e| format!("{}: {e}", pkg.manifest_path.display()))?;
        let package = table.get("package");
        let inherits = package
            .and_then(|p| p.get("license"))
            .and_then(|l| l.get("workspace"))
            .and_then(toml::Value::as_bool)
            == Some(true);
        let publish_off = package
            .and_then(|p| p.get("publish"))
            .and_then(toml::Value::as_bool)
            == Some(false);
        if !inherits || !publish_off {
            out.push(v(
                "T-3",
                &format!("{}/Cargo.toml", rel(root, pkg.dir())),
                format!(
                    "`{}` must use `license.workspace = true` and `publish = false`",
                    pkg.name
                ),
            ));
        }
    }
    let ws = std::fs::read_to_string(root.join("Cargo.toml")).map_err(|e| e.to_string())?;
    if !ws.contains(&format!("license = \"{LICENSE_ID}\"")) {
        out.push(v(
            "T-3",
            "Cargo.toml",
            format!("workspace licence must be `{LICENSE_ID}`"),
        ));
    }
    let text = std::fs::read_to_string(root.join("LICENSE")).unwrap_or_default();
    if !text.contains("proprietary") || text.contains("Apache License") {
        out.push(v(
            "T-3",
            "LICENSE",
            "LICENSE must be the proprietary Suiss licence".to_owned(),
        ));
    }
    Ok(out)
}

pub(crate) fn adr_paths<'a>(files: impl Iterator<Item = &'a str>) -> Vec<String> {
    files
        .filter(|file| {
            Path::new(file).components().any(|c| {
                let part = c.as_os_str().to_string_lossy().to_ascii_lowercase();
                part == "adr" || part == "adrs" || part == "decisions"
            })
        })
        .map(str::to_owned)
        .collect()
}

fn no_adr_folder(root: &Path) -> Result<Vec<Violation>, String> {
    let files = scan::repo_files(root)?;
    Ok(adr_paths(files.iter().map(String::as_str))
        .into_iter()
        .map(|p| {
            v(
                "T-43",
                &p,
                "no ADR folder: the spec registers are the decision record".to_owned(),
            )
        })
        .collect())
}

pub(crate) fn missing_layers(src: &Path) -> Vec<&'static str> {
    ["domain", "ports", "app", "adapters"]
        .into_iter()
        .filter(|layer| {
            !src.join(format!("{layer}.rs")).exists() && !src.join(layer).join("mod.rs").exists()
        })
        .collect()
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the Check signature returns a Result"
)]
fn component_layers(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for name in COMPONENTS {
        let src = root.join("crates").join(name).join("src");
        if !src.is_dir() {
            continue;
        }
        for layer in missing_layers(&src) {
            out.push(v(
                "T-27",
                &format!("crates/{name}/src"),
                format!("component crate `{name}` has no `{layer}` module"),
            ));
        }
    }
    Ok(out)
}

pub(crate) const ROOT_JS_FILES: &[&str] = &[
    "package.json",
    "package-lock.json",
    "pnpm-lock.yaml",
    "pnpm-workspace.yaml",
    "yarn.lock",
    ".npmrc",
    "tsconfig.json",
    "eslint.config.js",
    "prettier.config.js",
];

#[allow(
    clippy::unnecessary_wraps,
    reason = "the Check signature returns a Result"
)]
fn no_root_javascript(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(ROOT_JS_FILES
        .iter()
        .filter(|f| root.join(f).exists())
        .map(|f| {
            v(
                "T-53",
                f,
                "no JavaScript files at the repository root; every package is its own npm project"
                    .to_owned(),
            )
        })
        .collect())
}

pub(crate) const CONTRIBUTION_FILES: &[&str] = &[
    ".github/pull_request_template.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    "CODE_OF_CONDUCT.md",
    ".github/CODE_OF_CONDUCT.md",
];

fn no_contribution_files(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out: Vec<Violation> = CONTRIBUTION_FILES
        .iter()
        .filter(|f| root.join(f).exists())
        .map(|f| {
            v(
                "T-44",
                f,
                "no pull request template or code of conduct: there are no external contributions"
                    .to_owned(),
            )
        })
        .collect();
    for required in ["CONTRIBUTING.md", "SECURITY.md", ".github/CODEOWNERS"] {
        if !root.join(required).exists() {
            out.push(v("T-44", required, "required file is missing".to_owned()));
        }
    }
    let templates = root.join(".github/ISSUE_TEMPLATE");
    if !templates.is_dir() || walk(&templates)?.is_empty() {
        out.push(v(
            "T-44",
            ".github/ISSUE_TEMPLATE",
            "issue templates are missing".to_owned(),
        ));
    }
    Ok(out)
}

/// Numbered items under the `### title` heading of `markdown`.
pub(crate) fn numbered_items(markdown: &str, title: &str) -> usize {
    let Some(section) = markdown.split(&format!("### {title}\n")).nth(1) else {
        return 0;
    };
    section
        .split("\n#")
        .next()
        .unwrap_or_default()
        .lines()
        .filter(|l| {
            let digits: String = l.chars().take_while(char::is_ascii_digit).collect();
            !digits.is_empty() && l.get(digits.len()..).is_some_and(|r| r.starts_with(". "))
        })
        .count()
}

pub(crate) fn checklist_findings(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    if numbered_items(markdown, "Concept test") != 5 {
        out.push("the concept test must list the five questions of F-6".to_owned());
    }
    if numbered_items(markdown, "Change test") != 16 {
        out.push("the change test must list the sixteen items of F-7 and INV-41".to_owned());
    }
    out
}

fn review_checklist(root: &Path) -> Result<Vec<Violation>, String> {
    let text = std::fs::read_to_string(root.join("CONTRIBUTING.md"))
        .map_err(|e| format!("CONTRIBUTING.md: {e}"))?;
    Ok(checklist_findings(&text)
        .into_iter()
        .map(|m| v("INV-41", "CONTRIBUTING.md", m))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inv_41_change_test_must_be_complete() {
        let short = "### Concept test\n\n1. a\n2. b\n3. c\n4. d\n5. e\n\n### Change test\n\n1. x\n";
        assert_eq!(checklist_findings(short).len(), 1);
    }

    #[test]
    fn f_7_contributing_carries_both_checklists() {
        let text = include_str!("../../CONTRIBUTING.md");
        assert_eq!(checklist_findings(text).len(), 0);
    }

    #[test]
    fn t_43_adr_directory_is_rejected() {
        let found = adr_paths(["README.md", "docs/adr/1.md", "Decisions/x.md"].into_iter());
        assert_eq!(found, vec!["docs/adr/1.md", "Decisions/x.md"]);
    }

    #[test]
    fn t_27_component_without_layers_is_reported() {
        let dir = std::env::temp_dir().join(format!("one-xtask-layers-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("src")).unwrap();
        std::fs::write(dir.join("src/domain.rs"), "").unwrap();
        assert_eq!(
            missing_layers(&dir.join("src")),
            vec!["ports", "app", "adapters"]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
