//! `comment-policy`: code and configuration carry no explanatory comments; only `// SAFETY:`, doc comments with one module paragraph, bare spec IDs, `TODO(#123)`, shebangs, tool directives and version notes (T-47).

use std::path::Path;

use super::{at, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::read;
use crate::rules::lex::lex;

const SKIP_PREFIXES: &[&str] = &[
    "supply-chain/",
    "docs/",
    "conformance/catalog/",
    "core/bindings/uniffi/generated/",
    "crates/rpc/src/gen/",
];
const SKIP_SUFFIXES: &[&str] = &[".lock", "package-lock.json", ".min.js"];
const DIRECTIVES: &[&str] = &[
    "syntax=",
    "shellcheck ",
    "yaml-language-server:",
    "type: ignore",
    "noqa",
    "pragma",
    "eslint-",
    "@ts-expect-error",
    "prettier-ignore",
    "swiftlint:",
    "ktlint-",
    "fmt: ",
    "rustfmt::",
    "clippy::",
];

fn is_spec_id(token: &str) -> bool {
    let raw = token.trim();
    let sibling = ["Access ", "Relay ", "Work "]
        .iter()
        .any(|p| raw.starts_with(p));
    let token = raw
        .trim_start_matches("Access ")
        .trim_start_matches("Relay ")
        .trim_start_matches("Work ")
        .trim();
    if let Some(section) = token.strip_prefix('§') {
        return !section.is_empty()
            && section
                .chars()
                .all(|c| c.is_ascii_digit() || c == '.' || c.is_ascii_lowercase());
    }
    let (head, tail) = match token.split_once(" (") {
        Some((h, t)) => (h, Some(t)),
        None => (token, None),
    };
    let tail_ok = tail.is_none_or(|t| {
        t.strip_suffix(')').is_some_and(|inner| {
            !inner.is_empty()
                && inner
                    .chars()
                    .all(|c| c.is_ascii_digit() || matches!(c, ',' | ' ' | '–' | '-'))
        })
    });
    if sibling
        && let Some(split) = head.find(|c: char| c.is_ascii_digit())
        && let (family, number) = head.split_at(split)
        && !family.is_empty()
        && family.chars().all(|c| c.is_ascii_uppercase())
        && number.chars().all(|c| c.is_ascii_digit())
    {
        return tail_ok;
    }
    let mut parts = head.rsplitn(2, '-');
    let number = parts.next().unwrap_or_default();
    let family = parts.next().unwrap_or_default();
    tail_ok
        && !number.is_empty()
        && number.chars().all(|c| c.is_ascii_digit())
        && !family.is_empty()
        && family
            .split('-')
            .all(|f| !f.is_empty() && f.chars().all(|c| c.is_ascii_uppercase()))
}

fn top_level_parts(text: &str) -> Vec<String> {
    let mut parts = vec![String::new()];
    let mut depth = 0_usize;
    for c in text.chars() {
        match c {
            '(' => depth = depth.saturating_add(1),
            ')' => depth = depth.saturating_sub(1),
            ',' | ';' if depth == 0 => {
                parts.push(String::new());
                continue;
            }
            _ => {}
        }
        if let Some(last) = parts.last_mut() {
            last.push(c);
        }
    }
    parts
}

/// True if `text` (without the comment marker) is a list of bare spec IDs.
pub(crate) fn is_id_list(text: &str) -> bool {
    let text = text.trim();
    let parts = top_level_parts(text);
    !text.is_empty()
        && parts.iter().all(|t| t.trim().is_empty() || is_spec_id(t))
        && parts.iter().any(|t| !t.trim().is_empty())
}

fn is_version_note(text: &str) -> bool {
    let t = text.trim().trim_start_matches('v');
    let numeric =
        t.chars().next().is_some_and(|c| c.is_ascii_digit()) && t.split_whitespace().count() <= 2;
    let tag = !t.is_empty()
        && t.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'));
    numeric || tag
}

fn line_comment_ok(body: &str) -> bool {
    let body = body.trim();
    body.starts_with("SAFETY:")
        || body.starts_with("TODO(#")
        || is_id_list(body)
        || DIRECTIVES.iter().any(|d| body.starts_with(d))
}

/// Violations in a Rust file.
pub(crate) fn rust_findings(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut module_doc_blank = false;
    for c in lex(src).comments {
        let text = c.text.as_str();
        if let Some(rest) = text.strip_prefix("//!") {
            if rest.trim().is_empty() {
                module_doc_blank = true;
            }
            continue;
        }
        if text.starts_with("///") || text.starts_with("/**") {
            continue;
        }
        let body = text
            .strip_prefix("//")
            .or_else(|| text.strip_prefix("/*").and_then(|t| t.strip_suffix("*/")))
            .unwrap_or(text);
        if !line_comment_ok(body) {
            out.push((
                c.line,
                "explanatory comment; the reason belongs in the spec".to_owned(),
            ));
        }
    }
    if module_doc_blank {
        out.push((
            1,
            "module documentation must be a single paragraph".to_owned(),
        ));
    }
    out
}

fn hash_comment(line: &str) -> Option<(usize, &str)> {
    let mut quote: Option<char> = None;
    for (i, c) in line.char_indices() {
        match (quote, c) {
            (None, '"' | '\'') => quote = Some(c),
            (Some(q), _) if c == q => quote = None,
            (None, '#') => return line.get(i.saturating_add(1)..).map(|b| (i, b)),
            _ => {}
        }
    }
    None
}

/// Violations in a `#`-comment file (TOML, YAML, shell, Python, justfile, Dockerfile, ignore files).
pub(crate) fn hash_findings(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_multiline = false;
    for (i, line) in src.lines().enumerate() {
        let n = i.saturating_add(1);
        if n == 1 && line.starts_with("#!") {
            continue;
        }
        let fences = line
            .matches("\"\"\"")
            .count()
            .saturating_add(line.matches("'''").count());
        if in_multiline {
            if fences % 2 == 1 {
                in_multiline = false;
            }
            continue;
        }
        if fences % 2 == 1 {
            in_multiline = true;
        }
        let Some((col, body)) = hash_comment(line) else {
            continue;
        };
        let trailing = !line.get(..col).unwrap_or_default().trim().is_empty();
        let ok = line_comment_ok(body) || (trailing && is_version_note(body));
        if !ok {
            out.push((
                n,
                "explanatory comment; the reason belongs in the spec".to_owned(),
            ));
        }
    }
    out
}

/// Violations in a `//` and `/* */` file (TypeScript, JavaScript, Swift, Kotlin).
pub(crate) fn slash_findings(src: &str) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut in_block: Option<(usize, bool, String)> = None;
    for (i, line) in src.lines().enumerate() {
        let n = i.saturating_add(1);
        let trimmed = line.trim();
        if let Some((start, doc, mut body)) = in_block.take() {
            body.push(' ');
            body.push_str(trimmed);
            if trimmed.contains("*/") {
                if !doc && !line_comment_ok(body.trim_end_matches("*/")) {
                    out.push((
                        start,
                        "explanatory comment; the reason belongs in the spec".to_owned(),
                    ));
                }
            } else {
                in_block = Some((start, doc, body));
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("/*") {
            let doc = rest.starts_with('*');
            if rest.contains("*/") {
                if !doc && !line_comment_ok(rest.trim_end_matches("*/")) {
                    out.push((
                        n,
                        "explanatory comment; the reason belongs in the spec".to_owned(),
                    ));
                }
            } else {
                in_block = Some((n, doc, rest.to_owned()));
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("//") {
            if rest.starts_with('/') || line_comment_ok(rest) {
                continue;
            }
            out.push((
                n,
                "explanatory comment; the reason belongs in the spec".to_owned(),
            ));
        }
    }
    out
}

type Scanner = fn(&str) -> Vec<(usize, String)>;

fn kind(file: &str) -> Option<Scanner> {
    let name = file.rsplit('/').next().unwrap_or(file);
    let ext = name.rsplit_once('.').map(|(_, e)| e).unwrap_or_default();
    if SKIP_PREFIXES.iter().any(|p| file.starts_with(p))
        || SKIP_SUFFIXES.iter().any(|s| file.ends_with(s))
    {
        return None;
    }
    match ext {
        "rs" => Some(rust_findings),
        "toml" | "yml" | "yaml" | "sh" | "py" | "cfg" | "ini" | "conf" => Some(hash_findings),
        "ts" | "tsx" | "js" | "mjs" | "cjs" | "swift" | "kt" | "kts" => Some(slash_findings),
        _ if name == "justfile"
            || name.starts_with("Dockerfile")
            || matches!(
                name,
                ".gitignore" | ".dockerignore" | ".editorconfig" | ".npmrc" | "pre-commit"
            ) =>
        {
            Some(hash_findings)
        }
        _ => None,
    }
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let Some(scan) = kind(&file) else { continue };
        for (line, message) in scan(&read(&root.join(&file))?) {
            out.push(v("T-47", at(&file, line), message));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_42_generated_code_is_not_scanned() {
        assert!(kind("core/bindings/uniffi/generated/swift/OneCore.swift").is_none());
        assert!(kind("crates/rpc/src/gen/one.serving.v1.rs").is_none());
        assert!(kind("core/bindings/uniffi/tests/swift/main.swift").is_some());
    }

    #[test]
    fn t_47_bare_spec_ids_are_allowed() {
        for ok in [
            "T-28 (4)",
            "SEC-12",
            "T-26 (3), T-48",
            "T-28 (3, 9)",
            "Access OP-72",
            "§17.10",
            "T-45, Access OP-72",
            "Access TN-136, Access E42 (4), E-3",
        ] {
            assert!(is_id_list(ok), "{ok}");
        }
        assert!(!is_id_list("the reason is speed"));
        assert!(!is_id_list("T-28: overflow checks stay on"));
    }

    #[test]
    fn t_47_explanatory_rust_comment_is_rejected() {
        let src = "//! One paragraph.\n// T-27 (2)\nfn f() {\n    // SAFETY: none\n    // this explains why\n}\n";
        let found = rust_findings(src);
        assert_eq!(found.len(), 1);
        assert_eq!(found.first().map(|f| f.0), Some(5));
    }

    #[test]
    fn t_47_module_doc_must_be_one_paragraph() {
        assert_eq!(rust_findings("//! A.\n//!\n//! B.\n").len(), 1);
    }

    #[test]
    fn t_47_hash_comments_allow_ids_versions_and_shebang() {
        let src = "#!/usr/bin/env bash\n# T-42\nh = \"\"\"\n# Changelog\n\"\"\"\nimage: x@sha256:abc # 18.6-trixie\nimage: y@sha256:abc # main-e711dde\nurl = \"a#b\"\n# explains things\n";
        assert_eq!(
            hash_findings(src),
            vec![(
                9,
                "explanatory comment; the reason belongs in the spec".to_owned()
            )]
        );
    }

    #[test]
    fn t_47_slash_comments_allow_docs_and_directives() {
        let src = "/** Doc. */\n// eslint-disable-next-line no-console\n// T-29 (3)\n/* explains */\n// explains too\n";
        assert_eq!(slash_findings(src).len(), 2);
    }
}
