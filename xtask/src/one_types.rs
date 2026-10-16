//! `typed-ids`: identifier fields never carry a bare `String`, `&str`, `Uuid` or integer; they use the typed IDs of `one-proto` (T-28 (5)).

use std::path::Path;

use super::{at, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::{is_test_file, read};
use crate::rules::lex::{in_regions, lex, test_regions};

const SCOPES: &[&str] = &["crates/", "bins/", "core/"];
const BARE: &[&str] = &[
    "String",
    "&str",
    "&'static str",
    "Uuid",
    "uuid::Uuid",
    "u128",
    "u64",
    "i64",
    "Vec<u8>",
];

/// `(line, field)` for identifier fields declared with a bare type.
pub(crate) fn bare_id_fields(src: &str) -> Vec<(usize, String)> {
    let lexed = lex(src);
    let tests = test_regions(&lexed.code);
    let mut out = Vec::new();
    for (i, line) in lexed.code.lines().enumerate() {
        let n = i.saturating_add(1);
        if in_regions(&tests, n) {
            continue;
        }
        let decl = line
            .trim()
            .trim_start_matches("pub(crate) ")
            .trim_start_matches("pub ");
        let Some((name, ty)) = decl.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name.contains(' ') || name.contains('(') || !(name == "id" || name.ends_with("_id")) {
            continue;
        }
        let ty = ty.trim().trim_end_matches(',').trim();
        let inner = ty
            .strip_prefix("Option<")
            .and_then(|t| t.strip_suffix('>'))
            .unwrap_or(ty);
        if BARE.contains(&inner) {
            out.push((n, name.to_owned()));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let rust = Path::new(&file)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
        if !rust || !SCOPES.iter().any(|s| file.starts_with(s)) || is_test_file(&file) {
            continue;
        }
        for (line, name) in bare_id_fields(&read(&root.join(&file))?) {
            out.push(v(
                "T-28",
                at(&file, line),
                format!(
                    "`{name}` is an identifier with a bare type; use a typed ID from one-proto"
                ),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_28_bare_identifier_fields_are_rejected() {
        let src = "struct A {\n    pub task_id: String,\n    id: Option<Uuid>,\n    owner_id: TaskId,\n    name: String,\n}\n";
        let found = bare_id_fields(src);
        assert_eq!(found, vec![(2, "task_id".to_owned()), (3, "id".to_owned())]);
    }

    #[test]
    fn t_28_test_code_is_not_checked() {
        let src = "#[cfg(test)]\nmod tests {\n    struct A { id: String }\n}\n";
        assert_eq!(bare_id_fields(src).len(), 0);
    }
}
