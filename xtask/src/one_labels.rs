//! `trusted-label-callers`: the trusted-label constructors and the confirmation path are called only inside `one-provenance`, so no other module can launder an untrusted value into a trusted one (T-36 (3)).

use std::path::Path;

use super::{at, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::read;
use crate::rules::lex::{find_token, lex, line_at};

pub(crate) const ALLOWED: &[&str] = &["crates/provenance/src/", "crates/provenance/tests/"];

pub(crate) const ENTRY_POINTS: &[&str] = &[
    "Trusted::user_direct",
    "Trusted::record",
    "ShownConfirmation::new",
    ".confirm(",
    "upgrade_label",
    "corroborate",
    "Label::from_wire",
    "TrustedLabel::UserDirect",
    "TrustedLabel::UserMemory",
    "TrustedLabel::RecordTrusted",
];

/// `(line, entry point)` for every label-raising call in `src` when `rel` is outside the allowlist.
pub(crate) fn findings(rel: &str, src: &str) -> Vec<(usize, &'static str)> {
    if ALLOWED.iter().any(|p| rel.starts_with(p)) {
        return Vec::new();
    }
    let code = lex(src).code;
    let mut out: Vec<(usize, &'static str)> = ENTRY_POINTS
        .iter()
        .flat_map(|needle| {
            find_token(&code, needle)
                .into_iter()
                .map(|i| (line_at(&code, i), *needle))
                .collect::<Vec<_>>()
        })
        .collect();
    out.sort_unstable();
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let rust = Path::new(&file)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
        if !rust || file.starts_with("xtask/") {
            continue;
        }
        for (line, entry) in findings(&file, &read(&root.join(&file))?) {
            out.push(v(
                "T-36",
                at(&file, line),
                format!("`{entry}` raises a provenance label; only one-provenance may call it"),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_36_trusted_constructors_outside_provenance_are_rejected() {
        let src = "fn f(v: Untrusted<&str>) {\n    let a = Trusted::user_direct(\"x\");\n    let b = Trusted::record(1);\n    let p = ShownConfirmation::new(Surface::TrustedSurface, true, Target::Memory).unwrap();\n    let c = p.confirm(v);\n    let l = upgrade_label(&l, e, t);\n    let d = Labelled::derive(t, &[Label::Trusted(TrustedLabel::UserDirect)], 1);\n}\n";
        let found = findings("crates/memory/src/a.rs", src);
        assert_eq!(
            found,
            vec![
                (2, "Trusted::user_direct"),
                (3, "Trusted::record"),
                (4, "ShownConfirmation::new"),
                (5, ".confirm("),
                (6, "upgrade_label"),
                (7, "TrustedLabel::UserDirect"),
            ]
        );
        assert_eq!(findings("crates/http/tests/router.rs", src).len(), 6);
    }

    #[test]
    fn t_36_provenance_and_its_tests_may_raise_labels() {
        let src = "let a = Trusted::user_direct(\"x\");\n";
        assert_eq!(findings("crates/provenance/src/value.rs", src), []);
        assert_eq!(findings("crates/provenance/tests/lattice.rs", src), []);
    }

    #[test]
    fn t_36_comments_strings_and_lookalikes_are_not_calls() {
        let src = "// Trusted::user_direct(x)\nlet s = \"upgrade_label\";\nlet u = UnTrusted::user_directly(1);\nlet w = my_upgrade_label_count;\n";
        assert_eq!(findings("crates/memory/src/a.rs", src), []);
    }
}
