//! TEE boundary checks: `Unsealed` is made only in the job frame under `crates/tee/src/frame` (T-27 (3)), and a release build's attestation trust store holds the vendor roots of `conformance/tee/trust-roots.toml` alone: local roots are compiled only with debug assertions and no release profile turns them on (T-27 (10), T-42 (3)).

use std::collections::BTreeSet;
use std::path::Path;

use super::{at, read_opt, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::read;
use crate::rules::lex::{find_token, lex, line_at};

pub(crate) const FRAME: &str = "crates/tee/src/frame/";
pub(crate) const ROOTS_RS: &str = "crates/tee/src/domain/roots.rs";
pub(crate) const ROOTS_TOML: &str = "conformance/tee/trust-roots.toml";

const CONSTRUCTORS: &[&str] = &["Unsealed::new", "Unsealed {", "Unsealed::<"];

/// `(line, constructor)` for every `Unsealed` construction in `src` when `rel` is outside the frame.
pub(crate) fn constructor_findings(rel: &str, src: &str) -> Vec<(usize, &'static str)> {
    if rel.starts_with(FRAME) {
        return Vec::new();
    }
    let code = lex(src).code;
    let mut out: Vec<(usize, &'static str)> = CONSTRUCTORS
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

pub(crate) fn check_constructor(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        let rust = Path::new(&file)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("rs"));
        if !rust || file.starts_with("xtask/") {
            continue;
        }
        for (line, needle) in constructor_findings(&file, &read(&root.join(&file))?) {
            out.push(v(
                "T-27",
                at(&file, line),
                format!("`{needle}` outside {FRAME}: decrypted content is made only in the TEE job frame"),
            ));
        }
    }
    Ok(out)
}

/// One `pub const NAME: &[TrustRoot] = &[...];` declaration of the roots file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Store {
    pub(crate) name: String,
    pub(crate) cfg: Option<String>,
    pub(crate) line: usize,
    pub(crate) roots: Vec<(String, bool)>,
}

/// Every root table declared in `src`, with the `cfg` attribute right above it and each root's name and whether it lists `Profile::Release`.
pub(crate) fn stores(src: &str) -> Vec<Store> {
    let lines: Vec<&str> = src.lines().collect();
    let mut out = Vec::new();
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        let Some(rest) = t.strip_prefix("pub const ") else {
            continue;
        };
        let Some((name, ty)) = rest.split_once(':') else {
            continue;
        };
        if !ty.trim_start().starts_with("&[TrustRoot]") {
            continue;
        }
        let cfg = i
            .checked_sub(1)
            .and_then(|p| lines.get(p))
            .map(|l| l.trim())
            .filter(|l| l.starts_with("#[cfg("))
            .map(str::to_owned);
        let mut body = String::new();
        for l in lines.iter().skip(i) {
            body.push_str(l);
            body.push('\n');
            if l.trim_end().ends_with("];") {
                break;
            }
        }
        let mut roots = Vec::new();
        for entry in body.split("TrustRoot {").skip(1) {
            let id = entry
                .split_once("name: \"")
                .and_then(|(_, r)| r.split_once('"'))
                .map(|(id, _)| id.to_owned());
            let profiles = entry
                .split_once("profiles:")
                .map(|(_, r)| r.split_once(']').map_or(r, |(p, _)| p))
                .unwrap_or_default();
            if let Some(id) = id {
                roots.push((id, profiles.contains("Profile::Release")));
            }
        }
        out.push(Store {
            name: name.trim().to_owned(),
            cfg,
            line: i.saturating_add(1),
            roots,
        });
    }
    out
}

/// Problems of the declared stores against the release and local root ids of the TOML file.
pub(crate) fn store_findings(
    stores: &[Store],
    release_ids: &BTreeSet<String>,
    local_ids: &BTreeSet<String>,
) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut seen_release = BTreeSet::new();
    let mut seen_local = BTreeSet::new();
    for s in stores {
        let gated = s.cfg.as_deref() == Some("#[cfg(debug_assertions)]");
        for (id, release) in &s.roots {
            if gated {
                if *release || release_ids.contains(id) {
                    out.push((
                        s.line,
                        format!("`{id}` is a release root in a debug-only store"),
                    ));
                }
                seen_local.insert(id.clone());
            } else {
                if local_ids.contains(id) || !release_ids.contains(id) {
                    out.push((
                        s.line,
                        format!("`{id}` would ship in a release build; only vendor roots listed for every release profile may"),
                    ));
                }
                if !*release {
                    out.push((s.line, format!("`{id}` does not list Profile::Release")));
                }
                seen_release.insert(id.clone());
            }
        }
    }
    for id in release_ids.difference(&seen_release) {
        out.push((0, format!("release root `{id}` of {ROOTS_TOML} is missing")));
    }
    for id in local_ids.difference(&seen_local) {
        out.push((0, format!("local root `{id}` of {ROOTS_TOML} is missing")));
    }
    out
}

fn toml_ids(table: &toml::Table) -> Result<(BTreeSet<String>, BTreeSet<String>), String> {
    let release: Vec<&str> = table
        .get("release_profiles")
        .and_then(toml::Value::as_array)
        .ok_or_else(|| format!("{ROOTS_TOML}: release_profiles"))?
        .iter()
        .filter_map(toml::Value::as_str)
        .collect();
    let mut release_ids = BTreeSet::new();
    let mut local_ids = BTreeSet::new();
    for root in table
        .get("root")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
    {
        let id = root
            .get("id")
            .and_then(toml::Value::as_str)
            .ok_or_else(|| format!("{ROOTS_TOML}: root without id"))?;
        let profiles: Vec<&str> = root
            .get("profiles")
            .and_then(toml::Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(toml::Value::as_str)
            .collect();
        if release.iter().all(|p| profiles.contains(p)) {
            release_ids.insert(id.to_owned());
        } else {
            local_ids.insert(id.to_owned());
        }
    }
    Ok((release_ids, local_ids))
}

/// Release profiles of a manifest that turn debug assertions, and so the local roots, on.
pub(crate) fn profile_findings(manifest: &str, release: &[&str]) -> Result<Vec<String>, String> {
    let table: toml::Table = manifest.parse().map_err(|e| format!("Cargo.toml: {e}"))?;
    let profiles = table.get("profile").and_then(toml::Value::as_table);
    Ok(release
        .iter()
        .filter(|p| {
            profiles
                .and_then(|t| t.get(**p))
                .and_then(|t| t.get("debug-assertions"))
                .and_then(toml::Value::as_bool)
                == Some(true)
        })
        .map(|p| {
            format!("[profile.{p}] sets debug-assertions = true and would ship the local roots")
        })
        .collect())
}

pub(crate) fn check_roots(root: &Path) -> Result<Vec<Violation>, String> {
    let Some(src) = read_opt(root, ROOTS_RS)? else {
        return Ok(Vec::new());
    };
    let table: toml::Table = read(&root.join(ROOTS_TOML))?
        .parse()
        .map_err(|e| format!("{ROOTS_TOML}: {e}"))?;
    let (release_ids, local_ids) = toml_ids(&table)?;
    let mut out: Vec<Violation> = store_findings(&stores(&src), &release_ids, &local_ids)
        .into_iter()
        .map(|(line, m)| v("T-27", at(ROOTS_RS, line), m))
        .collect();
    let release: Vec<&str> = table
        .get("release_profiles")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(toml::Value::as_str)
        .collect();
    let manifest = read(&root.join("Cargo.toml"))?;
    for m in profile_findings(&manifest, &release)? {
        out.push(v("T-42", "Cargo.toml", m));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_27_unsealed_is_made_only_in_the_frame() {
        let src = "fn f() {\n    let a = Unsealed::new(1);\n    let b = Unsealed { value: 2 };\n    let c = Unsealed::<u8>::new(3);\n}\n";
        assert_eq!(
            constructor_findings("crates/memory/src/a.rs", src),
            [(2, "Unsealed::new"), (3, "Unsealed {"), (4, "Unsealed::<"),]
        );
        assert_eq!(constructor_findings("crates/tee/src/frame/mod.rs", src), []);
        assert_eq!(
            constructor_findings("crates/tee/src/sealed.rs", src).len(),
            3
        );
    }

    #[test]
    fn t_27_comments_and_doc_tests_are_not_constructions() {
        let src = "/// ```compile_fail\n/// let u = one_tee::Unsealed::new(7);\n/// ```\nfn f(u: &Unsealed<u8>) {}\n// Unsealed::new\n";
        assert_eq!(constructor_findings("crates/tee/src/lib.rs", src), []);
    }

    #[test]
    fn t_27_the_repository_passes() {
        let root = crate::workspace_root();
        assert!(check_constructor(&root).unwrap().is_empty());
        assert!(check_roots(&root).unwrap().is_empty());
    }

    fn ids(list: &[&str]) -> BTreeSet<String> {
        list.iter().map(|s| (*s).to_owned()).collect()
    }

    #[test]
    fn t_42_local_roots_are_debug_only() {
        let good = "pub const VENDOR_ROOTS: &[TrustRoot] = &[\n    TrustRoot {\n        name: \"amd\",\n        profiles: &[Profile::Release, Profile::Dev],\n    },\n];\n\n#[cfg(debug_assertions)]\npub const LOCAL_ROOTS: &[TrustRoot] = &[TrustRoot {\n    name: \"sim\",\n    profiles: &[Profile::Dev],\n}];\n\n#[cfg(not(debug_assertions))]\npub const LOCAL_ROOTS: &[TrustRoot] = &[];\n";
        let parsed = stores(good);
        assert_eq!(parsed.len(), 3);
        assert_eq!(store_findings(&parsed, &ids(&["amd"]), &ids(&["sim"])), []);
        let ungated = good.replace("#[cfg(debug_assertions)]\n", "");
        assert_eq!(
            store_findings(&stores(&ungated), &ids(&["amd"]), &ids(&["sim"])).len(),
            3
        );
        let release_local = good.replace("&[Profile::Dev],\n}]", "&[Profile::Release],\n}]");
        assert_eq!(
            store_findings(&stores(&release_local), &ids(&["amd"]), &ids(&["sim"])).len(),
            1
        );
        let missing = store_findings(&parsed, &ids(&["amd", "intel"]), &ids(&["sim"]));
        assert_eq!(missing.len(), 1);
    }

    #[test]
    fn t_42_release_profile_never_enables_debug_assertions() {
        let ok = "[profile.release]\noverflow-checks = true\n";
        assert_eq!(profile_findings(ok, &["release"]).unwrap().len(), 0);
        let bad = "[profile.release]\ndebug-assertions = true\n";
        assert_eq!(profile_findings(bad, &["release"]).unwrap().len(), 1);
    }
}
