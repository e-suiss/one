//! Boundary checks: clock and randomness only through ports (T-27 (2)), no Python in the production control plane (T-2), and no re-implementation of identity, permission, push, waiting or payment (MD-2 (2), INV-37).

use std::path::Path;

use super::{at, read_opt, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::{is_test_file, read};
use crate::rules::lex::{find_token, lex, line_at};
use crate::supply_chain::cooldown_lock;

fn is_rust(file: &str) -> bool {
    Path::new(file)
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("rs"))
}

pub(crate) const PORT_ALLOWED: &[&str] = &["bins/one-server/src/system.rs", "load/", "xtask/"];

const CLIPPY_REQUIRED: &[&str] = &[
    "std::time::SystemTime::now",
    "std::time::Instant::now",
    "uuid::Uuid::new_v4",
    "getrandom::fill",
];

pub(crate) fn port_findings(rel: &str, src: &str) -> Vec<usize> {
    if PORT_ALLOWED.iter().any(|p| rel.starts_with(p)) || is_test_file(rel) {
        return Vec::new();
    }
    let code: String = lex(src).code;
    let squeezed: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if !squeezed.contains("clippy::disallowed_methods") {
        return Vec::new();
    }
    find_token(&code, "disallowed_methods")
        .into_iter()
        .map(|i| line_at(&code, i))
        .collect()
}

pub(crate) fn check_ports(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let clippy = read_opt(root, "clippy.toml")?.unwrap_or_default();
    for path in CLIPPY_REQUIRED {
        if !clippy.contains(path) {
            out.push(v(
                "T-27",
                "clippy.toml",
                format!("`{path}` must stay in disallowed-methods"),
            ));
        }
    }
    for file in repo_files(root)?.iter().filter(|f| is_rust(f)) {
        for line in port_findings(file, &read(&root.join(file))?) {
            out.push(v(
                "T-27",
                at(file, line),
                "only the composition root may read the clock or randomness directly".to_owned(),
            ));
        }
    }
    Ok(out)
}

pub(crate) const PYTHON_CALLS: &[&str] =
    &["\"python", "\"python3", "\"uv\"", "\"pip\"", "\"pip3\""];

pub(crate) fn python_call_lines(src: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (i, line) in src.lines().enumerate() {
        if line.contains("Command::new(") && PYTHON_CALLS.iter().any(|p| line.contains(p)) {
            out.push(i.saturating_add(1));
        }
    }
    out
}

pub(crate) fn check_python(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    for file in repo_files(root)? {
        if is_rust(&file) && !file.starts_with("xtask/") && !is_test_file(&file) {
            for line in python_call_lines(&read(&root.join(&file))?) {
                out.push(v(
                    "T-2",
                    at(&file, line),
                    "Rust code never runs Python; ML jobs talk through manifests".to_owned(),
                ));
            }
        }
        let name = file
            .rsplit('/')
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if file.starts_with("deploy/docker/") && name.starts_with("dockerfile") {
            let text = read(&root.join(&file))?.to_ascii_lowercase();
            if text.contains("python") || text.contains("pip install") {
                out.push(v(
                    "T-2",
                    file.clone(),
                    "server images carry no Python".to_owned(),
                ));
            }
        }
    }
    let lock = read(&root.join("Cargo.lock"))?;
    for pkg in cooldown_lock(&lock)? {
        if matches!(
            pkg.name.as_str(),
            "pyo3" | "pyo3-ffi" | "cpython" | "rustpython"
        ) {
            out.push(v(
                "T-2",
                "Cargo.lock",
                format!("`{}` embeds Python in Rust", pkg.name),
            ));
        }
    }
    Ok(out)
}

pub(crate) const SIBLING_CRATES: &[(&str, &str)] = &[
    ("a2", "push delivery belongs to Relay"),
    ("apns2", "push delivery belongs to Relay"),
    ("fcm", "push delivery belongs to Relay"),
    ("fcm-rs", "push delivery belongs to Relay"),
    ("web-push", "push delivery belongs to Relay"),
    ("lettre", "notification delivery belongs to Relay"),
    ("stripe", "payments belong to Pay"),
    ("async-stripe", "payments belong to Pay"),
    ("stripe-rust", "payments belong to Pay"),
    ("argon2", "password handling belongs to Access"),
    ("rust-argon2", "password handling belongs to Access"),
    ("bcrypt", "password handling belongs to Access"),
    ("scrypt", "password handling belongs to Access"),
    ("password-hash", "password handling belongs to Access"),
    ("oxide-auth", "identity and authorization belong to Access"),
    (
        "tokio-cron-scheduler",
        "human waits and timers belong to Relay",
    ),
];

pub(crate) const SIBLING_NPM: &[(&str, &str)] = &[
    ("firebase-admin", "push delivery belongs to Relay"),
    ("web-push", "push delivery belongs to Relay"),
    ("apn", "push delivery belongs to Relay"),
    ("node-apn", "push delivery belongs to Relay"),
    ("stripe", "payments belong to Pay"),
    ("@stripe/stripe-js", "payments belong to Pay"),
    ("bcrypt", "password handling belongs to Access"),
    ("argon2", "password handling belongs to Access"),
];

pub(crate) fn npm_findings(manifest: &str) -> Result<Vec<String>, String> {
    let json: serde_json::Value = serde_json::from_str(manifest).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for section in ["dependencies", "devDependencies", "optionalDependencies"] {
        if let Some(deps) = json.get(section).and_then(serde_json::Value::as_object) {
            for (name, why) in SIBLING_NPM {
                if deps.contains_key(*name) {
                    out.push(format!("`{name}`: {why}"));
                }
            }
        }
    }
    Ok(out)
}

pub(crate) fn check_siblings(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let lock = read(&root.join("Cargo.lock"))?;
    for pkg in cooldown_lock(&lock)? {
        if let Some((_, why)) = SIBLING_CRATES.iter().find(|(n, _)| *n == pkg.name) {
            out.push(v(
                "INV-37",
                "Cargo.lock",
                format!("`{}`: {why} (MD-2)", pkg.name),
            ));
        }
    }
    for file in repo_files(root)?
        .iter()
        .filter(|f| f.ends_with("package.json"))
    {
        for finding in npm_findings(&read(&root.join(file))?)? {
            out.push(v("INV-37", file.clone(), format!("{finding} (MD-2)")));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_27_allowing_disallowed_methods_outside_the_root_is_rejected() {
        let src = "#[allow(clippy::disallowed_methods)]\nfn f() {}\n";
        assert_eq!(port_findings("crates/memory/src/a.rs", src), vec![1]);
        assert_eq!(port_findings("bins/one-server/src/system.rs", src).len(), 0);
        assert_eq!(
            port_findings("crates/memory/src/a.rs", "fn f() {}").len(),
            0
        );
    }

    #[test]
    fn t_2_rust_spawning_python_is_rejected() {
        assert_eq!(
            python_call_lines("let c = Command::new(\"python3\");"),
            vec![1]
        );
        assert_eq!(python_call_lines("let c = Command::new(\"git\");").len(), 0);
    }

    #[test]
    fn inv_37_push_and_payment_sdks_are_rejected() {
        let found =
            npm_findings(r#"{"dependencies":{"stripe":"1.0.0","react":"19.0.0"}}"#).unwrap();
        assert_eq!(found.len(), 1);
        assert!(SIBLING_CRATES.iter().any(|(n, _)| *n == "web-push"));
    }
}
