//! `dependency-direction`: internal crates depend only on the internal crates the T-26 (6) table allows; component crates never depend on each other.

use std::path::Path;

use crate::Violation;
use crate::rules::files::rel;
use crate::supply_chain::metadata::{DepKind, Metadata};

const RULE: &str = "dependency-direction";

/// The T-26 (6) crate classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Class {
    Proto,
    NoStdCore,
    Parse,
    KeyLayer,
    Storage,
    Rpc,
    Client,
    Component,
    Http,
    Telemetry,
    Runtime,
    Config,
    Testkit,
    Bin,
    Core,
    Tooling,
}

const CLIENTS: &[&str] = &[
    "model-client",
    "access-client",
    "relay-client",
    "work-client",
    "pay-client",
    "executor-client",
];

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

/// Classifies a workspace crate by its directory relative to the root.
pub(crate) fn classify(dir: &str) -> Option<Class> {
    if dir == "core" {
        return Some(Class::Core);
    }
    if dir == "xtask" || dir == "load" {
        return Some(Class::Tooling);
    }
    let (group, name) = dir.split_once('/')?;
    if name.contains('/') {
        return None;
    }
    let class = match (group, name) {
        ("crates", "proto") => Class::Proto,
        ("crates", "provenance" | "interaction") => Class::NoStdCore,
        ("crates", "parse") => Class::Parse,
        ("crates", "keys" | "tee") => Class::KeyLayer,
        ("crates", "store" | "objects") => Class::Storage,
        ("crates", "rpc") => Class::Rpc,
        ("crates", "http") => Class::Http,
        ("crates", "telemetry") => Class::Telemetry,
        ("crates", "runtime") => Class::Runtime,
        ("crates", "config") => Class::Config,
        ("crates", "testkit") => Class::Testkit,
        ("crates", n) if CLIENTS.contains(&n) => Class::Client,
        ("crates", n) if COMPONENTS.contains(&n) => Class::Component,
        ("bins", n) if !n.is_empty() => Class::Bin,
        _ => return None,
    };
    Some(class)
}

/// The T-26 (6) table: the internal classes a crate of class `from` may depend on; `None` means every class.
fn allowed_targets(from: Class) -> Option<&'static [Class]> {
    use Class::{
        Bin, Client, Component, Config, Core, Http, KeyLayer, NoStdCore, Parse, Proto, Rpc,
        Runtime, Storage, Telemetry, Testkit, Tooling,
    };
    let targets: &'static [Class] = match from {
        Bin => return None,
        Proto | Telemetry | Runtime | Config | Tooling => &[],
        Testkit => &[Runtime],
        NoStdCore | KeyLayer | Rpc => &[Proto],
        Parse => &[Proto, NoStdCore],
        Storage => &[Proto, KeyLayer],
        Client => &[Proto, NoStdCore, Rpc, Telemetry],
        Component => &[
            Proto, NoStdCore, Parse, KeyLayer, Storage, Rpc, Client, Telemetry, Runtime, Config,
        ],
        Http => &[Component, Proto, Telemetry, Runtime, Config],
        Core => &[Proto, NoStdCore, Parse],
    };
    Some(targets)
}

/// May a crate of class `from` depend on a crate of class `to`?
pub(crate) fn allowed(from: Class, to: Class) -> bool {
    if to == Class::Testkit && from != Class::Bin {
        return false;
    }
    if to == Class::Runtime && !matches!(from, Class::Tooling | Class::Core) {
        return true;
    }
    allowed_targets(from).is_none_or(|targets| targets.contains(&to))
}

/// Checks every workspace crate's internal dependencies against the table.
pub(crate) fn check_metadata(root: &Path, md: &Metadata) -> Vec<Violation> {
    let mut out = Vec::new();
    for pkg in md.members() {
        let dir = rel(root, pkg.dir());
        let manifest = pkg
            .manifest_path
            .strip_prefix(root)
            .unwrap_or(&pkg.manifest_path)
            .to_path_buf();
        let Some(from) = classify(&dir) else {
            out.push(Violation {
                rule: RULE,
                path: manifest,
                message: format!(
                    "crate `{}` in `{dir}` has no T-26 (6) class; add its directory to xtask/src/rules_deps.rs",
                    pkg.name
                ),
            });
            continue;
        };
        for dep in pkg.deps.iter().filter(|d| d.kind != DepKind::Dev) {
            let Some(dep_path) = &dep.path else { continue };
            let dep_dir = rel(root, dep_path);
            let Some(to) = classify(&dep_dir) else {
                out.push(Violation {
                    rule: RULE,
                    path: manifest.clone(),
                    message: format!(
                        "depends on `{}` in `{dep_dir}`, which has no T-26 (6) class",
                        dep.name
                    ),
                });
                continue;
            };
            if !allowed(from, to) {
                out.push(Violation {
                    rule: RULE,
                    path: manifest.clone(),
                    message: format!(
                        "`{}` ({from:?}) must not depend on `{}` ({to:?}) (T-26 (6))",
                        pkg.name, dep.name
                    ),
                });
            }
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let md = crate::supply_chain::metadata::load(root)?;
    Ok(check_metadata(root, &md))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::supply_chain::metadata::fixture::{member, metadata};
    use crate::supply_chain::metadata::parse;

    fn run(packages: &[serde_json::Value]) -> Vec<Violation> {
        let md = parse(&metadata(packages, &[])).unwrap_or_default();
        check_metadata(Path::new("/ws"), &md)
    }

    #[test]
    fn t_26_component_crates_never_depend_on_each_other() {
        let v = run(&[
            member("crates/memory", &[]),
            member("crates/task", &[("crates/memory", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn t_26_core_never_depends_on_server_crates() {
        for server in ["crates/store", "crates/tee", "crates/http", "crates/memory"] {
            let v = run(&[member(server, &[]), member("core", &[(server, None)])]);
            assert_eq!(v.len(), 1, "{server}");
        }
        let ok = run(&[
            member("crates/provenance", &[]),
            member("core", &[("crates/provenance", None)]),
        ]);
        assert_eq!(ok.len(), 0);
    }

    #[test]
    fn t_26_no_std_crates_depend_only_on_proto() {
        let v = run(&[
            member("crates/telemetry", &[]),
            member("crates/provenance", &[("crates/telemetry", None)]),
        ]);
        assert_eq!(v.len(), 1);
    }

    #[test]
    fn t_26_testkit_is_dev_only() {
        let v = run(&[
            member("crates/testkit", &[]),
            member("crates/http", &[("crates/testkit", None)]),
        ]);
        assert_eq!(v.len(), 1);
        let dev = run(&[
            member("crates/testkit", &[]),
            member("crates/http", &[("crates/testkit", Some("dev"))]),
        ]);
        assert_eq!(dev.len(), 0);
    }

    #[test]
    fn t_26_bins_may_depend_on_everything() {
        let v = run(&[
            member("crates/memory", &[]),
            member("crates/http", &[]),
            member(
                "bins/one-server",
                &[("crates/memory", None), ("crates/http", None)],
            ),
        ]);
        assert_eq!(v.len(), 0);
    }

    #[test]
    fn t_26_crate_in_unknown_directory_fails_closed() {
        let v = run(&[member("crates/mystery", &[])]);
        assert_eq!(v.len(), 1);
    }
}
