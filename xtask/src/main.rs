//! Repository rule checks, catalog generation and commit checks for One (T-26 (6), T-41 (2), T-44 (3), T-55).

#![allow(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "xtask is a developer CLI; it reports to the terminal"
)]
#![allow(clippy::disallowed_methods, reason = "T-27")]

mod catalog;
mod devtools;
mod one_checks;
mod policy;
mod rules;
mod supply_chain;

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// One rule violation, reported as `path: [rule] message`.
#[derive(Debug)]
pub(crate) struct Violation {
    pub(crate) rule: &'static str,
    pub(crate) path: PathBuf,
    pub(crate) message: String,
}

/// A named check over the repository.
pub(crate) struct Check {
    pub(crate) name: &'static str,
    pub(crate) run: fn(&Path) -> Result<Vec<Violation>, String>,
}

fn checks() -> Vec<Check> {
    let mut all = Vec::new();
    all.extend(rules::checks());
    all.extend(supply_chain::checks());
    all.extend(policy::checks());
    all.extend(one_checks::checks());
    all.extend(catalog::checks());
    all
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .map_or_else(|| PathBuf::from("."), Path::to_path_buf)
}

fn run_checks(root: &Path, only: Option<&str>) -> ExitCode {
    if let Some(name) = only
        && !checks().iter().any(|check| check.name == name)
    {
        eprintln!("unknown check `{name}`; see `cargo xtask list`");
        return ExitCode::FAILURE;
    }
    let mut failed = false;
    for check in checks() {
        if only.is_some_and(|name| name != check.name) {
            continue;
        }
        match (check.run)(root) {
            Ok(violations) if violations.is_empty() => println!("ok    {}", check.name),
            Ok(violations) => {
                failed = true;
                println!("FAIL  {} ({} violations)", check.name, violations.len());
                for v in violations {
                    println!("      {}: [{}] {}", v.path.display(), v.rule, v.message);
                }
            }
            Err(error) => {
                failed = true;
                println!("ERROR {}: {error}", check.name);
            }
        }
    }
    if failed {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: cargo xtask <command>");
    eprintln!("  check [NAME]        run all rule checks, or only NAME");
    eprintln!("  list                list check names");
    eprintln!("  catalog             regenerate conformance/catalog from the local spec (T-55)");
    eprintln!("  coverage            print the rule coverage report (T-38 (1))");
    eprintln!("  commits BASE HEAD   check commit trailers on BASE..HEAD (T-44 (3))");
    eprintln!("  asyncapi-breaking BASE  fail on breaking event catalog changes since BASE (T-31)");
    eprintln!("  sibling-refs [--update]  check the sibling rows §7.11 cites (E-38, local spec)");
    eprintln!("  watchlist           fail when a WATCH entry is overdue for review (X-59)");
    eprintln!("  dev-preflight       refuse `just dev` until sibling images are pinned (T-42)");
    eprintln!("  sarif-gate DIR      fail on high-severity SARIF findings (T-39 (9))");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let root = workspace_root();
    let result = match args.first().map(String::as_str) {
        Some("check") => return run_checks(&root, args.get(1).map(String::as_str)),
        Some("list") => {
            for check in checks() {
                println!("{}", check.name);
            }
            return ExitCode::SUCCESS;
        }
        Some("catalog") => catalog::generate(&root),
        Some("coverage") => catalog::report(&root),
        Some("sibling-refs") => {
            devtools::sibling_refs(&root, args.get(1).map(String::as_str) == Some("--update"))
        }
        Some("watchlist") => devtools::watchlist(&root),
        Some("dev-preflight") => devtools::dev_preflight(&root),
        Some("sarif-gate") => match args.get(1) {
            Some(dir) => devtools::sarif_gate(Path::new(dir)),
            None => return usage(),
        },
        Some("asyncapi-breaking") => match args.get(1) {
            Some(base) => one_checks::events::breaking(&root, base),
            None => return usage(),
        },
        Some("commits") => match (args.get(1), args.get(2)) {
            (Some(base), Some(head)) => one_checks::commits::check_range(&root, base, head),
            _ => return usage(),
        },
        _ => return usage(),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}
