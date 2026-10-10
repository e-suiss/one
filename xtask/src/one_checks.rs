//! Checks specific to One: clock and randomness ports, comment policy, claims language, catalogs, data inventory, platform policy, model files, migrations, the Python boundary, sibling-product code and commit trailers.

#[path = "one_boundaries.rs"]
mod boundaries;
#[path = "one_claims.rs"]
mod claims;
#[path = "one_comments.rs"]
pub(crate) mod comments;
#[path = "one_commits.rs"]
pub(crate) mod commits;
#[path = "one_inventory.rs"]
mod inventory;
#[path = "one_migrations.rs"]
mod migrations;
#[path = "one_models.rs"]
mod models;
#[path = "one_platform.rs"]
mod platform;

use std::path::{Path, PathBuf};

use crate::{Check, Violation};

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "ports-only-clock-rng",
            run: boundaries::check_ports,
        },
        Check {
            name: "comment-policy",
            run: comments::check,
        },
        Check {
            name: "forbidden-claims",
            run: claims::check,
        },
        Check {
            name: "i18n-catalogs",
            run: claims::check_i18n,
        },
        Check {
            name: "data-inventory",
            run: inventory::check,
        },
        Check {
            name: "platform-policy",
            run: platform::check,
        },
        Check {
            name: "device-model-budget",
            run: models::check_budget,
        },
        Check {
            name: "model-file-formats",
            run: models::check_formats,
        },
        Check {
            name: "migrations",
            run: migrations::check,
        },
        Check {
            name: "python-boundary",
            run: boundaries::check_python,
        },
        Check {
            name: "no-sibling-rewrite",
            run: boundaries::check_siblings,
        },
    ]
}

pub(crate) fn v(rule: &'static str, path: impl Into<PathBuf>, message: String) -> Violation {
    Violation {
        rule,
        path: path.into(),
        message,
    }
}

pub(crate) fn at(file: &str, line: usize) -> PathBuf {
    PathBuf::from(format!("{file}:{line}"))
}

pub(crate) fn read_opt(root: &Path, rel: &str) -> Result<Option<String>, String> {
    match std::fs::read_to_string(root.join(rel)) {
        Ok(s) => Ok(Some(s)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(format!("{rel}: {e}")),
    }
}
