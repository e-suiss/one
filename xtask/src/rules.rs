//! Architecture and code rules; each check lives in a `rules_*` module (T-26, T-27, T-28, T-32).

#[path = "rules_deps.rs"]
pub(crate) mod deps;
#[path = "rules_files.rs"]
pub(crate) mod files;
#[path = "rules_lex.rs"]
pub(crate) mod lex;
#[path = "rules_profile.rs"]
mod profile;
#[path = "rules_source.rs"]
pub(crate) mod source;
#[path = "rules_switches.rs"]
mod switches;

use crate::Check;

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "dependency-direction",
            run: deps::check,
        },
        Check {
            name: "no-std-purity",
            run: source::check_purity,
        },
        Check {
            name: "sql-only-in-store",
            run: source::check_sql,
        },
        Check {
            name: "no-physical-delete",
            run: source::check_delete,
        },
        Check {
            name: "no-dev-mode",
            run: switches::check,
        },
        Check {
            name: "unsafe-allowlist",
            run: source::check_unsafe,
        },
        Check {
            name: "todo-has-issue",
            run: source::check_todo,
        },
        Check {
            name: "panic-profile",
            run: profile::check,
        },
    ]
}
