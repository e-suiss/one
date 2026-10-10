//! The tracked rule catalog: rule IDs, must-never mapping and threat rows generated from the local spec into `conformance/catalog/`, with English titles curated in place, and the rule coverage report over tests in every language (T-55, T-38 (1), F-9).

#[path = "catalog_spec.rs"]
mod spec;

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

use crate::policy::scan::repo_files;
use crate::{Check, Violation};

pub(crate) const DIR: &str = "conformance/catalog";
const RULES: &str = "rules.toml";
const MUST_NEVER: &str = "must-never.toml";
const THREATS: &str = "threat-model.toml";
const CONFIG: &str = "catalog.toml";

pub(crate) const FAMILIES: &[&str] = &[
    "MD", "F", "L", "C", "INV", "E", "M", "MF", "A", "AT", "CP", "OO", "X", "PV", "SEC", "T", "OP",
];
const STATUSES: &[&str] = &[
    "canonical",
    "central",
    "frozen-product",
    "frozen-technical",
    "frozen-protocol",
    "policy-default",
    "engineering-assumption",
    "watch",
    "out-of-scope",
    "principle",
    "information",
];
const STRIDE: &[&str] = &["S", "T", "R", "I", "D", "E"];
const LINDDUN: &[&str] = &[
    "Linking",
    "Identifying",
    "Non-repudiation",
    "Detecting",
    "Data disclosure",
    "Unawareness",
    "Non-compliance",
];
const TURKISH_LETTERS: &str = "çğıöşüÇĞİÖŞÜ";
const MAX_TITLE_WORDS: usize = 16;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Config {
    pub(crate) current_stage: u8,
    pub(crate) test_roots: Vec<String>,
    #[serde(default)]
    pub(crate) deferred: Vec<Deferred>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Deferred {
    pub(crate) id: String,
    pub(crate) until_stage: u8,
    pub(crate) reason: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Rule {
    pub(crate) id: String,
    pub(crate) family: String,
    pub(crate) section: String,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) day1: bool,
    #[serde(default)]
    pub(crate) stage: Option<u8>,
    #[serde(default)]
    pub(crate) bound_stage: Option<u8>,
    pub(crate) title: String,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct MustNever {
    pub(crate) item: u8,
    pub(crate) title: String,
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(crate) struct Threat {
    pub(crate) row: u8,
    pub(crate) title: String,
    pub(crate) stride: Vec<String>,
    pub(crate) linddun: Vec<String>,
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    #[serde(default)]
    rule: Vec<Rule>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct MustNeverFile {
    #[serde(default)]
    must_never: Vec<MustNever>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct ThreatFile {
    #[serde(default)]
    threat: Vec<Threat>,
}

fn read_toml<T: for<'de> Deserialize<'de> + Default>(path: &Path) -> Result<T, String> {
    match std::fs::read_to_string(path) {
        Ok(text) => toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(T::default()),
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

pub(crate) fn load_config(root: &Path) -> Result<Config, String> {
    let path = root.join(DIR).join(CONFIG);
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

fn load_rules(root: &Path) -> Result<Vec<Rule>, String> {
    Ok(read_toml::<RuleFile>(&root.join(DIR).join(RULES))?.rule)
}

fn load_must_never(root: &Path) -> Result<Vec<MustNever>, String> {
    Ok(read_toml::<MustNeverFile>(&root.join(DIR).join(MUST_NEVER))?.must_never)
}

fn load_threats(root: &Path) -> Result<Vec<Threat>, String> {
    Ok(read_toml::<ThreatFile>(&root.join(DIR).join(THREATS))?.threat)
}

fn quote(s: &str) -> String {
    toml::Value::String(s.to_owned()).to_string()
}

fn list(items: &[String]) -> String {
    let quoted: Vec<String> = items.iter().map(|s| quote(s)).collect();
    format!("[{}]", quoted.join(", "))
}

fn write(root: &Path, name: &str, body: &str) -> Result<(), String> {
    let path = root.join(DIR).join(name);
    std::fs::write(&path, format!("# T-55\n{body}")).map_err(|e| format!("{}: {e}", path.display()))
}

/// Regenerates the catalog files from `docs/spec`, keeping curated titles and mappings.
pub(crate) fn generate(root: &Path) -> Result<(), String> {
    let parsed = spec::parse(&root.join("docs/spec"))?;
    let old: BTreeMap<String, Rule> = load_rules(root)?
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
    let mut out = String::new();
    let mut untitled = 0_usize;
    for r in &parsed.rules {
        let title = old.get(&r.id).map(|o| o.title.clone()).unwrap_or_default();
        if title.is_empty() {
            untitled = untitled.saturating_add(1);
        }
        let _ = writeln!(out, "\n[[rule]]");
        let _ = writeln!(out, "id = {}", quote(&r.id));
        let _ = writeln!(out, "family = {}", quote(&r.family));
        let _ = writeln!(out, "section = {}", quote(&r.section));
        let _ = writeln!(out, "status = {}", quote(&r.status));
        if r.day1 {
            let _ = writeln!(out, "day1 = true");
        }
        if let Some(stage) = parsed.stages.get(&r.id) {
            let _ = writeln!(out, "stage = {stage}");
        }
        if let Some(stage) = parsed.bounds.get(&r.id) {
            let _ = writeln!(out, "bound_stage = {stage}");
        }
        let _ = writeln!(out, "title = {}", quote(&title));
    }
    write(root, RULES, &out)?;

    let old_mn: BTreeMap<u8, MustNever> = load_must_never(root)?
        .into_iter()
        .map(|m| (m.item, m))
        .collect();
    let mut mn = String::new();
    for item in 1..=parsed.must_never {
        let prev = old_mn.get(&item).cloned().unwrap_or_default();
        let _ = writeln!(mn, "\n[[must_never]]");
        let _ = writeln!(mn, "item = {item}");
        let _ = writeln!(mn, "title = {}", quote(&prev.title));
        let _ = writeln!(mn, "rules = {}", list(&prev.rules));
    }
    write(root, MUST_NEVER, &mn)?;

    let old_th: BTreeMap<u8, Threat> = load_threats(root)?
        .into_iter()
        .map(|t| (t.row, t))
        .collect();
    let mut th = String::new();
    for (i, rules) in parsed.threat_rows.iter().enumerate() {
        let row = u8::try_from(i.saturating_add(1)).map_err(|e| e.to_string())?;
        let prev = old_th.get(&row).cloned().unwrap_or_default();
        let _ = writeln!(th, "\n[[threat]]");
        let _ = writeln!(th, "row = {row}");
        let _ = writeln!(th, "title = {}", quote(&prev.title));
        let _ = writeln!(th, "stride = {}", list(&prev.stride));
        let _ = writeln!(th, "linddun = {}", list(&prev.linddun));
        let _ = writeln!(th, "rules = {}", list(rules));
    }
    write(root, THREATS, &th)?;
    println!(
        "catalog: {} rules, {} must-never items, {} threat rows; {untitled} rules need an English title",
        parsed.rules.len(),
        parsed.must_never,
        parsed.threat_rows.len()
    );
    Ok(())
}

/// The spec ID a test name or comment token cites, e.g. `sec_12_x` → `SEC-12`.
pub(crate) fn id_from_test_name(name: &str) -> Option<String> {
    let name = name.strip_prefix("test_").unwrap_or(name);
    let mut parts = name.split('_');
    let family = parts.next()?.to_ascii_uppercase();
    let number = parts.next()?;
    (FAMILIES.contains(&family.as_str())
        && !number.is_empty()
        && number.chars().all(|c| c.is_ascii_digit()))
    .then(|| format!("{family}-{number}"))
}

fn test_names(text: &str, ext: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim_start();
        let name = match ext {
            "rs" => t
                .strip_prefix("fn ")
                .or_else(|| t.strip_prefix("async fn ")),
            "py" => t
                .strip_prefix("def ")
                .or_else(|| t.strip_prefix("async def ")),
            _ => ["test(\"", "it(\"", "test('", "it('"]
                .iter()
                .find_map(|p| t.strip_prefix(p)),
        };
        if let Some(name) = name {
            let ident: String = name
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            out.push(ident);
        }
    }
    out
}

/// Spec IDs cited by test names under the configured roots.
pub(crate) fn tested_ids(root: &Path, roots: &[String]) -> Result<BTreeSet<String>, String> {
    let mut out = BTreeSet::new();
    for file in repo_files(root)? {
        if !roots.iter().any(|r| file.starts_with(r.as_str())) {
            continue;
        }
        let ext = file.rsplit_once('.').map_or("", |(_, e)| e);
        if !matches!(ext, "rs" | "py" | "ts" | "tsx" | "js" | "mjs") {
            continue;
        }
        let text = std::fs::read_to_string(root.join(&file)).map_err(|e| format!("{file}: {e}"))?;
        for name in test_names(&text, ext) {
            if let Some(id) = id_from_test_name(&name) {
                out.insert(id);
            }
        }
    }
    Ok(out)
}

fn title_problem(title: &str) -> Option<String> {
    if title.trim().is_empty() {
        return Some("missing English title".to_owned());
    }
    if title.chars().any(|c| TURKISH_LETTERS.contains(c)) {
        return Some(format!("title is not English: {title:?}"));
    }
    let words = title.split_whitespace().count();
    (words > MAX_TITLE_WORDS).then(|| format!("title has {words} words (max {MAX_TITLE_WORDS})"))
}

fn v(path: &str, message: String) -> Violation {
    Violation {
        rule: "T-55",
        path: std::path::PathBuf::from(format!("{DIR}/{path}")),
        message,
    }
}

pub(crate) fn format_findings(
    rules: &[Rule],
    must_never: &[MustNever],
    threats: &[Threat],
) -> Vec<Violation> {
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let ids: BTreeSet<&str> = rules.iter().map(|r| r.id.as_str()).collect();
    for r in rules {
        if !seen.insert(r.id.as_str()) {
            out.push(v(RULES, format!("duplicate `{}`", r.id)));
        }
        if !FAMILIES.contains(&r.family.as_str()) || !r.id.starts_with(&format!("{}-", r.family)) {
            out.push(v(RULES, format!("`{}` has family `{}`", r.id, r.family)));
        }
        if !STATUSES.contains(&r.status.as_str()) {
            out.push(v(
                RULES,
                format!("`{}` has unknown status `{}`", r.id, r.status),
            ));
        }
        if let Some(p) = title_problem(&r.title) {
            out.push(v(RULES, format!("`{}`: {p}", r.id)));
        }
    }
    for m in must_never {
        if let Some(p) = title_problem(&m.title) {
            out.push(v(MUST_NEVER, format!("item {}: {p}", m.item)));
        }
        for id in &m.rules {
            if !ids.contains(id.as_str()) {
                out.push(v(
                    MUST_NEVER,
                    format!("item {} maps to unknown `{id}`", m.item),
                ));
            }
        }
    }
    for t in threats {
        if let Some(p) = title_problem(&t.title) {
            out.push(v(THREATS, format!("row {}: {p}", t.row)));
        }
        if t.stride.is_empty() || t.stride.iter().any(|s| !STRIDE.contains(&s.as_str())) {
            out.push(v(
                THREATS,
                format!("row {} needs STRIDE classes from {STRIDE:?}", t.row),
            ));
        }
        if t.linddun.iter().any(|s| !LINDDUN.contains(&s.as_str())) {
            out.push(v(
                THREATS,
                format!("row {} has an unknown LINDDUN class", t.row),
            ));
        }
        for id in &t.rules {
            if !ids.contains(id.as_str()) {
                out.push(v(THREATS, format!("row {} cites unknown `{id}`", t.row)));
            }
        }
    }
    out
}

fn check_format(root: &Path) -> Result<Vec<Violation>, String> {
    let rules = load_rules(root)?;
    if rules.is_empty() {
        return Ok(vec![v(
            RULES,
            "catalog is empty; run `cargo xtask catalog`".to_owned(),
        )]);
    }
    Ok(format_findings(
        &rules,
        &load_must_never(root)?,
        &load_threats(root)?,
    ))
}

/// Rules whose verification bound is due at `stage` but which no test cites (T-38 (1)).
pub(crate) fn missing_bound_tests(
    rules: &[Rule],
    tested: &BTreeSet<String>,
    config: &Config,
) -> Vec<String> {
    rules
        .iter()
        .filter(|r| r.bound_stage.is_some_and(|s| s <= config.current_stage))
        .filter(|r| !tested.contains(&r.id))
        .filter(|r| {
            !config.deferred.iter().any(|d| {
                d.id == r.id && d.until_stage > config.current_stage && !d.reason.trim().is_empty()
            })
        })
        .map(|r| r.id.clone())
        .collect()
}

fn check_coverage(root: &Path) -> Result<Vec<Violation>, String> {
    let config = load_config(root)?;
    let rules = load_rules(root)?;
    let tested = tested_ids(root, &config.test_roots)?;
    Ok(missing_bound_tests(&rules, &tested, &config)
        .into_iter()
        .map(|id| {
            v(
                RULES,
                format!(
                    "`{id}` is a verification bound of stage ≤ {} and has no test",
                    config.current_stage
                ),
            )
        })
        .collect())
}

/// Prints coverage per family, untested rules of reached stages and unmapped must-never items (T-38 (1), F-9).
pub(crate) fn report(root: &Path) -> Result<(), String> {
    let config = load_config(root)?;
    let rules = load_rules(root)?;
    let tested = tested_ids(root, &config.test_roots)?;
    println!("rule coverage (current stage {})", config.current_stage);
    for family in FAMILIES {
        let all: Vec<&Rule> = rules.iter().filter(|r| r.family == *family).collect();
        let covered = all.iter().filter(|r| tested.contains(&r.id)).count();
        println!("  {family:<4} {covered:>3}/{:<3}", all.len());
    }
    let due: Vec<&str> = rules
        .iter()
        .filter(|r| r.stage.is_some_and(|s| s <= config.current_stage) && !tested.contains(&r.id))
        .map(|r| r.id.as_str())
        .collect();
    println!("rules of reached stages without a test: {}", due.len());
    for id in due {
        println!("  {id}");
    }
    for m in load_must_never(root)? {
        let untested = m.rules.iter().all(|id| !tested.contains(id));
        if m.rules.is_empty() || untested {
            println!(
                "must-never {}: {}",
                m.item,
                if m.rules.is_empty() {
                    "no rule mapping"
                } else {
                    "no test"
                }
            );
        }
    }
    Ok(())
}

pub(crate) fn checks() -> Vec<Check> {
    vec![
        Check {
            name: "catalog-format",
            run: check_format,
        },
        Check {
            name: "rule-coverage",
            run: check_coverage,
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(id: &str, family: &str, title: &str, bound: Option<u8>) -> Rule {
        Rule {
            id: id.into(),
            family: family.into(),
            section: "17".into(),
            status: "frozen-technical".into(),
            title: title.into(),
            bound_stage: bound,
            ..Rule::default()
        }
    }

    #[test]
    fn t_55_test_names_map_to_spec_ids() {
        assert_eq!(
            id_from_test_name("sec_12_planner_rejects"),
            Some("SEC-12".into())
        );
        assert_eq!(id_from_test_name("test_t_33_hash"), Some("T-33".into()));
        assert_eq!(id_from_test_name("t_29_missing_key"), Some("T-29".into()));
        assert_eq!(id_from_test_name("helper_fn"), None);
        assert_eq!(id_from_test_name("zz_1_x"), None);
    }

    #[test]
    fn t_55_format_rejects_turkish_or_missing_titles_and_duplicates() {
        let rules = vec![
            rule("T-1", "T", "Rust in the cloud", None),
            rule("T-1", "T", "Rust in the cloud", None),
            rule("T-2", "T", "Python yalnız ML", None),
            rule("T-3", "T", "", None),
        ];
        assert_eq!(format_findings(&rules, &[], &[]).len(), 3);
    }

    #[test]
    fn t_38_bound_rule_without_test_fails_unless_deferred() {
        let rules = vec![
            rule("T-26", "T", "x", Some(0)),
            rule("T-24", "T", "x", Some(0)),
        ];
        let tested: BTreeSet<String> = ["T-26".to_owned()].into();
        let mut config = Config {
            current_stage: 0,
            test_roots: Vec::new(),
            deferred: Vec::new(),
        };
        assert_eq!(missing_bound_tests(&rules, &tested, &config), vec!["T-24"]);
        config.deferred.push(Deferred {
            id: "T-24".into(),
            until_stage: 13,
            reason: "release pipeline".into(),
        });
        assert_eq!(missing_bound_tests(&rules, &tested, &config).len(), 0);
    }

    #[test]
    fn f_9_must_never_mapping_must_name_known_rules() {
        let rules = vec![rule("INV-1", "INV", "One never creates authority", None)];
        let mn = vec![MustNever {
            item: 1,
            title: "Never creates authority".into(),
            rules: vec!["INV-1".into(), "INV-99".into()],
        }];
        assert_eq!(format_findings(&rules, &mn, &[]).len(), 1);
    }
}
