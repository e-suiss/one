//! `dev-preflight` refuses to start the local environment until every sibling image in `deploy/compat.toml` is pinned by digest (T-42 (1), E-2); `sarif-gate` fails on high-severity static-analysis findings (T-39 (9)).

use std::path::Path;

pub(crate) const COMPAT: &str = "deploy/compat.toml";

/// Siblings that block `just dev`, with what is missing.
pub(crate) fn missing_siblings(compat: &toml::Table) -> Vec<String> {
    let mut out = Vec::new();
    let Some(siblings) = compat.get("siblings").and_then(toml::Value::as_table) else {
        return vec!["deploy/compat.toml has no [siblings]".to_owned()];
    };
    for (name, entry) in siblings {
        let required = entry
            .get("required_for_dev")
            .and_then(toml::Value::as_bool)
            .unwrap_or(true);
        if !required {
            continue;
        }
        let image = entry
            .get("image")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        let compose = entry
            .get("compose")
            .and_then(toml::Value::as_str)
            .unwrap_or_default();
        if !image.contains("@sha256:") {
            out.push(format!("{name}: no published image pinned by digest"));
        }
        if compose.is_empty() {
            out.push(format!("{name}: no compose file"));
        }
    }
    out
}

pub(crate) fn dev_preflight(root: &Path) -> Result<(), String> {
    let text = std::fs::read_to_string(root.join(COMPAT)).map_err(|e| format!("{COMPAT}: {e}"))?;
    let compat: toml::Table = text.parse().map_err(|e| format!("{COMPAT}: {e}"))?;
    let missing = missing_siblings(&compat);
    if missing.is_empty() {
        return Ok(());
    }
    Err(format!(
        "just dev needs local Access, Relay, Work and Executor; there is no fallback mode (E-2, T-42):\n  {}\nUse `just deps` for One's own services.",
        missing.join("\n  ")
    ))
}

fn high_severity(result: &serde_json::Value, rules: &[serde_json::Value]) -> bool {
    if result.get("level").and_then(serde_json::Value::as_str) == Some("error") {
        return true;
    }
    let id = result
        .get("ruleId")
        .and_then(serde_json::Value::as_str)
        .unwrap_or_default();
    rules
        .iter()
        .filter(|r| r.get("id").and_then(serde_json::Value::as_str) == Some(id))
        .filter_map(|r| r.pointer("/properties/security-severity"))
        .filter_map(|s| {
            s.as_str()
                .and_then(|s| s.parse::<f64>().ok())
                .or_else(|| s.as_f64())
        })
        .any(|score| score >= 7.0)
}

/// High-severity findings in one SARIF document, as `rule: message`.
pub(crate) fn sarif_findings(json: &serde_json::Value) -> Vec<String> {
    let mut out = Vec::new();
    for run in json
        .get("runs")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
    {
        let rules: Vec<serde_json::Value> = run
            .pointer("/tool/driver/rules")
            .and_then(serde_json::Value::as_array)
            .cloned()
            .unwrap_or_default();
        for result in run
            .get("results")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
        {
            if high_severity(result, &rules) {
                let id = result
                    .get("ruleId")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("?");
                let text = result
                    .pointer("/message/text")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default();
                out.push(format!("{id}: {text}"));
            }
        }
    }
    out
}

pub(crate) fn sarif_gate(dir: &Path) -> Result<(), String> {
    let mut found = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("sarif"))
        {
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            let json: serde_json::Value =
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
            found.extend(sarif_findings(&json));
        }
    }
    if found.is_empty() {
        Ok(())
    } else {
        Err(format!("high-severity findings:\n  {}", found.join("\n  ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_42_dev_refuses_unpublished_siblings() {
        let compat: toml::Table = "[siblings.access]\nimage = \"\"\ncompose = \"\"\n[siblings.pay]\nimage = \"\"\ncompose = \"\"\nrequired_for_dev = false\n".parse().unwrap();
        assert_eq!(missing_siblings(&compat).len(), 2);
        let ready: toml::Table = "[siblings.access]\nimage = \"ghcr.io/e-suiss/access@sha256:ab\"\ncompose = \"deploy/compose/access.yaml\"\n".parse().unwrap();
        assert_eq!(missing_siblings(&ready).len(), 0);
    }

    #[test]
    fn t_39_high_severity_sarif_results_fail() {
        let sarif: serde_json::Value = serde_json::from_str(
            r#"{"runs":[{"tool":{"driver":{"rules":[{"id":"a","properties":{"security-severity":"8.1"}},{"id":"b","properties":{"security-severity":"3.0"}}]}},
            "results":[{"ruleId":"a","level":"warning","message":{"text":"x"}},{"ruleId":"b","level":"note","message":{"text":"y"}}]}]}"#,
        )
        .unwrap();
        assert_eq!(sarif_findings(&sarif), vec!["a: x"]);
    }
}

pub(crate) const SIBLING_REFS: &str = "conformance/catalog/sibling-refs.toml";
const PRODUCTS: &[(&str, &str)] = &[("Access", "access"), ("Relay", "relay"), ("Work", "work")];

/// `(product, id)` pairs cited in the first column of the §7.11 table.
pub(crate) fn cited_sibling_ids(section: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for line in section.lines().filter(|l| l.starts_with("| ")).skip(1) {
        let first = line
            .trim_start_matches('|')
            .split('|')
            .next()
            .unwrap_or_default()
            .trim();
        let Some((product, rest)) = first.split_once(' ') else {
            continue;
        };
        if !PRODUCTS.iter().any(|(p, _)| *p == product) {
            continue;
        }
        let mut family = String::new();
        for token in rest.split(',').map(str::trim) {
            let id = if token.chars().next().is_some_and(|c| c.is_ascii_digit()) {
                format!("{family}{token}")
            } else {
                token.to_owned()
            };
            if id.starts_with('§') || id.is_empty() {
                continue;
            }
            id.trim_end_matches(|c: char| c.is_ascii_digit())
                .clone_into(&mut family);
            out.push((product.to_owned(), id));
        }
    }
    out
}

/// FNV-1a 64-bit over whitespace-normalised text, as 16 hex digits.
pub(crate) fn fingerprint(text: &str) -> String {
    let normalised: Vec<&str> = text.split_whitespace().collect();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in normalised.join(" ").bytes() {
        hash ^= u64::from(b);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// The register row defining `id` in a sibling spec directory.
pub(crate) fn sibling_row(files: &[(String, String)], id: &str) -> Option<String> {
    let bare = format!("| {id} |");
    let bold = format!("| **{id}** |");
    let bullet = format!("- **{id}");
    let lead = format!("**{id} —");
    let lines = || {
        files
            .iter()
            .filter(|(name, _)| !name.starts_with("appendix") && !name.starts_with("00-"))
            .flat_map(|(_, text)| text.lines())
    };
    lines()
        .find(|l| l.starts_with(&bare) || l.starts_with(&bold))
        .or_else(|| {
            lines().find(|l| {
                l.strip_prefix(&bullet)
                    .is_some_and(|r| r.starts_with("**") || r.starts_with(" —"))
                    || l.starts_with(&lead)
            })
        })
        .map(str::to_owned)
}

fn spec_files(dir: &Path) -> Result<Vec<(String, String)>, String> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let path = entry.map_err(|e| e.to_string())?.path();
        if path
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let text =
                std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
            out.push((name, text));
        }
    }
    out.sort();
    Ok(out)
}

/// Compares (or with `update` rewrites) the fingerprints of the sibling rows §7.11 cites (E-38).
pub(crate) fn sibling_refs(root: &Path, update: bool) -> Result<(), String> {
    let spec = std::fs::read_to_string(root.join("docs/spec/07-ecosystem-boundaries.md"))
        .map_err(|e| format!("docs/spec/07-ecosystem-boundaries.md: {e}"))?;
    let section = spec
        .split("### 7.11")
        .nth(1)
        .and_then(|s| s.split("\n### ").next())
        .ok_or("§7.11 not found")?;
    let old: toml::Table = std::fs::read_to_string(root.join(SIBLING_REFS))
        .ok()
        .and_then(|t| t.parse().ok())
        .unwrap_or_default();
    let mut lines = vec!["# E-38".to_owned()];
    let mut changed = Vec::new();
    for (product, dir) in PRODUCTS {
        let files = spec_files(&root.join("..").join(dir).join("docs/spec"))?;
        lines.push(String::new());
        lines.push(format!("[{dir}]"));
        for (p, id) in cited_sibling_ids(section)
            .into_iter()
            .filter(|(p, _)| p == product)
        {
            let print = sibling_row(&files, &id)
                .map_or_else(|| "missing".to_owned(), |row| fingerprint(&row));
            let before = old
                .get(*dir)
                .and_then(|t| t.get(&id))
                .and_then(toml::Value::as_str);
            if before != Some(print.as_str()) {
                changed.push(format!("{p} {id}: {} -> {print}", before.unwrap_or("new")));
            }
            lines.push(format!("{} = \"{print}\"", toml::Value::String(id)));
        }
    }
    if update {
        std::fs::write(root.join(SIBLING_REFS), lines.join("\n") + "\n")
            .map_err(|e| e.to_string())?;
        println!("sibling-refs: {} changes written", changed.len());
        return Ok(());
    }
    if changed.is_empty() {
        println!("sibling-refs: every cited Access, Relay and Work row is unchanged");
        Ok(())
    } else {
        Err(format!(
            "sibling rows cited in §7.11 changed; reopen §7 (E-38), then run `cargo xtask sibling-refs --update`:\n  {}",
            changed.join("\n  ")
        ))
    }
}

#[cfg(test)]
mod sibling_tests {
    use super::*;

    #[test]
    fn e_38_cited_ids_expand_shorthand_lists() {
        let section = "| a | b |\n|---|---|\n| Access E61, E62 | x |\n| Relay AG-56, AG-57 | y |\n| Access §7.9.6 | z |\n| Pay X-1 | w |\n";
        let ids: Vec<String> = cited_sibling_ids(section)
            .into_iter()
            .map(|(p, i)| format!("{p} {i}"))
            .collect();
        assert_eq!(
            ids,
            vec!["Access E61", "Access E62", "Relay AG-56", "Relay AG-57"]
        );
    }

    #[test]
    fn e_38_fingerprint_ignores_whitespace_but_not_words() {
        assert_eq!(fingerprint("| E42 |  a b |"), fingerprint("| E42 | a  b |"));
        assert_ne!(fingerprint("| E42 | a |"), fingerprint("| E42 | b |"));
    }
}

pub(crate) const WATCHLIST: &str = "conformance/catalog/watchlist.toml";

fn day_number(date: &str) -> Option<i64> {
    let mut parts = date.split('-').map(|p| p.parse::<i64>().ok());
    let (y, m, d) = (parts.next()??, parts.next()??, parts.next()??);
    let y = if m <= 2 { y.checked_sub(1)? } else { y };
    let era = y.div_euclid(400);
    let yoe = y.checked_sub(era.checked_mul(400)?)?;
    let mp = if m > 2 {
        m.checked_sub(3)?
    } else {
        m.checked_add(9)?
    };
    let doy = mp
        .checked_mul(153)?
        .checked_add(2)?
        .checked_div(5)?
        .checked_add(d)?
        .checked_sub(1)?;
    let doe = yoe
        .checked_mul(365)?
        .checked_add(yoe / 4)?
        .checked_sub(yoe / 100)?
        .checked_add(doy)?;
    era.checked_mul(146_097)?
        .checked_add(doe)?
        .checked_sub(719_468)
}

/// Watch entries not reviewed within `every_days` of `today` (a day number since 1970-01-01).
pub(crate) fn overdue(list: &toml::Table, today: i64) -> Vec<String> {
    let every = list
        .get("every_days")
        .and_then(toml::Value::as_integer)
        .unwrap_or(90);
    list.get("watch")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|w| {
            let topic = w.get("topic").and_then(toml::Value::as_str).unwrap_or("?");
            let rule = w.get("rule").and_then(toml::Value::as_str).unwrap_or("?");
            let checked = w
                .get("checked")
                .and_then(toml::Value::as_str)
                .and_then(day_number);
            let late = checked.is_none_or(|c| today.saturating_sub(c) > every);
            late.then(|| {
                format!(
                    "{rule} {topic}: review it and record a new decision ID if it changes anything"
                )
            })
        })
        .collect()
}

pub(crate) fn watchlist(root: &Path) -> Result<(), String> {
    let text =
        std::fs::read_to_string(root.join(WATCHLIST)).map_err(|e| format!("{WATCHLIST}: {e}"))?;
    let list: toml::Table = text.parse().map_err(|e| format!("{WATCHLIST}: {e}"))?;
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| e.to_string())?
        .as_secs();
    let today = i64::try_from(secs / 86_400).map_err(|e| e.to_string())?;
    let late = overdue(&list, today);
    if late.is_empty() {
        println!("watchlist: every entry reviewed within the interval");
        Ok(())
    } else {
        Err(format!("watch entries overdue:\n  {}", late.join("\n  ")))
    }
}

#[cfg(test)]
mod watch_tests {
    use super::*;

    #[test]
    fn x_59_overdue_watch_entries_are_reported() {
        let list: toml::Table = "every_days = 90\n[[watch]]\nrule = \"X-59\"\ntopic = \"a\"\nchecked = \"2026-01-01\"\n[[watch]]\nrule = \"CP-41\"\ntopic = \"b\"\nchecked = \"2026-10-01\"\n".parse().unwrap();
        let today = day_number("2026-10-10").unwrap_or_default();
        assert_eq!(overdue(&list, today).len(), 1);
        assert_eq!(day_number("1970-01-02"), Some(1));
    }
}
