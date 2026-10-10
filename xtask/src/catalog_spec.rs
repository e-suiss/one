//! Reads rule IDs, statuses, Ek B stages and verification bounds, the must-never list and the threat table from the local, untracked spec for `cargo xtask catalog` (T-55).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use super::FAMILIES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SpecRule {
    pub(crate) id: String,
    pub(crate) family: String,
    pub(crate) section: String,
    pub(crate) status: String,
    pub(crate) day1: bool,
}

#[derive(Debug, Default)]
pub(crate) struct Parsed {
    pub(crate) rules: Vec<SpecRule>,
    pub(crate) stages: BTreeMap<String, u8>,
    pub(crate) bounds: BTreeMap<String, u8>,
    pub(crate) must_never: u8,
    pub(crate) threat_rows: Vec<Vec<String>>,
}

const FILES: &[(&str, &[&str])] = &[
    ("01", &["MD"]),
    ("02", &["F"]),
    ("03", &["F"]),
    ("04", &["L"]),
    ("05", &["C"]),
    ("06", &["INV"]),
    ("07", &["E"]),
    ("08", &["M"]),
    ("09", &["MF"]),
    ("10", &["A"]),
    ("11", &["AT"]),
    ("12", &["CP"]),
    ("13", &["OO"]),
    ("14", &["X"]),
    ("15", &["PV"]),
    ("16", &["SEC"]),
    ("17", &["T"]),
    ("18", &["OP"]),
];

const STATUS_WORDS: &[(&str, &str)] = &[
    ("KANONİK DEĞİŞMEZ", "canonical"),
    ("MERKEZİ KARAR", "central"),
    ("FROZEN (ürün)", "frozen-product"),
    ("FROZEN (teknik)", "frozen-technical"),
    ("FROZEN (protokol)", "frozen-protocol"),
    ("POLICY DEFAULT", "policy-default"),
    ("ENGINEERING ASSUMPTION", "engineering-assumption"),
    ("WATCH", "watch"),
    ("KAPSAM DIŞI", "out-of-scope"),
];

const SIBLING_PREFIXES: &[&str] = &["Access ", "Relay ", "Work ", "Pay "];

/// One-family IDs in `text`, skipping sibling-product IDs and range ends.
pub(crate) fn ids_in(text: &str) -> Vec<String> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out = Vec::new();
    let mut k = 0_usize;
    while k < chars.len() {
        let Some(&(start, c)) = chars.get(k) else {
            break;
        };
        let prev = k.checked_sub(1).and_then(|p| chars.get(p)).map(|&(_, c)| c);
        if !c.is_ascii_uppercase() || prev.is_some_and(|p| p.is_alphanumeric() || p == '-') {
            k = k.saturating_add(1);
            continue;
        }
        let mut j = k;
        while chars.get(j).is_some_and(|&(_, c)| c.is_ascii_uppercase()) {
            j = j.saturating_add(1);
        }
        if chars.get(j).map(|&(_, c)| c) != Some('-') {
            k = j.max(k.saturating_add(1));
            continue;
        }
        let mut d = j.saturating_add(1);
        while chars.get(d).is_some_and(|&(_, c)| c.is_ascii_digit()) {
            d = d.saturating_add(1);
        }
        let family: String = chars
            .get(k..j)
            .map(|s| s.iter().map(|&(_, c)| c).collect())
            .unwrap_or_default();
        let digits: String = chars
            .get(j.saturating_add(1)..d)
            .map(|s| s.iter().map(|&(_, c)| c).collect())
            .unwrap_or_default();
        let next = chars.get(d).map(|&(_, c)| c);
        let before = text.get(..start).unwrap_or_default();
        let sibling = SIBLING_PREFIXES.iter().any(|p| before.ends_with(p));
        let range = matches!(prev, Some('…' | '–')) || matches!(next, Some('…' | '–'));
        let boundary = !next.is_some_and(char::is_alphanumeric);
        if !digits.is_empty()
            && FAMILIES.contains(&family.as_str())
            && !sibling
            && !range
            && boundary
        {
            out.push(format!("{family}-{digits}"));
        }
        k = d.max(k.saturating_add(1));
    }
    out
}

fn cells(line: &str) -> Vec<&str> {
    line.trim()
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(str::trim)
        .collect()
}

pub(crate) fn register_row(line: &str, families: &[&str], chapter: &str) -> Option<SpecRule> {
    let cells = cells(line);
    let id = (*cells.first()?).to_owned();
    let (family, number) = id.rsplit_once('-')?;
    if !families.contains(&family)
        || number.is_empty()
        || !number.chars().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    let status_cell = cells
        .iter()
        .skip(1)
        .find(|c| STATUS_WORDS.iter().any(|(w, _)| c.starts_with(w)))?;
    let status = STATUS_WORDS
        .iter()
        .find(|(w, _)| status_cell.starts_with(w))
        .map(|(_, s)| *s)?;
    Some(SpecRule {
        family: family.to_owned(),
        id,
        section: chapter.to_owned(),
        status: status.to_owned(),
        day1: status_cell.contains("DAY-1"),
    })
}

fn stage_of(heading: &str) -> Option<u8> {
    heading
        .strip_prefix("### Aşama ")?
        .split_whitespace()
        .next()?
        .parse()
        .ok()
}

pub(crate) fn stages_and_bounds(md: &str) -> (BTreeMap<String, u8>, BTreeMap<String, u8>) {
    let mut stages = BTreeMap::new();
    let mut bounds = BTreeMap::new();
    let mut stage: Option<u8> = None;
    let mut in_bounds = false;
    for line in md.lines() {
        if line.starts_with("### ") {
            stage = stage_of(line);
            in_bounds = false;
            continue;
        }
        if line.starts_with("#### ") {
            in_bounds = line.contains("Doğrulanacak sınırlar");
            continue;
        }
        let Some(s) = stage else { continue };
        if in_bounds {
            if let Some(bold) = line.strip_prefix("- **").and_then(|r| r.split("**").next()) {
                for id in ids_in(bold) {
                    bounds.entry(id).or_insert(s);
                }
            }
        } else if let Some(source) = line.split("_Kaynak:_").nth(1) {
            let source = source.split("_Durum:_").next().unwrap_or_default();
            for id in ids_in(source) {
                let e = stages.entry(id).or_insert(s);
                *e = (*e).min(s);
            }
        }
    }
    (stages, bounds)
}

fn read(dir: &Path, prefix: &str) -> Result<(String, String), String> {
    let entries = std::fs::read_dir(dir).map_err(|e| format!("{}: {e}", dir.display()))?;
    for entry in entries {
        let name = entry
            .map_err(|e| e.to_string())?
            .file_name()
            .to_string_lossy()
            .into_owned();
        if name.starts_with(&format!("{prefix}-"))
            && Path::new(&name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("md"))
        {
            let text =
                std::fs::read_to_string(dir.join(&name)).map_err(|e| format!("{name}: {e}"))?;
            return Ok((name, text));
        }
    }
    Err(format!("{}: no file for §{prefix}", dir.display()))
}

pub(crate) fn parse(dir: &Path) -> Result<Parsed, String> {
    let mut parsed = Parsed::default();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (prefix, families) in FILES {
        let (_, text) = read(dir, prefix)?;
        let chapter = prefix.trim_start_matches('0');
        for line in text.lines().filter(|l| l.starts_with("| ")) {
            if let Some(rule) = register_row(line, families, chapter)
                && seen.insert(rule.id.clone())
            {
                parsed.rules.push(rule);
            }
        }
    }
    parsed.rules.sort_by(|a, b| {
        let key = |r: &SpecRule| {
            let pos = FAMILIES
                .iter()
                .position(|f| *f == r.family)
                .unwrap_or(usize::MAX);
            let n: u32 =
                r.id.rsplit('-')
                    .next()
                    .and_then(|n| n.parse().ok())
                    .unwrap_or(0);
            (pos, n)
        };
        key(a).cmp(&key(b))
    });
    let ek_b = std::fs::read_to_string(dir.join("appendix-b-feature-inventory.md"))
        .map_err(|e| format!("appendix-b: {e}"))?;
    (parsed.stages, parsed.bounds) = stages_and_bounds(&ek_b);
    let (_, thesis) = read(dir, "02")?;
    let in_list = thesis
        .split("### 2.10")
        .nth(1)
        .and_then(|s| s.split("\n### ").next())
        .unwrap_or_default();
    let count = in_list
        .lines()
        .filter(|l| cells(l).first().is_some_and(|c| c.parse::<u8>().is_ok()))
        .count();
    parsed.must_never = u8::try_from(count).map_err(|e| e.to_string())?;
    let (_, security) = read(dir, "16")?;
    let posture = security
        .split("#### 16.2.3")
        .nth(1)
        .and_then(|s| s.split("\n---").next())
        .unwrap_or_default();
    for line in posture.lines().filter(|l| l.starts_with("| ")).skip(1) {
        parsed.threat_rows.push(ids_in(line));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_55_ids_skip_siblings_and_ranges() {
        assert_eq!(
            ids_in("T-26 (6), Access OP-73, MD-1…MD-23, SEC-12; OP-6 (1)"),
            vec!["T-26", "SEC-12", "OP-6"]
        );
        assert_eq!(ids_in("UTF-8 and X-ray").len(), 0);
    }

    #[test]
    fn t_55_register_rows_yield_status_and_day1() {
        let r = register_row(
            "| T-1 | Rust | FROZEN (teknik) · DAY-1 | why |",
            &["T"],
            "17",
        )
        .unwrap();
        assert_eq!((r.status.as_str(), r.day1), ("frozen-technical", true));
        assert!(register_row("| T-47 | Neden | Reddedilen | x |", &["T"], "17").is_none());
    }

    #[test]
    fn t_55_stages_take_the_earliest_citation_and_bounds() {
        let md = "### Aşama 0 — x\n- [ ] **a** — x. _Kaynak:_ §17; T-26 (6). _Durum:_ FT\n#### Doğrulanacak sınırlar\n- **INV-41, F-7** — x\n### Aşama 2 — y\n- [ ] **b** — _Kaynak:_ T-26, M-1. _Durum:_ FT\n";
        let (stages, bounds) = stages_and_bounds(md);
        assert_eq!(stages.get("T-26"), Some(&0));
        assert_eq!(stages.get("M-1"), Some(&2));
        assert_eq!(bounds.get("INV-41"), Some(&0));
    }
}
