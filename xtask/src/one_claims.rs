//! `forbidden-claims` keeps user-facing text and documents inside the §3.3a claims language (INV-40, SEC-34, F-23); `i18n-catalogs` keeps the Turkish and English catalogs complete and consistent (T-29 (6)).

use std::collections::BTreeSet;
use std::path::Path;

use serde::Deserialize;

use super::{read_opt, v};
use crate::Violation;

pub(crate) const CLAIMS_FILE: &str = "conformance/catalog/forbidden-claims.toml";
const CATALOG_DIR: &str = "packages/i18n/messages";
const DOCUMENTS: &[&str] = &["README.md", "CONTRIBUTING.md", "SECURITY.md"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claims {
    #[serde(default)]
    pub(crate) claim: Vec<Claim>,
    #[serde(default)]
    pub(crate) allow: Vec<Allow>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Claim {
    pub(crate) id: String,
    pub(crate) lang: String,
    pub(crate) phrase: String,
    pub(crate) instead: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Allow {
    pub(crate) location: String,
    pub(crate) phrase: String,
    pub(crate) rule: String,
}

/// One piece of user-facing text: where it lives and what it says.
pub(crate) struct Text {
    pub(crate) location: String,
    pub(crate) body: String,
}

fn lower(s: &str) -> String {
    s.replace('İ', "i").replace('I', "ı").to_lowercase()
}

fn lower_en(s: &str) -> String {
    s.to_lowercase()
}

fn contains_phrase(text: &str, phrase: &str, lang: &str) -> bool {
    let (t, p) = if lang == "tr" {
        (lower(text), lower(phrase))
    } else {
        (lower_en(text), lower_en(phrase))
    };
    t.match_indices(&p).any(|(i, _)| {
        let before = t.get(..i).and_then(|s| s.chars().last());
        let after = t
            .get(i.saturating_add(p.len())..)
            .and_then(|s| s.chars().next());
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// Findings as (location, claim id, phrase, instead).
pub(crate) fn findings(claims: &Claims, texts: &[Text]) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    for text in texts {
        for claim in &claims.claim {
            if !contains_phrase(&text.body, &claim.phrase, &claim.lang) {
                continue;
            }
            let allowed = claims
                .allow
                .iter()
                .any(|a| a.location == text.location && a.phrase == claim.phrase);
            if !allowed {
                out.push((
                    text.location.clone(),
                    claim.id.clone(),
                    claim.phrase.clone(),
                    claim.instead.clone(),
                ));
            }
        }
    }
    out
}

fn catalog(
    root: &Path,
    lang: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>, String> {
    let rel = format!("{CATALOG_DIR}/{lang}.json");
    let Some(text) = read_opt(root, &rel)? else {
        return Ok(None);
    };
    let json: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("{rel}: {e}"))?;
    json.as_object()
        .cloned()
        .map(Some)
        .ok_or_else(|| format!("{rel}: not a JSON object"))
}

fn texts(root: &Path) -> Result<Vec<Text>, String> {
    let mut out = Vec::new();
    for doc in DOCUMENTS {
        if let Some(body) = read_opt(root, doc)? {
            for (i, line) in body.lines().enumerate() {
                out.push(Text {
                    location: format!("{doc}:{}", i.saturating_add(1)),
                    body: line.to_owned(),
                });
            }
        }
    }
    for lang in ["en", "tr"] {
        if let Some(map) = catalog(root, lang)? {
            for (key, value) in map {
                out.push(Text {
                    location: format!("{CATALOG_DIR}/{lang}.json#{key}"),
                    body: value.as_str().unwrap_or_default().to_owned(),
                });
            }
        }
    }
    Ok(out)
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read_opt(root, CLAIMS_FILE)?.ok_or_else(|| format!("{CLAIMS_FILE} is missing"))?;
    let claims: Claims = toml::from_str(&text).map_err(|e| format!("{CLAIMS_FILE}: {e}"))?;
    if claims.claim.is_empty() {
        return Err(format!("{CLAIMS_FILE}: no claims"));
    }
    let mut out: Vec<Violation> = findings(&claims, &texts(root)?)
        .into_iter()
        .map(|(location, id, phrase, instead)| {
            v(
                "INV-40",
                location,
                format!("`{phrase}` overstates the guarantee ({id}); say: {instead}"),
            )
        })
        .collect();
    let texts = texts(root)?;
    for allow in &claims.allow {
        if allow.rule.trim().is_empty() {
            out.push(v(
                "INV-40",
                CLAIMS_FILE,
                format!("allow entry `{}` names no rule", allow.location),
            ));
        }
        let used = texts.iter().any(|t| {
            t.location == allow.location
                && claims.claim.iter().any(|c| {
                    c.phrase == allow.phrase && contains_phrase(&t.body, &c.phrase, &c.lang)
                })
        });
        if !used {
            out.push(v(
                "INV-40",
                CLAIMS_FILE,
                format!(
                    "allow entry `{}` / `{}` is stale",
                    allow.location, allow.phrase
                ),
            ));
        }
    }
    Ok(out)
}

fn placeholders(message: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut depth = 0_usize;
    let mut current = String::new();
    for c in message.chars() {
        match c {
            '{' => {
                depth = depth.saturating_add(1);
                if depth == 1 {
                    current.clear();
                }
            }
            '}' => {
                if depth == 1 {
                    let name = current
                        .split(',')
                        .next()
                        .unwrap_or_default()
                        .trim()
                        .to_owned();
                    if !name.is_empty() {
                        out.insert(name);
                    }
                }
                depth = depth.saturating_sub(1);
            }
            _ if depth == 1 => current.push(c),
            _ => {}
        }
    }
    out
}

/// Differences between the English and Turkish catalogs.
pub(crate) fn i18n_findings(
    en: &serde_json::Map<String, serde_json::Value>,
    tr: &serde_json::Map<String, serde_json::Value>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (key, value) in en {
        match (
            value.as_str(),
            tr.get(key).and_then(serde_json::Value::as_str),
        ) {
            (None, _) => out.push(format!("en `{key}` is not a string")),
            (Some(_), None) => out.push(format!("tr is missing `{key}`")),
            (Some(a), Some(b)) => {
                if a.trim().is_empty() || b.trim().is_empty() {
                    out.push(format!("`{key}` is empty in one language"));
                }
                if placeholders(a) != placeholders(b) {
                    out.push(format!("`{key}` has different placeholders"));
                }
            }
        }
    }
    for key in tr.keys().filter(|k| !en.contains_key(*k)) {
        out.push(format!("en is missing `{key}`"));
    }
    out
}

pub(crate) fn check_i18n(root: &Path) -> Result<Vec<Violation>, String> {
    match (catalog(root, "en")?, catalog(root, "tr")?) {
        (None, None) => Ok(Vec::new()),
        (Some(en), Some(tr)) => Ok(i18n_findings(&en, &tr)
            .into_iter()
            .map(|m| v("T-29", CATALOG_DIR, m))
            .collect()),
        _ => Ok(vec![v(
            "T-29",
            CATALOG_DIR,
            "both en.json and tr.json are required".to_owned(),
        )]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn claims() -> Claims {
        toml::from_str(
            r#"
            [[claim]]
            id = "SEC-34"
            lang = "tr"
            phrase = "sildim"
            instead = "Kalıcı olarak unuttum; geri getirilemez."
            [[claim]]
            id = "SEC-34"
            lang = "en"
            phrase = "end-to-end encrypted"
            instead = "processed so that Suiss cannot read it"
            [[allow]]
            location = "README.md:3"
            phrase = "end-to-end encrypted"
            rule = "OO-12"
            "#,
        )
        .unwrap()
    }

    fn text(location: &str, body: &str) -> Text {
        Text {
            location: location.to_owned(),
            body: body.to_owned(),
        }
    }

    #[test]
    fn sec_34_forbidden_phrases_are_found_on_word_boundaries() {
        let found = findings(
            &claims(),
            &[
                text("a", "Bunu SİLDİM."),
                text("b", "silindim değil"),
                text("c", "Your data is End-to-End Encrypted."),
            ],
        );
        assert_eq!(found.len(), 2);
    }

    #[test]
    fn inv_40_allowlisted_location_passes() {
        let found = findings(
            &claims(),
            &[text(
                "README.md:3",
                "One↔One messages are end-to-end encrypted.",
            )],
        );
        assert_eq!(found.len(), 0);
    }

    #[test]
    fn t_29_missing_key_and_placeholder_drift_are_rejected() {
        let en: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"a":"Hi {name}","b":"x"}"#).unwrap();
        let tr: serde_json::Map<String, serde_json::Value> =
            serde_json::from_str(r#"{"a":"Merhaba {ad}"}"#).unwrap();
        assert_eq!(i18n_findings(&en, &tr).len(), 2);
    }
}
