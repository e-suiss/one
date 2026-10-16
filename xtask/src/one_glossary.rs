//! `glossary`: the canonical concept and relation code names live only in `conformance/catalog/glossary.toml`, unique, in English and tied to their spec rule; changing it needs a `Concept-Candidate:` commit line (C-3, C-23, C-29).

use std::path::Path;

use serde::Deserialize;

use super::{read_opt, v};
use crate::Violation;

pub(crate) const GLOSSARY: &str = "conformance/catalog/glossary.toml";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Glossary {
    pub(crate) concept: Vec<Term>,
    pub(crate) relation: Vec<Term>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Term {
    pub(crate) name: String,
    pub(crate) rule: String,
    pub(crate) meaning: String,
}

fn pascal(name: &str) -> bool {
    name.chars().next().is_some_and(|c| c.is_ascii_uppercase())
        && name.chars().all(|c| c.is_ascii_alphanumeric())
}

fn kebab(name: &str) -> bool {
    !name.is_empty()
        && name
            .split('-')
            .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_lowercase()))
}

pub(crate) fn findings(glossary: &Glossary) -> Vec<String> {
    let mut out = Vec::new();
    if glossary.concept.len() != 9 {
        out.push(format!(
            "C-1: there are nine canonical concepts, found {}",
            glossary.concept.len()
        ));
    }
    if glossary.relation.len() != 6 {
        out.push(format!(
            "C-23: there are six canonical relations, found {}",
            glossary.relation.len()
        ));
    }
    let terms = glossary
        .concept
        .iter()
        .map(|t| (t, true))
        .chain(glossary.relation.iter().map(|t| (t, false)));
    let mut seen: Vec<&str> = Vec::new();
    for (term, concept) in terms {
        if seen.contains(&term.name.as_str()) {
            out.push(format!("`{}` is listed twice", term.name));
        }
        seen.push(&term.name);
        let shape = if concept {
            pascal(&term.name)
        } else {
            kebab(&term.name)
        };
        if !shape {
            out.push(format!(
                "`{}` is not a {} code name",
                term.name,
                if concept { "PascalCase" } else { "kebab-case" }
            ));
        }
        if !term.rule.starts_with("C-")
            || term.meaning.trim().is_empty()
            || !term.meaning.is_ascii()
        {
            out.push(format!(
                "`{}` needs a C rule and an English meaning",
                term.name
            ));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read_opt(root, GLOSSARY)?.ok_or_else(|| format!("{GLOSSARY} is missing"))?;
    let glossary: Glossary = toml::from_str(&text).map_err(|e| format!("{GLOSSARY}: {e}"))?;
    Ok(findings(&glossary)
        .into_iter()
        .map(|m| v("C-29", GLOSSARY, m))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn term(name: &str) -> Term {
        Term {
            name: name.into(),
            rule: "C-10".into(),
            meaning: "x".into(),
        }
    }

    #[test]
    fn c_29_glossary_needs_nine_concepts_and_six_relations() {
        let g = Glossary {
            concept: vec![term("Observation"), term("Observation")],
            relation: vec![term("derived-from"), term("DerivedFrom")],
        };
        assert_eq!(findings(&g).len(), 4);
    }

    #[test]
    fn c_3_repository_glossary_is_valid() {
        let text = include_str!("../../conformance/catalog/glossary.toml");
        let g: Glossary = toml::from_str(text).unwrap();
        assert_eq!(findings(&g).len(), 0);
    }
}
