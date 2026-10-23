//! `conformance-vectors`: every JSON Schema under `conformance/` compiles against the 2020-12 metaschema, every `$ref` resolves, and every schema vector gives its expected result (T-31, T-55, C-25, C-26).

use std::collections::BTreeMap;
use std::path::Path;

use serde::Deserialize;

use super::v;
use crate::Violation;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Index {
    #[serde(default)]
    pub(crate) schema: Vec<SchemaEntry>,
    #[serde(default)]
    pub(crate) vectors: Vec<VectorEntry>,
    #[serde(default)]
    pub(crate) table: Vec<TableEntry>,
    #[serde(default)]
    pub(crate) event: Vec<EventEntry>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EventEntry {
    #[serde(rename = "type")]
    pub(crate) kind: String,
    pub(crate) schema: String,
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SchemaEntry {
    pub(crate) path: String,
    pub(crate) id: String,
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct VectorEntry {
    pub(crate) path: String,
    pub(crate) kind: String,
    #[serde(default)]
    pub(crate) schema: Option<String>,
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct TableEntry {
    pub(crate) path: String,
    pub(crate) rules: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct SchemaVector {
    pub(crate) rule: String,
    pub(crate) description: String,
    pub(crate) input: serde_json::Value,
    pub(crate) valid: bool,
}

pub(crate) fn read_json(path: &Path) -> Result<serde_json::Value, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    serde_json::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))
}

pub(crate) fn indexes(root: &Path) -> Result<Vec<(String, Index)>, String> {
    let dir = root.join("conformance");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(&dir).map_err(|e| format!("{}: {e}", dir.display()))? {
        let folder = entry.map_err(|e| e.to_string())?.path();
        let index = folder.join("index.toml");
        if !index.is_file() {
            continue;
        }
        let name = folder
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let text =
            std::fs::read_to_string(&index).map_err(|e| format!("{}: {e}", index.display()))?;
        match toml::from_str::<Index>(&text) {
            Ok(parsed) => out.push((name, parsed)),
            Err(e) => return Err(format!("conformance/{name}/index.toml: {e}")),
        }
    }
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn catalog_ids(root: &Path) -> Result<std::collections::BTreeSet<String>, String> {
    let path = root.join("conformance/catalog/rules.toml");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let table: toml::Table = text
        .parse()
        .map_err(|e| format!("{}: {e}", path.display()))?;
    Ok(table
        .get("rule")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("id").and_then(toml::Value::as_str).map(str::to_owned))
        .collect())
}

/// Every indexed schema under `conformance/`, compiled.
pub(crate) struct Compiled {
    pub(crate) schemas: boon::Schemas,
    pub(crate) by_id: BTreeMap<String, boon::SchemaIndex>,
    pub(crate) paths: BTreeMap<String, String>,
}

pub(crate) fn compile(
    root: &Path,
    all: &[(String, Index)],
    out: &mut Vec<Violation>,
) -> Result<Compiled, String> {
    let mut compiler = boon::Compiler::new();
    let mut ids: BTreeMap<String, String> = BTreeMap::new();
    for (folder, index) in all {
        for s in &index.schema {
            let rel = format!("conformance/{folder}/{}", s.path);
            let json = read_json(&root.join(&rel))?;
            if json.get("$id").and_then(serde_json::Value::as_str) != Some(s.id.as_str()) {
                out.push(v("T-31", rel.clone(), format!("`$id` must be `{}`", s.id)));
            }
            if let Some(prev) = ids.insert(s.id.clone(), rel.clone()) {
                out.push(v("T-31", rel.clone(), format!("`$id` also used by {prev}")));
            }
            if let Err(e) = compiler.add_resource(&s.id, json) {
                out.push(v("T-31", rel, format!("cannot load schema: {e}")));
            }
        }
    }
    let mut schemas = boon::Schemas::new();
    let mut by_id: BTreeMap<String, boon::SchemaIndex> = BTreeMap::new();
    for (id, rel) in &ids {
        match compiler.compile(id, &mut schemas) {
            Ok(index) => {
                by_id.insert(id.clone(), index);
            }
            Err(e) => out.push(v(
                "T-31",
                rel.clone(),
                format!("schema does not compile: {e:#}"),
            )),
        }
    }
    Ok(Compiled {
        schemas,
        by_id,
        paths: ids,
    })
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let mut out = Vec::new();
    let all = indexes(root)?;
    let Compiled { schemas, by_id, .. } = compile(root, &all, &mut out)?;
    let known = catalog_ids(root)?;
    for (folder, index) in &all {
        let cited = index
            .schema
            .iter()
            .flat_map(|s| s.rules.iter())
            .chain(index.vectors.iter().flat_map(|e| e.rules.iter()))
            .chain(index.table.iter().flat_map(|t| t.rules.iter()))
            .chain(index.event.iter().flat_map(|e| e.rules.iter()));
        for rule in cited {
            let base = rule.split(" (").next().unwrap_or(rule);
            let sibling = ["Access ", "Relay ", "Work ", "Pay "]
                .iter()
                .any(|p| base.starts_with(p));
            if !sibling && !known.contains(base) {
                out.push(v(
                    "T-55",
                    format!("conformance/{folder}/index.toml"),
                    format!("`{rule}` is not a catalog rule ID"),
                ));
            }
        }
        for t in &index.table {
            let rel = format!("conformance/{folder}/{}", t.path);
            if !root.join(&rel).is_file() {
                out.push(v("T-55", rel, "listed table is missing".to_owned()));
            }
        }
        for entry in &index.vectors {
            let rel = format!("conformance/{folder}/{}", entry.path);
            let json = read_json(&root.join(&rel))?;
            match entry.kind.as_str() {
                "behaviour" => {}
                "schema" => {
                    let Some(index) = entry.schema.as_ref().and_then(|id| by_id.get(id)) else {
                        out.push(v(
                            "T-31",
                            rel,
                            "schema vectors name no compiled schema".to_owned(),
                        ));
                        continue;
                    };
                    let vectors: Vec<SchemaVector> =
                        serde_json::from_value(json).map_err(|e| format!("{rel}: {e}"))?;
                    for (i, vector) in vectors.iter().enumerate() {
                        let valid = schemas.validate(&vector.input, *index).is_ok();
                        if valid != vector.valid {
                            out.push(v(
                                "T-31",
                                format!("{rel}#{i}"),
                                format!(
                                    "[{}] {}: expected valid={}, got {valid}",
                                    vector.rule, vector.description, vector.valid
                                ),
                            ));
                        }
                    }
                }
                other => out.push(v("T-55", rel, format!("unknown vector kind `{other}`"))),
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    #[test]
    fn t_31_schema_vectors_are_checked_against_their_schema() {
        let mut compiler = boon::Compiler::new();
        let schema = serde_json::json!({
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "https://suiss.app/schemas/one/test/x/v1.json",
            "type": "object",
            "required": ["kind"],
            "properties": { "kind": { "enum": ["approval"] } }
        });
        compiler
            .add_resource("https://suiss.app/schemas/one/test/x/v1.json", schema)
            .unwrap();
        let mut schemas = boon::Schemas::new();
        let index = compiler
            .compile("https://suiss.app/schemas/one/test/x/v1.json", &mut schemas)
            .unwrap();
        assert!(
            schemas
                .validate(&serde_json::json!({"kind": "approval"}), index)
                .is_ok()
        );
        assert!(
            schemas
                .validate(&serde_json::json!({"kind": "other"}), index)
                .is_err()
        );
    }
}
