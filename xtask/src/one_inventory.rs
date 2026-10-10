//! `data-inventory`: telemetry fields in code equal the single data inventory, analytics events and plain metadata columns are declared there, and identifiers are never metric labels (T-37 (1, 3), §18 OP-17 (4)).

use std::path::Path;

use serde::Deserialize;

use super::{read_opt, v};
use crate::Violation;

pub(crate) const INVENTORY: &str = "conformance/data-inventory.toml";
const FIELDS: &str = "crates/telemetry/src/fields.rs";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Inventory {
    pub(crate) version: u32,
    #[serde(default)]
    pub(crate) telemetry_field: Vec<Field>,
    #[serde(default)]
    pub(crate) analytics_event: Vec<Named>,
    #[serde(default)]
    pub(crate) plain_metadata_column: Vec<Named>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Field {
    pub(crate) name: String,
    pub(crate) kind: String,
    pub(crate) label: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Named {
    pub(crate) name: String,
    pub(crate) purpose: String,
}

fn value_after<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let at = block.find(key)?;
    let rest = block.get(at.saturating_add(key.len())..)?;
    let end = rest.find([',', '\n', '}']).unwrap_or(rest.len());
    rest.get(..end).map(str::trim)
}

/// The `Spec { .. }` rows of `fields.rs`, in order.
pub(crate) fn code_fields(src: &str) -> Vec<Field> {
    let mut out = Vec::new();
    for block in src.split("Spec {").skip(1) {
        let block = block.split('}').next().unwrap_or_default();
        if !block.contains("field: Field::") {
            continue;
        }
        let name = value_after(block, "name:").map(|n| n.trim_matches('"').to_owned());
        let kind = value_after(block, "kind:")
            .map(|k| k.trim_start_matches("Kind::").to_ascii_lowercase());
        let label = value_after(block, "label:").map(|l| l == "true");
        if let (Some(name), Some(kind), Some(label)) = (name, kind, label) {
            out.push(Field { name, kind, label });
        }
    }
    out
}

pub(crate) fn diff(inventory: &Inventory, code: &[Field]) -> Vec<String> {
    let mut out = Vec::new();
    if inventory.version == 0 {
        out.push("version must be at least 1".to_owned());
    }
    for f in &inventory.telemetry_field {
        if f.kind == "id" && f.label {
            out.push(format!(
                "`{}` is an identifier and cannot be a metric label",
                f.name
            ));
        }
        match code.iter().find(|c| c.name == f.name) {
            None => out.push(format!(
                "`{}` is in the inventory but not in {FIELDS}",
                f.name
            )),
            Some(c) if c != f => out.push(format!(
                "`{}` differs between the inventory and {FIELDS}",
                f.name
            )),
            Some(_) => {}
        }
    }
    for c in code {
        if !inventory.telemetry_field.iter().any(|f| f.name == c.name) {
            out.push(format!(
                "`{}` is in {FIELDS} but not in the inventory",
                c.name
            ));
        }
    }
    for n in inventory
        .analytics_event
        .iter()
        .chain(&inventory.plain_metadata_column)
    {
        if n.purpose.trim().is_empty() {
            out.push(format!("`{}` has no purpose", n.name));
        }
    }
    out
}

pub(crate) fn check(root: &Path) -> Result<Vec<Violation>, String> {
    let text = read_opt(root, INVENTORY)?.ok_or_else(|| format!("{INVENTORY} is missing"))?;
    let inventory: Inventory = toml::from_str(&text).map_err(|e| format!("{INVENTORY}: {e}"))?;
    let code = read_opt(root, FIELDS)?.unwrap_or_default();
    Ok(diff(&inventory, &code_fields(&code))
        .into_iter()
        .map(|m| v("T-37", INVENTORY, m))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    const SRC: &str =
        "Spec {\n field: Field::A,\n name: \"a_ms\",\n kind: Kind::Millis,\n label: false,\n},";

    #[test]
    fn t_37_code_fields_are_parsed() {
        assert_eq!(
            code_fields(SRC),
            vec![Field {
                name: "a_ms".into(),
                kind: "millis".into(),
                label: false
            }]
        );
    }

    #[test]
    fn t_37_inventory_and_code_must_match() {
        let inventory = Inventory {
            version: 1,
            telemetry_field: vec![Field {
                name: "user_id".into(),
                kind: "id".into(),
                label: true,
            }],
            analytics_event: Vec::new(),
            plain_metadata_column: Vec::new(),
        };
        let found = diff(&inventory, &code_fields(SRC));
        assert_eq!(found.len(), 3);
    }
}
