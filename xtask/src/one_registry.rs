//! `model-registry` pins every model file by hash, signature, source, licence and a non-code-executing format (T-39 (5), SEC-26, T-34 (1)); `native-supply-chain` keeps Swift and Kotlin dependencies resolved, exact and verified (T-39 (3)).

use std::path::Path;

use serde::Deserialize;

use super::{read_opt, v};
use crate::Violation;
use crate::policy::scan::repo_files;
use crate::rules::files::read;

const REGISTRY: &str = "conformance/models/registry.toml";
const LICENSES: &str = "ml/licenses.toml";
const GRADLE_PLUGINS: &str = "conformance/platform/gradle-plugins.toml";

pub(crate) const FORMATS: &[&str] = &[
    "safetensors",
    "gguf",
    "onnx",
    "tflite",
    "litertlm",
    "mlpackage",
    "pte",
];

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Registry {
    #[serde(default)]
    pub(crate) model: Vec<Model>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Model {
    pub(crate) name: String,
    pub(crate) version: String,
    pub(crate) role: String,
    pub(crate) component: String,
    pub(crate) format: String,
    pub(crate) sha256: String,
    pub(crate) source: String,
    pub(crate) status: String,
    #[serde(default)]
    pub(crate) signature: String,
}

fn allowed_components(licenses: &toml::Table) -> Vec<String> {
    licenses
        .get("component")
        .and_then(toml::Value::as_array)
        .into_iter()
        .flatten()
        .filter(|c| c.get("status").and_then(toml::Value::as_str) == Some("allowed"))
        .filter_map(|c| {
            c.get("name")
                .and_then(toml::Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

pub(crate) fn registry_findings(registry: &Registry, allowed: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for m in &registry.model {
        let id = format!("{}@{}", m.name, m.version);
        if !FORMATS.contains(&m.format.as_str()) {
            out.push(format!(
                "{id}: format `{}` is not a non-code-executing format",
                m.format
            ));
        }
        if m.sha256.len() != 64
            || !m
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            out.push(format!("{id}: sha256 must be 64 lower-case hex digits"));
        }
        if !allowed.contains(&m.component) {
            out.push(format!(
                "{id}: component `{}` is not allowed in {LICENSES}",
                m.component
            ));
        }
        if !matches!(m.role.as_str(), "cloud" | "device") {
            out.push(format!("{id}: role must be cloud or device"));
        }
        if m.source.trim().is_empty() {
            out.push(format!("{id}: source is required"));
        }
        match m.status.as_str() {
            "released" if m.signature.trim().is_empty() => {
                out.push(format!("{id}: a released model needs a signature"));
            }
            "candidate" | "released" | "retired" => {}
            other => out.push(format!("{id}: unknown status `{other}`")),
        }
    }
    out
}

pub(crate) fn check_registry(root: &Path) -> Result<Vec<Violation>, String> {
    let registry: Registry = match read_opt(root, REGISTRY)? {
        Some(text) => toml::from_str(&text).map_err(|e| format!("{REGISTRY}: {e}"))?,
        None => {
            return Ok(vec![v(
                "T-39",
                REGISTRY,
                "the model registry file is missing".to_owned(),
            )]);
        }
    };
    let licenses: toml::Table = read_opt(root, LICENSES)?
        .unwrap_or_default()
        .parse()
        .map_err(|e| format!("{LICENSES}: {e}"))?;
    Ok(registry_findings(&registry, &allowed_components(&licenses))
        .into_iter()
        .map(|m| v("T-39", REGISTRY, m))
        .collect())
}

/// Problems with a `Package.swift` manifest: every package dependency uses `exact:`.
pub(crate) fn swift_findings(manifest: &str) -> Vec<String> {
    manifest
        .lines()
        .filter(|l| l.contains(".package(") && l.contains("url:"))
        .filter(|l| !l.contains("exact:"))
        .map(|l| format!("dependency without an exact version: {}", l.trim()))
        .collect()
}

/// Problems with a Gradle build or version catalog: no dynamic or open-ended versions.
pub(crate) fn gradle_findings(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let t = line.trim();
        let dynamic = t.contains("latest.release")
            || t.contains("latest.integration")
            || t.contains(".+\"")
            || t.contains(":+\"")
            || t.contains("= \"+\"");
        let range = t.contains("strictly") && (t.contains('[') || t.contains('('));
        if dynamic || range {
            out.push(format!("dynamic version: {t}"));
        }
    }
    out
}

/// Plugin ids applied in a Gradle build script.
pub(crate) fn gradle_plugins(text: &str) -> Vec<String> {
    text.lines()
        .filter_map(|l| {
            let t = l.trim();
            let rest = t
                .strip_prefix("id(\"")
                .or_else(|| t.strip_prefix("id \""))?;
            rest.split('"').next().map(str::to_owned)
        })
        .collect()
}

pub(crate) fn check_native(root: &Path) -> Result<Vec<Violation>, String> {
    let files = repo_files(root)?;
    let allowed_plugins: Vec<String> = read_opt(root, GRADLE_PLUGINS)?
        .map(|t| t.parse::<toml::Table>())
        .transpose()
        .map_err(|e| format!("{GRADLE_PLUGINS}: {e}"))?
        .and_then(|t| t.get("allow").and_then(toml::Value::as_array).cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(|p| p.as_str().map(str::to_owned))
        .collect();
    let mut out = Vec::new();
    for file in files.iter().filter(|f| f.starts_with("apps/")) {
        let name = file.rsplit('/').next().unwrap_or_default();
        let dir = file.rsplit_once('/').map_or("", |(d, _)| d);
        if name == "Package.swift" {
            if !files.contains(&format!("{dir}/Package.resolved")) {
                out.push(v(
                    "T-39",
                    file.clone(),
                    "Package.resolved is not committed".to_owned(),
                ));
            }
            out.extend(
                swift_findings(&read(&root.join(file))?)
                    .into_iter()
                    .map(|m| v("T-39", file.clone(), m)),
            );
        }
        let gradle = name.ends_with(".gradle.kts")
            || name.ends_with(".gradle")
            || name.ends_with(".versions.toml")
            || name == "versions.toml";
        if gradle {
            let text = read(&root.join(file))?;
            out.extend(
                gradle_findings(&text)
                    .into_iter()
                    .map(|m| v("T-39", file.clone(), m)),
            );
            for plugin in gradle_plugins(&text) {
                if !allowed_plugins.contains(&plugin) {
                    out.push(v(
                        "T-39",
                        file.clone(),
                        format!("Gradle plugin `{plugin}` is not in {GRADLE_PLUGINS}"),
                    ));
                }
            }
        }
        if name == "settings.gradle.kts"
            && !files.contains(&format!("{dir}/gradle/verification-metadata.xml"))
        {
            out.push(v(
                "T-39",
                file.clone(),
                "gradle/verification-metadata.xml is not committed".to_owned(),
            ));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn model(format: &str, component: &str, status: &str, signature: &str) -> Model {
        Model {
            name: "embed".into(),
            version: "1".into(),
            role: "device".into(),
            component: component.into(),
            format: format.into(),
            sha256: "a".repeat(64),
            source: "https://huggingface.co/google/embeddinggemma-2".into(),
            status: status.into(),
            signature: signature.into(),
        }
    }

    #[test]
    fn sec_26_model_entries_need_safe_format_licence_and_signature() {
        let allowed = vec!["EmbeddingGemma 2".to_owned()];
        let ok = Registry {
            model: vec![model("safetensors", "EmbeddingGemma 2", "released", "sig")],
        };
        assert_eq!(registry_findings(&ok, &allowed).len(), 0);
        let bad = Registry {
            model: vec![model("pt", "LaMP", "released", "")],
        };
        assert_eq!(registry_findings(&bad, &allowed).len(), 3);
    }

    #[test]
    fn t_39_swift_and_gradle_dependencies_must_be_exact() {
        let swift = ".package(url: \"https://github.com/a/b\", from: \"1.0.0\"),\n.package(url: \"https://github.com/c/d\", exact: \"2.0.0\"),";
        assert_eq!(swift_findings(swift).len(), 1);
        assert_eq!(
            gradle_findings("implementation(\"a:b:1.+\")\nimplementation(\"c:d:2.0.0\")").len(),
            1
        );
        assert_eq!(
            gradle_plugins("plugins {\n    id(\"com.android.application\")\n}"),
            vec!["com.android.application"]
        );
    }
}
