//! `device-model-budget` keeps the phone's models within the size budget and model files out of app packages (T-30 (2), MF-13, MF-17); `model-file-formats` rejects code-executing model formats anywhere in the repository (T-39 (5), SEC-26).

use std::path::Path;

use serde::Deserialize;

use super::{read_opt, v};
use crate::Violation;
use crate::policy::scan::repo_files;

const DEVICE_MODELS: &str = "conformance/models/device-models.toml";

pub(crate) const MODEL_EXTENSIONS: &[&str] = &[
    "gguf",
    "safetensors",
    "onnx",
    "tflite",
    "litertlm",
    "mlmodel",
    "mlmodelc",
    "mlpackage",
    "pte",
];

pub(crate) const PICKLE_EXTENSIONS: &[&str] = &["pkl", "pickle", "pt", "pth", "ckpt", "joblib"];

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DeviceModels {
    pub(crate) budget_bytes: u64,
    #[serde(default)]
    pub(crate) model: Vec<Model>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Model {
    pub(crate) name: String,
    pub(crate) bytes: u64,
    pub(crate) status: String,
}

pub(crate) fn budget_findings(models: &DeviceModels) -> Vec<String> {
    let mut out = Vec::new();
    let mut total = 0_u64;
    for m in &models.model {
        match m.status.as_str() {
            "candidate" | "released" => total = total.saturating_add(m.bytes),
            "retired" => {}
            other => out.push(format!("`{}` has unknown status `{other}`", m.name)),
        }
    }
    if total > models.budget_bytes {
        out.push(format!(
            "device models total {total} bytes; the budget is {} bytes",
            models.budget_bytes
        ));
    }
    out
}

fn extension(file: &str) -> &str {
    file.rsplit('/')
        .next()
        .and_then(|n| n.rsplit_once('.'))
        .map_or("", |(_, e)| e)
}

pub(crate) fn check_budget(root: &Path) -> Result<Vec<Violation>, String> {
    let text =
        read_opt(root, DEVICE_MODELS)?.ok_or_else(|| format!("{DEVICE_MODELS} is missing"))?;
    let models: DeviceModels =
        toml::from_str(&text).map_err(|e| format!("{DEVICE_MODELS}: {e}"))?;
    let mut out: Vec<Violation> = budget_findings(&models)
        .into_iter()
        .map(|m| v("T-30", DEVICE_MODELS, m))
        .collect();
    for file in repo_files(root)? {
        let in_app =
            file.starts_with("apps/") || file.starts_with("packages/") || file.starts_with("core/");
        if in_app && MODEL_EXTENSIONS.contains(&extension(&file).to_ascii_lowercase().as_str()) {
            out.push(v(
                "T-30",
                file.clone(),
                "model files are downloaded, never bundled in an app (MF-17)".to_owned(),
            ));
        }
    }
    Ok(out)
}

pub(crate) fn check_formats(root: &Path) -> Result<Vec<Violation>, String> {
    Ok(repo_files(root)?
        .into_iter()
        .filter(|f| PICKLE_EXTENSIONS.contains(&extension(f).to_ascii_lowercase().as_str()))
        .map(|f| {
            v(
                "T-39",
                f,
                "pickle-based model formats execute code; use safetensors or a platform format"
                    .to_owned(),
            )
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_30_models_over_budget_are_rejected() {
        let models = DeviceModels {
            budget_bytes: 250_000_000,
            model: vec![
                Model {
                    name: "a".into(),
                    bytes: 200_000_000,
                    status: "released".into(),
                },
                Model {
                    name: "b".into(),
                    bytes: 60_000_000,
                    status: "candidate".into(),
                },
                Model {
                    name: "c".into(),
                    bytes: 900_000_000,
                    status: "retired".into(),
                },
            ],
        };
        assert_eq!(budget_findings(&models).len(), 1);
    }

    #[test]
    fn t_39_pickle_extensions_are_known() {
        assert_eq!(extension("ml/x/model.PT").to_ascii_lowercase(), "pt");
        assert!(PICKLE_EXTENSIONS.contains(&"ckpt"));
    }
}
