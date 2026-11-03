//! The router's adapters: serving deployments joined with the model registry, so a version the registry does not list as released, signed and passed is never served and an unlisted version is never loaded (MF-52, SEC-26, T-34).

use one_proto::ModelVersionId;
use one_proto::model::registry::Registry;
use one_proto::model::roles::Placement;
use one_proto::model::routing::Region;

use crate::domain::gate::{Family, Instance};

/// One deployed serving instance as the serving fleet reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// The model version loaded.
    pub version: ModelVersionId,
    /// Its family.
    pub family: Family,
    /// Its region.
    pub region: Region,
    /// It runs inside an attested TEE.
    pub attested_tee: bool,
    /// It answers now.
    pub available: bool,
}

/// The instances the router may consider: each deployment whose version is a cloud entry of `registry`, released only when the entry is released, signed and passed; a deployment of an unlisted version is left out.
#[must_use]
pub fn instances(registry: &Registry, deployments: &[Deployment]) -> Vec<Instance> {
    let entries: Vec<_> = registry
        .model
        .iter()
        .flatten()
        .filter(|e| e.role == Placement::Cloud)
        .collect();
    deployments
        .iter()
        .filter_map(|d| {
            let entry = entries.iter().find(|e| e.model_version_id == d.version)?;
            Some(Instance {
                role: entry.model_role,
                version: d.version,
                family: d.family,
                region: d.region.clone(),
                attested_tee: d.attested_tee,
                released: registry
                    .releasable()
                    .any(|e| e.model_version_id == d.version),
                available: d.available,
            })
        })
        .collect()
}
