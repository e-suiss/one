//! The Annex III exclusion (PV-3): One has no capability for screening job candidates, judging creditworthiness, pricing insurance, deciding access to public benefits or assessing students, and cannot be configured into one; a registry entry whose name carries one of [`FORBIDDEN_SEGMENTS`] is refused; a weighty decision stays "One prepares, a person decides", and the user's own application stays open.

use one_proto::capability::CapabilityName;

/// Name segments of the Annex III uses.
pub const FORBIDDEN_SEGMENTS: &[&str] = &[
    "hiring",
    "recruitment",
    "candidate",
    "applicant",
    "credit",
    "creditworthiness",
    "scoring",
    "insurance",
    "underwriting",
    "benefits",
    "welfare",
    "grading",
    "exam",
    "admission",
];

/// Whether `name` names an Annex III use.
#[must_use]
pub fn forbidden(name: &CapabilityName) -> bool {
    name.segments().any(|s| FORBIDDEN_SEGMENTS.contains(&s))
}
