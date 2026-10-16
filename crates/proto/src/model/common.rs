//! Shared pieces of the model and attention contracts: artifact and snake-word name grammars and the content-class rules (MF-6, MF-22, MF-55).

use crate::data_class::{DataClass, RetentionClass};
use crate::ontology::validate::{ContractViolation, require, unique};

/// `[a-z0-9][a-z0-9._-]*`
#[must_use]
pub fn is_artifact_name(s: &str) -> bool {
    let mut chars = s.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'))
}

/// `[a-z][a-z0-9_]*`
#[must_use]
pub fn is_snake_word(s: &str) -> bool {
    let mut chars = s.chars();
    chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Checks the content data class rules shared by requests and routing records.
///
/// # Errors
/// Rejects a data class or retention class list that breaks `ContentClasses`.
pub fn validate_content_classes(
    data_class: &DataClass,
    retention_classes: &[RetentionClass],
) -> Result<(), ContractViolation> {
    require(unique(retention_classes), "retention_classes repeated")?;
    require(
        !retention_classes.iter().any(|c| {
            matches!(
                c,
                RetentionClass::OneProviderTrace | RetentionClass::OneTrainingLineage
            )
        }),
        "retention_classes carries a record-only class",
    )?;
    require(
        data_class.is_sensitive() == retention_classes.contains(&RetentionClass::OneSensitive),
        "one_sensitive exactly for PV-20 data",
    )?;
    require(
        data_class.is_general() == retention_classes.is_empty(),
        "general data carries no retention class",
    )
}
