//! The `OpenAPI` document of the client and developer API, generated from code and committed under `conformance/openapi/` (T-31, Access OP-65).

use utoipa::OpenApi as _;

use crate::Problem;

#[derive(utoipa::OpenApi)]
#[openapi(
    info(
        title = "One API",
        version = "1",
        description = "The One client and developer API."
    ),
    components(schemas(Problem))
)]
struct Api;

/// The `OpenAPI` document as pretty JSON with a trailing newline.
///
/// # Errors
/// Returns the serialisation error.
pub fn document() -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&Api::openapi())?;
    text.push('\n');
    Ok(text)
}
