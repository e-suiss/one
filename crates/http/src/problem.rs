//! RFC 9457 problem responses with a stable `code`; internal detail never reaches the body (T-28 (6), T-31).

use std::any::Any;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;

/// An RFC 9457 problem response.
#[derive(Debug, Serialize)]
pub struct Problem {
    #[serde(rename = "type")]
    type_uri: &'static str,
    title: &'static str,
    status: u16,
    code: &'static str,
    #[serde(skip)]
    status_code: StatusCode,
}

impl Problem {
    /// A problem with a stable `code` and a short title.
    #[must_use]
    pub fn new(status: StatusCode, code: &'static str, title: &'static str) -> Self {
        Self {
            type_uri: "about:blank",
            title,
            status: status.as_u16(),
            code,
            status_code: status,
        }
    }
}

impl IntoResponse for Problem {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self).unwrap_or_default();
        let mut response = (self.status_code, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "signature required by tower_http::catch_panic::ResponseForPanic"
)]
pub(crate) fn from_panic(_payload: Box<dyn Any + Send + 'static>) -> Response {
    tracing::error!(event = "http.handler_panic", outcome = "error");
    Problem::new(
        StatusCode::INTERNAL_SERVER_ERROR,
        "internal",
        "Internal Server Error",
    )
    .into_response()
}
