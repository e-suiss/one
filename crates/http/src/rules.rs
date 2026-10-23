//! The common API rules every One API family applies with the same code: `Request-Id`, `Idempotency-Key`, `ETag`/`If-Match`, opaque cursors, RFC 3339 UTC times, big integers as strings, `RateLimit` and `Deprecation`/`Sunset` headers (T-31 (1, 2), Access OP-65).

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use one_proto::RequestId;
use one_proto::id::uuid_v7;
use one_runtime::{Clock, Rng, UnixNanos};

use crate::Problem;

/// The `Request-Id` response header.
pub static REQUEST_ID: HeaderName = HeaderName::from_static("request-id");
/// The `Idempotency-Key` request header.
pub static IDEMPOTENCY_KEY: HeaderName = HeaderName::from_static("idempotency-key");

/// The time and randomness sources request identifiers are made from.
#[derive(Clone)]
pub struct Sources {
    /// The clock port.
    pub clock: Arc<dyn Clock>,
    /// The randomness port.
    pub rng: Arc<dyn Rng>,
}

/// A fresh request identifier from the ports.
#[must_use]
pub fn new_request_id(sources: &Sources) -> Option<RequestId> {
    let ms = u64::try_from(sources.clock.now().0 / 1_000_000).ok()?;
    let mut random = [0_u8; 10];
    sources.rng.fill(&mut random);
    RequestId::from_bytes(uuid_v7(ms, random)).ok()
}

/// Middleware adding a `Request-Id` header to every response.
pub async fn request_id(State(sources): State<Sources>, request: Request, next: Next) -> Response {
    let id = new_request_id(&sources);
    let mut response = next.run(request).await;
    if let Some(value) = id.and_then(|id| HeaderValue::from_str(&id.to_string()).ok()) {
        response.headers_mut().insert(REQUEST_ID.clone(), value);
    }
    response
}

/// A validated `Idempotency-Key`: an RFC 8941 string of 1 to 255 visible ASCII characters.
#[derive(Clone, PartialEq, Eq)]
pub struct IdempotencyKey(String);

impl core::fmt::Debug for IdempotencyKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IdempotencyKey([masked])")
    }
}

impl IdempotencyKey {
    /// Parses the header value.
    #[must_use]
    pub fn parse(value: &str) -> Option<Self> {
        let inner = value.strip_prefix('"')?.strip_suffix('"')?;
        let ok = (1..=255).contains(&inner.len())
            && inner
                .bytes()
                .all(|b| (0x20..=0x7e).contains(&b) && b != b'"' && b != b'\\');
        ok.then(|| Self(inner.to_owned()))
    }

    /// The key.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn mutating(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

/// Checks the `Idempotency-Key` of a request.
///
/// # Errors
/// Returns the problem to answer with when a mutating request has no valid key.
pub fn require_idempotency_key(
    method: &Method,
    headers: &HeaderMap,
) -> Result<Option<IdempotencyKey>, Problem> {
    if !mutating(method) {
        return Ok(None);
    }
    let Some(raw) = headers.get(&IDEMPOTENCY_KEY) else {
        return Err(Problem::new(
            StatusCode::BAD_REQUEST,
            "idempotency_key_required",
            "Idempotency-Key Required",
        ));
    };
    raw.to_str()
        .ok()
        .and_then(IdempotencyKey::parse)
        .map(Some)
        .ok_or_else(|| {
            Problem::new(
                StatusCode::BAD_REQUEST,
                "idempotency_key_invalid",
                "Invalid Idempotency-Key",
            )
        })
}

/// Middleware rejecting mutating requests without a valid `Idempotency-Key`.
pub async fn idempotency(request: Request, next: Next) -> Response {
    match require_idempotency_key(request.method(), request.headers()) {
        Ok(_) => next.run(request).await,
        Err(problem) => problem.into_response(),
    }
}

/// The strong entity tag for a resource version.
#[must_use]
pub fn etag(version: u64) -> HeaderValue {
    HeaderValue::from_str(&format!("\"v{version}\""))
        .unwrap_or_else(|_| HeaderValue::from_static("\"v0\""))
}

/// Checks `If-Match` against the current version.
///
/// # Errors
/// 428 when the header is missing, 412 when it names another version.
pub fn check_if_match(headers: &HeaderMap, current: u64) -> Result<(), Problem> {
    let Some(value) = headers.get(axum::http::header::IF_MATCH) else {
        return Err(Problem::new(
            StatusCode::PRECONDITION_REQUIRED,
            "if_match_required",
            "If-Match Required",
        ));
    };
    let expected = etag(current);
    let matches = value.to_str().is_ok_and(|v| {
        v.split(',')
            .map(str::trim)
            .any(|t| t == "*" || t.as_bytes() == expected.as_bytes())
    });
    if matches {
        Ok(())
    } else {
        Err(Problem::new(
            StatusCode::PRECONDITION_FAILED,
            "version_mismatch",
            "Precondition Failed",
        ))
    }
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// An opaque pagination cursor; clients never see page numbers or offsets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(pub Vec<u8>);

impl Cursor {
    /// Unpadded base64url text.
    #[must_use]
    pub fn encode(&self) -> String {
        let mut out = String::with_capacity(self.0.len().saturating_mul(2));
        for chunk in self.0.chunks(3) {
            let b = [
                chunk.first().copied().unwrap_or(0),
                chunk.get(1).copied().unwrap_or(0),
                chunk.get(2).copied().unwrap_or(0),
            ];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            let digits = chunk.len().saturating_add(1);
            for i in 0..digits {
                let shift = 18_usize.saturating_sub(i.saturating_mul(6));
                let index = usize::try_from((n >> shift) & 0x3f).unwrap_or(0);
                out.push(char::from(B64.get(index).copied().unwrap_or(b'A')));
            }
        }
        out
    }

    /// Parses unpadded base64url text.
    ///
    /// # Errors
    /// Returns a 400 problem for malformed text.
    pub fn decode(text: &str) -> Result<Self, Problem> {
        let invalid = || Problem::new(StatusCode::BAD_REQUEST, "invalid_cursor", "Invalid Cursor");
        if text.len().checked_rem(4) == Some(1) {
            return Err(invalid());
        }
        let mut out = Vec::with_capacity(text.len());
        let mut acc: u32 = 0;
        let mut bits: u32 = 0;
        for c in text.bytes() {
            let value = B64.iter().position(|&a| a == c).ok_or_else(invalid)?;
            acc = (acc << 6) | u32::try_from(value).map_err(|_| invalid())?;
            bits = bits.saturating_add(6);
            if bits >= 8 {
                bits = bits.saturating_sub(8);
                out.push(u8::try_from((acc >> bits) & 0xff).map_err(|_| invalid())?);
            }
        }
        Ok(Self(out))
    }
}

fn civil(days: i64) -> Option<(i64, u32, u32)> {
    let z = days.checked_add(719_468)?;
    let era = z.div_euclid(146_097);
    let doe = z.checked_sub(era.checked_mul(146_097)?)?;
    let yoe = doe
        .checked_sub(doe.checked_div(1460)?)?
        .checked_add(doe.checked_div(36_524)?)?
        .checked_sub(doe.checked_div(146_096)?)?
        .checked_div(365)?;
    let y = yoe.checked_add(era.checked_mul(400)?)?;
    let doy = doe.checked_sub(
        yoe.checked_mul(365)?
            .checked_add(yoe.checked_div(4)?)?
            .checked_sub(yoe.checked_div(100)?)?,
    )?;
    let mp = doy.checked_mul(5)?.checked_add(2)?.checked_div(153)?;
    let d = doy
        .checked_sub(mp.checked_mul(153)?.checked_add(2)?.checked_div(5)?)?
        .checked_add(1)?;
    let m = if mp < 10 {
        mp.checked_add(3)?
    } else {
        mp.checked_sub(9)?
    };
    let y = if m <= 2 { y.checked_add(1)? } else { y };
    Some((y, u32::try_from(m).ok()?, u32::try_from(d).ok()?))
}

/// RFC 3339 UTC text with millisecond precision, e.g. `2026-10-16T08:30:00.000Z`.
#[must_use]
pub fn rfc3339(time: UnixNanos) -> Option<String> {
    let ms = i64::try_from(time.0 / 1_000_000).ok()?;
    let secs = ms.div_euclid(1000);
    let (y, m, d) = civil(secs.div_euclid(86_400))?;
    let rem = secs.rem_euclid(86_400);
    let hours = rem.checked_div(3600)?;
    let minutes = rem.checked_rem(3600)?.checked_div(60)?;
    let seconds = rem.checked_rem(60)?;
    Some(format!(
        "{y:04}-{m:02}-{d:02}T{hours:02}:{minutes:02}:{seconds:02}.{:03}Z",
        ms.rem_euclid(1000)
    ))
}

/// Serde adapter carrying a `u64` as a JSON string.
pub mod u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    /// Writes the number as a string.
    ///
    /// # Errors
    /// Propagates the serializer's error.
    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    /// Reads the number from a string.
    ///
    /// # Errors
    /// Fails for anything but a decimal string.
    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

/// `RateLimit-Policy` and `RateLimit` header values for one policy.
#[must_use]
pub fn rate_limit(
    policy: &str,
    quota: u64,
    window_secs: u64,
    remaining: u64,
    reset_secs: u64,
) -> (HeaderValue, HeaderValue) {
    let policy_value = HeaderValue::from_str(&format!("\"{policy}\";q={quota};w={window_secs}"))
        .unwrap_or_else(|_| HeaderValue::from_static("\"default\""));
    let state = HeaderValue::from_str(&format!("\"{policy}\";r={remaining};t={reset_secs}"))
        .unwrap_or_else(|_| HeaderValue::from_static("\"default\""));
    (policy_value, state)
}

/// `Deprecation` (RFC 9745) and `Sunset` (RFC 8594) header values.
#[must_use]
pub fn deprecation(
    deprecated_at_unix: i64,
    sunset_http_date: &str,
) -> (HeaderValue, Option<HeaderValue>) {
    let deprecation = HeaderValue::from_str(&format!("@{deprecated_at_unix}"))
        .unwrap_or_else(|_| HeaderValue::from_static("@0"));
    (deprecation, HeaderValue::from_str(sunset_http_date).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn t_31_idempotency_key_is_required_and_validated_on_mutations() {
        let mut headers = HeaderMap::new();
        assert!(require_idempotency_key(&Method::GET, &headers).is_ok());
        assert!(require_idempotency_key(&Method::POST, &headers).is_err());
        headers.insert(
            IDEMPOTENCY_KEY.clone(),
            HeaderValue::from_static("\"8e03978e-40d5\""),
        );
        assert_eq!(
            require_idempotency_key(&Method::POST, &headers)
                .ok()
                .flatten()
                .map(|k| k.as_str().to_owned()),
            Some("8e03978e-40d5".to_owned())
        );
        headers.insert(
            IDEMPOTENCY_KEY.clone(),
            HeaderValue::from_static("unquoted"),
        );
        assert!(require_idempotency_key(&Method::PATCH, &headers).is_err());
    }

    #[test]
    fn t_31_if_match_needs_the_current_version() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            check_if_match(&headers, 3).err().map(|p| p.status()),
            Some(StatusCode::PRECONDITION_REQUIRED)
        );
        headers.insert(
            axum::http::header::IF_MATCH,
            HeaderValue::from_static("\"v2\""),
        );
        assert_eq!(
            check_if_match(&headers, 3).err().map(|p| p.status()),
            Some(StatusCode::PRECONDITION_FAILED)
        );
        headers.insert(axum::http::header::IF_MATCH, etag(3));
        assert!(check_if_match(&headers, 3).is_ok());
    }

    #[test]
    fn t_31_cursor_round_trips_and_rejects_garbage() {
        for bytes in [
            vec![],
            vec![1],
            vec![1, 2],
            vec![1, 2, 3],
            vec![255, 0, 7, 9, 200],
        ] {
            let cursor = Cursor(bytes);
            assert_eq!(Cursor::decode(&cursor.encode()).ok(), Some(cursor));
        }
        assert!(Cursor::decode("a").is_err());
        assert!(Cursor::decode("ab+c").is_err());
    }

    #[test]
    fn t_31_times_are_rfc_3339_utc() {
        assert_eq!(
            rfc3339(UnixNanos(0)),
            Some("1970-01-01T00:00:00.000Z".to_owned())
        );
        assert_eq!(
            rfc3339(UnixNanos(1_791_504_000_123_000_000)),
            Some("2026-10-09T00:00:00.123Z".to_owned())
        );
        assert_eq!(
            rfc3339(UnixNanos(951_782_400_000_000_000)),
            Some("2000-02-29T00:00:00.000Z".to_owned())
        );
    }

    #[test]
    fn t_31_big_integers_travel_as_strings() {
        #[derive(serde::Serialize, serde::Deserialize, PartialEq, Debug)]
        struct Amount {
            #[serde(with = "u64_string")]
            minor_units: u64,
        }
        let json = serde_json::to_string(&Amount {
            minor_units: u64::MAX,
        })
        .unwrap();
        assert_eq!(json, "{\"minor_units\":\"18446744073709551615\"}");
        assert_eq!(
            serde_json::from_str::<Amount>(&json).unwrap(),
            Amount {
                minor_units: u64::MAX
            }
        );
    }

    #[test]
    fn t_31_rate_limit_and_deprecation_headers() {
        let (policy, state) = rate_limit("default", 100, 60, 42, 30);
        assert_eq!(policy, "\"default\";q=100;w=60");
        assert_eq!(state, "\"default\";r=42;t=30");
        let (dep, sunset) = deprecation(1_688_169_599, "Sat, 01 Jan 2028 00:00:00 GMT");
        assert_eq!(dep, "@1688169599");
        assert!(sunset.is_some());
    }
}
