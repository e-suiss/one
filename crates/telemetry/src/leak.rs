//! Linear-time scanner for secret-shaped text in log, telemetry and model-context lines; if the patterns cannot be compiled every line counts as a leak (SEC-6, SEC-22 (8)).

use std::sync::LazyLock;

use regex::{Regex, RegexSet};

/// A kind of secret-shaped data.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LeakKind {
    /// A password assignment.
    Password,
    /// A cookie header or session cookie value.
    Cookie,
    /// A payment card number that passes the Luhn check.
    Card,
    /// A one-time code next to its label.
    OneTimeCode,
    /// A bearer token or a JSON Web Token.
    Token,
    /// A PEM private key.
    PrivateKey,
    /// An upstream provider credential (cloud, source host, chat, model provider).
    UpstreamCredential,
    /// The scanner could not be built.
    ScannerUnavailable,
}

const PATTERNS: &[(LeakKind, &str)] = &[
    (
        LeakKind::Password,
        r"(?i)\b(?:pass(?:word|wd)?|pwd|parola|şifre)\s*[:=]\s*\S",
    ),
    (LeakKind::Cookie, r"(?i)\b(?:set-)?cookie\s*:\s*\S"),
    (
        LeakKind::Cookie,
        r"(?i)\b(?:session|sessionid|sid)=[A-Za-z0-9%._-]{8,}",
    ),
    (
        LeakKind::OneTimeCode,
        r"(?i)\b(?:otp|one[- ]time (?:code|password)|verification code|doğrulama kodu|tek kullanımlık kod)\D{0,12}\d{4,8}\b",
    ),
    (LeakKind::Token, r"(?i)\bbearer\s+[A-Za-z0-9._~+/-]{16,}"),
    (
        LeakKind::Token,
        r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}",
    ),
    (LeakKind::PrivateKey, r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    (
        LeakKind::UpstreamCredential,
        r"\b(?:ghp|gho|ghs|ghu|ghr|github_pat)_[A-Za-z0-9_]{20,}",
    ),
    (
        LeakKind::UpstreamCredential,
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
    ),
    (LeakKind::UpstreamCredential, r"\bsk-[A-Za-z0-9_-]{20,}"),
    (
        LeakKind::UpstreamCredential,
        r"\bxox[abprs]-[A-Za-z0-9-]{10,}",
    ),
];

const CARD: &str = r"\b\d(?:[ -]?\d){12,18}\b";

struct Scanner {
    set: RegexSet,
    card: Regex,
}

static SCANNER: LazyLock<Option<Scanner>> = LazyLock::new(|| {
    let set = RegexSet::new(PATTERNS.iter().map(|(_, p)| *p)).ok()?;
    let card = Regex::new(CARD).ok()?;
    Some(Scanner { set, card })
});

/// True if the digits of `candidate` (separators ignored) pass the Luhn check.
#[must_use]
pub fn luhn(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if !(13..=19).contains(&digits.len()) {
        return false;
    }
    let mut sum = 0_u32;
    for (i, d) in digits.iter().rev().enumerate() {
        let v = if i % 2 == 1 {
            let doubled = d.saturating_mul(2);
            if doubled > 9 {
                doubled.saturating_sub(9)
            } else {
                doubled
            }
        } else {
            *d
        };
        sum = sum.saturating_add(v);
    }
    sum.is_multiple_of(10)
}

/// The sorted, de-duplicated kinds of secret-shaped data in `line`; empty if none.
#[must_use]
pub fn scan(line: &str) -> Vec<LeakKind> {
    let Some(scanner) = SCANNER.as_ref() else {
        return vec![LeakKind::ScannerUnavailable];
    };
    let mut kinds: Vec<LeakKind> = scanner
        .set
        .matches(line)
        .iter()
        .filter_map(|i| PATTERNS.get(i).map(|(k, _)| *k))
        .collect();
    if scanner.card.find_iter(line).any(|m| luhn(m.as_str())) {
        kinds.push(LeakKind::Card);
    }
    kinds.sort_unstable();
    kinds.dedup();
    kinds
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sec_6_secret_shapes_are_found() {
        let cases = [
            ("login password=hunter2", LeakKind::Password),
            ("Cookie: a=b", LeakKind::Cookie),
            ("pay 4111 1111 1111 1111 now", LeakKind::Card),
            ("your verification code is 482913", LeakKind::OneTimeCode),
            (
                "Authorization: Bearer abcdefghijklmnopqrstuv",
                LeakKind::Token,
            ),
            ("-----BEGIN PRIVATE KEY-----", LeakKind::PrivateKey),
            ("key AKIAABCDEFGHIJKLMNOP", LeakKind::UpstreamCredential),
            (
                "ghp_abcdefghijklmnopqrstuvwxyz0123",
                LeakKind::UpstreamCredential,
            ),
        ];
        for (line, kind) in cases {
            assert!(scan(line).contains(&kind), "{line}");
        }
    }

    #[test]
    fn sec_6_ordinary_telemetry_is_clean() {
        for line in [
            r#"{"event":"http.request","outcome":"ok","fields":"request_id=req_01j9 duration_ms=12 http_status=200"}"#,
            "card number field validated",
            "order 1234567890123 shipped",
        ] {
            assert!(scan(line).is_empty(), "{line}");
        }
    }

    #[test]
    fn sec_6_scanner_builds_with_the_enabled_regex_features() {
        assert!(SCANNER.is_some());
        assert_eq!(scan(""), Vec::new());
    }

    #[test]
    fn sec_6_luhn_rejects_invalid_numbers() {
        assert!(luhn("4111-1111-1111-1111"));
        assert!(!luhn("4111-1111-1111-1112"));
        assert!(!luhn("123"));
    }
}
