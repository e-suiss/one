//! Shared Interaction value types: core kinds, Mandate fit, localized text and the checked string forms of the common schema (X-3, X-12, C-25).

use alloc::string::String;
use core::fmt;

use one_proto::ontology::Instant;
use serde::{Deserialize, Serialize};

/// A value that does not match its schema pattern or range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Invalid(pub &'static str);

impl fmt::Display for Invalid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("invalid ")?;
        f.write_str(self.0)
    }
}

macro_rules! checked_string {
    ($(#[$meta:meta])* $name:ident, $what:literal, $check:path) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Checks and wraps a value.
            ///
            /// # Errors
            /// Rejects a value outside the schema pattern.
            pub fn new(value: String) -> Result<Self, Invalid> {
                if $check(&value) { Ok(Self(value)) } else { Err(Invalid($what)) }
            }

            /// The wire text.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = Invalid;
            fn try_from(value: String) -> Result<Self, Invalid> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> String {
                value.0
            }
        }
    };
}

/// A one-line text: non-empty, without CR, LF or TAB.
#[must_use]
pub fn is_line(text: &str) -> bool {
    !text.is_empty() && !text.contains(['\r', '\n', '\t'])
}

/// The length of a text in Unicode code points, the budget text unit (X-13).
#[must_use]
pub fn chars(text: &str) -> usize {
    text.chars().count()
}

/// A one-line text of at most `max` code points.
#[must_use]
pub fn is_line_within(text: &str, max: usize) -> bool {
    is_line(text) && chars(text) <= max
}

fn is_nonce(text: &str) -> bool {
    (22..=86).contains(&text.len())
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

fn is_action_id(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && text.len() <= 32
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_lower_segment(segment: &str, underscore: bool) -> bool {
    let mut bytes = segment.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_lowercase())
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || (underscore && b == b'_'))
}

fn is_extension_name(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("app.suiss.") else {
        return false;
    };
    let mut segments = rest.split('.');
    let first = segments.next().unwrap_or_default();
    let mut tail = 0_usize;
    let tail_ok = segments.all(|s| {
        tail = tail.saturating_add(1);
        is_lower_segment(s, true)
    });
    text.len() <= 128 && first != "one" && is_lower_segment(first, false) && tail_ok && tail >= 1
}

fn digits(text: &str) -> bool {
    !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit())
}

/// Splits `n<unit>` designators off a duration part in the given unit order.
fn designators(mut text: &str, units: &[char]) -> Option<usize> {
    let mut found = 0_usize;
    for unit in units {
        if let Some(at) = text.find(*unit) {
            let (number, rest) = text.split_at(at);
            if !digits(number) {
                return None;
            }
            text = rest.get(1..)?;
            found = found.saturating_add(1);
        }
    }
    text.is_empty().then_some(found)
}

fn is_duration(text: &str) -> bool {
    let Some(body) = text.strip_prefix('P') else {
        return false;
    };
    let (date, time) = match body.split_once('T') {
        Some((d, t)) => (d, Some(t)),
        None => (body, None),
    };
    let date_ok = match designators(date, &['D']) {
        Some(n) => date.is_empty() || n == 1,
        None => false,
    };
    let time_ok = time.is_none_or(|t| designators(t, &['H', 'M', 'S']).is_some_and(|n| n >= 1));
    date_ok && time_ok && (!date.is_empty() || time.is_some())
}

checked_string!(
    /// An ISO 8601 duration in days, hours, minutes and seconds (common `duration`).
    Duration,
    "duration",
    is_duration
);

checked_string!(
    /// The single-use answer nonce: 22 to 86 base64url characters (X-22).
    Nonce,
    "nonce",
    is_nonce
);

checked_string!(
    /// An action, option or field identifier local to one Interaction.
    ActionId,
    "action id",
    is_action_id
);

checked_string!(
    /// A reverse-DNS extension kind name under `app.suiss`, outside `app.suiss.one` (C-7).
    ExtensionName,
    "extension name",
    is_extension_name
);

/// An RFC 3339 UTC time with at most six fraction digits (common `timestamp`), a narrower form of the C-19 [`Instant`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "Instant", into = "Instant")]
pub struct Timestamp(Instant);

impl Timestamp {
    /// Checks the fraction width of an instant.
    ///
    /// # Errors
    /// Rejects more than six fraction digits.
    pub const fn new(instant: Instant) -> Result<Self, Invalid> {
        if instant.fraction_digits() <= 6 {
            Ok(Self(instant))
        } else {
            Err(Invalid("timestamp"))
        }
    }

    /// Parses the wire text.
    ///
    /// # Errors
    /// Rejects anything but an RFC 3339 UTC time with at most six fraction digits.
    pub fn parse(text: &str) -> Result<Self, Invalid> {
        Self::new(Instant::parse(text).map_err(|_| Invalid("timestamp"))?)
    }

    /// The instant.
    #[must_use]
    pub const fn instant(self) -> Instant {
        self.0
    }
}

impl TryFrom<Instant> for Timestamp {
    type Error = Invalid;
    fn try_from(instant: Instant) -> Result<Self, Invalid> {
        Self::new(instant)
    }
}

impl From<Timestamp> for Instant {
    fn from(value: Timestamp) -> Self {
        value.0
    }
}

/// A display locale; every user-facing text exists in both (X-52).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Locale {
    /// Turkish.
    Tr,
    /// English.
    En,
}

impl Locale {
    /// Both locales.
    pub const ALL: [Self; 2] = [Self::Tr, Self::En];
}

/// TR and EN text, both required.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Localized {
    /// Turkish text.
    pub tr: String,
    /// English text.
    pub en: String,
}

impl Localized {
    /// The text in a locale.
    #[must_use]
    pub fn get(&self, locale: Locale) -> &str {
        match locale {
            Locale::Tr => &self.tr,
            Locale::En => &self.en,
        }
    }

    /// True if both texts are single lines of at most `max` code points.
    #[must_use]
    pub fn lines_within(&self, max: usize) -> bool {
        is_line_within(&self.tr, max) && is_line_within(&self.en, max)
    }

    /// The longer of the two texts in code points.
    #[must_use]
    pub fn max_chars(&self) -> usize {
        chars(&self.tr).max(chars(&self.en))
    }
}

/// The closed core kind list (X-12).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreKind {
    /// Approval of an action an Access request allows.
    Approval,
    /// A pick among typed options.
    Choice,
    /// A question while a task waits.
    Question,
    /// Information with no decision.
    Info,
    /// Ongoing work updated in place.
    Progress,
    /// The result of finished work.
    Receipt,
    /// Two to four options side by side.
    Comparison,
    /// Typed fields to fill.
    Form,
    /// One entry of the daily digest.
    DigestItem,
}

impl CoreKind {
    /// Every core kind in contract order.
    pub const ALL: [Self; 9] = [
        Self::Approval,
        Self::Choice,
        Self::Question,
        Self::Info,
        Self::Progress,
        Self::Receipt,
        Self::Comparison,
        Self::Form,
        Self::DigestItem,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Approval => "approval",
            Self::Choice => "choice",
            Self::Question => "question",
            Self::Info => "info",
            Self::Progress => "progress",
            Self::Receipt => "receipt",
            Self::Comparison => "comparison",
            Self::Form => "form",
            Self::DigestItem => "digest_item",
        }
    }
}

/// Fit of the action with the Mandate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MandateFit {
    /// Within the Mandate and budget.
    Within,
    /// Exceeds the Mandate or budget.
    Exceeds,
    /// Non-delegable (Access E45).
    NonDelegable,
}

/// The common deep link grammar: `https://suiss.app/one/i/<InteractionId>` with an optional `?v=<version>`.
fn is_deep_link(text: &str) -> bool {
    let Some(rest) = text.strip_prefix("https://suiss.app/one/i/") else {
        return false;
    };
    let (id, version) = match rest.split_once("?v=") {
        Some((i, v)) => (i, Some(v)),
        None => (rest, None),
    };
    let version_ok = version.is_none_or(|v| digits(v) && !v.starts_with('0'));
    version_ok && one_proto::InteractionId::parse(id).is_ok()
}

checked_string!(
    /// Deep link to an Interaction version (X-11).
    DeepLink,
    "deep link",
    is_deep_link
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_25_durations_and_times_follow_the_common_patterns() {
        for ok in ["PT30M", "PT5M", "P1D", "P1DT2H", "PT1H30S", "PT10S"] {
            assert!(is_duration(ok), "{ok}");
        }
        for bad in ["P", "PT", "P1DT", "30M", "PT1S1M", "P1W", "PT-1M"] {
            assert!(!is_duration(bad), "{bad}");
        }
        let a = Timestamp::parse("2026-10-16T09:30:00Z").unwrap();
        let b = Timestamp::parse("2026-10-16T09:30:00.5Z").unwrap();
        assert!(b > a);
        assert!(a <= b);
        assert!(Timestamp::parse("2026-10-16T09:30:00+03:00").is_err());
        assert!(Timestamp::parse("2026-10-16T09:30:00.1234567Z").is_err());
        assert!(Instant::parse("2026-10-16T09:30:00.123456789Z").is_ok());
    }

    #[test]
    fn x_12_extension_names_stay_under_app_suiss_outside_one() {
        assert!(is_extension_name("app.suiss.commerce.order_tracking"));
        assert!(!is_extension_name("app.suiss.commerce"));
        assert!(!is_extension_name("app.suiss.one.thing"));
        assert!(!is_extension_name("com.example.tracking.order"));
    }
}
