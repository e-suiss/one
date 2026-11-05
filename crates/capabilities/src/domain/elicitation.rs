//! Narrow elicitation (CP-30, SEC-22 (5)): in form mode One fills only the low-sensitivity profile fields in [`LOW_SENSITIVITY`] and only for a server it holds a Grant for, asks the user for every other field and never gives a password, API key, token or payment detail; URL mode always goes to the user in the platform's safe browser view with the full URL, the host highlighted and a Punycode warning, never fetched ahead and never opened without the user, and only by the person who started the request; `accept`, `decline` and `cancel` stay apart.

use one_proto::capability::is_forbidden_field_name;

/// The profile fields One may fill itself.
pub const LOW_SENSITIVITY: [&str; 3] = ["display_name", "preferred_language", "time_zone"];

/// Who fills a form field.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fill {
    /// One fills it.
    One,
    /// The user is asked.
    User,
    /// Never given, not even by asking: a secret-like field.
    Never,
}

/// Who fills form field `name` for a server One holds a Grant for when `granted`.
#[must_use]
pub fn field(name: &str, granted: bool) -> Fill {
    let lower = name.to_ascii_lowercase();
    if is_forbidden_field_name(&lower) || lower.contains("payment") || lower.contains("iban") {
        Fill::Never
    } else if granted && LOW_SENSITIVITY.contains(&lower.as_str()) {
        Fill::One
    } else {
        Fill::User
    }
}

/// How a URL-mode request is shown.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools, reason = "CP-30")]
pub struct UrlPrompt {
    /// The full URL, as shown.
    pub url: String,
    /// The host, highlighted.
    pub host: String,
    /// The host has a Punycode or non-ASCII label: warn.
    pub punycode_warning: bool,
    /// Fetched ahead: never.
    pub prefetch: bool,
    /// Opened in the safe browser view, not an in-app web view.
    pub safe_view: bool,
}

/// The prompt for `url`; `None` for anything but an `https` URL with a host.
#[must_use]
pub fn url_prompt(url: &str) -> Option<UrlPrompt> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?', '#']).next()?;
    let host = authority
        .rsplit_once('@')
        .map_or(authority, |(_, h)| h)
        .split(':')
        .next()?;
    if host.is_empty() {
        return None;
    }
    let punycode_warning = !host.is_ascii()
        || host
            .split('.')
            .any(|label| label.to_ascii_lowercase().starts_with("xn--"));
    Some(UrlPrompt {
        url: url.to_owned(),
        host: host.to_owned(),
        punycode_warning,
        prefetch: false,
        safe_view: true,
    })
}

/// Whether the person opening the URL is the one who started the request.
#[must_use]
pub fn opener_ok<T: PartialEq>(started_by: &T, opened_by: &T) -> bool {
    started_by == opened_by
}

/// The user's answer, three ways apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Answer {
    /// `accept`.
    Accept,
    /// `decline`.
    Decline,
    /// `cancel`.
    Cancel,
}

impl Answer {
    /// The wire word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Accept => "accept",
            Self::Decline => "decline",
            Self::Cancel => "cancel",
        }
    }
}
