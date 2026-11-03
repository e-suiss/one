//! The training-data filter of the personal adapter (MF-33, MF-32, MF-36, MF-37, T-35 (2), `conformance/memory/training-filter-v1.toml`): only an active behaviour rule the user stated, or one verified with a recorded user confirmation, of an adult profile, outside every sensitive class, about nobody but the user and with no usage restriction becomes an example; e-mail addresses, links (with or without a scheme) and long numbers in any script are masked, and a text that still holds a digit of any script or a likely proper name is dropped as suspicious.

use one_proto::id::MemoryRecordId;
use one_proto::memory::fields::{EpistemicState, Layer, LiveStatus, SourceKind};
use one_proto::memory::record::LiveMemoryRecord;
use one_proto::ontology::reference::EntityRef;

/// The mask of an e-mail address.
pub const EMAIL: &str = "⟨email⟩";

/// The mask of a link.
pub const URL: &str = "⟨url⟩";

/// The mask of a phone number or any run of four or more digits.
pub const NUMBER: &str = "⟨number⟩";

/// The fewest digits a run needs to be masked as a number.
pub const NUMBER_MIN_DIGITS: usize = 4;

const URL_PREFIXES: [&str; 3] = ["http://", "https://", "www."];

/// The shortest top-level label a bare domain needs to be masked as a link.
const TLD_MIN: usize = 2;

/// The profile whose memory is filtered (MF-37).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Profile {
    /// An adult profile.
    Adult,
    /// A child profile: no personal adapter, nothing is learned.
    Child,
}

/// Why a record does not become a training example; the checks run in this order and the first failing one is returned.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, thiserror::Error)]
pub enum Excluded {
    /// A child profile (MF-37).
    #[error("a child profile is never learned")]
    ChildProfile,
    /// A candidate or set-aside record.
    #[error("only an active record is learned")]
    NotActive,
    /// An imported record (MF-36).
    #[error("an imported record never trains")]
    Imported,
    /// External content.
    #[error("external content never trains")]
    External,
    /// Neither stated by the user nor verified with a recorded user confirmation.
    #[error("only what the user said or confirmed is learned")]
    Unconfirmed,
    /// An event or a consolidated fact (MF-32).
    #[error("facts are never learned")]
    Fact,
    /// A sensitive data class.
    #[error("a sensitive record is never learned")]
    Sensitive,
    /// About someone other than the user.
    #[error("a record about another person is never learned")]
    ThirdParty,
    /// Restricted to some areas or projects.
    #[error("a restricted record is never learned")]
    Restricted,
    /// The masked text still holds a digit or a likely proper name.
    #[error("a suspicious example is dropped")]
    Suspicious,
}

impl Excluded {
    /// The checks in the order they run.
    pub const ORDER: [Self; 10] = [
        Self::ChildProfile,
        Self::NotActive,
        Self::Imported,
        Self::External,
        Self::Unconfirmed,
        Self::Fact,
        Self::Sensitive,
        Self::ThirdParty,
        Self::Restricted,
        Self::Suspicious,
    ];

    /// The contract name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::ChildProfile => "child_profile",
            Self::NotActive => "not_active",
            Self::Imported => "imported",
            Self::External => "external",
            Self::Unconfirmed => "unconfirmed",
            Self::Fact => "fact",
            Self::Sensitive => "sensitive",
            Self::ThirdParty => "third_party",
            Self::Restricted => "restricted",
            Self::Suspicious => "suspicious",
        }
    }
}

/// A masked training example; it can only come from [`example`], so a fact, a sensitive, external or imported record never becomes one (T-35 (2)).
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TrainingExample {
    record: MemoryRecordId,
    text: String,
}

impl TrainingExample {
    /// The masked text.
    #[must_use]
    pub fn text(&self) -> &str {
        &self.text
    }

    /// The record it comes from.
    #[must_use]
    pub const fn record(&self) -> MemoryRecordId {
        self.record
    }
}

impl core::fmt::Debug for TrainingExample {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TrainingExample")
            .field("record", &self.record)
            .finish_non_exhaustive()
    }
}

/// The first eligibility check `record` of `profile` fails, before masking.
///
/// # Errors
/// The first failing [`Excluded`] reason other than [`Excluded::Suspicious`].
pub fn eligible(record: &LiveMemoryRecord, profile: Profile) -> Result<(), Excluded> {
    if profile == Profile::Child {
        return Err(Excluded::ChildProfile);
    }
    if record.status != LiveStatus::Active {
        return Err(Excluded::NotActive);
    }
    match record.source_kind {
        SourceKind::Import => return Err(Excluded::Imported),
        SourceKind::ExternalContent => return Err(Excluded::External),
        SourceKind::UserStatement | SourceKind::UserBehaviour | SourceKind::ConnectedSource => {}
    }
    let confirmed = match record.epistemic_state {
        EpistemicState::Stated => true,
        EpistemicState::Verified => record.evidence.user_confirmed_at.is_some(),
        _ => false,
    };
    if !confirmed {
        return Err(Excluded::Unconfirmed);
    }
    if record.layer != Layer::BehaviourRule {
        return Err(Excluded::Fact);
    }
    if record.header.data_class.is_sensitive() {
        return Err(Excluded::Sensitive);
    }
    let owner = &record.header.owner;
    let only_self = record
        .about
        .iter()
        .flatten()
        .all(|r| matches!(r, EntityRef::Party(p) if p == owner));
    if !only_self {
        return Err(Excluded::ThirdParty);
    }
    if record.usage_restriction.is_some() {
        return Err(Excluded::Restricted);
    }
    Ok(())
}

/// The training example `record` of `profile` becomes: eligible, masked and not suspicious.
///
/// # Errors
/// The first failing [`Excluded`] reason.
pub fn example(record: &LiveMemoryRecord, profile: Profile) -> Result<TrainingExample, Excluded> {
    eligible(record, profile)?;
    let text = mask(&record.statement.text);
    if suspicious(&text) {
        return Err(Excluded::Suspicious);
    }
    Ok(TrainingExample {
        record: record.id,
        text,
    })
}

/// `text` with e-mail addresses, links and runs of four or more digits masked.
#[must_use]
pub fn mask(text: &str) -> String {
    mask_numbers(&mask_chunks(text))
}

fn is_lead(c: char) -> bool {
    matches!(c, '"' | '\'' | '(' | '[' | '{' | '<' | '«' | '“' | '‘')
}

fn is_trail(c: char) -> bool {
    matches!(
        c,
        '.' | ',' | ';' | ':' | '!' | '?' | '"' | '\'' | ')' | ']' | '}' | '>' | '»' | '”' | '’'
    )
}

fn is_closer(c: char) -> bool {
    matches!(c, '"' | '\'' | ')' | ']' | '}' | '>' | '»' | '”' | '’')
}

fn is_url(core: &str) -> bool {
    core.contains("://")
        || URL_PREFIXES.iter().any(|p| {
            core.len() > p.len()
                && core
                    .as_bytes()
                    .get(..p.len())
                    .is_some_and(|b| b.eq_ignore_ascii_case(p.as_bytes()))
        })
        || is_bare_domain(core)
}

/// `name.tld`, `a.b.tld` or either followed by a port or a path: dot-separated labels of letters, digits and hyphens whose last label is two or more ASCII letters.
fn is_bare_domain(core: &str) -> bool {
    if core.contains('@') {
        return false;
    }
    let host = core.split(['/', '?', '#']).next().unwrap_or_default();
    let host = host.split_once(':').map_or(host, |(h, _)| h);
    let labels: Vec<&str> = host.split('.').collect();
    labels.len() >= 2
        && labels
            .iter()
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_alphanumeric() || c == '-'))
        && labels
            .last()
            .is_some_and(|tld| tld.len() >= TLD_MIN && tld.chars().all(|c| c.is_ascii_alphabetic()))
}

fn is_email(core: &str) -> bool {
    core.split_once('@').is_some_and(|(local, domain)| {
        !local.is_empty()
            && !domain.contains('@')
            && domain.contains('.')
            && domain.split('.').all(|part| !part.is_empty())
    })
}

fn mask_chunk(chunk: &str, out: &mut String) {
    let rest = chunk.trim_start_matches(is_lead);
    let core = rest.trim_end_matches(is_trail);
    let lead = chunk.strip_suffix(rest).unwrap_or_default();
    let trail = rest.strip_prefix(core).unwrap_or_default();
    let masked = if is_url(core) {
        Some(URL)
    } else if is_email(core) {
        Some(EMAIL)
    } else {
        None
    };
    if let Some(m) = masked {
        out.push_str(lead);
        out.push_str(m);
        out.push_str(trail);
    } else {
        out.push_str(chunk);
    }
}

fn mask_chunks(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chunk = String::new();
    for c in text.chars() {
        if c.is_whitespace() {
            mask_chunk(&chunk, &mut out);
            chunk.clear();
            out.push(c);
        } else {
            chunk.push(c);
        }
    }
    mask_chunk(&chunk, &mut out);
    out
}

fn is_separator(c: char) -> bool {
    matches!(c, ' ' | '-' | '.' | '/')
}

fn mask_numbers(text: &str) -> String {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;
    while let Some(&c) = chars.get(i) {
        if !c.is_numeric() {
            out.push(c);
            i = i.saturating_add(1);
            continue;
        }
        let start = i;
        let mut end = i;
        let mut digits = 0usize;
        let mut j = i;
        while let Some(&d) = chars.get(j) {
            if d.is_numeric() {
                digits = digits.saturating_add(1);
                j = j.saturating_add(1);
                end = j;
            } else if is_separator(d) {
                let mut k = j;
                while chars.get(k).copied().is_some_and(is_separator) {
                    k = k.saturating_add(1);
                }
                if chars.get(k).is_some_and(|n| n.is_numeric()) {
                    j = k;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        if digits >= NUMBER_MIN_DIGITS {
            if out.ends_with('+') {
                out.pop();
            }
            out.push_str(NUMBER);
        } else {
            out.extend(chars.get(start..end).into_iter().flatten());
        }
        i = end;
    }
    out
}

/// A masked `text` that still holds a digit of any script, or a word not at the start of a sentence that begins with a capital letter other than the pronoun "I".
#[must_use]
pub fn suspicious(text: &str) -> bool {
    if text.chars().any(char::is_numeric) {
        return true;
    }
    let mut initial = true;
    for chunk in text.split_whitespace() {
        let word = chunk.trim_start_matches(|c: char| !c.is_alphanumeric());
        let mut letters = word.chars();
        if let Some(first) = letters.next() {
            let pronoun = first == 'I' && letters.next().is_none_or(|c| !c.is_alphanumeric());
            if !initial && first.is_uppercase() && !pronoun {
                return true;
            }
        }
        initial = chunk
            .trim_end_matches(is_closer)
            .ends_with(['.', '!', '?', ':']);
    }
    false
}
