//! Quarantine output: only typed fields (date, date-time, amount, integer, boolean, name, email, phone, URL, address, choice) and an optional display summary, never free text; code labels every field and the summary with the input's `external.*` label, and the summary is display-only (SEC-13 (1, 3, 4), T-36 (6), T-9).

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use one_proto::money::Money;
use one_proto::ontology::validate::ContractViolation;
use one_proto::ontology::{Instant, JsonValue, UiLang};
use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::text::{
    FieldName, chars_within, checked_text, decode, has_unique, is_ecma_space, is_uri_text,
    map_at_most,
};
use crate::label::{ExternalSource, Label, LabelKind, MixedSources, Source, UntrustedLabel};
use crate::value::Untrusted;

/// The most fields one output carries.
pub const MAX_FIELDS: usize = 64;

fn is_line(text: &str) -> bool {
    chars_within(text, 1, 200)
        && !text.chars().any(
            |c| matches!(c, '\u{0}'..='\u{1f}' | '\u{7f}'..='\u{9f}' | '\u{2028}' | '\u{2029}'),
        )
}

fn is_date(text: &str) -> bool {
    let b = text.as_bytes();
    let num = |from: usize, to: usize| -> Option<u32> {
        let part = b.get(from..to)?;
        part.iter()
            .all(u8::is_ascii_digit)
            .then(|| core::str::from_utf8(part).ok()?.parse().ok())?
    };
    let shape = b.len() == 10 && b.get(4) == Some(&b'-') && b.get(7) == Some(&b'-');
    match (shape, num(0, 4), num(5, 7), num(8, 10)) {
        (true, Some(year), Some(month), Some(day)) => {
            let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
            let days = match month {
                1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
                4 | 6 | 9 | 11 => 30,
                2 if leap => 29,
                2 => 28,
                _ => 0,
            };
            (1..=days).contains(&day)
        }
        _ => false,
    }
}

fn is_email(text: &str) -> bool {
    let plain =
        |part: &str| !part.is_empty() && !part.chars().any(|c| c == '@' || is_ecma_space(c));
    chars_within(text, 1, 254)
        && text
            .split_once('@')
            .is_some_and(|(local, domain)| plain(local) && plain(domain))
}

fn is_phone(text: &str) -> bool {
    text.strip_prefix('+').is_some_and(|digits| {
        (7..=15).contains(&digits.len())
            && !digits.starts_with('0')
            && digits.bytes().all(|b| b.is_ascii_digit())
    })
}

fn is_url(text: &str) -> bool {
    let rest = text
        .strip_prefix("https://")
        .or_else(|| text.strip_prefix("http://"));
    text.len() <= 2048 && is_uri_text(text) && rest.is_some_and(|r| !r.is_empty())
}

fn is_option_code(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && text.len() <= 64
        && bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

fn is_postal_code(text: &str) -> bool {
    let mut bytes = text.bytes();
    bytes.next().is_some_and(|b| b.is_ascii_alphanumeric())
        && text.len() <= 16
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b' ' || b == b'-')
}

fn is_country(text: &str) -> bool {
    text.len() == 2 && text.bytes().all(|b| b.is_ascii_uppercase())
}

fn is_summary_text(text: &str) -> bool {
    chars_within(text, 1, 2000)
}

checked_text!(
    /// A calendar date `YYYY-MM-DD`.
    masked Date,
    "date",
    is_date
);
checked_text!(
    /// One line of 1–200 characters without control or line-separator characters.
    masked Line,
    "single line",
    is_line
);
checked_text!(
    /// An email address of at most 254 characters: one `@` between two parts without spaces.
    masked Email,
    "email",
    is_email
);
checked_text!(
    /// An E.164 phone number.
    masked Phone,
    "phone number",
    is_phone
);
checked_text!(
    /// An `http` or `https` URL of at most 2048 characters.
    masked Url,
    "url",
    is_url
);
checked_text!(
    /// An option code, `^[a-z0-9][a-z0-9_]{0,63}$`.
    plain OptionCode,
    "option code",
    is_option_code
);
checked_text!(
    /// A postal code.
    masked PostalCode,
    "postal code",
    is_postal_code
);
checked_text!(
    /// An ISO 3166-1 alpha-2 country code.
    plain CountryCode,
    "country code",
    is_country
);
checked_text!(
    /// Summary text of 1–2000 characters, shown to the user and never given to a model as instructions.
    masked SummaryText,
    "summary text",
    is_summary_text
);

/// The largest integer magnitude a field carries, `2^53 - 1`.
pub const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// An integer within ±(2^53 − 1).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct SafeInteger(i64);

impl SafeInteger {
    /// Checks and wraps an integer.
    #[must_use]
    pub const fn new(value: i64) -> Option<Self> {
        if -MAX_SAFE_INTEGER <= value && value <= MAX_SAFE_INTEGER {
            Some(Self(value))
        } else {
            None
        }
    }

    /// The integer.
    #[must_use]
    pub const fn get(self) -> i64 {
        self.0
    }
}

impl<'de> Deserialize<'de> for SafeInteger {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(i64::deserialize(deserializer)?)
            .ok_or_else(|| D::Error::custom("integer outside ±(2^53 - 1)"))
    }
}

/// A postal address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Address {
    /// One to five address lines.
    #[serde(deserialize_with = "address_lines")]
    pub lines: Vec<Line>,
    /// The locality.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub locality: Option<Line>,
    /// The region.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub region: Option<Line>,
    /// The postal code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub postal_code: Option<PostalCode>,
    /// The country.
    pub country: CountryCode,
}

fn address_lines<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Line>, D::Error> {
    let lines = Vec::<Line>::deserialize(deserializer)?;
    if (1..=5).contains(&lines.len()) {
        Ok(lines)
    } else {
        Err(D::Error::custom("one to five address lines"))
    }
}

/// The kind of a typed field (`typed_field` `kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FieldKind {
    /// A date.
    Date,
    /// A UTC date-time.
    DateTime,
    /// An amount of money.
    Amount,
    /// An integer.
    Integer,
    /// A boolean.
    Boolean,
    /// A person or organisation name.
    Name,
    /// An email address.
    Email,
    /// A phone number.
    Phone,
    /// A URL.
    Url,
    /// A postal address.
    Address,
    /// One option code.
    Choice,
    /// A set of option codes.
    ChoiceList,
}

/// One typed value the quarantine model extracted; there is no free-text kind (SEC-13 (1)).
#[derive(Clone, PartialEq, Eq)]
pub enum TypedField {
    /// A date.
    Date(Date),
    /// A UTC date-time.
    DateTime(Instant),
    /// An amount of money.
    Amount(Money),
    /// An integer.
    Integer(SafeInteger),
    /// A boolean.
    Boolean(bool),
    /// A name.
    Name(Line),
    /// An email address.
    Email(Email),
    /// A phone number.
    Phone(Phone),
    /// A URL.
    Url(Url),
    /// A postal address.
    Address(Address),
    /// One option code.
    Choice(OptionCode),
    /// Up to 64 distinct option codes.
    ChoiceList(Vec<OptionCode>),
}

impl TypedField {
    /// The kind.
    #[must_use]
    pub const fn kind(&self) -> FieldKind {
        match self {
            Self::Date(_) => FieldKind::Date,
            Self::DateTime(_) => FieldKind::DateTime,
            Self::Amount(_) => FieldKind::Amount,
            Self::Integer(_) => FieldKind::Integer,
            Self::Boolean(_) => FieldKind::Boolean,
            Self::Name(_) => FieldKind::Name,
            Self::Email(_) => FieldKind::Email,
            Self::Phone(_) => FieldKind::Phone,
            Self::Url(_) => FieldKind::Url,
            Self::Address(_) => FieldKind::Address,
            Self::Choice(_) => FieldKind::Choice,
            Self::ChoiceList(_) => FieldKind::ChoiceList,
        }
    }

    /// Reads the value of a kind.
    ///
    /// # Errors
    /// Rejects a value that is not of the kind's type.
    pub fn from_parts(kind: FieldKind, value: JsonValue) -> Result<Self, serde::de::value::Error> {
        Ok(match kind {
            FieldKind::Date => Self::Date(decode(value)?),
            FieldKind::DateTime => Self::DateTime(decode(value)?),
            FieldKind::Amount => Self::Amount(decode(value)?),
            FieldKind::Integer => Self::Integer(decode(value)?),
            FieldKind::Boolean => Self::Boolean(decode(value)?),
            FieldKind::Name => Self::Name(decode(value)?),
            FieldKind::Email => Self::Email(decode(value)?),
            FieldKind::Phone => Self::Phone(decode(value)?),
            FieldKind::Url => Self::Url(decode(value)?),
            FieldKind::Address => Self::Address(decode(value)?),
            FieldKind::Choice => Self::Choice(decode(value)?),
            FieldKind::ChoiceList => {
                let codes: Vec<OptionCode> = decode(value)?;
                if codes.len() > MAX_FIELDS || !has_unique(&codes) {
                    return Err(serde::de::value::Error::custom(
                        "up to 64 distinct option codes",
                    ));
                }
                Self::ChoiceList(codes)
            }
        })
    }

    fn serialize_value<S: SerializeStruct>(&self, s: &mut S) -> Result<(), S::Error> {
        match self {
            Self::Date(v) => s.serialize_field("value", v),
            Self::DateTime(v) => s.serialize_field("value", v),
            Self::Amount(v) => s.serialize_field("value", v),
            Self::Integer(v) => s.serialize_field("value", v),
            Self::Boolean(v) => s.serialize_field("value", v),
            Self::Name(v) => s.serialize_field("value", v),
            Self::Email(v) => s.serialize_field("value", v),
            Self::Phone(v) => s.serialize_field("value", v),
            Self::Url(v) => s.serialize_field("value", v),
            Self::Address(v) => s.serialize_field("value", v),
            Self::Choice(v) => s.serialize_field("value", v),
            Self::ChoiceList(v) => s.serialize_field("value", v),
        }
    }
}

impl fmt::Debug for TypedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TypedField")
            .field("kind", &self.kind())
            .finish_non_exhaustive()
    }
}

impl Serialize for TypedField {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut s = serializer.serialize_struct("TypedField", 2)?;
        s.serialize_field("kind", &self.kind())?;
        self.serialize_value(&mut s)?;
        s.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireField {
    kind: FieldKind,
    value: JsonValue,
}

impl<'de> Deserialize<'de> for TypedField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireField::deserialize(deserializer)?;
        Self::from_parts(wire.kind, wire.value).map_err(D::Error::custom)
    }
}

/// An `external.*` label; `external.mixed` carries its two or more sources, and quarantine output never carries any other label (SEC-13 (3), labelled-value/v1).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExternalLabel(UntrustedLabel);

impl ExternalLabel {
    /// The label of one external source.
    #[must_use]
    pub const fn source(source: ExternalSource) -> Self {
        Self(UntrustedLabel::External(source))
    }

    /// `external.mixed` with its sources.
    #[must_use]
    pub const fn mixed(sources: MixedSources) -> Self {
        Self(UntrustedLabel::Mixed(sources))
    }

    /// Checks an untrusted label; `None` for `one.inferred`.
    #[must_use]
    pub fn new(label: UntrustedLabel) -> Option<Self> {
        match label {
            UntrustedLabel::OneInferred => None,
            external => Some(Self(external)),
        }
    }

    /// The label string.
    #[must_use]
    pub const fn kind(&self) -> LabelKind {
        self.0.kind()
    }

    /// The internal label.
    #[must_use]
    pub const fn untrusted(&self) -> &UntrustedLabel {
        &self.0
    }

    /// Unwraps the internal label.
    #[must_use]
    pub fn into_untrusted(self) -> UntrustedLabel {
        self.0
    }
}

/// The `sources` list sent beside a label; present exactly for `external.mixed`.
pub(super) type WireSources = Option<Vec<Source>>;

/// The wire pair of an untrusted label: its string and, for `external.mixed` only, its sources.
pub(super) fn untrusted_to_wire(label: &UntrustedLabel) -> (LabelKind, WireSources) {
    let sources = match label {
        UntrustedLabel::Mixed(mixed) => Some(
            mixed
                .as_slice()
                .iter()
                .copied()
                .map(Source::External)
                .collect(),
        ),
        UntrustedLabel::OneInferred | UntrustedLabel::External(_) => None,
    };
    (label.kind(), sources)
}

/// Reads an untrusted label from its wire pair; `None` for a trusted label, a bare `external.mixed`, `sources` beside any other label, or sources that are not two or more distinct `external.*` labels.
pub(super) fn untrusted_from_wire(
    kind: LabelKind,
    sources: Option<&[Source]>,
) -> Option<UntrustedLabel> {
    if sources.is_some() != (kind == LabelKind::Mixed) {
        return None;
    }
    match Label::from_wire(kind, sources)? {
        Label::Untrusted(label) => Some(label),
        Label::Trusted(_) => None,
    }
}

/// Reads an `external.*` label from its wire pair, under the rules of [`untrusted_from_wire`].
pub(super) fn external_from_wire(
    kind: LabelKind,
    sources: Option<&[Source]>,
) -> Result<ExternalLabel, ContractViolation> {
    untrusted_from_wire(kind, sources)
        .and_then(ExternalLabel::new)
        .ok_or(ContractViolation("external label with its sources"))
}

/// Deserializes a present `sources` list; `null` is not a list.
pub(super) fn present_sources<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<WireSources, D::Error> {
    Vec::<Source>::deserialize(deserializer).map(Some)
}

/// The display summary the quarantine model may write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelSummary {
    /// The text.
    pub text: SummaryText,
    /// Its language.
    pub lang: UiLang,
}

/// What the quarantine model returns (`quarantine-model-output/v1`); it carries no label, code attaches one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineModelOutput {
    /// The typed fields by name.
    #[serde(deserialize_with = "map_at_most::<_, _, _, MAX_FIELDS>")]
    pub fields: BTreeMap<FieldName, TypedField>,
    /// The optional display summary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display_summary: Option<ModelSummary>,
}

impl QuarantineModelOutput {
    /// Labels every field and the summary with the input's label; extraction never clears it (SEC-13 (3), SEC-14 (1)).
    #[must_use]
    pub fn label(self, label: ExternalLabel) -> QuarantineOutput {
        QuarantineOutput {
            fields: self
                .fields
                .into_iter()
                .map(|(name, field)| {
                    let label = label.clone();
                    (name, LabelledField { field, label })
                })
                .collect(),
            display_summary: self.display_summary.map(|s| DisplaySummary {
                text: s.text,
                lang: s.lang,
                label: label.clone(),
                display_only: DisplayOnly,
            }),
            label,
        }
    }
}

/// A typed field with its `external.*` label.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LabelledField {
    /// The field.
    pub field: TypedField,
    /// Its label.
    pub label: ExternalLabel,
}

impl LabelledField {
    /// The field as an untrusted value, for binding to a planner variable (T-36 (2)).
    #[must_use]
    pub fn into_untrusted(self) -> Untrusted<TypedField> {
        Untrusted::with_label(self.field, self.label.into_untrusted())
    }
}

impl Serialize for LabelledField {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let (kind, sources) = untrusted_to_wire(self.label.untrusted());
        let mut s = serializer.serialize_struct("LabelledField", 4)?;
        s.serialize_field("kind", &self.field.kind())?;
        self.field.serialize_value(&mut s)?;
        s.serialize_field("label", &kind)?;
        if let Some(sources) = &sources {
            s.serialize_field("sources", sources)?;
        }
        s.end()
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLabelledField {
    kind: FieldKind,
    value: JsonValue,
    label: LabelKind,
    #[serde(default, deserialize_with = "present_sources")]
    sources: WireSources,
}

impl<'de> Deserialize<'de> for LabelledField {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = WireLabelledField::deserialize(deserializer)?;
        Ok(Self {
            field: TypedField::from_parts(wire.kind, wire.value).map_err(D::Error::custom)?,
            label: external_from_wire(wire.label, wire.sources.as_deref())
                .map_err(D::Error::custom)?,
        })
    }
}

/// The marker that a summary is for display only.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct DisplayOnly;

impl Serialize for DisplayOnly {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bool(true)
    }
}

impl<'de> Deserialize<'de> for DisplayOnly {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        if bool::deserialize(deserializer)? {
            Ok(Self)
        } else {
            Err(D::Error::custom("display_only must be true"))
        }
    }
}

/// The labelled display summary; shown to the user, never given to the planner (SEC-13 (1), T-36 (6)).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireDisplaySummary", into = "WireDisplaySummary")]
pub struct DisplaySummary {
    /// The text.
    pub text: SummaryText,
    /// Its language.
    pub lang: UiLang,
    /// The input's label.
    pub label: ExternalLabel,
    /// Always true.
    pub display_only: DisplayOnly,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDisplaySummary {
    text: SummaryText,
    lang: UiLang,
    label: LabelKind,
    #[serde(
        default,
        deserialize_with = "present_sources",
        skip_serializing_if = "Option::is_none"
    )]
    sources: WireSources,
    display_only: DisplayOnly,
}

impl TryFrom<WireDisplaySummary> for DisplaySummary {
    type Error = ContractViolation;

    fn try_from(wire: WireDisplaySummary) -> Result<Self, Self::Error> {
        Ok(Self {
            text: wire.text,
            lang: wire.lang,
            label: external_from_wire(wire.label, wire.sources.as_deref())?,
            display_only: wire.display_only,
        })
    }
}

impl From<DisplaySummary> for WireDisplaySummary {
    fn from(summary: DisplaySummary) -> Self {
        let (label, sources) = untrusted_to_wire(summary.label.untrusted());
        Self {
            text: summary.text,
            lang: summary.lang,
            label,
            sources,
            display_only: summary.display_only,
        }
    }
}

/// The labelled quarantine output (`quarantine-output/v1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "WireOutput", into = "WireOutput")]
pub struct QuarantineOutput {
    /// The input's label.
    pub label: ExternalLabel,
    /// The labelled fields by name.
    pub fields: BTreeMap<FieldName, LabelledField>,
    /// The optional display summary.
    pub display_summary: Option<DisplaySummary>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOutput {
    label: LabelKind,
    #[serde(
        default,
        deserialize_with = "present_sources",
        skip_serializing_if = "Option::is_none"
    )]
    sources: WireSources,
    #[serde(deserialize_with = "map_at_most::<_, _, _, MAX_FIELDS>")]
    fields: BTreeMap<FieldName, LabelledField>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    display_summary: Option<DisplaySummary>,
}

impl TryFrom<WireOutput> for QuarantineOutput {
    type Error = ContractViolation;

    fn try_from(wire: WireOutput) -> Result<Self, Self::Error> {
        Ok(Self {
            label: external_from_wire(wire.label, wire.sources.as_deref())?,
            fields: wire.fields,
            display_summary: wire.display_summary,
        })
    }
}

impl From<QuarantineOutput> for WireOutput {
    fn from(output: QuarantineOutput) -> Self {
        let (label, sources) = untrusted_to_wire(output.label.untrusted());
        Self {
            label,
            sources,
            fields: output.fields,
            display_summary: output.display_summary,
        }
    }
}

impl QuarantineOutput {
    /// The fields as untrusted values by name; the summary is left out, it is for display only.
    #[must_use]
    pub fn into_untrusted(self) -> BTreeMap<FieldName, Untrusted<TypedField>> {
        self.fields
            .into_iter()
            .map(|(name, field)| (name, field.into_untrusted()))
            .collect()
    }
}
