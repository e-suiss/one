//! The typed A2A message of One↔One: the envelope with every mandatory field, one typed body, and at most one free-text note that is a separate untrusted type with no path into a field value, operation or the planner (OO-4, OO-15, OO-16, OO-17).

use alloc::string::String;
use core::convert::Infallible;
use core::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::ser::SerializeSeq;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::wire::{
    A2aId, AuthorityRef, DeclineReason, Digest, Extensions, HandleCompact, Kind, LangTag, Party,
    Refusal, SchemaVersion, Uuid7,
};
use crate::capability::CapabilityRef;
use crate::ontology::Instant;
use crate::ontology::JsonObject;
use crate::ontology::validate::ContractViolation;
use crate::ontology::validate::checked_string;
use crate::ontology::validate::require;
use crate::ontology::validate::unique;

/// The message an envelope answers, with the echoed handle (OO-5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct InReplyTo {
    /// The answered message.
    pub message_id: Uuid7,
    /// Its offer version.
    pub offer_version: u32,
    /// Its digest.
    pub digest: Digest,
    /// The handle it carried, unchanged.
    pub handle: HandleCompact,
}

/// Why the sender opens first contact (OO-31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Initiation {
    /// The person asked.
    UserRequest,
    /// Inside the person's mandate, organisation agents only.
    Mandate,
}

/// The kind of party the recipient is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PartyKind {
    /// A person.
    Person,
    /// An organisation.
    Organization,
}

/// First-contact fields; the relationship level is never carried (OO-11, OO-31).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Contact {
    /// No relationship exists yet.
    pub first_contact: bool,
    /// Why first contact is opened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub initiation: Option<Initiation>,
    /// The recipient's party kind.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recipient_party_kind: Option<PartyKind>,
}

impl Contact {
    /// Checks the first-contact rules.
    ///
    /// # Errors
    /// Rejects missing or stray first-contact fields and a mandate towards a person.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        let present = (
            self.initiation.is_some(),
            self.recipient_party_kind.is_some(),
        );
        require(
            present == (self.first_contact, self.first_contact),
            "first-contact fields exactly on first contact",
        )?;
        require(
            self.initiation != Some(Initiation::Mandate)
                || self.recipient_party_kind == Some(PartyKind::Organization),
            "mandate only towards an organisation",
        )
    }
}

/// The extension object in `Message.metadata` (OO-16).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Envelope {
    /// The extension schema version.
    pub schema_version: SchemaVersion,
    /// The kind.
    pub kind: Kind,
    /// The sending person and agent.
    pub sender: Party,
    /// The receiving person and agent.
    pub recipient: Party,
    /// The authority proof reference.
    pub authority: AuthorityRef,
    /// The Work correlation identifier, equal to `contextId`.
    pub correlation_id: Uuid7,
    /// The offer version.
    pub offer_version: u32,
    /// The sender's claim of the send time; informational.
    pub sent_at: Instant,
    /// The last instant the message can be answered.
    pub expires_at: Instant,
    /// The answered message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_reply_to: Option<InReplyTo>,
    /// The handle the sender issues for the reply it awaits.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<HandleCompact>,
    /// First-contact fields.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contact: Option<Contact>,
}

impl Envelope {
    /// Checks the per-kind rules of the envelope: versions, reply reference and handle.
    ///
    /// # Errors
    /// Rejects an envelope that breaks a rule of `envelope.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        if let Some(contact) = &self.contact {
            contact.validate()?;
        }
        let reply = self.in_reply_to.is_some();
        let handle = self.handle.is_some();
        match self.kind {
            Kind::Offer => {
                require(self.offer_version == 1, "offer version 1")?;
                require(
                    handle && !reply,
                    "offer carries a handle and no reply reference",
                )
            }
            Kind::CounterOffer => {
                require(self.offer_version >= 2, "counter-offer version at least 2")?;
                require(
                    handle && reply,
                    "counter-offer carries a handle and a reply reference",
                )
            }
            Kind::Commitment | Kind::Rejection => {
                require(self.offer_version >= 1, "reply version at least 1")?;
                require(
                    reply && !handle,
                    "reply carries a reply reference and no handle",
                )
            }
            Kind::Query => require(handle, "query carries a handle"),
            Kind::Answer => require(
                reply && !handle,
                "answer carries a reply reference and no handle",
            ),
        }
    }
}

checked_string!(
    /// A verifiable credential type.
    Vct,
    "vct",
    |s| !s.is_empty() && s.len() <= 512 && s.contains(':')
);

checked_string!(
    /// A claim name.
    ClaimName,
    "claim name",
    |s| {
        let mut chars = s.chars();
        s.len() <= 64
            && chars.next().is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
            && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
    }
);

fn is_jwt(s: &str) -> bool {
    let parts: alloc::vec::Vec<&str> = s.split('.').collect();
    parts.len() == 3
        && parts.iter().all(|p| {
            !p.is_empty()
                && p.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
}

checked_string!(
    /// An SD-JWT with its disclosures and key-binding JWT in compact form.
    SdJwtKb,
    "sdJwtKb",
    |s| {
        let parts: alloc::vec::Vec<&str> = s.split('~').collect();
        s.len() <= 16_384
            && parts.len() >= 2
            && parts.first().is_some_and(|p| is_jwt(p))
            && parts.last().is_some_and(|p| is_jwt(p))
            && parts.iter().skip(1).take(parts.len().saturating_sub(2)).all(|p| {
                !p.is_empty() && p.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            })
    }
);

/// A selective-disclosure request: the least set of attributes, no purpose text (OO-21).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisclosureRequest {
    /// The credential type.
    pub vct: Vct,
    /// The claims to disclose.
    pub claims: alloc::vec::Vec<ClaimName>,
}

/// The selective-disclosure format.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PresentationFormat {
    /// `dc+sd-jwt`.
    #[serde(rename = "dc+sd-jwt")]
    DcSdJwt,
}

/// A selective-disclosure presentation (OO-22).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Presentation {
    /// The format.
    pub format: PresentationFormat,
    /// The SD-JWT+KB.
    pub sd_jwt_kb: SdJwtKb,
}

/// The typed body; its fields are values of a taxonomy capability schema and it carries no free text (OO-15).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum Body {
    /// An offer.
    Offer {
        /// The capability.
        capability: CapabilityRef,
        /// Its typed field values.
        fields: JsonObject,
    },
    /// A counter-offer.
    CounterOffer {
        /// The capability, the same as in the superseded version.
        capability: CapabilityRef,
        /// Its typed field values.
        fields: JsonObject,
    },
    /// A commitment; the accepted version's fields become the commitment's fields.
    Commitment {},
    /// A rejection.
    Rejection {
        /// The reason code.
        reason: DeclineReason,
    },
    /// A query by capability fields or by disclosure request.
    #[serde(rename_all = "camelCase")]
    Query {
        /// The query capability.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability: Option<CapabilityRef>,
        /// Its typed parameters.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fields: Option<JsonObject>,
        /// The disclosure request.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        disclosure_request: Option<DisclosureRequest>,
    },
    /// An answer by derived capability values or by presentation.
    Answer {
        /// The capability.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        capability: Option<CapabilityRef>,
        /// The derived values.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fields: Option<JsonObject>,
        /// The presentation.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        presentation: Option<Presentation>,
    },
}

/// The most typed fields a body carries.
pub const MAX_FIELDS: usize = 64;

impl Body {
    /// The body kind.
    #[must_use]
    pub const fn kind(&self) -> Kind {
        match self {
            Self::Offer { .. } => Kind::Offer,
            Self::CounterOffer { .. } => Kind::CounterOffer,
            Self::Commitment {} => Kind::Commitment,
            Self::Rejection { .. } => Kind::Rejection,
            Self::Query { .. } => Kind::Query,
            Self::Answer { .. } => Kind::Answer,
        }
    }

    /// The capability the body names.
    #[must_use]
    pub const fn capability(&self) -> Option<&CapabilityRef> {
        match self {
            Self::Offer { capability, .. } | Self::CounterOffer { capability, .. } => {
                Some(capability)
            }
            Self::Query { capability, .. } | Self::Answer { capability, .. } => capability.as_ref(),
            Self::Commitment {} | Self::Rejection { .. } => None,
        }
    }

    /// The typed field values; the only values that bind (OO-17).
    #[must_use]
    pub const fn fields(&self) -> Option<&JsonObject> {
        match self {
            Self::Offer { fields, .. } | Self::CounterOffer { fields, .. } => Some(fields),
            Self::Query { fields, .. } | Self::Answer { fields, .. } => fields.as_ref(),
            Self::Commitment {} | Self::Rejection { .. } => None,
        }
    }

    /// Checks the body rules.
    ///
    /// # Errors
    /// Rejects too many fields, a query or answer mixing its two forms, or a malformed disclosure request.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        require(
            self.fields().is_none_or(|f| f.len() <= MAX_FIELDS),
            "at most 64 typed fields",
        )?;
        match self {
            Self::Query {
                capability,
                fields,
                disclosure_request,
            } => {
                if let Some(request) = disclosure_request {
                    require(
                        (1..=8).contains(&request.claims.len()) && unique(&request.claims),
                        "disclosure claims",
                    )?;
                }
                require(
                    match disclosure_request {
                        Some(_) => capability.is_none() && fields.is_none(),
                        None => capability.is_some() && fields.is_some(),
                    },
                    "query by fields or by disclosure",
                )
            }
            Self::Answer {
                capability,
                fields,
                presentation,
            } => require(
                match presentation {
                    Some(_) => capability.is_none() && fields.is_none(),
                    None => capability.is_some() && fields.is_some(),
                },
                "answer by fields or by presentation",
            ),
            _ => Ok(()),
        }
    }
}

checked_string!(
    /// Note text: 1 to 2000 characters.
    NoteText,
    "note text",
    |s| (1..=2000).contains(&s.chars().count())
);

/// The trust label of a note; always untrusted (OO-17).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NoteTrust {
    /// Untrusted external data, whatever the sender or relationship.
    Untrusted,
}

/// The provenance a note carries towards Access.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AccessProvenance {
    /// `untrusted-external`.
    UntrustedExternal,
}

/// How a note is shown.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NoteLabel {
    /// "The other party's note", shown as literal text, never rendered.
    CounterpartyNoteUnrendered,
}

/// `text/plain`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TextPlain {
    /// `text/plain`.
    #[serde(rename = "text/plain")]
    TextPlain,
}

/// `application/json`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ApplicationJson {
    /// `application/json`.
    #[serde(rename = "application/json")]
    ApplicationJson,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum NoteMarker {
    #[serde(rename = "note")]
    Note,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteExtension {
    part: NoteMarker,
    trust: NoteTrust,
    lang: LangTag,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct NoteMetadata {
    #[serde(rename = "https://suiss.app/a2a/one-federation/v1")]
    extension: NoteExtension,
}

/// A free-text note for a human only. It has no accessor to its text and no conversion into a field value, operation, action or planner input; it can only be displayed, labelled untrusted (OO-17).
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Note {
    text: NoteText,
    media_type: TextPlain,
    metadata: NoteMetadata,
}

impl fmt::Debug for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Note([untrusted])")
    }
}

impl Note {
    /// Builds an outgoing note.
    #[must_use]
    pub const fn new(text: NoteText, lang: LangTag) -> Self {
        Self {
            text,
            media_type: TextPlain::TextPlain,
            metadata: NoteMetadata {
                extension: NoteExtension {
                    part: NoteMarker::Note,
                    trust: NoteTrust::Untrusted,
                    lang,
                },
            },
        }
    }

    /// Always untrusted, whatever the sender's relationship level.
    #[must_use]
    pub const fn trust(&self) -> NoteTrust {
        NoteTrust::Untrusted
    }

    /// The provenance it carries towards Access.
    #[must_use]
    pub const fn access_provenance(&self) -> AccessProvenance {
        AccessProvenance::UntrustedExternal
    }

    /// The sender's declared language; informational.
    #[must_use]
    pub const fn lang(&self) -> &LangTag {
        &self.metadata.extension.lang
    }

    /// The note as the person sees it: literal visible text under the counterparty-note label.
    #[must_use]
    pub fn display(&self) -> NoteDisplay {
        NoteDisplay {
            text: visible_text(self.text.as_str()),
        }
    }
}

/// A note shown to the person; it formats as literal text and converts into nothing else (OO-17).
#[derive(Clone, PartialEq, Eq)]
pub struct NoteDisplay {
    text: String,
}

impl NoteDisplay {
    /// The display label.
    #[must_use]
    pub const fn label(&self) -> NoteLabel {
        NoteLabel::CounterpartyNoteUnrendered
    }

    /// Never rendered as markup.
    #[must_use]
    pub const fn rendered(&self) -> bool {
        false
    }
}

impl fmt::Display for NoteDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl fmt::Debug for NoteDisplay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoteDisplay([untrusted])")
    }
}

/// The character ranges removed from note text: controls, format and bidi characters, fillers, variation selectors and tags (`note-filter.toml`).
pub const INVISIBLE: &[(char, char)] = &[
    ('\u{0}', '\u{8}'),
    ('\u{b}', '\u{1f}'),
    ('\u{7f}', '\u{9f}'),
    ('\u{ad}', '\u{ad}'),
    ('\u{34f}', '\u{34f}'),
    ('\u{61c}', '\u{61c}'),
    ('\u{115f}', '\u{1160}'),
    ('\u{17b4}', '\u{17b5}'),
    ('\u{180b}', '\u{180f}'),
    ('\u{200b}', '\u{200f}'),
    ('\u{202a}', '\u{202e}'),
    ('\u{2060}', '\u{206f}'),
    ('\u{3164}', '\u{3164}'),
    ('\u{fe00}', '\u{fe0f}'),
    ('\u{feff}', '\u{feff}'),
    ('\u{ffa0}', '\u{ffa0}'),
    ('\u{fff9}', '\u{fffb}'),
    ('\u{1d173}', '\u{1d17a}'),
    ('\u{e0000}', '\u{e0fff}'),
];

fn is_invisible(c: char) -> bool {
    INVISIBLE
        .iter()
        .any(|(from, to)| (*from..=*to).contains(&c))
}

/// Normalises note text to visible characters: hidden controls, format characters and tags are removed; markup stays literal.
#[must_use]
pub fn visible_text(text: &str) -> String {
    text.chars().filter(|c| !is_invisible(*c)).collect()
}

/// The only answer to turning a note into a field value (OO-17).
///
/// # Errors
/// Always [`Refusal::NoteNotConvertible`].
pub const fn note_to_field(_note: &Note, _field: &str) -> Result<Infallible, Refusal> {
    Err(Refusal::NoteNotConvertible)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
enum BodyMarker {
    #[serde(rename = "body")]
    Body,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyExtension {
    part: BodyMarker,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BodyMetadata {
    #[serde(rename = "https://suiss.app/a2a/one-federation/v1")]
    extension: BodyExtension,
}

/// The body `DataPart`.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct BodyPart {
    /// The typed body.
    pub data: Body,
    media_type: ApplicationJson,
    metadata: BodyMetadata,
}

impl BodyPart {
    /// Wraps a body.
    #[must_use]
    pub const fn new(data: Body) -> Self {
        Self {
            data,
            media_type: ApplicationJson::ApplicationJson,
            metadata: BodyMetadata {
                extension: BodyExtension {
                    part: BodyMarker::Body,
                },
            },
        }
    }
}

/// The parts: exactly one body first, then at most one note.
#[derive(Clone, Debug, PartialEq)]
pub struct Parts {
    /// The body part.
    pub body: BodyPart,
    /// The note part.
    pub note: Option<Note>,
}

impl Serialize for Parts {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(if self.note.is_some() { 2 } else { 1 }))?;
        seq.serialize_element(&self.body)?;
        if let Some(note) = &self.note {
            seq.serialize_element(note)?;
        }
        seq.end()
    }
}

struct PartsVisitor;

impl<'de> Visitor<'de> for PartsVisitor {
    type Value = Parts;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("one body part and at most one note part")
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Parts, A::Error> {
        let body = seq
            .next_element::<BodyPart>()?
            .ok_or_else(|| de::Error::invalid_length(0, &self))?;
        let note = seq.next_element::<Note>()?;
        if seq.next_element::<de::IgnoredAny>()?.is_some() {
            return Err(de::Error::invalid_length(3, &self));
        }
        Ok(Parts { body, note })
    }
}

impl<'de> Deserialize<'de> for Parts {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_seq(PartsVisitor)
    }
}

/// The A2A message role.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Role {
    /// The party that opened the chain.
    RoleUser,
    /// The party serving the Task.
    RoleAgent,
}

/// `Message.metadata`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageMetadata {
    /// The envelope.
    #[serde(rename = "https://suiss.app/a2a/one-federation/v1")]
    pub envelope: Envelope,
}

/// A typed One↔One message (A2A v1.0 Message profile, OO-4).
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Message {
    /// The message identifier; the receiver deduplicates on it.
    pub message_id: Uuid7,
    /// Equals the envelope correlation identifier.
    pub context_id: Uuid7,
    /// The A2A Task of the chain; absent on the opening message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_id: Option<A2aId>,
    /// The role.
    pub role: Role,
    /// The parts.
    pub parts: Parts,
    /// The envelope.
    pub metadata: MessageMetadata,
    /// The extension list.
    pub extensions: Extensions,
}

/// What the planner and Work may see of a message: the typed content only, never the note (OO-17).
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
pub struct TypedContent<'a> {
    /// The kind.
    pub kind: Kind,
    /// The typed body.
    pub body: &'a Body,
}

impl Message {
    /// The envelope.
    #[must_use]
    pub const fn envelope(&self) -> &Envelope {
        &self.metadata.envelope
    }

    /// The typed body.
    #[must_use]
    pub const fn body(&self) -> &Body {
        &self.parts.body.data
    }

    /// The note, for display only.
    #[must_use]
    pub const fn note(&self) -> Option<&Note> {
        self.parts.note.as_ref()
    }

    /// The typed content handed to the planner and Work.
    #[must_use]
    pub const fn typed_content(&self) -> TypedContent<'_> {
        TypedContent {
            kind: self.metadata.envelope.kind,
            body: &self.parts.body.data,
        }
    }

    /// Checks the schema rules of the envelope and body.
    ///
    /// # Errors
    /// Rejects a message that breaks a rule of `message.v1.json`.
    pub fn validate(&self) -> Result<(), ContractViolation> {
        self.metadata.envelope.validate()?;
        self.parts.body.data.validate()
    }

    /// Checks the cross-member rules: `contextId` equals the correlation identifier and the body kind equals the envelope kind.
    ///
    /// # Errors
    /// Returns the refusal for the first broken rule.
    pub fn check_consistency(&self) -> Result<(), Refusal> {
        self.validate()?;
        let envelope = &self.metadata.envelope;
        if self.context_id != envelope.correlation_id {
            return Err(Refusal::CorrelationMismatch);
        }
        if self.parts.body.data.kind() != envelope.kind {
            return Err(Refusal::KindMismatch);
        }
        Ok(())
    }
}
