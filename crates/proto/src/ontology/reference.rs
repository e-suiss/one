//! References to objects owned by Access, Work, Relay, the Executor, Pay and source systems: One stores `{ref, id}` pointers, never a second canonical copy (C-4, C-24, MD-6 (1)).

use alloc::string::String;
use core::fmt;

use serde::de::Error as _;
use serde::ser::SerializeStruct;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use super::concept::{CanonicalId, EntityRecordId};
use crate::capability::{CapabilityName, CapabilityVersion};
use crate::task::common::{Sha256Digest, SnakeName};

/// An identifier minted by another product or system: 1 to 255 printable ASCII characters, opaque to One.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpaqueId(String);

/// A malformed reference value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReferenceError;

impl OpaqueId {
    /// Checks the opaque form.
    ///
    /// # Errors
    /// Rejects an empty, longer than 255 or non-printable value.
    pub fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let value = value.into();
        let ok =
            (1..=255).contains(&value.len()) && value.bytes().all(|b| (0x21..=0x7e).contains(&b));
        if ok {
            Ok(Self(value))
        } else {
            Err(ReferenceError)
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpaqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Serialize for OpaqueId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for OpaqueId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text)
            .map_err(|_| D::Error::custom("opaque identifier must be 1-255 printable ASCII"))
    }
}

/// A source-system locator: 1 to 2048 characters.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Locator(String);

impl Locator {
    /// Checks the length.
    ///
    /// # Errors
    /// Rejects an empty or longer than 2048 character value.
    pub fn new(value: impl Into<String>) -> Result<Self, ReferenceError> {
        let value = value.into();
        if (1..=2048).contains(&value.chars().count()) {
            Ok(Self(value))
        } else {
            Err(ReferenceError)
        }
    }

    /// The text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Serialize for Locator {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Locator {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        Self::new(text).map_err(|_| D::Error::custom("locator must be 1-2048 characters"))
    }
}

/// A reference that may carry an identifier minted by the owning product.
pub trait OwnerId {
    /// The owner's identifier of a `{ref, id}` reference to another product; `None` for any other reference.
    fn owner_id(&self) -> Option<&OpaqueId>;
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOpaque {
    #[serde(rename = "ref")]
    tag: String,
    id: OpaqueId,
}

macro_rules! opaque_ref {
    ($($(#[$meta:meta])* $name:ident),* $(,)?) => {
        $(
            $(#[$meta])*
            #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
            pub struct $name {
                /// The owner's identifier.
                pub id: OpaqueId,
            }

            impl $name {
                /// The `ref` value.
                pub const REF: &'static str = stringify!($name);

                /// Wraps an owner's identifier.
                #[must_use]
                pub const fn new(id: OpaqueId) -> Self {
                    Self { id }
                }
            }

            impl OwnerId for $name {
                fn owner_id(&self) -> Option<&OpaqueId> {
                    Some(&self.id)
                }
            }

            impl Serialize for $name {
                fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                    let mut out = serializer.serialize_struct(stringify!($name), 2)?;
                    out.serialize_field("ref", Self::REF)?;
                    out.serialize_field("id", &self.id)?;
                    out.end()
                }
            }

            impl<'de> Deserialize<'de> for $name {
                fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                    let raw = RawOpaque::deserialize(deserializer)?;
                    if raw.tag == Self::REF {
                        Ok(Self { id: raw.id })
                    } else {
                        Err(D::Error::custom(format_args!("expected ref {:?}", Self::REF)))
                    }
                }
            }
        )*

        /// The `ref` value of every `{ref, id}` reference to another product.
        pub const OPAQUE_REFS: &[&str] = &[$(stringify!($name)),*];
    };
}

opaque_ref!(
    /// A user or other Suiss person in Access.
    PartyRef,
    /// A One identity, sub-agent or execution instance in Access.
    InstanceRef,
    /// A device key binding in Access.
    KeyBindingRef,
    /// A local executor in Access.
    ExecutorRef,
    /// An Access Grant; One holds the reference, never the authority.
    GrantRef,
    /// An Access Mandate; One holds the reference, never the authority.
    MandateRef,
    /// An Access Trigger.
    TriggerRef,
    /// An Access Exercise.
    ExerciseRef,
    /// An Access decision record, approval act or continuation decision.
    DecisionRecordRef,
    /// An Access or Executor Claim.
    ClaimRef,
    /// An Access acceptance that sets a relationship level.
    AcceptanceRef,
    /// A connected account in Access.
    ConnectedAccountRef,
    /// An Access household.
    HouseholdRef,
    /// An Access guardianship.
    GuardianshipRef,
    /// An Access age band; One never stores a birth date.
    AgeBandRef,
    /// A Work Commitment.
    CommitmentRef,
    /// A Work offer chain.
    OfferChainRef,
    /// A Work Needs Attention item.
    NeedsAttentionRef,
    /// A Work personal tenant.
    TenantRef,
    /// A Relay notification.
    NotificationRef,
    /// A Relay waitpoint.
    WaitpointRef,
    /// A Relay mailbox message.
    MailboxMessageRef,
    /// An Executor execution report.
    ExecutionReportRef,
    /// An Executor checkpoint.
    CheckpointRef,
    /// A Pay payment.
    PaymentRef,
    /// A Pay order.
    OrderRef,
    /// A Pay agent token.
    AgentTokenRef,
);

/// The structured Access action requirement: capability namespace, action, dated version and input schema digest.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionRef {
    /// Capability name (`app.suiss.…` or a third-party reverse-DNS name).
    pub namespace: CapabilityName,
    /// Action name, `[a-z][a-z0-9_]{0,63}`.
    pub name: SnakeName,
    /// Dated capability version, `YYYY-MM-DD`.
    pub version: CapabilityVersion,
    /// `sha256:` and 64 lower-case hex digits of the input schema.
    pub schema_digest: Sha256Digest,
}

/// A source system that owns an external object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExternalSystem {
    /// Address book.
    Contacts,
    /// E-mail.
    Email,
    /// Calendar.
    Calendar,
    /// Messaging.
    Messaging,
    /// Document.
    Document,
    /// File store.
    Files,
    /// Photo library.
    Photos,
    /// Web page.
    Web,
    /// Place.
    Place,
    /// Agent.
    Agent,
    /// Service.
    Service,
}

/// A source system that can hold a person outside Suiss.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PersonSystem {
    /// Address book.
    Contacts,
    /// E-mail.
    Email,
    /// Messaging.
    Messaging,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawExternal<S> {
    #[serde(rename = "ref")]
    tag: String,
    system: S,
    locator: Locator,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    account: Option<ConnectedAccountRef>,
}

/// A calendar event, e-mail, document, booking, place or other source-system object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalRef {
    /// The owning system.
    pub system: ExternalSystem,
    /// Where the object lives in that system.
    pub locator: Locator,
    /// The connected account it was read through.
    pub account: Option<ConnectedAccountRef>,
}

/// A person not in Suiss, pointed at in the source system's entry.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExternalPersonRef {
    /// The owning system.
    pub system: PersonSystem,
    /// Where the entry lives in that system.
    pub locator: Locator,
    /// The connected account it was read through.
    pub account: Option<ConnectedAccountRef>,
}

macro_rules! external_ref {
    ($name:ident, $system:ty) => {
        impl $name {
            /// The `ref` value.
            pub const REF: &'static str = stringify!($name);
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                RawExternal {
                    tag: String::from(Self::REF),
                    system: self.system,
                    locator: self.locator.clone(),
                    account: self.account.clone(),
                }
                .serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = RawExternal::<$system>::deserialize(deserializer)?;
                if raw.tag == Self::REF {
                    Ok(Self {
                        system: raw.system,
                        locator: raw.locator,
                        account: raw.account,
                    })
                } else {
                    Err(D::Error::custom(format_args!(
                        "expected ref {:?}",
                        Self::REF
                    )))
                }
            }
        }
    };
}

external_ref!(ExternalRef, ExternalSystem);
external_ref!(ExternalPersonRef, PersonSystem);

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecord<I> {
    #[serde(rename = "ref")]
    tag: String,
    id: I,
}

/// A reference to one of One's own canonical records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordRef {
    /// The record.
    pub id: CanonicalId,
}

/// A reference to a Goal or Routine as the subject or object of a memory record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct EntityRecordRef {
    /// The Goal or Routine.
    pub id: EntityRecordId,
}

macro_rules! record_ref {
    ($name:ident, $id:ty) => {
        impl $name {
            /// The `ref` value.
            pub const REF: &'static str = "RecordRef";
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                RawRecord {
                    tag: String::from(Self::REF),
                    id: self.id,
                }
                .serialize(serializer)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let raw = RawRecord::<$id>::deserialize(deserializer)?;
                if raw.tag == Self::REF {
                    Ok(Self { id: raw.id })
                } else {
                    Err(D::Error::custom("expected ref \"RecordRef\""))
                }
            }
        }
    };
}

record_ref!(RecordRef, CanonicalId);
record_ref!(EntityRecordRef, EntityRecordId);

/// Declares an untagged union of references with a `From` for each member.
macro_rules! ref_union {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident($ty:ty)),* $(,)? }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize)]
        #[serde(untagged)]
        pub enum $name {
            $($(#[$vmeta])* $variant($ty),)*
        }

        $(impl From<$ty> for $name {
            fn from(r: $ty) -> Self {
                Self::$variant(r)
            }
        })*

        impl $crate::ontology::reference::OwnerId for $name {
            fn owner_id(&self) -> Option<&$crate::ontology::reference::OpaqueId> {
                match self {
                    $(Self::$variant(r) => $crate::ontology::reference::OwnerId::owner_id(r),)*
                }
            }
        }
    };
}

pub(crate) use ref_union;

macro_rules! no_owner_id {
    ($($name:ty),*) => {
        $(impl OwnerId for $name {
            fn owner_id(&self) -> Option<&OpaqueId> {
                None
            }
        })*
    };
}

no_owner_id!(
    ActionRef,
    ExternalRef,
    ExternalPersonRef,
    RecordRef,
    EntityRecordRef
);

ref_union!(
    /// An object owned by Access.
    AccessObjectRef {
        /// A person.
        Party(PartyRef),
        /// An instance.
        Instance(InstanceRef),
        /// A key binding.
        KeyBinding(KeyBindingRef),
        /// An executor.
        Executor(ExecutorRef),
        /// A Grant.
        Grant(GrantRef),
        /// A Mandate.
        Mandate(MandateRef),
        /// A Trigger.
        Trigger(TriggerRef),
        /// An Exercise.
        Exercise(ExerciseRef),
        /// A decision record.
        DecisionRecord(DecisionRecordRef),
        /// A Claim.
        Claim(ClaimRef),
        /// An acceptance.
        Acceptance(AcceptanceRef),
        /// A connected account.
        ConnectedAccount(ConnectedAccountRef),
        /// An action requirement.
        Action(ActionRef),
        /// A household.
        Household(HouseholdRef),
        /// A guardianship.
        Guardianship(GuardianshipRef),
        /// An age band.
        AgeBand(AgeBandRef),
    }
);

ref_union!(
    /// An object owned by Work.
    WorkObjectRef {
        /// A Commitment.
        Commitment(CommitmentRef),
        /// An offer chain.
        OfferChain(OfferChainRef),
        /// A Needs Attention item.
        NeedsAttention(NeedsAttentionRef),
        /// A personal tenant.
        Tenant(TenantRef),
    }
);

ref_union!(
    /// An object owned by Relay.
    RelayObjectRef {
        /// A notification.
        Notification(NotificationRef),
        /// A waitpoint.
        Waitpoint(WaitpointRef),
        /// A mailbox message.
        MailboxMessage(MailboxMessageRef),
    }
);

ref_union!(
    /// An object owned by the Executor.
    ExecutorObjectRef {
        /// An execution report.
        ExecutionReport(ExecutionReportRef),
        /// A checkpoint.
        Checkpoint(CheckpointRef),
    }
);

ref_union!(
    /// An object owned by Pay.
    PayObjectRef {
        /// A payment.
        Payment(PaymentRef),
        /// An order.
        Order(OrderRef),
        /// An agent token.
        AgentToken(AgentTokenRef),
    }
);

ref_union!(
    /// An object owned by another Suiss product.
    ProductRef {
        /// Access.
        Access(AccessObjectRef),
        /// Work.
        Work(WorkObjectRef),
        /// Relay.
        Relay(RelayObjectRef),
        /// Executor.
        Executor(ExecutorObjectRef),
        /// Pay.
        Pay(PayObjectRef),
    }
);

ref_union!(
    /// A person, in Suiss or outside it.
    PersonRef {
        /// A Suiss person.
        Party(PartyRef),
        /// A person outside Suiss.
        ExternalPerson(ExternalPersonRef),
    }
);

ref_union!(
    /// Any reference to an object One does not own.
    AnyRef {
        /// A Suiss product object.
        Product(ProductRef),
        /// A source-system object.
        External(ExternalRef),
        /// A person outside Suiss.
        ExternalPerson(ExternalPersonRef),
    }
);

ref_union!(
    /// The subject or object of a memory record: a person, a source-system object, a Goal or a Routine.
    EntityRef {
        /// A Suiss person.
        Party(PartyRef),
        /// A person outside Suiss.
        ExternalPerson(ExternalPersonRef),
        /// A source-system object.
        External(ExternalRef),
        /// A Goal or Routine.
        Record(EntityRecordRef),
    }
);

ref_union!(
    /// A relation or task target: one of One's records or any foreign reference.
    Target {
        /// One's own record.
        Record(RecordRef),
        /// A foreign object.
        Any(AnyRef),
    }
);
