//! A KEK recovery path of `conformance/recovery/recovery-method.json`: four kinds, each a separate wrapping of the same KEK registered in Access as a `recovery_method` (PV-12, PV-13, PV-14, Access E52 (2)).

use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::federation::Uuid7;
use crate::id::DeviceId;
use crate::ontology::validate::{ContractViolation, checked_string, require};
use crate::ontology::{Instant, OpaqueId, PartyRef};

/// The guess limit a PIN vault starts with (PV-12).
pub const DEFAULT_MAX_GUESSES: u8 = 10;

/// The lowest guess limit a user may set (PV-12).
pub const MIN_MAX_GUESSES: u8 = 3;

/// The shortest recovery PIN (PV-12).
pub const MIN_PIN_DIGITS: u8 = 6;

/// The number of vault realms (PV-12).
pub const VAULT_REALMS: usize = 3;

/// The number of realms a recovery needs (PV-12).
pub const VAULT_THRESHOLD: u8 = 2;

fn is_kek_id(s: &str) -> bool {
    (1..=64).contains(&s.chars().count())
}

fn is_realm_name(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

checked_string!(
    /// The identifier of the KEK a path wraps.
    KekId,
    "kek_id",
    is_kek_id
);

checked_string!(
    /// The name of a vault realm.
    RealmName,
    "realm",
    is_realm_name
);

/// The path kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryKind {
    /// Recovery PIN with the threshold vault.
    PinVault,
    /// A recovery key the user keeps.
    RecoveryKey,
    /// A trusted person holding one share.
    RecoveryContact,
    /// Another registered device.
    SecondDevice,
}

/// Whether the path can be used.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryStatus {
    /// Usable.
    Active,
    /// Exhausted or broken; the remaining paths are shown (PV-13).
    Unusable,
    /// Removed by the user.
    Removed,
}

/// The PIN vault parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawPinVault")]
pub struct PinVault {
    /// The three realms, distinct.
    pub realms: Vec<RealmName>,
    /// Always 2.
    pub threshold: u8,
    /// 3 to 10.
    pub max_guesses: u8,
    /// At least 6.
    pub pin_digits: u8,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPinVault {
    realms: Vec<RealmName>,
    threshold: u8,
    max_guesses: u8,
    pin_digits: u8,
}

impl TryFrom<RawPinVault> for PinVault {
    type Error = ContractViolation;

    fn try_from(r: RawPinVault) -> Result<Self, ContractViolation> {
        let mut sorted: Vec<&RealmName> = r.realms.iter().collect();
        sorted.sort();
        sorted.dedup();
        require(
            r.realms.len() == VAULT_REALMS && sorted.len() == VAULT_REALMS,
            "pin_vault.realms",
        )?;
        require(r.threshold == VAULT_THRESHOLD, "pin_vault.threshold")?;
        require(
            (MIN_MAX_GUESSES..=DEFAULT_MAX_GUESSES).contains(&r.max_guesses),
            "pin_vault.max_guesses",
        )?;
        require(
            (MIN_PIN_DIGITS..=64).contains(&r.pin_digits),
            "pin_vault.pin_digits",
        )?;
        Ok(Self {
            realms: r.realms,
            threshold: r.threshold,
            max_guesses: r.max_guesses,
            pin_digits: r.pin_digits,
        })
    }
}

/// The recovery contact parameters: contacts and the Access account share, so neither side opens the path alone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawContact")]
pub struct RecoveryContact {
    /// The contacts, distinct.
    pub contacts: Vec<PartyRef>,
    /// At least 2.
    pub threshold: u8,
    /// Always `true`.
    pub account_share: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawContact {
    contacts: Vec<PartyRef>,
    threshold: u8,
    account_share: bool,
}

impl TryFrom<RawContact> for RecoveryContact {
    type Error = ContractViolation;

    fn try_from(r: RawContact) -> Result<Self, ContractViolation> {
        let mut sorted: Vec<&PartyRef> = r.contacts.iter().collect();
        sorted.sort();
        sorted.dedup();
        require(
            !r.contacts.is_empty() && sorted.len() == r.contacts.len(),
            "recovery_contact.contacts",
        )?;
        require(r.threshold >= 2, "recovery_contact.threshold")?;
        require(r.account_share, "recovery_contact.account_share")?;
        Ok(Self {
            contacts: r.contacts,
            threshold: r.threshold,
            account_share: r.account_share,
        })
    }
}

/// The second device parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecondDevice {
    /// The device that transfers the KEK.
    pub device: DeviceId,
}

/// The recovery key parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawRecoveryKey")]
pub struct RecoveryKeyParams {
    /// Always 256.
    pub bits: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawRecoveryKey {
    bits: u16,
}

impl TryFrom<RawRecoveryKey> for RecoveryKeyParams {
    type Error = ContractViolation;

    fn try_from(r: RawRecoveryKey) -> Result<Self, ContractViolation> {
        require(r.bits == 256, "recovery_key.bits")?;
        Ok(Self { bits: r.bits })
    }
}

/// One recovery path; it carries no key material.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawMethod")]
pub struct RecoveryMethod {
    /// The path id.
    pub method_id: Uuid7,
    /// The account.
    pub owner: PartyRef,
    /// The kind.
    pub kind: RecoveryKind,
    /// The KEK the path wraps.
    pub kek_id: KekId,
    /// The Access `recovery_method` record.
    pub access_method: OpaqueId,
    /// Whether the path can be used.
    pub status: RecoveryStatus,
    /// Creation time.
    pub created_at: Instant,
    /// Last successful check of the path.
    pub last_verified_at: Option<Instant>,
    /// Present exactly when `kind` is `pin_vault`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pin_vault: Option<PinVault>,
    /// Present exactly when `kind` is `recovery_contact`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_contact: Option<RecoveryContact>,
    /// Present exactly when `kind` is `second_device`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_device: Option<SecondDevice>,
    /// Present exactly when `kind` is `recovery_key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_key: Option<RecoveryKeyParams>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawMethod {
    method_id: Uuid7,
    owner: PartyRef,
    kind: RecoveryKind,
    kek_id: KekId,
    access_method: OpaqueId,
    status: RecoveryStatus,
    created_at: Instant,
    last_verified_at: Option<Instant>,
    pin_vault: Option<PinVault>,
    recovery_contact: Option<RecoveryContact>,
    second_device: Option<SecondDevice>,
    recovery_key: Option<RecoveryKeyParams>,
}

impl TryFrom<RawMethod> for RecoveryMethod {
    type Error = ContractViolation;

    fn try_from(r: RawMethod) -> Result<Self, ContractViolation> {
        let present = [
            (RecoveryKind::PinVault, r.pin_vault.is_some()),
            (RecoveryKind::RecoveryContact, r.recovery_contact.is_some()),
            (RecoveryKind::SecondDevice, r.second_device.is_some()),
            (RecoveryKind::RecoveryKey, r.recovery_key.is_some()),
        ];
        require(
            present.iter().all(|(kind, set)| *set == (*kind == r.kind)),
            "kind parameters",
        )?;
        Ok(Self {
            method_id: r.method_id,
            owner: r.owner,
            kind: r.kind,
            kek_id: r.kek_id,
            access_method: r.access_method,
            status: r.status,
            created_at: r.created_at,
            last_verified_at: r.last_verified_at,
            pin_vault: r.pin_vault,
            recovery_contact: r.recovery_contact,
            second_device: r.second_device,
            recovery_key: r.recovery_key,
        })
    }
}
