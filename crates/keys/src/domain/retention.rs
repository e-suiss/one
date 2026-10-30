//! Automatic retention end: the destroy time is the start event plus the class duration read from the pinned Access Appendix C file, never a value One holds; the hourly sweep bound, the six-month sweep floor and the pin check (PV-16, PV-17, OP-7).

use one_proto::data_class::RetentionClass;
use one_proto::ontology::{CalendarDuration, Instant};

/// The longest gap between two destroy sweeps of a class.
pub const SWEEP_FLOOR: CalendarDuration = CalendarDuration {
    months: 6,
    days: 0,
    seconds: 0,
};

/// How often a class is swept beyond the floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sweep {
    /// Every hour (`one_observation`).
    Hourly,
}

/// Where a duration came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DurationSource {
    /// The Access Appendix C file pinned in `conformance/retention/binding.toml`.
    PinnedAccessFile,
    /// A value One holds itself; always refused (OP-7).
    Local,
}

/// One class entry of the Access file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetentionRule {
    /// The class.
    pub class: RetentionClass,
    /// The event the period starts at.
    pub start_event: String,
    /// The period.
    pub duration: CalendarDuration,
    /// Where the period came from.
    pub source: DurationSource,
    /// The class's own sweep, if any.
    pub sweep: Option<Sweep>,
}

/// Why a destroy time cannot be computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RetentionError {
    /// The class has no entry in the Access file: a configuration error, not a default.
    NoAppendixCEntry,
    /// The duration is not from the pinned Access file.
    LocalDuration,
    /// The Access file is not the pinned one.
    PinMismatch,
    /// The arithmetic overflowed.
    Overflow,
}

impl RetentionError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NoAppendixCEntry => "no_appendix_c_entry",
            Self::LocalDuration => "local_duration",
            Self::PinMismatch => "pin_mismatch",
            Self::Overflow => "overflow",
        }
    }
}

/// How a record leaves at its retention end.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DestroyMethod {
    /// Soft delete of the row and crypto-shred of its record key (OP-6).
    SoftDeleteAndCryptoShred,
}

impl DestroyMethod {
    /// The method as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SoftDeleteAndCryptoShred => "soft_delete_and_crypto_shred",
        }
    }
}

/// When a record is destroyed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Destroy {
    /// The retention end.
    pub at: Instant,
    /// The latest time the sweep destroys it.
    pub by: Instant,
    /// How.
    pub method: DestroyMethod,
}

/// The class entries of the pinned Access file.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RetentionTable {
    rules: Vec<RetentionRule>,
}

impl RetentionTable {
    /// A table over the Access file's entries.
    #[must_use]
    pub const fn new(rules: Vec<RetentionRule>) -> Self {
        Self { rules }
    }

    /// The entry of `class` for `start_event`.
    ///
    /// # Errors
    /// [`RetentionError::NoAppendixCEntry`] when the file has none.
    pub fn rule(
        &self,
        class: RetentionClass,
        start_event: &str,
    ) -> Result<&RetentionRule, RetentionError> {
        self.rules
            .iter()
            .find(|r| r.class == class && r.start_event == start_event)
            .ok_or(RetentionError::NoAppendixCEntry)
    }
}

/// The destroy time of a record whose start event happened at `start_at`.
///
/// # Errors
/// [`RetentionError::LocalDuration`] for a duration One holds, [`RetentionError::Overflow`] past the calendar.
pub fn destroy(rule: &RetentionRule, start_at: &Instant) -> Result<Destroy, RetentionError> {
    if rule.source != DurationSource::PinnedAccessFile {
        return Err(RetentionError::LocalDuration);
    }
    let at = start_at
        .checked_add_calendar(&rule.duration)
        .ok_or(RetentionError::Overflow)?;
    let by = match rule.sweep {
        Some(Sweep::Hourly) => at
            .checked_add_calendar(&CalendarDuration {
                months: 0,
                days: 0,
                seconds: 3_600,
            })
            .ok_or(RetentionError::Overflow)?,
        None => at,
    };
    Ok(Destroy {
        at,
        by,
        method: DestroyMethod::SoftDeleteAndCryptoShred,
    })
}

/// Whether the destroy sweep of a class last run at `last_sweep_at` is overdue at `now`.
#[must_use]
pub fn sweep_overdue(last_sweep_at: &Instant, now: &Instant) -> bool {
    last_sweep_at
        .checked_add_calendar(&SWEEP_FLOOR)
        .is_none_or(|due| &due <= now)
}

/// Checks the Access file's SHA-256 against the pinned lower-case hex value; a pin still `pending` never matches.
///
/// # Errors
/// [`RetentionError::PinMismatch`].
pub fn check_pin(pinned_sha256: &str, file_sha256: &[u8; 32]) -> Result<(), RetentionError> {
    let mut hex = String::with_capacity(64);
    for b in file_sha256 {
        hex.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        hex.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    if pinned_sha256 == hex {
        Ok(())
    } else {
        Err(RetentionError::PinMismatch)
    }
}
