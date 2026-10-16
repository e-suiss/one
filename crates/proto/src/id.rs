//! Typed identifiers: a `UUIDv7` in 16 bytes, shown as a lower-case type prefix, `_` and 26 Crockford base32 digits; no identifier travels as a bare string or UUID (T-28 (5), T-31).

use core::fmt;

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

/// A malformed identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdError {
    /// The prefix is not the one this type expects.
    Prefix,
    /// The body is not 26 base32 digits.
    Body,
    /// The bytes are not a version 7, RFC 9562 variant UUID.
    Version,
}

/// Builds `UUIDv7` bytes from a millisecond timestamp and 10 random bytes (RFC 9562 §5.7).
#[must_use]
pub const fn uuid_v7(unix_ms: u64, random: [u8; 10]) -> [u8; 16] {
    let ms = unix_ms.to_be_bytes();
    [
        ms[2],
        ms[3],
        ms[4],
        ms[5],
        ms[6],
        ms[7],
        0x70 | (random[0] & 0x0f),
        random[1],
        0x80 | (random[2] & 0x3f),
        random[3],
        random[4],
        random[5],
        random[6],
        random[7],
        random[8],
        random[9],
    ]
}

/// Checks the version and variant bits of `UUIDv7` bytes.
///
/// # Errors
/// Returns [`IdError::Version`] for any other UUID.
pub const fn check_v7(bytes: &[u8; 16]) -> Result<(), IdError> {
    if bytes[6] >> 4 == 7 && bytes[8] >> 6 == 0b10 {
        Ok(())
    } else {
        Err(IdError::Version)
    }
}

/// Writes 128 bits as 26 Crockford base32 digits.
///
/// # Errors
/// Propagates the formatter's error.
pub fn write_base32(bytes: &[u8; 16], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    let value = u128::from_be_bytes(*bytes);
    for i in (0..26_u32).rev() {
        let shift = i.saturating_mul(5);
        let digit = usize::try_from(value.checked_shr(shift).unwrap_or(0) & 0x1f).unwrap_or(0);
        let c = ALPHABET.get(digit).copied().unwrap_or(b'0');
        fmt::Write::write_char(f, char::from(c))?;
    }
    Ok(())
}

/// Parses 26 Crockford base32 digits into 128 bits.
///
/// # Errors
/// Returns [`IdError::Body`] for a wrong length, an unknown digit or an overflowing first digit.
pub fn parse_base32(text: &str) -> Result<[u8; 16], IdError> {
    if text.len() != 26 {
        return Err(IdError::Body);
    }
    let mut value: u128 = 0;
    for (i, c) in text.bytes().enumerate() {
        let digit = ALPHABET.iter().position(|&a| a == c).ok_or(IdError::Body)?;
        if i == 0 && digit > 7 {
            return Err(IdError::Body);
        }
        let digit = u128::try_from(digit).map_err(|_| IdError::Body)?;
        value = value.checked_shl(5).ok_or(IdError::Body)? | digit;
    }
    Ok(value.to_be_bytes())
}

/// Declares a typed identifier with its wire prefix.
#[macro_export]
macro_rules! typed_id {
    ($(#[$meta:meta])* $name:ident, $prefix:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name([u8; 16]);

        impl $name {
            /// The wire prefix.
            pub const PREFIX: &'static str = $prefix;

            /// Wraps `UUIDv7` bytes.
            ///
            /// # Errors
            /// Rejects bytes that are not a `UUIDv7`.
            pub const fn from_bytes(bytes: [u8; 16]) -> Result<Self, $crate::id::IdError> {
                match $crate::id::check_v7(&bytes) {
                    Ok(()) => Ok(Self(bytes)),
                    Err(e) => Err(e),
                }
            }

            /// The `UUIDv7` bytes.
            #[must_use]
            pub const fn to_bytes(self) -> [u8; 16] {
                self.0
            }

            /// Parses `prefix_base32`.
            ///
            /// # Errors
            /// Rejects another prefix, a malformed body or a non-v7 UUID.
            pub fn parse(text: &str) -> Result<Self, $crate::id::IdError> {
                let body = text
                    .strip_prefix(Self::PREFIX)
                    .and_then(|rest| rest.strip_prefix('_'))
                    .ok_or($crate::id::IdError::Prefix)?;
                Self::from_bytes($crate::id::parse_base32(body)?)
            }
        }

        impl core::fmt::Display for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                f.write_str(Self::PREFIX)?;
                f.write_str("_")?;
                $crate::id::write_base32(&self.0, f)
            }
        }

        impl core::fmt::Debug for $name {
            fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
                core::fmt::Display::fmt(self, f)
            }
        }
    };
}

typed_id!(
    /// A task record.
    TaskId,
    "task"
);
typed_id!(
    /// A memory record.
    MemoryRecordId,
    "mem"
);
typed_id!(
    /// An episode.
    EpisodeId,
    "epi"
);
typed_id!(
    /// An interaction.
    InteractionId,
    "int"
);
typed_id!(
    /// A capability definition.
    CapabilityId,
    "cap"
);
typed_id!(
    /// A device.
    DeviceId,
    "dev"
);
typed_id!(
    /// A model version.
    ModelVersionId,
    "mdl"
);
typed_id!(
    /// A personal adapter.
    AdapterId,
    "adp"
);
typed_id!(
    /// An API request, returned in the `Request-Id` header.
    RequestId,
    "req"
);

#[cfg(test)]
mod tests {
    extern crate std;
    use std::string::ToString;

    use super::*;

    const RANDOM: [u8; 10] = [0xab, 0xcd, 0xef, 1, 2, 3, 4, 5, 6, 7];

    #[test]
    fn t_28_typed_id_round_trips_with_its_prefix() {
        let id = TaskId::from_bytes(uuid_v7(1_791_504_000_000, RANDOM)).unwrap();
        let text = id.to_string();
        assert!(text.starts_with("task_"));
        assert_eq!(text.len(), 31);
        assert_eq!(TaskId::parse(&text), Ok(id));
    }

    #[test]
    fn t_28_wrong_prefix_body_or_version_is_rejected() {
        let id = TaskId::from_bytes(uuid_v7(1, RANDOM)).unwrap();
        let text = id.to_string().replacen("task", "mem", 1);
        assert_eq!(TaskId::parse(&text), Err(IdError::Prefix));
        assert_eq!(TaskId::parse("task_short"), Err(IdError::Body));
        assert_eq!(TaskId::from_bytes([0; 16]), Err(IdError::Version));
        assert_eq!(
            MemoryRecordId::parse(&text).map(MemoryRecordId::to_bytes),
            Ok(id.to_bytes())
        );
    }

    #[test]
    fn t_31_ids_sort_by_time() {
        let early = TaskId::from_bytes(uuid_v7(1_000, RANDOM)).unwrap();
        let late = TaskId::from_bytes(uuid_v7(2_000, RANDOM)).unwrap();
        assert!(early < late);
        assert!(early.to_string() < late.to_string());
    }
}
