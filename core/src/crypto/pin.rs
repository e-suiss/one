//! The recovery PIN is stretched on the device with Argon2id under fixed parameters and the user's salt; the 64-byte tag splits into the access key the vault realms check and the seed of the key that seals the KEK share (PV-12, PV-14). The PIN never leaves the device.

use argon2::{Algorithm, Argon2, AssociatedData, ParamsBuilder, Version};
use one_proto::recovery::MIN_PIN_DIGITS;
use zeroize::Zeroizing;

/// The fixed Argon2id parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PinParams {
    /// Memory cost in KiB.
    pub memory_kib: u32,
    /// Passes.
    pub iterations: u32,
    /// Lanes.
    pub lanes: u32,
    /// Tag length in bytes.
    pub tag_length: usize,
}

/// The only parameters a PIN is stretched with: 64 MiB, 3 passes, 4 lanes, 64-byte tag, Argon2id version 0x13.
pub const PIN_PARAMS: PinParams = PinParams {
    memory_kib: 65_536,
    iterations: 3,
    lanes: 4,
    tag_length: 64,
};

/// Why a PIN is not stretched.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PinError {
    /// Fewer than six digits, or a character that is not a digit.
    PinTooShort,
    /// Parameters other than [`PIN_PARAMS`].
    Params,
    /// The Argon2 computation failed.
    Argon2,
}

impl PinError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::PinTooShort => "pin_too_short",
            Self::Params => "params",
            Self::Argon2 => "argon2",
        }
    }
}

/// The two halves of a stretched PIN.
pub struct PinKeys {
    /// The access key the vault realms check through the OPRF.
    pub access_key: Zeroizing<[u8; 32]>,
    /// The seed of the key that seals the KEK share.
    pub encryption_key_seed: Zeroizing<[u8; 32]>,
}

pub(crate) fn argon2id(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: PinParams,
) -> Result<Zeroizing<Vec<u8>>, PinError> {
    let mut builder = ParamsBuilder::new();
    builder
        .m_cost(params.memory_kib)
        .t_cost(params.iterations)
        .p_cost(params.lanes)
        .output_len(params.tag_length);
    if !associated_data.is_empty() {
        builder.data(AssociatedData::new(associated_data).map_err(|_| PinError::Params)?);
    }
    let built = builder.build().map_err(|_| PinError::Params)?;
    let argon = if secret.is_empty() {
        Argon2::new(Algorithm::Argon2id, Version::V0x13, built)
    } else {
        Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, built)
            .map_err(|_| PinError::Params)?
    };
    let mut tag = Zeroizing::new(vec![0_u8; params.tag_length]);
    argon
        .hash_password_into(password, salt, &mut tag)
        .map_err(|_| PinError::Argon2)?;
    Ok(tag)
}

/// Stretches `pin` under the user's 16-byte `salt`.
///
/// # Errors
/// [`PinError::PinTooShort`] before any stretching, [`PinError::Params`] for any parameters but [`PIN_PARAMS`].
pub fn stretch(pin: &str, salt: &[u8; 16], params: PinParams) -> Result<PinKeys, PinError> {
    if pin.len() < usize::from(MIN_PIN_DIGITS) || !pin.bytes().all(|b| b.is_ascii_digit()) {
        return Err(PinError::PinTooShort);
    }
    if params != PIN_PARAMS {
        return Err(PinError::Params);
    }
    let tag = argon2id(pin.as_bytes(), salt, &[], &[], params)?;
    let (access, seed) = tag.split_at_checked(32).ok_or(PinError::Argon2)?;
    let mut keys = PinKeys {
        access_key: Zeroizing::new([0; 32]),
        encryption_key_seed: Zeroizing::new([0; 32]),
    };
    keys.access_key.copy_from_slice(access);
    keys.encryption_key_seed.copy_from_slice(seed);
    Ok(keys)
}

#[cfg(test)]
mod tests;
