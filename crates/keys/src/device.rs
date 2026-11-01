//! The user KEK's copies (PV-5, PV-61): on a device it is sealed with HPKE DHKEM(P-256) to the Secure Enclave key or wrapped with AES-256 Key Wrap under the StrongBox or TPM key, on a passkey it is wrapped under a key stretched from the WebAuthn PRF output; no copy is ever wrapped by a key an operator holds.

use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use one_hpke::{HpkeError, Kem, KeyPair, setup_receiver, setup_sender, setup_sender_with};
use sha2::{Digest as _, Sha256};
use suiss_crypto::secret::Secret;
use zeroize::Zeroizing;

use crate::seal::{KeyError, WRAPPED_LEN, key_from_slice, unwrap, wrap};

/// The HPKE `info` prefix of a Secure Enclave copy; the KEK id follows.
pub const DEVICE_INFO: &[u8] = b"one/kek/device/v1\0";

/// The HKDF `info` prefix of a passkey copy; the KEK id follows.
pub const PASSKEY_INFO: &[u8] = b"one/kek/passkey/v1\0";

/// The label whose SHA-256 is the fixed PRF evaluation input.
pub const PRF_LABEL: &[u8] = b"one/kek/passkey/v1";

/// Where a KEK copy lives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Holder {
    /// An Apple device's Secure Enclave (P-256 only).
    SecureEnclave,
    /// An Android StrongBox.
    StrongBox,
    /// A TPM.
    Tpm,
    /// A passkey through the WebAuthn PRF extension.
    Passkey,
    /// A recovery path (PV-12).
    Recovery,
}

impl Holder {
    /// Every holder.
    pub const ALL: [Self; 5] = [
        Self::SecureEnclave,
        Self::StrongBox,
        Self::Tpm,
        Self::Passkey,
        Self::Recovery,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SecureEnclave => "secure_enclave",
            Self::StrongBox => "strongbox",
            Self::Tpm => "tpm",
            Self::Passkey => "passkey",
            Self::Recovery => "recovery",
        }
    }

    /// The holder with this wire name; any other holder, an operator key among them, is refused.
    ///
    /// # Errors
    /// [`DeviceError::HolderNotAllowed`].
    pub fn from_name(name: &str) -> Result<Self, DeviceError> {
        Self::ALL
            .into_iter()
            .find(|h| h.as_str() == name)
            .ok_or(DeviceError::HolderNotAllowed)
    }
}

/// Why a KEK copy cannot be made or opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeviceError {
    /// The holder is not a user device, passkey or recovery path.
    HolderNotAllowed,
    /// The HPKE seal or open failed.
    Hpke(HpkeError),
    /// The key wrap failed.
    Key(KeyError),
}

impl DeviceError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::HolderNotAllowed => "holder_not_allowed",
            Self::Hpke(e) => e.as_str(),
            Self::Key(e) => e.as_str(),
        }
    }
}

impl From<HpkeError> for DeviceError {
    fn from(e: HpkeError) -> Self {
        Self::Hpke(e)
    }
}

impl From<KeyError> for DeviceError {
    fn from(e: KeyError) -> Self {
        Self::Key(e)
    }
}

/// A KEK sealed to a Secure Enclave key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnclaveCopy {
    /// The HPKE encapsulation, a 65-byte P-256 point.
    pub enc: Vec<u8>,
    /// The sealed KEK with its tag.
    pub ct: Vec<u8>,
}

fn device_info(kek_id: &str) -> Vec<u8> {
    let mut info = DEVICE_INFO.to_vec();
    info.extend_from_slice(kek_id.as_bytes());
    info
}

/// Seals `kek` to the Secure Enclave public key `device_key`.
///
/// # Errors
/// [`DeviceError::Hpke`].
pub fn seal_to_enclave(
    kek_id: &str,
    kek: &Secret<[u8; 32]>,
    device_key: &[u8],
) -> Result<EnclaveCopy, DeviceError> {
    let (enc, mut ctx) = setup_sender(Kem::P256, device_key, &device_info(kek_id))?;
    let ct = ctx.seal(b"", kek.expose())?;
    Ok(EnclaveCopy { enc, ct })
}

/// Seals `kek` to `device_key` with the given ephemeral key, which is never reused.
///
/// # Errors
/// [`DeviceError::Hpke`].
pub fn seal_to_enclave_with(
    ephemeral: &KeyPair,
    kek_id: &str,
    kek: &Secret<[u8; 32]>,
    device_key: &[u8],
) -> Result<EnclaveCopy, DeviceError> {
    let (enc, mut ctx) = setup_sender_with(ephemeral, device_key, &device_info(kek_id))?;
    let ct = ctx.seal(b"", kek.expose())?;
    Ok(EnclaveCopy { enc, ct })
}

/// Opens a Secure Enclave copy with the enclave's key pair.
///
/// # Errors
/// [`DeviceError::Hpke`], [`DeviceError::Key`].
pub fn open_enclave_copy(
    device: &KeyPair,
    kek_id: &str,
    copy: &EnclaveCopy,
) -> Result<Secret<[u8; 32]>, DeviceError> {
    let mut ctx = setup_receiver(device, &copy.enc, &device_info(kek_id))?;
    let kek = ctx.open(b"", &copy.ct)?;
    Ok(key_from_slice(&kek)?)
}

/// Wraps `kek` under a StrongBox or TPM AES key.
///
/// # Errors
/// [`DeviceError::Key`].
pub fn wrap_for_device(
    device_key: &Secret<[u8; 32]>,
    kek: &Secret<[u8; 32]>,
) -> Result<[u8; WRAPPED_LEN], DeviceError> {
    Ok(wrap(device_key, kek)?)
}

/// The PRF evaluation input, fixed so every login with the passkey yields the same output.
#[must_use]
pub fn prf_input() -> [u8; 32] {
    Sha256::digest(PRF_LABEL).into()
}

/// The passkey wrapping key: HKDF-SHA256 with an empty salt over the PRF output, `info` = `one/kek/passkey/v1\0` and the KEK id.
///
/// # Errors
/// [`DeviceError::Key`].
pub fn passkey_wrapping_key(
    prf_output: &Secret<[u8; 32]>,
    kek_id: &str,
) -> Result<Secret<[u8; 32]>, DeviceError> {
    let mut info = PASSKEY_INFO.to_vec();
    info.extend_from_slice(kek_id.as_bytes());
    let prk = Salt::new(HKDF_SHA256, &[]).extract(prf_output.expose());
    let parts = [info.as_slice()];
    let okm = prk
        .expand(&parts, HKDF_SHA256)
        .map_err(|_| KeyError::Seal)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    okm.fill(key.as_mut_slice()).map_err(|_| KeyError::Seal)?;
    Ok(Secret::new(*key))
}

/// Wraps `kek` for a passkey whose PRF output is `prf_output`.
///
/// # Errors
/// [`DeviceError::Key`].
pub fn wrap_for_passkey(
    prf_output: &Secret<[u8; 32]>,
    kek_id: &str,
    kek: &Secret<[u8; 32]>,
) -> Result<[u8; WRAPPED_LEN], DeviceError> {
    Ok(wrap(&passkey_wrapping_key(prf_output, kek_id)?, kek)?)
}

/// Unwraps a passkey copy.
///
/// # Errors
/// [`DeviceError::Key`] for another passkey or a modified copy.
pub fn unwrap_passkey_copy(
    prf_output: &Secret<[u8; 32]>,
    kek_id: &str,
    wrapped: &[u8],
) -> Result<Secret<[u8; 32]>, DeviceError> {
    Ok(unwrap(&passkey_wrapping_key(prf_output, kek_id)?, wrapped)?)
}
