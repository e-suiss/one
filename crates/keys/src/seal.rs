//! The OP-4 key hierarchy over the shared Suiss envelope: a record key and a class DEK are wrapped with AES-256 Key Wrap (RFC 3394) to the key above them, each record part is sealed as one AES-256-GCM message under a key derived from the record key with HKDF-SHA256, and the additional data names owner, record, class and part so a part opens nowhere else (OP-4 (1), OP-5, M-25).

use aws_lc_rs::hkdf::{HKDF_SHA256, Salt};
use aws_lc_rs::key_wrap::{AES_256, AesKek, KeyWrap as _};
use one_proto::data_class::RetentionClass;
use suiss_crypto::envelope::{self, Dek, EnvelopeError, Sealed};
use suiss_crypto::secret::Secret;
use zeroize::Zeroizing;

/// The record context that follows the shared `access/aead/v1\0` prefix.
pub const RECORD_CONTEXT: &[u8] = b"one/record/v1\0";

/// The HKDF `info` prefix of a part key.
pub const PART_INFO: &[u8] = b"one/record/v1/part\0";

/// The format value every stored ciphertext starts with; a new format gets a new value and old values stay readable until re-encrypted (OP-27, T-32 (7)).
pub const FORMAT_V1: u8 = 1;

/// The length of a wrapped 256-bit key.
pub const WRAPPED_LEN: usize = 40;

/// Why a key operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyError {
    /// A key is not 256 bits.
    KeyLength,
    /// A wrapped key does not unwrap under this key: another key or a modified copy.
    Integrity,
    /// A part does not open: another key, another context or a modified ciphertext.
    Open,
    /// Sealing failed.
    Seal,
    /// A stored ciphertext has an unknown format value or is too short.
    Format,
}

impl KeyError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::KeyLength => "key_length",
            Self::Integrity => "integrity",
            Self::Open => "open",
            Self::Seal => "seal",
            Self::Format => "format",
        }
    }
}

impl From<EnvelopeError> for KeyError {
    fn from(e: EnvelopeError) -> Self {
        match e {
            EnvelopeError::Open => Self::Open,
            EnvelopeError::Wrap => Self::Integrity,
            _ => Self::Seal,
        }
    }
}

/// A part of a record, each sealed under its own derived key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Part {
    /// The record's content.
    Content,
    /// A summary.
    Summary,
    /// An embedding vector.
    Embedding,
    /// A text view.
    TextView,
    /// An object in the object store.
    Object,
}

impl Part {
    /// Every part.
    pub const ALL: [Self; 5] = [
        Self::Content,
        Self::Summary,
        Self::Embedding,
        Self::TextView,
        Self::Object,
    ];

    /// The wire name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Content => "content",
            Self::Summary => "summary",
            Self::Embedding => "embedding",
            Self::TextView => "text_view",
            Self::Object => "object",
        }
    }

    /// The part with this wire name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|p| p.as_str() == name)
    }
}

/// Where a sealed part belongs; every field is bound into its additional data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PartRef<'a> {
    /// The account the record belongs to.
    pub owner: &'a str,
    /// The record's typed id text.
    pub record: &'a str,
    /// The record's retention class.
    pub class: RetentionClass,
    /// The part.
    pub part: Part,
    /// The part's version; a new version gets a new key.
    pub version: u32,
}

impl PartRef<'_> {
    /// The context after the shared prefix: `one/record/v1\0` owner `\0` record `\0` class `\0` part.
    #[must_use]
    pub fn context(&self) -> Vec<u8> {
        let mut c = RECORD_CONTEXT.to_vec();
        for field in [self.owner, self.record, self.class.as_str()] {
            c.extend_from_slice(field.as_bytes());
            c.push(0);
        }
        c.extend_from_slice(self.part.as_str().as_bytes());
        c
    }

    fn info(&self) -> Vec<u8> {
        let mut info = PART_INFO.to_vec();
        info.extend_from_slice(self.part.as_str().as_bytes());
        info.push(0);
        info.extend_from_slice(self.version.to_string().as_bytes());
        info
    }
}

/// A 256-bit key from its bytes.
///
/// # Errors
/// [`KeyError::KeyLength`] for any other length.
pub fn key_from_slice(bytes: &[u8]) -> Result<Secret<[u8; 32]>, KeyError> {
    let key: [u8; 32] = bytes.try_into().map_err(|_| KeyError::KeyLength)?;
    Ok(Secret::new(key))
}

/// Wraps `key` under `kek`: a record key under its class DEK, or a class DEK under the user's KEK.
///
/// # Errors
/// [`KeyError::Seal`].
pub fn wrap(kek: &Secret<[u8; 32]>, key: &Secret<[u8; 32]>) -> Result<[u8; WRAPPED_LEN], KeyError> {
    let kek = AesKek::new(&AES_256, kek.expose()).map_err(|_| KeyError::Seal)?;
    let mut out = [0_u8; WRAPPED_LEN];
    let n = kek
        .wrap(key.expose(), &mut out)
        .map_err(|_| KeyError::Seal)?
        .len();
    if n == WRAPPED_LEN {
        Ok(out)
    } else {
        Err(KeyError::Seal)
    }
}

/// Unwraps a key wrapped under `kek`.
///
/// # Errors
/// [`KeyError::Integrity`] for another KEK or a modified wrapped key.
pub fn unwrap(kek: &Secret<[u8; 32]>, wrapped: &[u8]) -> Result<Secret<[u8; 32]>, KeyError> {
    let kek = AesKek::new(&AES_256, kek.expose()).map_err(|_| KeyError::Integrity)?;
    let mut out = Zeroizing::new([0_u8; WRAPPED_LEN]);
    let plain = kek
        .unwrap(wrapped, out.as_mut_slice())
        .map_err(|_| KeyError::Integrity)?;
    let key: [u8; 32] = (&*plain).try_into().map_err(|_| KeyError::Integrity)?;
    Ok(Secret::new(key))
}

/// The key of one version of one part: HKDF-SHA256 with an empty salt over the record key, `info` = `one/record/v1/part\0` part `\0` version.
///
/// # Errors
/// [`KeyError::Seal`].
pub fn part_key(record_key: &Secret<[u8; 32]>, part: &PartRef<'_>) -> Result<Dek, KeyError> {
    let info = part.info();
    let prk = Salt::new(HKDF_SHA256, &[]).extract(record_key.expose());
    let parts = [info.as_slice()];
    let okm = prk
        .expand(&parts, HKDF_SHA256)
        .map_err(|_| KeyError::Seal)?;
    let mut key = Zeroizing::new([0_u8; 32]);
    okm.fill(key.as_mut_slice()).map_err(|_| KeyError::Seal)?;
    Ok(Dek::from_secret(Secret::new(*key)))
}

/// Seals one part as a single AES-256-GCM message under its derived key.
///
/// # Errors
/// [`KeyError::Seal`].
pub fn seal_part(
    record_key: &Secret<[u8; 32]>,
    part: &PartRef<'_>,
    plaintext: &[u8],
) -> Result<Sealed, KeyError> {
    Ok(envelope::seal_body(
        part_key(record_key, part)?,
        &part.context(),
        plaintext,
    )?)
}

/// Opens a sealed part.
///
/// # Errors
/// [`KeyError::Open`] for another record key, another place or a modified ciphertext.
pub fn open_part(
    record_key: &Secret<[u8; 32]>,
    part: &PartRef<'_>,
    sealed: &Sealed,
) -> Result<Zeroizing<Vec<u8>>, KeyError> {
    let key = part_key(record_key, part)?;
    envelope::open_body(&key, &part.context(), sealed).map_err(|_| KeyError::Open)
}

/// The stored form of a sealed part: the format value, the nonce, then ciphertext and tag.
#[must_use]
pub fn to_stored(sealed: &Sealed) -> Vec<u8> {
    let mut out = Vec::with_capacity(sealed.ciphertext.len().saturating_add(13));
    out.push(FORMAT_V1);
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.ciphertext);
    out
}

/// A sealed part from its stored form.
///
/// # Errors
/// [`KeyError::Format`] for an unknown format value or a truncated value.
pub fn from_stored(stored: &[u8]) -> Result<Sealed, KeyError> {
    let (&format, rest) = stored.split_first().ok_or(KeyError::Format)?;
    if format != FORMAT_V1 {
        return Err(KeyError::Format);
    }
    let (nonce, ciphertext) = rest.split_at_checked(12).ok_or(KeyError::Format)?;
    if ciphertext.len() < 16 {
        return Err(KeyError::Format);
    }
    Ok(Sealed {
        nonce: nonce.try_into().map_err(|_| KeyError::Format)?,
        ciphertext: ciphertext.to_vec(),
    })
}
