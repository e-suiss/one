//! HPKE base mode (RFC 9180, mode 0x00) for the TEE request channel, the device KEK copy and the key permission: DHKEM(X25519, HKDF-SHA256) or DHKEM(P-256, HKDF-SHA256) with HKDF-SHA256 and AES-256-GCM, sequenced messages and the secret export, on aws-lc-rs until the shared Suiss crypto crate carries HPKE (SEC-27, PV-5, PV-65).

use aws_lc_rs::aead::{AES_256_GCM, Aad, LessSafeKey, NONCE_LEN, Nonce, UnboundKey};
use aws_lc_rs::agreement::{self, ECDH_P256, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::hmac;
use zeroize::Zeroizing;

/// HKDF-SHA256.
pub const KDF_ID: u16 = 0x0001;

/// AES-256-GCM.
pub const AEAD_ID: u16 = 0x0002;

const NK: usize = 32;
const NH: usize = 32;
const MAX_EXPAND: usize = 8160;

/// The key encapsulation mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kem {
    /// DHKEM(X25519, HKDF-SHA256): TEE nodes and job keys.
    X25519,
    /// DHKEM(P-256, HKDF-SHA256): the Secure Enclave, which holds only P-256 keys.
    P256,
}

impl Kem {
    /// The RFC 9180 identifier.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::X25519 => 0x0020,
            Self::P256 => 0x0010,
        }
    }

    /// The mechanism with this identifier.
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            0x0020 => Some(Self::X25519),
            0x0010 => Some(Self::P256),
            _ => None,
        }
    }

    fn algorithm(self) -> &'static agreement::Algorithm {
        match self {
            Self::X25519 => &X25519,
            Self::P256 => &ECDH_P256,
        }
    }

    fn kem_suite(self) -> [u8; 5] {
        let [a, b] = self.id().to_be_bytes();
        [b'K', b'E', b'M', a, b]
    }

    fn hpke_suite(self) -> [u8; 10] {
        let [a, b] = self.id().to_be_bytes();
        let [c, d] = KDF_ID.to_be_bytes();
        let [e, f] = AEAD_ID.to_be_bytes();
        [b'H', b'P', b'K', b'E', a, b, c, d, e, f]
    }
}

/// Why an HPKE operation failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HpkeError {
    /// A key is malformed, of another mechanism, or gives no shared secret.
    Key,
    /// A ciphertext does not open: another key, `info`, additional data or a modified ciphertext.
    Open,
    /// Sealing failed.
    Seal,
    /// A requested length or the message sequence is out of range.
    Length,
}

impl HpkeError {
    /// The error as the vectors write it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Key => "key",
            Self::Open => "open",
            Self::Seal => "seal",
            Self::Length => "length",
        }
    }
}

fn extract(salt: &[u8], ikm: &[&[u8]]) -> Zeroizing<Vec<u8>> {
    let key = hmac::Key::new(hmac::HMAC_SHA256, salt);
    let mut ctx = hmac::Context::with_key(&key);
    for part in ikm {
        ctx.update(part);
    }
    Zeroizing::new(ctx.sign().as_ref().to_vec())
}

fn expand(prk: &[u8], info: &[&[u8]], len: usize) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    if len > MAX_EXPAND {
        return Err(HpkeError::Length);
    }
    let key = hmac::Key::new(hmac::HMAC_SHA256, prk);
    let mut out = Zeroizing::new(Vec::with_capacity(len));
    let mut previous = Zeroizing::new(Vec::new());
    let mut block = 0_u8;
    while out.len() < len {
        block = block.checked_add(1).ok_or(HpkeError::Length)?;
        let mut ctx = hmac::Context::with_key(&key);
        ctx.update(&previous);
        for part in info {
            ctx.update(part);
        }
        ctx.update(&[block]);
        let t = ctx.sign();
        let need = len.saturating_sub(out.len());
        out.extend(t.as_ref().iter().take(need));
        *previous = t.as_ref().to_vec();
    }
    Ok(out)
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<Vec<u8>> {
    extract(salt, &[b"HPKE-v1", suite, label, ikm])
}

fn labeled_expand(
    suite: &[u8],
    prk: &[u8],
    label: &[u8],
    info: &[u8],
    len: usize,
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    let l = u16::try_from(len)
        .map_err(|_| HpkeError::Length)?
        .to_be_bytes();
    expand(prk, &[&l, b"HPKE-v1", suite, label, info], len)
}

/// A private key of one mechanism with its public key.
pub struct KeyPair {
    kem: Kem,
    key: PrivateKey,
}

impl KeyPair {
    /// A fresh key pair from the system random source.
    ///
    /// # Errors
    /// [`HpkeError::Key`].
    pub fn generate(kem: Kem) -> Result<Self, HpkeError> {
        let key = PrivateKey::generate(kem.algorithm()).map_err(|_| HpkeError::Key)?;
        Ok(Self { kem, key })
    }

    /// A key pair from its private key bytes: 32 raw bytes for X25519, the 32-byte scalar for P-256.
    ///
    /// # Errors
    /// [`HpkeError::Key`].
    pub fn from_private(kem: Kem, bytes: &[u8]) -> Result<Self, HpkeError> {
        let key =
            PrivateKey::from_private_key(kem.algorithm(), bytes).map_err(|_| HpkeError::Key)?;
        Ok(Self { kem, key })
    }

    /// The mechanism.
    #[must_use]
    pub const fn kem(&self) -> Kem {
        self.kem
    }

    /// The serialized public key: 32 bytes for X25519, the 65-byte uncompressed point for P-256.
    ///
    /// # Errors
    /// [`HpkeError::Key`].
    pub fn public_key(&self) -> Result<Vec<u8>, HpkeError> {
        Ok(self
            .key
            .compute_public_key()
            .map_err(|_| HpkeError::Key)?
            .as_ref()
            .to_vec())
    }

    fn dh(&self, public: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        agreement::agree(
            &self.key,
            &UnparsedPublicKey::new(self.kem.algorithm(), public),
            HpkeError::Key,
            |secret| Ok(Zeroizing::new(secret.to_vec())),
        )
    }
}

fn shared_secret(
    kem: Kem,
    dh: &[u8],
    enc: &[u8],
    pk_r: &[u8],
) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
    let suite = kem.kem_suite();
    let prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    let mut context = enc.to_vec();
    context.extend_from_slice(pk_r);
    labeled_expand(&suite, &prk, b"shared_secret", &context, NH)
}

/// An HPKE context: the AEAD key, base nonce, message sequence and exporter secret of one encapsulation.
pub struct Context {
    key: LessSafeKey,
    base_nonce: [u8; NONCE_LEN],
    sequence: u64,
    exporter: Zeroizing<Vec<u8>>,
    suite: [u8; 10],
    #[cfg(test)]
    secrets: (Vec<u8>, Vec<u8>),
}

impl Context {
    fn schedule(kem: Kem, shared: &[u8], info: &[u8]) -> Result<Self, HpkeError> {
        let suite = kem.hpke_suite();
        let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
        let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
        let mut context = vec![0_u8];
        context.extend_from_slice(&psk_id_hash);
        context.extend_from_slice(&info_hash);
        let secret = labeled_extract(&suite, shared, b"secret", b"");
        let key = labeled_expand(&suite, &secret, b"key", &context, NK)?;
        let nonce = labeled_expand(&suite, &secret, b"base_nonce", &context, NONCE_LEN)?;
        let exporter = labeled_expand(&suite, &secret, b"exp", &context, NH)?;
        let base_nonce: [u8; NONCE_LEN] =
            nonce.as_slice().try_into().map_err(|_| HpkeError::Key)?;
        Ok(Self {
            key: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key).map_err(|_| HpkeError::Key)?),
            base_nonce,
            sequence: 0,
            exporter,
            suite,
            #[cfg(test)]
            secrets: (shared.to_vec(), key.to_vec()),
        })
    }

    fn nonce(&mut self) -> Result<Nonce, HpkeError> {
        let mut n = self.base_nonce;
        let seq = self.sequence.to_be_bytes();
        let tail = n.iter_mut().rev().zip(seq.iter().rev());
        for (byte, s) in tail {
            *byte ^= *s;
        }
        self.sequence = self.sequence.checked_add(1).ok_or(HpkeError::Length)?;
        Ok(Nonce::assume_unique_for_key(n))
    }

    /// Encrypts the next message.
    ///
    /// # Errors
    /// [`HpkeError::Seal`], [`HpkeError::Length`] past the last sequence number.
    pub fn seal(&mut self, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, HpkeError> {
        let nonce = self.nonce()?;
        let mut buf = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(aad), &mut buf)
            .map_err(|_| HpkeError::Seal)?;
        Ok(buf)
    }

    /// Decrypts the next message.
    ///
    /// # Errors
    /// [`HpkeError::Open`], [`HpkeError::Length`] past the last sequence number.
    pub fn open(&mut self, aad: &[u8], ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        let nonce = self.nonce()?;
        let mut buf = Zeroizing::new(ciphertext.to_vec());
        let len = self
            .key
            .open_in_place(nonce, Aad::from(aad), buf.as_mut_slice())
            .map_err(|_| HpkeError::Open)?
            .len();
        buf.truncate(len);
        Ok(buf)
    }

    /// A secret of `len` bytes for `exporter_context`, such as the response key of a TEE request.
    ///
    /// # Errors
    /// [`HpkeError::Length`] above 65 535 bytes or the HKDF limit.
    pub fn export(
        &self,
        exporter_context: &[u8],
        len: usize,
    ) -> Result<Zeroizing<Vec<u8>>, HpkeError> {
        labeled_expand(&self.suite, &self.exporter, b"sec", exporter_context, len)
    }
}

/// Encapsulates to `pk_r` with a fresh ephemeral key; returns `enc` and the sender context.
///
/// # Errors
/// [`HpkeError::Key`] for a malformed recipient key.
pub fn setup_sender(kem: Kem, pk_r: &[u8], info: &[u8]) -> Result<(Vec<u8>, Context), HpkeError> {
    setup_sender_with(&KeyPair::generate(kem)?, pk_r, info)
}

/// Encapsulates to `pk_r` with `ephemeral`, which is never used for a second encapsulation.
///
/// # Errors
/// [`HpkeError::Key`] for a malformed recipient key.
pub fn setup_sender_with(
    ephemeral: &KeyPair,
    pk_r: &[u8],
    info: &[u8],
) -> Result<(Vec<u8>, Context), HpkeError> {
    let kem = ephemeral.kem();
    let dh = ephemeral.dh(pk_r)?;
    let enc = ephemeral.public_key()?;
    let shared = shared_secret(kem, &dh, &enc, pk_r)?;
    Ok((enc, Context::schedule(kem, &shared, info)?))
}

/// Decapsulates `enc` with the recipient's key pair.
///
/// # Errors
/// [`HpkeError::Key`] for a malformed or foreign `enc`.
pub fn setup_receiver(recipient: &KeyPair, enc: &[u8], info: &[u8]) -> Result<Context, HpkeError> {
    let kem = recipient.kem();
    let dh = recipient.dh(enc)?;
    let pk_r = recipient.public_key()?;
    let shared = shared_secret(kem, &dh, enc, &pk_r)?;
    Context::schedule(kem, &shared, info)
}

#[cfg(test)]
mod tests;
