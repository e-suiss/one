//! The in-TEE job frame: the only place an [`Unsealed`] value is made, by opening a [`Sealed`] one through the key port (T-27 (3), T-6).

use core::fmt;

use zeroize::Zeroize;

use crate::ports::{OpenError, Opener};
use crate::sealed::Sealed;

/// Decrypted personal content: made only in this frame; it does not serialize, clone or display, its `Debug` is `[unsealed]`, no outside-TEE port takes it, and dropping it zeroes the content.
///
/// Serializing it does not compile:
///
/// ```compile_fail,E0277
/// fn leak(u: &one_tee::Unsealed<u32>) -> String {
///     serde_json::to_string(u).unwrap_or_default()
/// }
/// ```
///
/// Formatting it with `{}` does not compile:
///
/// ```compile_fail,E0277
/// fn leak(u: &one_tee::Unsealed<u32>) -> String {
///     format!("{u}")
/// }
/// ```
///
/// Cloning it does not compile:
///
/// ```compile_fail,E0599
/// fn copy(u: &one_tee::Unsealed<u32>) -> one_tee::Unsealed<u32> {
///     u.clone()
/// }
/// ```
///
/// Handing it to the outbox port does not compile:
///
/// ```compile_fail,E0277
/// fn send<O: one_tee::ports::Outbox>(outbox: &O, u: &one_tee::Unsealed<u32>) {
///     let _ = outbox.enqueue("one.memory.updated", u);
/// }
/// ```
///
/// Making one outside `one-tee` does not compile:
///
/// ```compile_fail,E0624
/// let u = one_tee::Unsealed::new(7_u32);
/// ```
///
/// A sealed value does go to the outbox:
///
/// ```
/// fn send<O: one_tee::ports::Outbox>(outbox: &O, s: &one_tee::Sealed<u32>) {
///     let _ = outbox.enqueue("one.memory.updated", s);
/// }
/// ```
pub struct Unsealed<T: Zeroize> {
    value: T,
}

impl<T: Zeroize> Unsealed<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self { value }
    }

    /// The content, for code running in the frame.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.value
    }

    /// A value computed from the content; it stays unsealed, and the content is zeroed.
    #[must_use]
    pub fn map<U: Zeroize>(self, f: impl FnOnce(&T) -> U) -> Unsealed<U> {
        Unsealed::new(f(&self.value))
    }
}

impl<T: Zeroize> Drop for Unsealed<T> {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

impl<T: Zeroize> fmt::Debug for Unsealed<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[unsealed]")
    }
}

/// Why a sealed value did not open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnsealError {
    /// The key port refused: unknown or shredded key, or a failed authentication tag.
    Open(OpenError),
    /// The plaintext is not a `T`.
    Decode,
}

/// Opens `sealed` through the key port and decodes it; the plaintext buffer is zeroed before returning.
///
/// # Errors
/// [`UnsealError::Open`] when the port refuses, [`UnsealError::Decode`] when the plaintext does not decode.
pub fn unseal<T: Zeroize, O: Opener + ?Sized>(
    opener: &O,
    sealed: &Sealed<T>,
    decode: impl FnOnce(&[u8]) -> Option<T>,
) -> Result<Unsealed<T>, UnsealError> {
    let mut plaintext = Vec::new();
    let result = opener
        .open(
            sealed.record_key_id(),
            sealed.aad(),
            sealed.ciphertext(),
            &mut plaintext,
        )
        .map_err(UnsealError::Open);
    let decoded = result.and_then(|()| decode(&plaintext).ok_or(UnsealError::Decode));
    plaintext.zeroize();
    decoded.map(Unsealed::new)
}
