//! AES-256-GCM for a credential file.
//!
//! The key is 32 bytes. Each file gets its own 12-byte nonce from the
//! operating system's random source. The authentication tag is the 16 bytes
//! AES-GCM appends to the ciphertext, so a file that was changed, or that
//! was sealed for a different credential id, does not open.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroize;

/// AES-256 key length, in bytes.
pub const KEY_LEN: usize = 32;

const NONCE_LEN: usize = 12;
const MAGIC: &[u8; 4] = b"O4W1";

/// A 256-bit key. The bytes are wiped when the value is dropped.
pub struct Aes256Key([u8; KEY_LEN]);

impl Aes256Key {
    /// Draw a new key from the operating system's random source.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Wrap 32 bytes that already exist, usually the bytes just read from
    /// the credential store.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

impl Drop for Aes256Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl Clone for Aes256Key {
    fn clone(&self) -> Self {
        Self(self.0)
    }
}

impl std::fmt::Debug for Aes256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Aes256Key([redacted])")
    }
}

/// Why a credential file could not be sealed or opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The file is not a credential this wallet sealed.
    NotACredential,
    /// The key is wrong, or the file was modified.
    AuthenticationFailed,
}

impl std::fmt::Display for SealError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotACredential => f.write_str(&crate::i18n::t("wallet.seal.not_credential")),
            Self::AuthenticationFailed => f.write_str(&crate::i18n::t("wallet.seal.auth_failed")),
        }
    }
}

impl std::error::Error for SealError {}

/// Additional data bound to one credential file. The id is not stored in the
/// ciphertext, so renaming the file makes `open` fail.
pub fn credential_aad(id: &str) -> Vec<u8> {
    let mut aad = b"oid4vc-wallet credential v1\n".to_vec();
    aad.extend_from_slice(id.as_bytes());
    aad
}

/// Seal `plaintext` for `aad` under `key`.
pub fn seal(key: &Aes256Key, aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, SealError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let sealed = seal_with_nonce(key, &nonce_bytes, aad, plaintext)?;
    nonce_bytes.zeroize();
    Ok(sealed)
}

fn seal_with_nonce(
    key: &Aes256Key,
    nonce_bytes: &[u8; NONCE_LEN],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256 key is 32 bytes");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| SealError::AuthenticationFailed)?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(nonce_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a file produced by [`seal`].
pub fn open(key: &Aes256Key, aad: &[u8], sealed: &[u8]) -> Result<Vec<u8>, SealError> {
    if sealed.len() < MAGIC.len() + NONCE_LEN + 16 || !sealed.starts_with(MAGIC) {
        return Err(SealError::NotACredential);
    }
    let nonce_bytes = &sealed[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ciphertext = &sealed[MAGIC.len() + NONCE_LEN..];
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256 key is 32 bytes");
    cipher
        .decrypt(
            Nonce::from_slice(nonce_bytes),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| SealError::AuthenticationFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_rejects_a_modified_file_or_a_different_id() {
        let key = Aes256Key::generate();
        let aad = credential_aad("abc");
        let sealed = seal(&key, &aad, b"credential-document").unwrap();
        assert!(!sealed.windows(9).any(|window| window == b"credential"));
        assert_eq!(open(&key, &aad, &sealed).unwrap(), b"credential-document");

        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            open(&key, &aad, &tampered),
            Err(SealError::AuthenticationFailed)
        );

        let other = Aes256Key::generate();
        assert_eq!(
            open(&other, &aad, &sealed),
            Err(SealError::AuthenticationFailed)
        );
        assert_eq!(
            open(&key, &credential_aad("other"), &sealed),
            Err(SealError::AuthenticationFailed)
        );
        assert_eq!(open(&key, &aad, b"nope"), Err(SealError::NotACredential));
    }

    #[test]
    fn debug_does_not_include_key_bytes() {
        let key = Aes256Key::from_bytes([0xab; KEY_LEN]);
        let rendered = format!("{key:?}");
        assert!(!rendered.contains("ab"));
        assert!(rendered.contains("redacted"));
    }
}
