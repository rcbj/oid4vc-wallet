//! Seal the storage-key bundle with the 32-byte FIDO hmac-secret output.
//!
//! That output is already an AES-256 key. It is not mixed again. The salt
//! that produced it lives in the protection file and is not a secret. The
//! nonce is the only fresh value stored beside the ciphertext.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroize;

use super::key_store::KeyStoreError;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// `nonce || ciphertext`, sealed under `kek`.
pub(super) fn seal(kek: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    let mut key = *kek;
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key is 32 bytes");
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce_bytes), plaintext)
        .map_err(|_| {
            key.zeroize();
            nonce_bytes.zeroize();
            unwrap_error()
        })?;
    key.zeroize();
    let mut out = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&nonce_bytes);
    nonce_bytes.zeroize();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob from [`seal`].
pub(super) fn open(kek: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    if sealed.len() < NONCE_LEN + TAG_LEN {
        return Err(unwrap_error());
    }
    let mut key = *kek;
    let nonce = &sealed[..NONCE_LEN];
    let ciphertext = &sealed[NONCE_LEN..];
    let cipher = Aes256Gcm::new_from_slice(&key).expect("AES-256 key is 32 bytes");
    let plain = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| {
            key.zeroize();
            unwrap_error()
        })?;
    key.zeroize();
    Ok(plain)
}

fn unwrap_error() -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t("wallet.fido.unwrap"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrap_opens_with_the_same_kek_and_not_with_another() {
        let kek = [0x11; 32];
        let plaintext = b"storage-key-bytes-for-the-test!!";
        let sealed = seal(&kek, plaintext).unwrap();
        let again = seal(&kek, plaintext).unwrap();
        assert_ne!(sealed, again);
        assert_eq!(open(&kek, &sealed).unwrap(), plaintext);
        assert!(open(&[0x22; 32], &sealed).is_err());
        assert!(open(&kek, &sealed[..sealed.len() - 1]).is_err());
    }
}
