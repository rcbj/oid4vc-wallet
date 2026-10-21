//! Wrap the AES-256 storage key to a P-256 public key.
//!
//! The private key stays on the YubiKey. This module agrees a shared secret
//! with an ephemeral P-256 key, turns that secret into an AES-256 key with
//! HKDF, and seals the storage key with AES-256-GCM. The same HKDF runs on
//! the X coordinate the card returns, so the host never needs the card's
//! private key.

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use p256::ecdh::diffie_hellman;
use p256::elliptic_curve::ecdh::SharedSecret;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroize;

use super::key_store::KeyStoreError;

const SALT: &[u8] = b"oid4vc-wallet kek salt v1";
const INFO: &[u8] = b"oid4vc-wallet yubikey dek v1";
const EPHEMERAL_LEN: usize = 65;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// `ephemeral point || nonce || ciphertext`, sealed to `recipient`.
pub(super) fn seal(
    recipient: &[u8; EPHEMERAL_LEN],
    plaintext: &[u8],
) -> Result<Vec<u8>, KeyStoreError> {
    let public = PublicKey::from_sec1_bytes(recipient).map_err(|_| unwrap_error())?;
    let ephemeral = SecretKey::random(&mut OsRng);
    let shared = diffie_hellman(ephemeral.to_nonzero_scalar(), *public.as_affine());
    let mut key = derive(&shared)?;
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
    let point = uncompressed_point(&ephemeral.public_key());
    let mut out = Vec::with_capacity(EPHEMERAL_LEN + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(&point);
    out.extend_from_slice(&nonce_bytes);
    nonce_bytes.zeroize();
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Open a blob from [`seal`] with the X coordinate of the shared secret.
pub(super) fn open(shared_x: &[u8; 32], sealed: &[u8]) -> Result<Vec<u8>, KeyStoreError> {
    if sealed.len() < EPHEMERAL_LEN + NONCE_LEN + TAG_LEN {
        return Err(unwrap_error());
    }
    let nonce = &sealed[EPHEMERAL_LEN..EPHEMERAL_LEN + NONCE_LEN];
    let ciphertext = &sealed[EPHEMERAL_LEN + NONCE_LEN..];
    let mut field = p256::FieldBytes::default();
    field.copy_from_slice(shared_x);
    let shared = SharedSecret::<p256::NistP256>::from(field);
    let mut key = derive(&shared)?;
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

/// The ephemeral point stored at the front of a blob from [`seal`].
pub(super) fn ephemeral_point(sealed: &[u8]) -> Result<[u8; EPHEMERAL_LEN], KeyStoreError> {
    if sealed.len() < EPHEMERAL_LEN || sealed[0] != 0x04 {
        return Err(unwrap_error());
    }
    let mut point = [0u8; EPHEMERAL_LEN];
    point.copy_from_slice(&sealed[..EPHEMERAL_LEN]);
    PublicKey::from_sec1_bytes(&point).map_err(|_| unwrap_error())?;
    Ok(point)
}

/// The card's decipher of a P-256 point is the shared X, a raw point, or a short integer.
pub(super) fn shared_x_from_card(bytes: &[u8]) -> Result<[u8; 32], KeyStoreError> {
    let mut x = [0u8; 32];
    if bytes.len() == 32 {
        x.copy_from_slice(bytes);
    } else if bytes.len() == EPHEMERAL_LEN && bytes[0] == 0x04 {
        x.copy_from_slice(&bytes[1..33]);
    } else if (1..32).contains(&bytes.len()) {
        x[32 - bytes.len()..].copy_from_slice(bytes);
    } else {
        return Err(unwrap_error());
    }
    Ok(x)
}

pub(super) fn uncompressed_point(public: &PublicKey) -> [u8; EPHEMERAL_LEN] {
    let encoded = public.to_encoded_point(false);
    let mut point = [0u8; EPHEMERAL_LEN];
    point.copy_from_slice(encoded.as_bytes());
    point
}

fn derive(shared: &SharedSecret<p256::NistP256>) -> Result<[u8; 32], KeyStoreError> {
    let mut okm = [0u8; 32];
    shared
        .extract::<Sha256>(Some(SALT))
        .expand(INFO, &mut okm)
        .map_err(|_| unwrap_error())?;
    Ok(okm)
}

fn unwrap_error() -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t("wallet.yubi.unwrap"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_wrap_opens_with_the_recipients_secret_and_not_with_another() {
        let recipient = SecretKey::random(&mut OsRng);
        let public = uncompressed_point(&recipient.public_key());
        let plaintext = b"storage-key-bytes-for-the-test!!";
        let sealed = seal(&public, plaintext).unwrap();
        let again = seal(&public, plaintext).unwrap();
        assert_ne!(sealed, again);
        let opened = open(&agree(&recipient, &sealed), &sealed).unwrap();
        assert_eq!(opened, plaintext);
        let stranger = SecretKey::random(&mut OsRng);
        assert!(open(&agree(&stranger, &sealed), &sealed).is_err());
    }

    #[test]
    fn the_card_coordinate_may_be_a_point_or_a_short_integer() {
        let mut x = [0u8; 32];
        x[31] = 0x2a;
        assert_eq!(shared_x_from_card(&x).unwrap(), x);
        let mut point = vec![0x04];
        point.extend_from_slice(&x);
        point.extend_from_slice(&[0u8; 32]);
        assert_eq!(shared_x_from_card(&point).unwrap(), x);
        assert_eq!(shared_x_from_card(&[0x2a]).unwrap()[31], 0x2a);
        assert!(shared_x_from_card(&[]).is_err());
        assert!(shared_x_from_card(&[0u8; 40]).is_err());
    }

    fn agree(secret: &SecretKey, sealed: &[u8]) -> [u8; 32] {
        let point = ephemeral_point(sealed).unwrap();
        let public = PublicKey::from_sec1_bytes(&point).unwrap();
        let shared = diffie_hellman(secret.to_nonzero_scalar(), *public.as_affine());
        let mut x = [0u8; 32];
        x.copy_from_slice(shared.raw_secret_bytes());
        x
    }
}
