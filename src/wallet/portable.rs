//! A sealed copy of credentials, for moving them to another device.
//!
//! The file starts with the ASCII magic `OID4VC1` and a newline, then a
//! 12-byte nonce, then AES-256-GCM ciphertext and its tag. The additional
//! data is `OID4VC1`. The key is a new 32-byte value returned as standard
//! base64. It is not the key that seals the wallet's own files, and it is
//! not written into the file.

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use zeroize::Zeroize;

use crate::protocol::Json;

use super::b64;
use super::credentials::{Credential, NewCredential};
use super::seal::{Aes256Key, KEY_LEN};

/// ASCII magic at the start of an export file, including the newline.
const MAGIC: &[u8] = b"OID4VC1\n";
/// Additional data bound to the ciphertext. It does not include the newline.
const AAD: &[u8] = b"OID4VC1";
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// Ciphertext for another device, and the key that opens it.
///
/// `key` is standard base64, with padding, of a fresh 32-byte AES-256 key.
/// It is not the key GNOME Keyring or KWallet holds for this wallet.
pub struct PortableExport {
    pub bytes: Vec<u8>,
    pub key: String,
}

impl std::fmt::Debug for PortableExport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PortableExport")
            .field("bytes", &self.bytes.len())
            .field("key", &"[redacted]")
            .finish()
    }
}

/// Why an export could not be written or opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortableError {
    /// No credential was given.
    Empty,
    /// The magic is wrong, the file is truncated, or the key does not open it.
    BadKey,
}

impl std::fmt::Display for PortableError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match self {
            Self::Empty => crate::i18n::t("wallet.export.empty"),
            Self::BadKey => crate::i18n::t("wallet.export.bad_key"),
        };
        f.write_str(&message)
    }
}

impl std::error::Error for PortableError {}

/// Seal `credentials` under a new AES-256 key.
///
/// Pass one credential, or every credential. An empty slice is
/// [`PortableError::Empty`].
pub fn export_credentials(credentials: &[Credential]) -> Result<PortableExport, PortableError> {
    if credentials.is_empty() {
        return Err(PortableError::Empty);
    }
    let key = Aes256Key::generate();
    let mut plaintext = encode_documents(credentials);
    let sealed = seal(&key, plaintext.as_bytes());
    plaintext.zeroize();
    Ok(PortableExport {
        bytes: sealed?,
        key: b64::b64_encode(key.as_bytes()),
    })
}

/// Open a file from [`export_credentials`].
///
/// `key` is the standard base64 text that export returned. A holder key,
/// including its private `d`, is returned unchanged.
pub fn import_credentials(bytes: &[u8], key: &str) -> Result<Vec<NewCredential>, PortableError> {
    let key = decode_key(key)?;
    let mut plaintext = open(&key, bytes)?;
    let parsed = decode_documents(&plaintext);
    plaintext.zeroize();
    parsed
}

fn seal(key: &Aes256Key, plaintext: &[u8]) -> Result<Vec<u8>, PortableError> {
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256 key is 32 bytes");
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload {
                msg: plaintext,
                aad: AAD,
            },
        )
        .map_err(|_| PortableError::BadKey)?;
    let mut out = Vec::with_capacity(MAGIC.len() + NONCE_LEN + ciphertext.len());
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ciphertext);
    nonce_bytes.zeroize();
    Ok(out)
}

fn open(key: &Aes256Key, sealed: &[u8]) -> Result<String, PortableError> {
    if sealed.len() < MAGIC.len() + NONCE_LEN + TAG_LEN || !sealed.starts_with(MAGIC) {
        return Err(PortableError::BadKey);
    }
    let nonce = &sealed[MAGIC.len()..MAGIC.len() + NONCE_LEN];
    let ciphertext = &sealed[MAGIC.len() + NONCE_LEN..];
    let cipher = Aes256Gcm::new_from_slice(key.as_bytes()).expect("AES-256 key is 32 bytes");
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: AAD,
            },
        )
        .map_err(|_| PortableError::BadKey)?;
    match String::from_utf8(plaintext) {
        Ok(text) => Ok(text),
        Err(err) => {
            let mut bytes = err.into_bytes();
            bytes.zeroize();
            Err(PortableError::BadKey)
        }
    }
}

fn decode_key(text: &str) -> Result<Aes256Key, PortableError> {
    let mut bytes = match b64::b64_decode(text) {
        Some(bytes) => bytes,
        None => return Err(PortableError::BadKey),
    };
    if bytes.len() != KEY_LEN {
        bytes.zeroize();
        return Err(PortableError::BadKey);
    }
    let mut key_bytes = [0u8; KEY_LEN];
    key_bytes.copy_from_slice(&bytes);
    bytes.zeroize();
    let key = Aes256Key::from_bytes(key_bytes);
    key_bytes.zeroize();
    Ok(key)
}

fn encode_documents(credentials: &[Credential]) -> String {
    let items = credentials
        .iter()
        .map(|credential| {
            let holder_key = match &credential.holder_key {
                Some(key) => Json::String(key.clone()),
                None => Json::Null,
            };
            Json::Object(vec![
                (
                    "format".to_string(),
                    Json::String(credential.format.clone()),
                ),
                (
                    "issuer".to_string(),
                    Json::String(credential.issuer.clone()),
                ),
                (
                    "document".to_string(),
                    Json::String(credential.document.clone()),
                ),
                ("holder_key".to_string(), holder_key),
            ])
        })
        .collect();
    Json::Array(items).to_string()
}

fn decode_documents(text: &str) -> Result<Vec<NewCredential>, PortableError> {
    let value = Json::parse(text).map_err(|_| PortableError::BadKey)?;
    let items = value.as_array().ok_or(PortableError::BadKey)?;
    let mut credentials = Vec::with_capacity(items.len());
    for item in items {
        credentials.push(decode_one(item)?);
    }
    Ok(credentials)
}

fn decode_one(item: &Json) -> Result<NewCredential, PortableError> {
    let members = item.as_object().ok_or(PortableError::BadKey)?;
    let mut format = None;
    let mut issuer = None;
    let mut document = None;
    let mut holder_key = None;
    let mut saw_holder = false;
    for (name, member) in members {
        match name.as_str() {
            "format" => assign(&mut format, string_member(member)?)?,
            "issuer" => assign(&mut issuer, string_member(member)?)?,
            "document" => assign(&mut document, string_member(member)?)?,
            "holder_key" => {
                if saw_holder {
                    return Err(PortableError::BadKey);
                }
                saw_holder = true;
                holder_key = holder_member(member)?;
            }
            _ => return Err(PortableError::BadKey),
        }
    }
    if !saw_holder {
        return Err(PortableError::BadKey);
    }
    Ok(NewCredential {
        format: format.ok_or(PortableError::BadKey)?,
        issuer: issuer.ok_or(PortableError::BadKey)?,
        document: document.ok_or(PortableError::BadKey)?,
        holder_key,
    })
}

fn assign(slot: &mut Option<String>, value: String) -> Result<(), PortableError> {
    if slot.is_some() {
        return Err(PortableError::BadKey);
    }
    *slot = Some(value);
    Ok(())
}

fn string_member(member: &Json) -> Result<String, PortableError> {
    member
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or(PortableError::BadKey)
}

fn holder_member(member: &Json) -> Result<Option<String>, PortableError> {
    match member {
        Json::Null => Ok(None),
        Json::String(text) => Ok(Some(text.clone())),
        _ => Err(PortableError::BadKey),
    }
}

#[cfg(test)]
mod tests {
    use aes_gcm::aead::{Aead, KeyInit, Payload};
    use aes_gcm::{Aes256Gcm, Nonce};

    use super::b64;
    use super::*;
    use super::{Credential, KEY_LEN};

    const MARKER: &str = "DOCUMENT-PLAINTEXT-MARKER-oid4vc-export";
    const HOLDER: &str = r#"{"kty":"EC","d":"private-d-marker"}"#;

    fn credential(document: &str, holder_key: Option<&str>) -> Credential {
        Credential {
            id: "0123456789abcdef0123456789abcdef".to_string(),
            format: "dc+sd-jwt".to_string(),
            issuer: "https://issuer.example".to_string(),
            received_at: "20261018T120000.000Z".to_string(),
            document: document.to_string(),
            holder_key: holder_key.map(str::to_string),
        }
    }

    fn assert_canonical_key(key: &str) {
        let bytes = b64::b64_decode(key).expect("key is base64");
        assert_eq!(bytes.len(), KEY_LEN);
        assert_eq!(b64::b64_encode(&bytes), key);
        assert_eq!(key.len(), 44);
        assert!(key.ends_with('='));
        assert!(!key.ends_with("=="));
    }

    #[test]
    fn round_trips_one_credential_and_two_with_a_holder_key() {
        let one = credential("header.payload.sig", None);
        let exported = export_credentials(std::slice::from_ref(&one)).unwrap();
        assert!(exported.bytes.starts_with(b"OID4VC1\n"));
        assert_canonical_key(&exported.key);
        let imported = import_credentials(&exported.bytes, &exported.key).unwrap();
        assert_eq!(imported.len(), 1);
        assert_eq!(imported[0].format, one.format);
        assert_eq!(imported[0].issuer, one.issuer);
        assert_eq!(imported[0].document, one.document);
        assert_eq!(imported[0].holder_key, None);
        let plain = decrypt_for_test(&exported.bytes, &exported.key);
        assert_eq!(
            plain,
            r#"[{"format":"dc+sd-jwt","issuer":"https://issuer.example","document":"header.payload.sig","holder_key":null}]"#
        );

        let first = credential(MARKER, Some(HOLDER));
        let second = credential("other-document", None);
        let exported = export_credentials(&[first, second]).unwrap();
        let imported = import_credentials(&exported.bytes, &exported.key).unwrap();
        assert_eq!(imported.len(), 2);
        assert_eq!(imported[0].document, MARKER);
        assert_eq!(imported[0].holder_key.as_deref(), Some(HOLDER));
        assert!(imported[0].holder_key.as_ref().unwrap().contains("\"d\""));
        assert_eq!(imported[1].format, "dc+sd-jwt");
        assert_eq!(imported[1].issuer, "https://issuer.example");
        assert_eq!(imported[1].document, "other-document");
        assert_eq!(imported[1].holder_key, None);
        let plain = decrypt_for_test(&exported.bytes, &exported.key);
        assert!(plain.contains(MARKER));
        assert!(plain.contains("private-d-marker"));
        assert!(!plain.contains("0123456789abcdef0123456789abcdef"));
        assert!(!plain.contains("20261018T120000.000Z"));
    }

    #[test]
    fn a_wrong_key_truncated_file_or_bad_magic_does_not_open() {
        let exported = export_credentials(&[credential("doc", None)]).unwrap();
        let other = export_credentials(&[credential("doc", None)]).unwrap();
        let err = must_fail(import_credentials(&exported.bytes, &other.key));
        assert_eq!(err, PortableError::BadKey);
        assert_eq!(
            err.to_string(),
            "The export could not be opened. The encryption key may be wrong."
        );

        let mut wrong = exported.key.chars().collect::<Vec<_>>();
        wrong[0] = if wrong[0] == 'A' { 'B' } else { 'A' };
        let wrong: String = wrong.into_iter().collect();
        assert_eq!(
            must_fail(import_credentials(&exported.bytes, &wrong)),
            PortableError::BadKey
        );
        assert_eq!(
            must_fail(import_credentials(&exported.bytes, "aa")),
            PortableError::BadKey
        );
        assert_eq!(
            must_fail(import_credentials(&exported.bytes, "")),
            PortableError::BadKey
        );

        assert_eq!(
            must_fail(import_credentials(&exported.bytes[..20], &exported.key)),
            PortableError::BadKey
        );
        let mut short = exported.bytes.clone();
        short.pop();
        assert_eq!(
            must_fail(import_credentials(&short, &exported.key)),
            PortableError::BadKey
        );
        let mut bad_magic = exported.bytes.clone();
        bad_magic[0] = b'X';
        assert_eq!(
            must_fail(import_credentials(&bad_magic, &exported.key)),
            PortableError::BadKey
        );
        let mut tampered = exported.bytes.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            must_fail(import_credentials(&tampered, &exported.key)),
            PortableError::BadKey
        );
    }

    fn must_fail<T>(result: Result<T, PortableError>) -> PortableError {
        match result {
            Ok(_) => panic!("the export opened"),
            Err(err) => err,
        }
    }

    #[test]
    fn an_empty_export_is_refused() {
        let err = export_credentials(&[]).unwrap_err();
        assert_eq!(err, PortableError::Empty);
        assert_eq!(
            err.to_string(),
            "Check a credential, or export all of them."
        );
    }

    #[test]
    fn the_ciphertext_hides_the_document_and_each_export_has_a_new_key() {
        let credential = credential(MARKER, Some(HOLDER));
        let first = export_credentials(std::slice::from_ref(&credential)).unwrap();
        let second = export_credentials(std::slice::from_ref(&credential)).unwrap();
        assert_ne!(first.key, second.key);
        assert_ne!(first.bytes, second.bytes);
        assert_canonical_key(&first.key);
        assert_canonical_key(&second.key);

        let rendered = format!("{first:?}");
        assert!(!rendered.contains(&first.key));
        assert!(rendered.contains("redacted"));

        for exported in [&first, &second] {
            assert!(
                !exported
                    .bytes
                    .windows(MARKER.len())
                    .any(|window| window == MARKER.as_bytes()),
                "document plaintext leaked into the export"
            );
            assert!(!exported
                .bytes
                .windows(b"private-d-marker".len())
                .any(|window| window == b"private-d-marker"));
            let raw = b64::b64_decode(&exported.key).unwrap();
            assert!(!exported.bytes.windows(KEY_LEN).any(|window| window == raw));
            assert!(!exported
                .bytes
                .windows(exported.key.len())
                .any(|window| window == exported.key.as_bytes()));
        }
    }

    /// Decrypt with the public layout, so a wrong magic or AAD fails this check.
    fn decrypt_for_test(bytes: &[u8], key: &str) -> String {
        assert_eq!(&bytes[..8], b"OID4VC1\n");
        let raw = b64::b64_decode(key).unwrap();
        let cipher = Aes256Gcm::new_from_slice(&raw).unwrap();
        let plain = cipher
            .decrypt(
                Nonce::from_slice(&bytes[8..20]),
                Payload {
                    msg: &bytes[20..],
                    aad: b"OID4VC1",
                },
            )
            .unwrap();
        String::from_utf8(plain).unwrap()
    }
}
