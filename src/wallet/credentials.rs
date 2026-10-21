//! Verifiable credentials sealed with the AES-256 key from GNOME Keyring
//! or KWallet. Settings can instead wrap that key to two FIDO2 security
//! keys, and the process then needs a PIN before it can read.
//!
//! Each credential is one file under the wallet's data directory. The file
//! holds the nonce and the AES-256-GCM ciphertext. The format, the issuer,
//! the time, and the credential document are inside that ciphertext. The
//! file name is the credential id, and that id is bound to the ciphertext,
//! so the file cannot be renamed onto another id.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::OsRng;

use crate::protocol::is_http_url;
use crate::protocol::Json;

use super::inbox::utc_stamp;
use super::key_store::{
    DesktopKeyStore, EncryptionKeyStore, KeyStoreError, RetiredKey, RETIRED_KEY_SECS,
};
use super::seal::{self, Aes256Key, SealError};

/// The largest credential document this wallet will store.
const MAX_DOCUMENT_LEN: usize = 2 * 1024 * 1024;

/// One stored credential, after it has been opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Credential {
    pub id: String,
    pub format: String,
    pub issuer: String,
    /// UTC time the wallet stored it, `YYYYMMDDTHHMMSS.mmmZ`.
    pub received_at: String,
    /// The credential itself: a JWT, an SD-JWT, or a JSON-LD document.
    pub document: String,
    /// Private JWK for a key this wallet bound the credential to. Absent when
    /// the document was stored with `credential add`. It stays inside the
    /// sealed file and is not printed.
    pub holder_key: Option<String>,
}

/// What the caller supplies. The id and the time are assigned here.
pub struct NewCredential {
    pub format: String,
    pub issuer: String,
    pub document: String,
    /// Private JWK, sealed with the document. `None` for a document the
    /// person pasted in.
    pub holder_key: Option<String>,
}

/// The credential directory, opened with a particular key store.
pub struct CredentialVault<K> {
    root: PathBuf,
    keys: K,
}

impl CredentialVault<DesktopKeyStore> {
    /// `$XDG_DATA_HOME/oid4vc-wallet/credentials`. The key is in GNOME Keyring,
    /// or in KWallet when the Secret Service is not running.
    pub fn open_default() -> Result<Self, VaultError> {
        let root = crate::xdg::data_home()
            .map_err(VaultError::Message)?
            .join("oid4vc-wallet")
            .join("credentials");
        Ok(Self::open(root, DesktopKeyStore::wallet()))
    }
}

impl<K: EncryptionKeyStore> CredentialVault<K> {
    pub fn open(root: impl Into<PathBuf>, keys: K) -> Self {
        Self {
            root: root.into(),
            keys,
        }
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    #[cfg(test)]
    fn keys(&self) -> &K {
        &self.keys
    }

    /// Seal a credential and return it, including the id it was given.
    pub fn put(&self, new: NewCredential) -> Result<Credential, VaultError> {
        let format = require_format(&new.format)?;
        let issuer = require_issuer(&new.issuer)?;
        let document = require_document(&new.document)?;
        let credential = Credential {
            id: new_id(),
            format,
            issuer,
            received_at: utc_stamp(now_millis()),
            document,
            holder_key: new.holder_key,
        };
        self.write(&credential)?;
        Ok(credential)
    }

    /// Open one credential. The current key is tried first, then each retired
    /// key whose `expires_at` is still in the future.
    pub fn get(&self, id: &str) -> Result<Credential, VaultError> {
        require_id(id)?;
        let keys = self.opening_keys()?;
        self.read_with(&keys, id)
    }

    /// Open every credential. The document is included.
    pub fn list(&self) -> Result<Vec<Credential>, VaultError> {
        let ids = self.ids()?;
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let keys = self.opening_keys()?;
        let mut credentials = Vec::with_capacity(ids.len());
        for id in ids {
            credentials.push(self.read_with(&keys, &id)?);
        }
        credentials.sort_by(|left, right| {
            left.received_at
                .cmp(&right.received_at)
                .then_with(|| left.id.cmp(&right.id))
        });
        Ok(credentials)
    }

    /// Draw a new AES-256 key, keep the current key for 90 days, and seal
    /// every stored credential with the new key.
    pub fn rotate(&self) -> Result<RotateReport, VaultError> {
        let ids = self.ids()?;
        let records = if ids.is_empty() {
            Vec::new()
        } else {
            let keys = self.opening_keys()?;
            let mut records = Vec::with_capacity(ids.len());
            for id in &ids {
                records.push(self.read_with(&keys, id)?);
            }
            records
        };
        let new_key = Aes256Key::generate();
        let now = now_secs();
        let mut retired = self.keys.load_retired().map_err(VaultError::Key)?;
        retired.retain(|item| item.expires_at > now);
        if let Some(current) = self.keys.load_key().map_err(VaultError::Key)? {
            retired.push(RetiredKey {
                key: current,
                expires_at: now.saturating_add(RETIRED_KEY_SECS),
            });
        }
        // The previous key is in history before the current item is replaced,
        // so a crash while files are rewritten can still open them.
        self.keys.store_retired(&retired).map_err(VaultError::Key)?;
        self.keys.store_key(&new_key).map_err(VaultError::Key)?;
        for credential in &records {
            self.write_with(&new_key, credential)?;
        }
        Ok(RotateReport {
            count: records.len(),
        })
    }

    /// Replace the document of one stored credential. The id, the issuer, the
    /// format, the received time, and the holder key stay as they are.
    pub fn replace_document(&self, id: &str, document: &str) -> Result<Credential, VaultError> {
        require_id(id)?;
        let document = require_document(document)?;
        let mut credential = self.get(id)?;
        credential.document = document;
        self.write(&credential)?;
        Ok(credential)
    }

    /// Remove one credential file. The AES-256 key stays in the credential store.
    pub fn delete(&self, id: &str) -> Result<(), VaultError> {
        require_id(id)?;
        let path = self.path_for(id);
        match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Err(VaultError::Message(
                crate::i18n::t_args("wallet.cred.missing", &[("id", id)]),
            )),
            Err(err) => Err(VaultError::Io { path, source: err }),
        }
    }

    fn write(&self, credential: &Credential) -> Result<(), VaultError> {
        let key = self.key_for_write()?;
        self.write_with(&key, credential)
    }

    fn write_with(&self, key: &Aes256Key, credential: &Credential) -> Result<(), VaultError> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder
            .create(&self.root)
            .map_err(|source| VaultError::Io {
                path: self.root.clone(),
                source,
            })?;
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700)).map_err(|source| {
            VaultError::Io {
                path: self.root.clone(),
                source,
            }
        })?;
        let plaintext = encode_record(credential);
        let sealed = seal::seal(
            key,
            &seal::credential_aad(&credential.id),
            plaintext.as_bytes(),
        )
        .map_err(VaultError::Seal)?;
        let path = self.path_for(&credential.id);
        let temporary = path.with_extension("new");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(|source| VaultError::Io {
                path: temporary.clone(),
                source,
            })?;
        if let Err(source) = file.write_all(&sealed) {
            let _ = fs::remove_file(&temporary);
            return Err(VaultError::Io {
                path: temporary,
                source,
            });
        }
        if let Err(source) = file.sync_all() {
            let _ = fs::remove_file(&temporary);
            return Err(VaultError::Io {
                path: temporary,
                source,
            });
        }
        if let Err(source) = fs::rename(&temporary, &path) {
            let _ = fs::remove_file(&temporary);
            return Err(VaultError::Io { path, source });
        }
        Ok(())
    }

    fn read_with(&self, keys: &[Aes256Key], id: &str) -> Result<Credential, VaultError> {
        let path = self.path_for(id);
        let sealed = fs::read(&path).map_err(|source| {
            if source.kind() == io::ErrorKind::NotFound {
                VaultError::Message(crate::i18n::t_args("wallet.cred.missing", &[("id", id)]))
            } else {
                VaultError::Io {
                    path: path.clone(),
                    source,
                }
            }
        })?;
        let plaintext = open_with_keys(keys, id, &sealed)?;
        let text = String::from_utf8(plaintext).map_err(|_| {
            VaultError::Message(crate::i18n::t_args("wallet.cred.not_utf8", &[("id", id)]))
        })?;
        decode_record(id, &text)
    }

    fn ids(&self) -> Result<Vec<String>, VaultError> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|source| VaultError::Io {
            path: self.root.clone(),
            source,
        })? {
            let entry = entry.map_err(|source| VaultError::Io {
                path: self.root.clone(),
                source,
            })?;
            let name = entry.file_name();
            let Some(text) = name.to_str() else {
                continue;
            };
            let Some(id) = text.strip_suffix(".bin") else {
                continue;
            };
            if require_id(id).is_ok() {
                ids.push(id.to_string());
            }
        }
        Ok(ids)
    }

    fn path_for(&self, id: &str) -> PathBuf {
        self.root.join(format!("{id}.bin"))
    }

    /// Current key first, then retired keys that have not expired.
    /// An expired retired key is not included, so it cannot open a file.
    fn opening_keys(&self) -> Result<Vec<Aes256Key>, VaultError> {
        let now = now_secs();
        let mut keys = Vec::new();
        if let Some(key) = self.keys.load_key().map_err(VaultError::Key)? {
            keys.push(key);
        }
        for retired in self.keys.load_retired().map_err(VaultError::Key)? {
            if retired.expires_at > now {
                keys.push(retired.key);
            }
        }
        if keys.is_empty() {
            return Err(VaultError::Message(crate::i18n::t("wallet.cred.no_key")));
        }
        Ok(keys)
    }

    fn key_for_write(&self) -> Result<Aes256Key, VaultError> {
        if let Some(key) = self.keys.load_key().map_err(VaultError::Key)? {
            return Ok(key);
        }
        let generated = Aes256Key::generate();
        self.keys.store_key(&generated).map_err(VaultError::Key)?;
        // Another process may have stored its own key between the empty read
        // and this write. Use whatever the store holds now.
        match self.keys.load_key().map_err(VaultError::Key)? {
            Some(key) => Ok(key),
            None => Ok(generated),
        }
    }
}

fn encode_record(credential: &Credential) -> String {
    let mut members = vec![
        (
            "format".to_string(),
            Json::String(credential.format.clone()),
        ),
        (
            "issuer".to_string(),
            Json::String(credential.issuer.clone()),
        ),
        (
            "received_at".to_string(),
            Json::String(credential.received_at.clone()),
        ),
        (
            "document".to_string(),
            Json::String(credential.document.clone()),
        ),
    ];
    if let Some(holder_key) = &credential.holder_key {
        members.push(("holder_key".to_string(), Json::String(holder_key.clone())));
    }
    Json::Object(members).to_string()
}

fn decode_record(id: &str, text: &str) -> Result<Credential, VaultError> {
    let value = Json::parse(text).map_err(|err| {
        VaultError::Message(crate::i18n::t_args(
            "wallet.cred.bad_record",
            &[("id", id), ("error", &err.to_string())],
        ))
    })?;
    let members = value.as_object().ok_or_else(|| {
        VaultError::Message(crate::i18n::t_args("wallet.cred.not_record", &[("id", id)]))
    })?;
    let mut format = None;
    let mut issuer = None;
    let mut received_at = None;
    let mut document = None;
    let mut holder_key = None;
    for (name, member) in members {
        let text = member.as_str().ok_or_else(|| {
            VaultError::Message(crate::i18n::t_args(
                "wallet.cred.field_type",
                &[("id", id), ("name", name)],
            ))
        })?;
        match name.as_str() {
            "format" => format = Some(text.to_string()),
            "issuer" => issuer = Some(text.to_string()),
            "received_at" => received_at = Some(text.to_string()),
            "document" => document = Some(text.to_string()),
            "holder_key" => holder_key = Some(text.to_string()),
            other => {
                return Err(VaultError::Message(crate::i18n::t_args(
                    "wallet.cred.unexpected_field",
                    &[("id", id), ("field", other)],
                )));
            }
        }
    }
    Ok(Credential {
        id: id.to_string(),
        format: format.ok_or_else(|| missing(id, "format"))?,
        issuer: issuer.ok_or_else(|| missing(id, "issuer"))?,
        received_at: received_at.ok_or_else(|| missing(id, "received_at"))?,
        document: document.ok_or_else(|| missing(id, "document"))?,
        holder_key,
    })
}

fn missing(id: &str, field: &str) -> VaultError {
    VaultError::Message(crate::i18n::t_args(
        "wallet.cred.missing_field",
        &[("id", id), ("field", field)],
    ))
}

fn require_format(format: &str) -> Result<String, VaultError> {
    let format = format.trim();
    if format.is_empty()
        || format
            .chars()
            .any(|ch| ch.is_whitespace() || ch.is_control())
    {
        return Err(VaultError::Message(crate::i18n::t("wallet.cred.format")));
    }
    Ok(format.to_string())
}

fn require_issuer(issuer: &str) -> Result<String, VaultError> {
    let issuer = issuer.trim();
    if is_http_url(issuer) || is_jwk_thumbprint_uri(issuer) {
        return Ok(issuer.to_string());
    }
    Err(VaultError::Message(crate::i18n::t(
        "wallet.cred.issuer_url",
    )))
}

/// RFC 9278 SHA-256 JWK Thumbprint URI. A self-issued credential's issuer is
/// this, not an https URL.
pub(crate) fn is_jwk_thumbprint_uri(issuer: &str) -> bool {
    const PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";
    let Some(rest) = issuer.strip_prefix(PREFIX) else {
        return false;
    };
    rest.len() == 43
        && rest
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
}

fn require_document(document: &str) -> Result<String, VaultError> {
    if document.is_empty() {
        return Err(VaultError::Message(crate::i18n::t(
            "wallet.cred.empty_document",
        )));
    }
    if document.len() > MAX_DOCUMENT_LEN {
        return Err(VaultError::Message(crate::i18n::t_args(
            "wallet.cred.document_too_long",
            &[("limit", &MAX_DOCUMENT_LEN.to_string())],
        )));
    }
    Ok(document.to_string())
}

fn require_id(id: &str) -> Result<(), VaultError> {
    if id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(VaultError::Message(crate::i18n::t("wallet.cred.bad_id")))
    }
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    hex_encode(&bytes)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(HEX[(byte >> 4) as usize]));
        out.push(char::from(HEX[(byte & 0x0f) as usize]));
    }
    out
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn open_with_keys(keys: &[Aes256Key], id: &str, sealed: &[u8]) -> Result<Vec<u8>, VaultError> {
    let aad = seal::credential_aad(id);
    for key in keys {
        match seal::open(key, &aad, sealed) {
            Ok(plaintext) => return Ok(plaintext),
            Err(SealError::NotACredential) => {
                return Err(VaultError::Seal(SealError::NotACredential))
            }
            Err(SealError::AuthenticationFailed) => {}
        }
    }
    Err(VaultError::Seal(SealError::AuthenticationFailed))
}

/// How many credential files [`CredentialVault::rotate`] sealed with the new key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RotateReport {
    pub count: usize,
}

impl Credential {
    /// The JSON object printed by `credential show --json`.
    pub fn to_json(&self) -> Json {
        Json::Object(vec![
            ("id".to_string(), Json::String(self.id.clone())),
            ("format".to_string(), Json::String(self.format.clone())),
            ("issuer".to_string(), Json::String(self.issuer.clone())),
            (
                "received_at".to_string(),
                Json::String(self.received_at.clone()),
            ),
            ("document".to_string(), Json::String(self.document.clone())),
        ])
    }
}

/// A failure while storing or opening a credential.
#[derive(Debug)]
pub enum VaultError {
    Message(String),
    Key(KeyStoreError),
    Seal(SealError),
    Io { path: PathBuf, source: io::Error },
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => write!(f, "{message}"),
            Self::Key(err) => write!(f, "{err}"),
            Self::Seal(err) => write!(f, "{err}"),
            Self::Io { path, source } => f.write_str(&crate::i18n::t_args(
                "wallet.cli.path_error",
                &[
                    ("path", &path.display().to_string()),
                    ("error", &source.to_string()),
                ],
            )),
        }
    }
}

impl VaultError {
    /// The storage key is wrapped to a security key and has not been unwrapped.
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Key(err) if err.is_locked())
    }
}

impl std::error::Error for VaultError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::key_store::MemoryKeyStore;
    use std::os::unix::fs::PermissionsExt;

    fn sample() -> NewCredential {
        NewCredential {
            format: "dc+sd-jwt".to_string(),
            issuer: "https://sts.example".to_string(),
            document: "header.payload.sig~disclosure~".to_string(),
            holder_key: None,
        }
    }

    #[test]
    fn stores_the_document_only_as_ciphertext_and_opens_it_with_the_same_key() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-credentials-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let stored = vault.put(sample()).unwrap();
        let path = root.join(format!("{}.bin", stored.id));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let bytes = fs::read(&path).unwrap();
        assert!(!bytes
            .windows(stored.document.len())
            .any(|window| window == stored.document.as_bytes()));
        assert!(!String::from_utf8_lossy(&bytes).contains("sts.example"));

        let opened = vault.get(&stored.id).unwrap();
        assert_eq!(opened, stored);
        let listed = vault.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, stored.id);

        let replaced = vault
            .replace_document(&stored.id, "header.payload.sig~added~")
            .unwrap();
        assert_eq!(replaced.id, stored.id);
        assert_eq!(replaced.issuer, stored.issuer);
        assert_eq!(replaced.document, "header.payload.sig~added~");
        assert_eq!(vault.get(&stored.id).unwrap().document, replaced.document);

        vault.delete(&stored.id).unwrap();
        assert!(vault.list().unwrap().is_empty());
        assert!(vault.get(&stored.id).is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_different_key_does_not_open_the_file() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-credentials-key-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let stored = vault.put(sample()).unwrap();
        let other = CredentialVault::open(&root, MemoryKeyStore::empty());
        let err = other.get(&stored.id).unwrap_err();
        assert!(
            err.to_string().contains("no AES-256 key")
                || err.to_string().contains("could not be opened")
        );
        // The second vault has no key, so it refuses before decrypting.
        // Seed it with a different key and the seal must fail.
        let seeded = MemoryKeyStore::empty();
        seeded.store_key(&Aes256Key::generate()).unwrap();
        let other = CredentialVault::open(&root, seeded);
        let err = other.get(&stored.id).unwrap_err();
        assert!(err.to_string().contains("could not be opened"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn refuses_a_bad_issuer_and_a_bad_id() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-credentials-bad-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let mut bad = sample();
        bad.issuer = "javascript:alert(1)".to_string();
        assert!(vault.put(bad).is_err());
        let mut self_issued = sample();
        self_issued.issuer =
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJK012345"
                .to_string();
        let stored = vault.put(self_issued).unwrap();
        assert_eq!(
            stored.issuer,
            "urn:ietf:params:oauth:jwk-thumbprint:sha-256:abcdefghijklmnopqrstuvwxyzABCDEFGHIJK012345"
        );
        assert!(vault.get("../etc/passwd").is_err());
        assert!(vault.get("ABCD").is_err());
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn a_holder_key_stays_sealed_and_is_left_out_of_the_printed_record() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-credentials-holder-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let mut new = sample();
        new.holder_key = Some(r#"{"kty":"EC","d":"secret-holder"}"#.to_string());
        let stored = vault.put(new).unwrap();
        let opened = vault.get(&stored.id).unwrap();
        assert_eq!(
            opened.holder_key.as_deref(),
            Some(r#"{"kty":"EC","d":"secret-holder"}"#)
        );
        let printed = stored.to_json().to_string();
        assert!(!printed.contains("holder_key"));
        assert!(!printed.contains("secret-holder"));
        let bytes = fs::read(root.join(format!("{}.bin", stored.id))).unwrap();
        assert!(!String::from_utf8_lossy(&bytes).contains("secret-holder"));
        fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn rotation_reencrypts_every_credential_and_hides_the_document() {
        let root = temp_root("rotate-round");
        let _cleanup = RemoveOnDrop(&root);
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let first = vault.put(sample()).unwrap();
        let mut second_new = sample();
        second_new.document = "second-document-plaintext-unique".to_string();
        let second = vault.put(second_new).unwrap();
        let before = vault.keys().load_key().unwrap().unwrap();
        vault
            .keys()
            .store_retired(&[RetiredKey {
                key: Aes256Key::generate(),
                expires_at: 1,
            }])
            .unwrap();
        let started = now_secs();
        let report = vault.rotate().unwrap();
        let finished = now_secs();
        assert_eq!(report.count, 2);
        let after = vault.keys().load_key().unwrap().unwrap();
        assert_ne!(after.as_bytes(), before.as_bytes());
        let retired = vault.keys().load_retired().unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].key.as_bytes(), before.as_bytes());
        assert!(retired[0].expires_at >= started + RETIRED_KEY_SECS);
        assert!(retired[0].expires_at <= finished + RETIRED_KEY_SECS);

        let listed = vault.list().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(vault.get(&first.id).unwrap(), first);
        assert_eq!(vault.get(&second.id).unwrap(), second);
        for credential in [&first, &second] {
            let bytes = fs::read(root.join(format!("{}.bin", credential.id))).unwrap();
            assert!(!bytes
                .windows(credential.document.len())
                .any(|window| window == credential.document.as_bytes()));
        }
    }

    #[test]
    fn a_file_left_on_the_previous_key_still_opens() {
        let root = temp_root("rotate-old");
        let _cleanup = RemoveOnDrop(&root);
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let stored = vault.put(sample()).unwrap();
        let path = root.join(format!("{}.bin", stored.id));
        let old_bytes = fs::read(&path).unwrap();
        vault.rotate().unwrap();
        let rewritten = fs::read(&path).unwrap();
        assert_ne!(rewritten, old_bytes);
        assert!(!rewritten
            .windows(stored.document.len())
            .any(|window| window == stored.document.as_bytes()));
        fs::write(&path, &old_bytes).unwrap();
        assert_eq!(vault.get(&stored.id).unwrap().document, stored.document);
        let listed = vault.list().unwrap();
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].id, stored.id);
    }

    #[test]
    fn an_expired_retired_key_does_not_open_the_file() {
        let root = temp_root("rotate-expired");
        let _cleanup = RemoveOnDrop(&root);
        let vault = CredentialVault::open(&root, MemoryKeyStore::empty());
        let stored = vault.put(sample()).unwrap();
        let old = vault.keys().load_key().unwrap().unwrap();
        vault.keys().store_key(&Aes256Key::generate()).unwrap();
        vault
            .keys()
            .store_retired(&[RetiredKey {
                key: old,
                expires_at: 1,
            }])
            .unwrap();
        let err = vault.get(&stored.id).unwrap_err();
        assert!(err.to_string().contains("could not be opened"), "{err}");
        assert!(vault.list().is_err());
    }

    fn temp_root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "oid4vc-wallet-{name}-{}-{}",
            std::process::id(),
            now_millis()
        ))
    }

    struct RemoveOnDrop<'a>(&'a Path);

    impl Drop for RemoveOnDrop<'_> {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(self.0);
        }
    }
}
