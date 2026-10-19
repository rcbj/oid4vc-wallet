//! The AES-256 key, kept in the desktop credential store.
//!
//! GNOME Keyring is the first choice. It is reached through the Secret
//! Service, and so is KeePassXC when that application owns the service.
//! KWallet is the KDE store. It is used when the Secret Service is not
//! running. A locked GNOME Keyring is an error: the wallet does not invent a
//! second key in KWallet while the first store might still hold the real one.
//! The key is created the first time a credential is stored, and it is not
//! written into the credential files.

use zeroize::Zeroize;

use super::kwallet::{KWalletKeyStore, Prompt};
use super::secret_service::SecretServiceKeyStore;

use super::seal::{Aes256Key, KEY_LEN};

/// Service name of the Secret Service item that holds the key.
/// KWallet uses the same string as its folder name and application id.
pub const KEY_SERVICE: &str = "org.rcbj.oid4vc-wallet";

/// Username of that item. Together with [`KEY_SERVICE`] it identifies the key.
pub const KEY_USER: &str = "credential-encryption-key";

/// Username of the item that holds keys retired by rotation.
/// The service name is [`KEY_SERVICE`], the same item service as [`KEY_USER`].
pub const KEY_HISTORY_USER: &str = "credential-encryption-key-history";

/// How long a retired key can still open a credential that was not rewritten.
pub const RETIRED_KEY_SECS: u64 = 90 * 24 * 60 * 60;

/// A previous AES-256 key. `expires_at` is a unix timestamp, in seconds.
/// The vault does not use a key once that instant has passed.
pub struct RetiredKey {
    pub key: Aes256Key,
    pub expires_at: u64,
}

impl Clone for RetiredKey {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            expires_at: self.expires_at,
        }
    }
}

impl std::fmt::Debug for RetiredKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RetiredKey")
            .field("key", &self.key)
            .field("expires_at", &self.expires_at)
            .finish()
    }
}

/// Where the wallet reads and writes its AES-256 key.
///
/// Retired keys are a second item. A store that has not implemented them
/// returns an empty list. Writing a non-empty list fails, so a rotation
/// cannot drop the previous key.
pub trait EncryptionKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError>;
    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError>;

    /// Every retired key, including entries whose `expires_at` has passed.
    fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
        Ok(Vec::new())
    }

    /// Replace the retired-key list.
    ///
    /// An empty list is a no-op. A non-empty list must be stored by the
    /// implementation. Succeeding here would drop the previous key.
    fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
        if keys.is_empty() {
            Ok(())
        } else {
            Err(KeyStoreError::Store(crate::i18n::t(
                "wallet.keystore.history",
            )))
        }
    }
}

/// What one store reported. `Absent` means that store is not running.
/// `Failed` means it is running and refused the call, or the item is not a key.
pub(super) enum Probe {
    Found(Aes256Key),
    Empty,
    Absent,
    Failed(KeyStoreError),
}

impl Probe {
    /// Collapse a probe into the trait's result. `Absent` is an empty read
    /// only when the caller has already decided another store answered.
    #[cfg(test)]
    pub(super) fn into_key(self) -> Result<Option<Aes256Key>, KeyStoreError> {
        match self {
            Self::Found(key) => Ok(Some(key)),
            Self::Empty => Ok(None),
            Self::Absent => Err(KeyStoreError::Unavailable),
            Self::Failed(err) => Err(err),
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Presence {
    Found,
    Empty,
    Absent,
    Denied,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum LoadPlan {
    UseSecretService,
    Deny,
    CheckQuiet,
    Prompt,
    UseKWallet,
    Missing,
    NoStore,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum StorePlan {
    SecretService,
    KWallet,
    Deny,
}

fn presence(probe: &Probe) -> Presence {
    match probe {
        Probe::Found(_) => Presence::Found,
        Probe::Empty => Presence::Empty,
        Probe::Absent => Presence::Absent,
        Probe::Failed(_) => Presence::Denied,
    }
}

/// Which store answers a read. A denied Secret Service stops the search.
fn plan_load(secret_service: Presence) -> LoadPlan {
    match secret_service {
        Presence::Found => LoadPlan::UseSecretService,
        Presence::Denied => LoadPlan::Deny,
        Presence::Empty => LoadPlan::CheckQuiet,
        Presence::Absent => LoadPlan::Prompt,
    }
}

/// KWallet, looked at only because GNOME Keyring is up and has no key.
/// A closed KWallet is not opened here, so this path does not prompt.
fn plan_quiet(kwallet: Presence) -> LoadPlan {
    match kwallet {
        Presence::Found => LoadPlan::UseKWallet,
        Presence::Denied => LoadPlan::Deny,
        Presence::Empty | Presence::Absent => LoadPlan::Missing,
    }
}

/// KWallet, looked at because the Secret Service is not running.
fn plan_prompt(kwallet: Presence) -> LoadPlan {
    match kwallet {
        Presence::Found => LoadPlan::UseKWallet,
        Presence::Empty => LoadPlan::Missing,
        Presence::Absent => LoadPlan::NoStore,
        Presence::Denied => LoadPlan::Deny,
    }
}

/// Where a new key is written. An existing key is written back to the store
/// that `load` already chose; this plan runs only after that read was empty,
/// or when that store itself holds the item.
fn plan_store(secret_service: Presence) -> StorePlan {
    match secret_service {
        Presence::Found | Presence::Empty => StorePlan::SecretService,
        Presence::Absent => StorePlan::KWallet,
        Presence::Denied => StorePlan::Deny,
    }
}

/// GNOME Keyring when the Secret Service answers, and KWallet otherwise.
pub struct DesktopKeyStore {
    secret_service: SecretServiceKeyStore,
    kwallet: KWalletKeyStore,
}

impl DesktopKeyStore {
    /// The stores the installed wallet uses.
    pub fn wallet() -> Self {
        Self {
            secret_service: SecretServiceKeyStore::wallet(),
            kwallet: KWalletKeyStore::wallet(),
        }
    }
}

impl EncryptionKeyStore for DesktopKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        let secret = self.secret_service.probe();
        match (plan_load(presence(&secret)), secret) {
            (LoadPlan::UseSecretService, Probe::Found(key)) => Ok(Some(key)),
            (LoadPlan::Deny, Probe::Failed(err)) => Err(err),
            (LoadPlan::CheckQuiet, Probe::Empty) => self.after_quiet_check(),
            (LoadPlan::Prompt, Probe::Absent) => self.after_prompt(),
            _ => Err(KeyStoreError::Unavailable),
        }
    }

    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        let secret = self.secret_service.probe();
        match plan_store(presence(&secret)) {
            StorePlan::SecretService => self.secret_service.store_key(key),
            StorePlan::KWallet => self.kwallet.store_key(key),
            StorePlan::Deny => match secret {
                Probe::Failed(err) => Err(err),
                _ => Err(KeyStoreError::Unavailable),
            },
        }
    }

    fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
        let secret = self.secret_service.probe();
        match plan_load(presence(&secret)) {
            LoadPlan::UseSecretService => self.secret_service.load_retired(),
            LoadPlan::Deny => Err(probe_failure(secret)),
            LoadPlan::CheckQuiet => self.retired_after_quiet_check(),
            LoadPlan::Prompt => self.kwallet.load_retired(Prompt::IfLocked),
            LoadPlan::UseKWallet | LoadPlan::Missing | LoadPlan::NoStore => {
                Err(KeyStoreError::Unavailable)
            }
        }
    }

    fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
        let secret = self.secret_service.probe();
        match plan_store(presence(&secret)) {
            StorePlan::SecretService => self.secret_service.store_retired(keys),
            StorePlan::KWallet => self.kwallet.store_retired(keys),
            StorePlan::Deny => Err(probe_failure(secret)),
        }
    }
}

impl DesktopKeyStore {
    fn after_quiet_check(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        let quiet = self.kwallet.probe(Prompt::Never);
        match (plan_quiet(presence(&quiet)), quiet) {
            (LoadPlan::UseKWallet, Probe::Found(key)) => Ok(Some(key)),
            (LoadPlan::Deny, Probe::Failed(err)) => Err(err),
            (LoadPlan::Missing, _) => Ok(None),
            _ => Err(KeyStoreError::Unavailable),
        }
    }

    fn after_prompt(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        let opened = self.kwallet.probe(Prompt::IfLocked);
        match (plan_prompt(presence(&opened)), opened) {
            (LoadPlan::UseKWallet, Probe::Found(key)) => Ok(Some(key)),
            (LoadPlan::Missing, Probe::Empty) => Ok(None),
            (LoadPlan::NoStore, Probe::Absent) => Err(KeyStoreError::Unavailable),
            (LoadPlan::Deny, Probe::Failed(err)) => Err(err),
            _ => Err(KeyStoreError::Unavailable),
        }
    }

    /// Secret Service is up and has no current key, so the key may be in KWallet.
    /// History is read from the store that actually holds the current key.
    fn retired_after_quiet_check(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
        let quiet = self.kwallet.probe(Prompt::Never);
        match plan_quiet(presence(&quiet)) {
            LoadPlan::UseKWallet => self.kwallet.load_retired(Prompt::Never),
            LoadPlan::Deny => Err(probe_failure(quiet)),
            LoadPlan::Missing => self.secret_service.load_retired(),
            LoadPlan::UseSecretService
            | LoadPlan::CheckQuiet
            | LoadPlan::Prompt
            | LoadPlan::NoStore => Err(KeyStoreError::Unavailable),
        }
    }
}

fn probe_failure(probe: Probe) -> KeyStoreError {
    match probe {
        Probe::Failed(err) => err,
        Probe::Found(_) | Probe::Empty | Probe::Absent => KeyStoreError::Unavailable,
    }
}

#[cfg(test)]
struct MemoryState {
    key: Option<Aes256Key>,
    retired: Vec<RetiredKey>,
}

/// A key held in memory. Tests use it so they do not need a session bus.
#[cfg(test)]
pub struct MemoryKeyStore {
    inner: std::sync::Mutex<MemoryState>,
}

#[cfg(test)]
impl MemoryKeyStore {
    pub fn empty() -> Self {
        Self {
            inner: std::sync::Mutex::new(MemoryState {
                key: None,
                retired: Vec::new(),
            }),
        }
    }

    fn lock(&self) -> Result<std::sync::MutexGuard<'_, MemoryState>, KeyStoreError> {
        self.inner
            .lock()
            .map_err(|_| KeyStoreError::Store(crate::i18n::t("wallet.keystore.poisoned")))
    }
}

#[cfg(test)]
impl EncryptionKeyStore for MemoryKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        Ok(self.lock()?.key.clone())
    }

    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        self.lock()?.key = Some(key.clone());
        Ok(())
    }

    fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
        Ok(self.lock()?.retired.clone())
    }

    fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
        self.lock()?.retired = keys.to_vec();
        Ok(())
    }
}

pub(super) fn key_from_store(mut bytes: Vec<u8>) -> Result<Aes256Key, KeyStoreError> {
    let copied = match <[u8; KEY_LEN]>::try_from(bytes.as_slice()) {
        Ok(array) => array,
        Err(_) => {
            let len = bytes.len();
            bytes.zeroize();
            return Err(KeyStoreError::WrongLength(len));
        }
    };
    bytes.zeroize();
    Ok(Aes256Key::from_bytes(copied))
}

/// ASCII lines `base64url(32 bytes) TAB unix\n`. Empty is an empty list.
pub(super) fn encode_retired(keys: &[RetiredKey]) -> Vec<u8> {
    let mut out = Vec::new();
    for item in keys {
        let mut token = super::b64::b64url_encode(item.key.as_bytes());
        out.extend_from_slice(token.as_bytes());
        token.zeroize();
        out.push(b'\t');
        out.extend_from_slice(item.expires_at.to_string().as_bytes());
        out.push(b'\n');
    }
    out
}

/// Parse [`encode_retired`]. `bytes` is wiped before this returns.
pub(super) fn decode_retired(mut bytes: Vec<u8>) -> Result<Vec<RetiredKey>, KeyStoreError> {
    let parsed = parse_retired(&bytes);
    bytes.zeroize();
    parsed
}

fn parse_retired(bytes: &[u8]) -> Result<Vec<RetiredKey>, KeyStoreError> {
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| bad_history())?;
    if text.bytes().any(|byte| byte == b'\r') || !text.ends_with('\n') {
        return Err(bad_history());
    }
    let mut retired = Vec::new();
    for line in text.split_terminator('\n') {
        let Some((token, expiry)) = line.split_once('\t') else {
            return Err(bad_history());
        };
        if expiry.contains('\t') {
            return Err(bad_history());
        }
        let expires_at = parse_expiry(expiry).ok_or_else(bad_history)?;
        let key = parse_retired_key(token).ok_or_else(bad_history)?;
        retired.push(RetiredKey { key, expires_at });
    }
    Ok(retired)
}

fn parse_expiry(text: &str) -> Option<u64> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    if text.len() > 1 && text.starts_with('0') {
        return None;
    }
    text.parse().ok()
}

fn parse_retired_key(token: &str) -> Option<Aes256Key> {
    if token.len() != 43
        || !token.bytes().all(|byte| {
            matches!(
                byte,
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'
            )
        })
    {
        return None;
    }
    let mut decoded = super::b64::b64_decode(token)?;
    if decoded.len() != KEY_LEN {
        decoded.zeroize();
        return None;
    }
    let mut array = [0u8; KEY_LEN];
    array.copy_from_slice(&decoded);
    decoded.zeroize();
    let key = Aes256Key::from_bytes(array);
    let mut encoded = super::b64::b64url_encode(key.as_bytes());
    let matches_token = encoded == token;
    encoded.zeroize();
    array.zeroize();
    if matches_token {
        Some(key)
    } else {
        None
    }
}

fn bad_history() -> KeyStoreError {
    KeyStoreError::Store("retired key history is malformed".to_string())
}

/// A Secret Service error that means the daemon is not there.
/// A locked collection is not this case.
pub(super) fn secret_service_is_absent(err: &keyring::Error) -> bool {
    let text = err.to_string().to_ascii_lowercase();
    text.contains("serviceunknown")
        || text.contains("was not provided")
        || text.contains("namehasnoowner")
        || text.contains("failed to connect to socket")
        || text.contains("failed to connect to bus")
        || text.contains("cannot autolaunch")
        || text.contains("no such file or directory")
}

/// Why the credential store could not supply the key.
#[derive(Debug)]
pub enum KeyStoreError {
    /// The store answered, and the call failed. The text is the detail.
    Store(String),
    /// Neither GNOME Keyring nor KWallet is running.
    Unavailable,
    /// An item was found, and it is not a 32-byte AES-256 key.
    WrongLength(usize),
}

impl std::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(message) => f.write_str(&crate::i18n::t_args(
                "wallet.keystore.unusable",
                &[("message", message)],
            )),
            Self::Unavailable => f.write_str(&crate::i18n::t("wallet.keystore.unavailable")),
            Self::WrongLength(len) => f.write_str(&crate::i18n::t_args(
                "wallet.keystore.wrong_length",
                &[
                    ("len", &len.to_string()),
                    ("expected", &KEY_LEN.to_string()),
                ],
            )),
        }
    }
}

impl std::error::Error for KeyStoreError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memory_store_returns_the_key_it_was_given() {
        let store = MemoryKeyStore::empty();
        assert!(store.load_key().unwrap().is_none());
        let key = Aes256Key::generate();
        store.store_key(&key).unwrap();
        let loaded = store.load_key().unwrap().unwrap();
        assert_eq!(loaded.as_bytes(), key.as_bytes());
        assert!(store.load_retired().unwrap().is_empty());
        let retired = RetiredKey {
            key: key.clone(),
            expires_at: 90,
        };
        store.store_retired(&[retired]).unwrap();
        let loaded = store.load_retired().unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].expires_at, 90);
        assert_eq!(loaded[0].key.as_bytes(), key.as_bytes());
    }

    #[test]
    fn a_store_without_history_methods_keeps_none() {
        struct CurrentOnly;
        impl EncryptionKeyStore for CurrentOnly {
            fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
                Ok(None)
            }
            fn store_key(&self, _key: &Aes256Key) -> Result<(), KeyStoreError> {
                Ok(())
            }
        }
        let store = CurrentOnly;
        assert!(store.load_retired().unwrap().is_empty());
        store.store_retired(&[]).unwrap();
        let err = store
            .store_retired(&[RetiredKey {
                key: Aes256Key::from_bytes([3; KEY_LEN]),
                expires_at: 1,
            }])
            .unwrap_err();
        match err {
            KeyStoreError::Store(message) => {
                assert!(message.contains("previous encryption key"));
            }
            other => panic!("expected a store error, got {other}"),
        }
        assert!(store.load_retired().unwrap().is_empty());
    }

    #[test]
    fn retired_history_is_base64url_lines_and_rejects_a_bad_line() {
        let first = Aes256Key::from_bytes([0xfb; KEY_LEN]);
        let second = Aes256Key::from_bytes([0x02; KEY_LEN]);
        let encoded = encode_retired(&[
            RetiredKey {
                key: first.clone(),
                expires_at: 1_700_000_000,
            },
            RetiredKey {
                key: second.clone(),
                expires_at: 0,
            },
        ]);
        let text = std::str::from_utf8(&encoded).unwrap();
        assert_eq!(text.chars().filter(|ch| *ch == '\n').count(), 2);
        assert!(text.contains('\t'));
        assert!(!text.contains('+'));
        assert!(!text.contains('/'));
        assert!(!text.contains('='));
        let loaded = decode_retired(encoded.clone()).unwrap();
        assert_eq!(loaded.len(), 2);
        assert_eq!(loaded[0].key.as_bytes(), first.as_bytes());
        assert_eq!(loaded[0].expires_at, 1_700_000_000);
        assert_eq!(loaded[1].key.as_bytes(), second.as_bytes());
        assert_eq!(loaded[1].expires_at, 0);
        assert!(decode_retired(Vec::new()).unwrap().is_empty());

        let mut truncated = encoded.clone();
        truncated.pop();
        assert!(decode_retired(truncated).is_err());
        assert!(decode_retired(b"not-a-key\t10\n".to_vec()).is_err());
        assert!(decode_retired(b"\n".to_vec()).is_err());
        let short = crate::wallet::b64::b64url_encode(&[0x11; 16]);
        assert!(decode_retired(format!("{short}\t10\n").into_bytes()).is_err());
        let standard = crate::wallet::b64::b64_encode(first.as_bytes());
        assert!(decode_retired(format!("{standard}\t10\n").into_bytes()).is_err());
        let token = text.lines().next().unwrap().split('\t').next().unwrap();
        assert!(decode_retired(format!("{token}\t01\n").into_bytes()).is_err());
        assert!(decode_retired(format!("{token}\t10\textra\n").into_bytes()).is_err());
        assert!(decode_retired(format!("{token} 10\n").into_bytes()).is_err());
        assert!(decode_retired(b"@@@\t10\n".to_vec()).is_err());
    }

    #[test]
    fn gnome_keyring_wins_when_it_holds_the_key() {
        assert_eq!(plan_load(Presence::Found), LoadPlan::UseSecretService);
        assert_eq!(plan_store(Presence::Found), StorePlan::SecretService);
    }

    #[test]
    fn a_locked_gnome_keyring_is_not_treated_as_an_empty_kwallet() {
        assert_eq!(plan_load(Presence::Denied), LoadPlan::Deny);
        assert_eq!(plan_store(Presence::Denied), StorePlan::Deny);
    }

    #[test]
    fn an_empty_gnome_keyring_checks_kwallet_without_prompting() {
        assert_eq!(plan_load(Presence::Empty), LoadPlan::CheckQuiet);
        assert_eq!(plan_quiet(Presence::Found), LoadPlan::UseKWallet);
        assert_eq!(plan_quiet(Presence::Empty), LoadPlan::Missing);
        assert_eq!(plan_quiet(Presence::Absent), LoadPlan::Missing);
        assert_eq!(plan_quiet(Presence::Denied), LoadPlan::Deny);
        assert_eq!(plan_store(Presence::Empty), StorePlan::SecretService);
    }

    #[test]
    fn kwallet_is_the_store_when_gnome_keyring_is_not_running() {
        assert_eq!(plan_load(Presence::Absent), LoadPlan::Prompt);
        assert_eq!(plan_prompt(Presence::Found), LoadPlan::UseKWallet);
        assert_eq!(plan_prompt(Presence::Empty), LoadPlan::Missing);
        assert_eq!(plan_prompt(Presence::Denied), LoadPlan::Deny);
        assert_eq!(plan_prompt(Presence::Absent), LoadPlan::NoStore);
        assert_eq!(plan_store(Presence::Absent), StorePlan::KWallet);
    }

    #[test]
    fn a_missing_secret_service_is_recognized_from_the_dbus_text() {
        let missing = keyring::Error::PlatformFailure(Box::new(Text(
            "Platform failure: org.freedesktop.DBus.Error.ServiceUnknown: The name org.freedesktop.secrets was not provided by any .service files",
        )));
        assert!(secret_service_is_absent(&missing));
        let locked = keyring::Error::NoStorageAccess(Box::new(Text(
            "Couldn't access platform secure storage: Secret Service: object locked",
        )));
        assert!(!secret_service_is_absent(&locked));
        assert!(!secret_service_is_absent(&keyring::Error::NoEntry));
    }

    #[test]
    fn the_unavailable_error_names_both_stores() {
        let text = KeyStoreError::Unavailable.to_string();
        assert!(text.contains("GNOME Keyring"), "{text}");
        assert!(text.contains("KWallet"), "{text}");
    }

    #[derive(Debug)]
    struct Text(&'static str);

    impl std::fmt::Display for Text {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for Text {}
}
