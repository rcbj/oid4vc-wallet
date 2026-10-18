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

/// Where the wallet reads and writes its AES-256 key.
pub trait EncryptionKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError>;
    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError>;
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
}

/// A key held in memory. Tests use it so they do not need a session bus.
#[cfg(test)]
pub struct MemoryKeyStore {
    key: std::sync::Mutex<Option<Aes256Key>>,
}

#[cfg(test)]
impl MemoryKeyStore {
    pub fn empty() -> Self {
        Self {
            key: std::sync::Mutex::new(None),
        }
    }
}

#[cfg(test)]
impl EncryptionKeyStore for MemoryKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        let guard = self
            .key
            .lock()
            .map_err(|_| KeyStoreError::Store(crate::i18n::t("wallet.keystore.poisoned")))?;
        Ok(guard.clone())
    }

    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        let mut guard = self
            .key
            .lock()
            .map_err(|_| KeyStoreError::Store(crate::i18n::t("wallet.keystore.poisoned")))?;
        *guard = Some(key.clone());
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
