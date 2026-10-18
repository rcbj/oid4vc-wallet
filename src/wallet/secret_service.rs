//! GNOME Keyring, through the FreeDesktop Secret Service.
//!
//! `org.freedesktop.secrets` is the service GNOME Keyring provides. KeePassXC
//! provides the same service when its Secret Service integration is on, and
//! current KWallet can provide it too. The wallet talks to whichever process
//! owns that name. The item is created in the default collection, which is
//! the login keyring on GNOME.

use keyring::Entry;

use super::key_store::{
    key_from_store, secret_service_is_absent, KeyStoreError, Probe, KEY_SERVICE, KEY_USER,
};
use super::seal::Aes256Key;

/// The Secret Service item for this wallet.
pub struct SecretServiceKeyStore {
    service: String,
    user: String,
}

impl SecretServiceKeyStore {
    /// The item the installed wallet uses.
    pub fn wallet() -> Self {
        Self::new(KEY_SERVICE, KEY_USER)
    }

    pub fn new(service: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            service: service.into(),
            user: user.into(),
        }
    }

    /// Read the item without turning a missing daemon into "no key".
    pub(super) fn probe(&self) -> Probe {
        let entry = match self.entry() {
            Ok(entry) => entry,
            Err(err) => return Probe::Failed(err),
        };
        match entry.get_secret() {
            Ok(bytes) => match key_from_store(bytes) {
                Ok(key) => Probe::Found(key),
                Err(err) => Probe::Failed(err),
            },
            Err(keyring::Error::NoEntry) => Probe::Empty,
            Err(err) if secret_service_is_absent(&err) => Probe::Absent,
            Err(err) => Probe::Failed(KeyStoreError::Store(err.to_string())),
        }
    }

    /// Remove the item. Used by tests so a trial key is not left behind.
    pub fn delete(&self) -> Result<(), KeyStoreError> {
        let entry = self.entry()?;
        match entry.delete_credential() {
            Ok(()) => Ok(()),
            Err(keyring::Error::NoEntry) => Ok(()),
            Err(err) if secret_service_is_absent(&err) => Err(KeyStoreError::Unavailable),
            Err(err) => Err(KeyStoreError::Store(err.to_string())),
        }
    }

    pub(super) fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        let entry = self.entry()?;
        match entry.set_secret(key.as_bytes()) {
            Ok(()) => Ok(()),
            Err(err) if secret_service_is_absent(&err) => Err(KeyStoreError::Unavailable),
            Err(err) => Err(KeyStoreError::Store(err.to_string())),
        }
    }

    fn entry(&self) -> Result<Entry, KeyStoreError> {
        Entry::new(&self.service, &self.user).map_err(|err| KeyStoreError::Store(err.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_service_round_trip() {
        let store = SecretServiceKeyStore::new(
            format!("org.rcbj.oid4vc-wallet.test.{}", std::process::id()),
            KEY_USER,
        );
        let key = Aes256Key::generate();
        if let Err(err) = store.store_key(&key) {
            eprintln!("secret service is not available, skipping: {err}");
            return;
        }
        // The item is removed even when an assertion below fails.
        let _cleanup = RemoveItem(&store);
        let loaded = store
            .probe()
            .into_key()
            .unwrap_or_else(|err| panic!("stored key could not be read back: {err}"));
        let loaded = loaded.expect("the key was just stored");
        assert_eq!(loaded.as_bytes(), key.as_bytes());
        store.delete().expect("test key could not be removed");
        assert!(store.probe().into_key().unwrap().is_none());
    }

    struct RemoveItem<'a>(&'a SecretServiceKeyStore);

    impl Drop for RemoveItem<'_> {
        fn drop(&mut self) {
            let _ = self.0.delete();
        }
    }
}
