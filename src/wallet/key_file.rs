//! The AES-256 key in a file, for a wallet that has no desktop key ring.
//!
//! A test job in a container has no session bus, so neither GNOME Keyring nor
//! KWallet is there, and the person running the job must not have their own
//! key ring touched by it. Setting `OID4VC_WALLET_KEY_FILE` to a path keeps
//! the key in that file instead. It is chosen only by that variable: nothing
//! falls back to the file when the desktop stores fail, because a silent
//! fallback would put a key on disk that the person thought was in their key
//! ring, and would create a second key while the first one may still exist.
//!
//! The file holds the key in the clear, so it gets the protection a private
//! SSH key gets: mode `0600`, refused when another user can read it, written
//! through a temp file and a rename so a crash leaves the old key or the new
//! one, never half of either. Retired keys live in the same file, so a
//! rotation still keeps the previous key for [`super::key_store::RETIRED_KEY_SECS`].

use std::ffi::OsString;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use zeroize::Zeroize;

use super::key_store::{
    decode_retired, encode_retired, key_from_store, EncryptionKeyStore, KeyStoreError, RetiredKey,
};
use super::seal::{Aes256Key, KEY_LEN};

/// The environment variable that names the key file.
pub const KEY_FILE_ENV: &str = "OID4VC_WALLET_KEY_FILE";

/// Distinct from the credential seal (`O4W1`) and the FIDO bundle (`O4FK`),
/// so one kind of file is never read as another.
const MAGIC: &[u8; 4] = b"O4KF";
const VERSION: u8 = 1;

/// The path `OID4VC_WALLET_KEY_FILE` names. An empty value is unset, the
/// same rule the XDG variables follow.
#[must_use]
pub fn configured_path() -> Option<PathBuf> {
    configured_from(std::env::var_os(KEY_FILE_ENV))
}

fn configured_from(value: Option<OsString>) -> Option<PathBuf> {
    value.filter(|value| !value.is_empty()).map(PathBuf::from)
}

/// `true` when the storage key is in a key file rather than the desktop
/// key ring or a security key.
#[must_use]
pub fn uses_key_file() -> bool {
    configured_path().is_some()
}

/// The storage key, and the retired keys, in one private file.
pub struct FileKeyStore {
    path: PathBuf,
}

/// What the file holds once it has been read.
struct Contents {
    key: Aes256Key,
    retired: Vec<RetiredKey>,
}

impl FileKeyStore {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    fn shown(&self) -> String {
        self.path.display().to_string()
    }

    fn io_error(&self, err: &io::Error) -> KeyStoreError {
        KeyStoreError::Plain(crate::i18n::t_args(
            "wallet.keystore.file_io",
            &[("path", &self.shown()), ("error", &err.to_string())],
        ))
    }

    fn malformed(&self) -> KeyStoreError {
        KeyStoreError::Plain(crate::i18n::t_args(
            "wallet.keystore.file_bad",
            &[("path", &self.shown())],
        ))
    }

    /// `Ok(None)` only when the file does not exist. Anything unreadable is
    /// an error, so a damaged file is never replaced by a fresh key.
    fn read(&self) -> Result<Option<Contents>, KeyStoreError> {
        let metadata = match fs::metadata(&self.path) {
            Ok(metadata) => metadata,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(self.io_error(&err)),
        };
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(KeyStoreError::Plain(crate::i18n::t_args(
                "wallet.keystore.file_open",
                &[("path", &self.shown())],
            )));
        }
        let mut bytes = fs::read(&self.path).map_err(|err| self.io_error(&err))?;
        let parsed = self.parse(&bytes);
        bytes.zeroize();
        parsed.map(Some)
    }

    fn parse(&self, bytes: &[u8]) -> Result<Contents, KeyStoreError> {
        let header = MAGIC.len() + 1;
        if bytes.len() < header + KEY_LEN
            || &bytes[..MAGIC.len()] != MAGIC
            || bytes[MAGIC.len()] != VERSION
        {
            return Err(self.malformed());
        }
        let key = key_from_store(bytes[header..header + KEY_LEN].to_vec())?;
        let retired =
            decode_retired(bytes[header + KEY_LEN..].to_vec()).map_err(|_| self.malformed())?;
        Ok(Contents { key, retired })
    }

    fn write(&self, key: &Aes256Key, retired: &[RetiredKey]) -> Result<(), KeyStoreError> {
        let mut bytes = Vec::with_capacity(MAGIC.len() + 1 + KEY_LEN);
        bytes.extend_from_slice(MAGIC);
        bytes.push(VERSION);
        bytes.extend_from_slice(key.as_bytes());
        let mut history = encode_retired(retired);
        bytes.extend_from_slice(&history);
        history.zeroize();
        let written = self.write_bytes(&bytes);
        bytes.zeroize();
        written.map_err(|err| self.io_error(&err))
    }

    fn write_bytes(&self, bytes: &[u8]) -> io::Result<()> {
        if let Some(parent) = self.path.parent().filter(|p| !p.as_os_str().is_empty()) {
            if !parent.exists() {
                fs::DirBuilder::new()
                    .recursive(true)
                    .mode(0o700)
                    .create(parent)?;
            }
        }
        let mut temp = self.path.clone().into_os_string();
        temp.push(format!(".tmp-{}", std::process::id()));
        let temp = PathBuf::from(temp);
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temp)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temp, &self.path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temp);
        }
        result
    }
}

impl EncryptionKeyStore for FileKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        Ok(self.read()?.map(|contents| contents.key))
    }

    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        let retired = self
            .read()?
            .map(|contents| contents.retired)
            .unwrap_or_default();
        self.write(key, &retired)
    }

    fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
        Ok(self
            .read()?
            .map(|contents| contents.retired)
            .unwrap_or_default())
    }

    /// The vault stores the retired keys before the new key, so there is
    /// always a current key here when this is called. Without one there is
    /// nothing to keep them beside, and dropping them would lose a key.
    fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
        let Some(contents) = self.read()? else {
            if keys.is_empty() {
                return Ok(());
            }
            return Err(self.malformed());
        };
        self.write(&contents.key, keys)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let millis = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis();
            let path = std::env::temp_dir().join(format!(
                "oid4vc-wallet-{name}-{}-{millis}",
                std::process::id()
            ));
            fs::create_dir_all(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn an_empty_variable_is_unset() {
        assert!(configured_from(None).is_none());
        assert!(configured_from(Some(OsString::new())).is_none());
        assert_eq!(
            configured_from(Some(OsString::from("/k"))),
            Some(PathBuf::from("/k"))
        );
    }

    #[test]
    fn a_missing_file_is_no_key_and_a_stored_key_comes_back() {
        let dir = TempDir::new("key-file-roundtrip");
        let store = FileKeyStore::new(dir.0.join("nested").join("key"));
        assert!(store.load_key().unwrap().is_none());
        assert!(store.load_retired().unwrap().is_empty());
        let key = Aes256Key::generate();
        store.store_key(&key).unwrap();
        let mode = fs::metadata(store.path()).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
        let parent = fs::metadata(dir.0.join("nested"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(parent & 0o777, 0o700);
        assert_eq!(
            store.load_key().unwrap().unwrap().as_bytes(),
            key.as_bytes()
        );
    }

    #[test]
    fn rotation_keeps_the_retired_key_beside_the_new_one() {
        let dir = TempDir::new("key-file-rotate");
        let store = FileKeyStore::new(dir.0.join("key"));
        let old = Aes256Key::generate();
        store.store_key(&old).unwrap();
        let retired = RetiredKey {
            key: old.clone(),
            expires_at: 1_234,
        };
        store.store_retired(&[retired]).unwrap();
        let new = Aes256Key::generate();
        store.store_key(&new).unwrap();
        assert_eq!(
            store.load_key().unwrap().unwrap().as_bytes(),
            new.as_bytes()
        );
        let kept = store.load_retired().unwrap();
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].expires_at, 1_234);
        assert_eq!(kept[0].key.as_bytes(), old.as_bytes());
    }

    #[test]
    fn a_damaged_file_is_an_error_and_not_a_missing_key() {
        let dir = TempDir::new("key-file-damaged");
        let path = dir.0.join("key");
        OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap()
            .write_all(b"O4KF\x01short")
            .unwrap();
        let store = FileKeyStore::new(&path);
        assert!(store.load_key().is_err());
        assert!(store.store_key(&Aes256Key::generate()).is_err());
        assert_eq!(fs::read(&path).unwrap(), b"O4KF\x01short");
    }

    #[test]
    fn a_file_other_users_can_read_is_refused() {
        let dir = TempDir::new("key-file-open");
        let store = FileKeyStore::new(dir.0.join("key"));
        store.store_key(&Aes256Key::generate()).unwrap();
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644)).unwrap();
        let err = store.load_key().unwrap_err();
        assert!(err.to_string().contains("0600"), "{err}");
    }

    #[test]
    fn retired_keys_without_a_current_key_are_refused() {
        let dir = TempDir::new("key-file-no-current");
        let store = FileKeyStore::new(dir.0.join("key"));
        store.store_retired(&[]).unwrap();
        let retired = RetiredKey {
            key: Aes256Key::generate(),
            expires_at: 1,
        };
        assert!(store.store_retired(&[retired]).is_err());
        assert!(!store.path().exists());
    }
}
