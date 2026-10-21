//! Where the AES-256 storage key is kept.
//!
//! The desktop key ring is the default. YubiKey protection replaces that
//! with two P-256 key pairs, one on each key, and deletes the desktop copy
//! only after both wrapped copies are on disk. Either key can unwrap the
//! storage key. Replacing a key checks the one that stays, then enrolls the
//! new one, so the file never holds fewer than two.
//!
//! The unwrapped key is cached for this process. A later launch asks for a
//! PIN again. Tests pass their own session, file, and software keys, so they
//! do not touch this cache, the real key ring, or a reader.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use zeroize::Zeroize;

use crate::protocol::Json;

use super::b64::{b64_decode, b64_encode};
use super::kek::{self, ephemeral_point};
use super::key_store::{
    decode_retired, encode_retired, DesktopKeyStore, KeyStoreError, RetiredKey,
};
use super::piv::{HardwarePiv, Piv, PivError};
use super::seal::Aes256Key;

const FILE_NAME: &str = "key-protection.json";
const MAGIC: &[u8; 4] = b"O4YK";

static SESSION: Mutex<Session> = Mutex::new(Session::empty());

/// Which store currently protects the storage key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Keyring,
    YubiKey,
}

/// What Settings → Security shows, and what the credential list consults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionStatus {
    pub mechanism: Mechanism,
    pub enrolled: Vec<u32>,
    pub pending: Vec<u32>,
    pub unlocked: bool,
    /// YubiKey mode is on, and a desktop copy could not be deleted yet.
    pub keyring_pending_removal: bool,
}

struct Session {
    dek: Option<Aes256Key>,
    retired: Vec<RetiredKey>,
    generation: u64,
    last_enrolled: Option<(u32, [u8; 65])>,
    pending_new: Option<(u32, [u8; 65])>,
    replacing: Option<u32>,
}

impl Session {
    const fn empty() -> Self {
        Self {
            dek: None,
            retired: Vec::new(),
            generation: 0,
            last_enrolled: None,
            pending_new: None,
            replacing: None,
        }
    }
}

#[derive(Clone)]
struct Record {
    serial: u32,
    public: [u8; 65],
    wrapped: Vec<u8>,
}

#[derive(Clone)]
struct Pending {
    serial: u32,
    public: [u8; 65],
}

#[derive(Clone)]
struct Doc {
    mechanism: Mechanism,
    generation: u64,
    keyring_cleared: bool,
    keys: Vec<Record>,
    pending: Vec<Pending>,
}

impl Doc {
    fn keyring() -> Self {
        Self {
            mechanism: Mechanism::Keyring,
            generation: 0,
            keyring_cleared: true,
            keys: Vec::new(),
            pending: Vec::new(),
        }
    }
}

struct SecretBytes(Vec<u8>);

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// The installed wallet's protection file and the process-wide cache.
struct Work<'a, P, D> {
    piv: &'a mut P,
    desktop: &'a D,
    session: &'a mut Session,
    path: &'a Path,
}

/// Read `$XDG_DATA_HOME/oid4vc-wallet/key-protection.json` and the cache.
pub fn protection_status() -> Result<ProtectionStatus, KeyStoreError> {
    with_global(|work| work.status())
}

/// True when a credential command must ask for a YubiKey PIN before it can read.
pub fn yubikey_locked() -> Result<bool, KeyStoreError> {
    let doc = read_doc(&default_path()?)?;
    if doc.mechanism != Mechanism::YubiKey {
        return Ok(false);
    }
    let session = lock_session()?;
    Ok(!cache_matches(&session, &doc))
}

/// Enroll the one connected YubiKey. The storage key stays in the key ring
/// until [`activate_yubikeys`].
pub fn enroll_yubikey(pin: &str) -> Result<u32, KeyStoreError> {
    with_global(|work| work.enroll(pin))
}

/// Wrap the storage key to the two enrolled YubiKeys and remove the desktop copy.
pub fn activate_yubikeys() -> Result<(), KeyStoreError> {
    with_global(|work| work.activate())
}

/// Forget YubiKeys enrolled while the key ring is still in use.
pub fn discard_pending() -> Result<(), KeyStoreError> {
    with_global(|work| work.discard())
}

/// Unwrap with one connected enrolled YubiKey and cache the storage key.
pub fn unlock_yubikey(pin: &str) -> Result<(), KeyStoreError> {
    with_global(|work| work.unlock(pin))
}

/// Check the YubiKey that will stay, before the other one is replaced.
pub fn begin_replace(remove_serial: u32, staying_pin: &str) -> Result<(), KeyStoreError> {
    with_global(|work| work.begin_replace(remove_serial, staying_pin))
}

/// Enroll the new YubiKey and drop `remove_serial` from the protection file.
pub fn finish_replace(remove_serial: u32, pin: &str) -> Result<u32, KeyStoreError> {
    with_global(|work| work.finish_replace(remove_serial, pin))
}

/// Stop a replacement without changing the enrolled keys.
pub fn cancel_replace() -> Result<(), KeyStoreError> {
    with_global(|work| {
        work.session.replacing = None;
        Ok(())
    })
}

/// Unwrap with a YubiKey, store that key in the desktop key ring, and stop
/// using the YubiKeys. The key pairs stay on the devices.
pub fn switch_to_keyring(pin: &str) -> Result<(), KeyStoreError> {
    with_global(|work| work.switch_to_keyring(pin))
}

pub(super) fn protects_with_yubikey() -> Result<bool, KeyStoreError> {
    Ok(read_doc(&default_path()?)?.mechanism == Mechanism::YubiKey)
}

pub(super) fn cached_key() -> Result<Aes256Key, KeyStoreError> {
    let doc = read_doc(&default_path()?)?;
    let mut session = lock_session()?;
    session_dek(&mut session, &doc)
}

pub(super) fn cached_retired() -> Result<Vec<RetiredKey>, KeyStoreError> {
    let doc = read_doc(&default_path()?)?;
    let mut session = lock_session()?;
    session_dek(&mut session, &doc)?;
    Ok(session.retired.clone())
}

pub(super) fn rewrap_stored_key(key: &Aes256Key) -> Result<(), KeyStoreError> {
    let mut session = lock_session()?;
    rewrap_key_at(&default_path()?, &mut session, key)
}

pub(super) fn rewrap_stored_retired(keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
    let mut session = lock_session()?;
    rewrap_retired_at(&default_path()?, &mut session, keys)
}

fn with_global<T>(
    body: impl FnOnce(&mut Work<'_, HardwarePiv, DesktopKeyStore>) -> Result<T, KeyStoreError>,
) -> Result<T, KeyStoreError> {
    let mut session = lock_session()?;
    let path = default_path()?;
    let mut piv = HardwarePiv;
    let desktop = DesktopKeyStore::wallet();
    let mut work = Work {
        piv: &mut piv,
        desktop: &desktop,
        session: &mut session,
        path: &path,
    };
    body(&mut work)
}

fn lock_session() -> Result<MutexGuard<'static, Session>, KeyStoreError> {
    SESSION
        .lock()
        .map_err(|_| plain("wallet.keystore.poisoned"))
}

fn default_path() -> Result<PathBuf, KeyStoreError> {
    Ok(crate::xdg::data_home()
        .map_err(KeyStoreError::Plain)?
        .join("oid4vc-wallet")
        .join(FILE_NAME))
}

impl<P: Piv, D: DesktopSecrets> Work<'_, P, D> {
    fn status(&mut self) -> Result<ProtectionStatus, KeyStoreError> {
        let doc = read_doc(self.path)?;
        Ok(ProtectionStatus {
            mechanism: doc.mechanism,
            enrolled: doc.keys.iter().map(|key| key.serial).collect(),
            pending: doc.pending.iter().map(|key| key.serial).collect(),
            unlocked: doc.mechanism != Mechanism::YubiKey || cache_matches(self.session, &doc),
            keyring_pending_removal: doc.mechanism == Mechanism::YubiKey && !doc.keyring_cleared,
        })
    }

    fn enroll(&mut self, pin: &str) -> Result<u32, KeyStoreError> {
        check_pin(pin)?;
        let mut doc = read_doc(self.path)?;
        if doc.mechanism != Mechanism::Keyring {
            return Err(plain("wallet.yubi.always_two"));
        }
        let serial = one_connected(self.piv)?;
        if doc.pending.iter().any(|item| item.serial == serial) {
            return Err(plain("wallet.yubi.already"));
        }
        if doc.pending.len() >= 2 {
            return Err(plain("wallet.yubi.pending_full"));
        }
        let public = self.public_key(serial, pin)?;
        doc.pending.push(Pending { serial, public });
        doc.generation = bump(doc.generation)?;
        write_doc(self.path, &doc)?;
        Ok(serial)
    }

    fn activate(&mut self) -> Result<(), KeyStoreError> {
        let doc = read_doc(self.path)?;
        if doc.mechanism == Mechanism::YubiKey {
            if doc.keys.len() != 2 {
                return Err(plain("wallet.yubi.malformed"));
            }
            if !doc.keyring_cleared {
                let _ = self.finish_clearance(doc);
            }
            return Ok(());
        }
        if doc.pending.len() != 2 {
            return Err(plain("wallet.yubi.need_two"));
        }
        let dek = match self.desktop.load_key()? {
            Some(key) => key,
            None => Aes256Key::generate(),
        };
        let retired = self.desktop.load_retired()?;
        let body = SecretBytes(bundle(&dek, &retired));
        let mut keys = Vec::with_capacity(2);
        for pending in &doc.pending {
            keys.push(Record {
                serial: pending.serial,
                public: pending.public,
                wrapped: kek::seal(&pending.public, &body.0)?,
            });
        }
        if keys.len() != 2 || keys[0].serial == keys[1].serial {
            return Err(plain("wallet.yubi.malformed"));
        }
        let previous = fs::read(self.path).ok();
        let mut next = doc.clone();
        next.mechanism = Mechanism::YubiKey;
        next.keys = keys;
        next.pending.clear();
        next.keyring_cleared = false;
        next.generation = bump(doc.generation)?;
        write_doc(self.path, &next)?;
        self.session.dek = Some(dek);
        self.session.retired = retired;
        self.session.generation = next.generation;
        self.session.replacing = None;
        match self.desktop.delete_secrets() {
            Ok(()) => {
                next.keyring_cleared = true;
                next.generation = bump(next.generation)?;
                if write_doc(self.path, &next).is_ok() {
                    self.session.generation = next.generation;
                }
                Ok(())
            }
            Err(err) => {
                if matches!(self.desktop.load_key(), Ok(Some(_)))
                    && restore_bytes(self.path, previous.as_deref()).is_ok()
                {
                    self.session.dek = None;
                    self.session.retired.clear();
                    self.session.generation = doc.generation;
                    self.session.replacing = None;
                }
                Err(err)
            }
        }
    }

    fn discard(&mut self) -> Result<(), KeyStoreError> {
        let mut doc = read_doc(self.path)?;
        if doc.mechanism != Mechanism::Keyring {
            return Err(plain("wallet.yubi.always_two"));
        }
        doc.pending.clear();
        doc.generation = bump(doc.generation)?;
        write_doc(self.path, &doc)
    }

    fn unlock(&mut self, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let doc = read_doc(self.path)?;
        self.require_pair(&doc)?;
        let serial = connected_enrolled(self.piv, &doc)?;
        let record = doc
            .keys
            .iter()
            .find(|key| key.serial == serial)
            .ok_or_else(|| plain("wallet.yubi.not_enrolled"))?;
        let (dek, retired) = self.open_record(record, pin)?;
        self.session.dek = Some(dek);
        self.session.retired = retired;
        self.session.generation = doc.generation;
        self.session.replacing = None;
        if !doc.keyring_cleared {
            let _ = self.finish_clearance(doc);
        }
        Ok(())
    }

    fn begin_replace(&mut self, remove: u32, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let doc = read_doc(self.path)?;
        self.require_pair(&doc)?;
        if !doc.keys.iter().any(|key| key.serial == remove) {
            return Err(plain("wallet.yubi.not_enrolled"));
        }
        let staying = doc
            .keys
            .iter()
            .find(|key| key.serial != remove)
            .ok_or_else(|| plain("wallet.yubi.malformed"))?;
        let connected = self.piv.connected()?;
        if !connected.contains(&staying.serial) {
            return Err(plain_args(
                "wallet.yubi.missing_serial",
                &[("serial", &staying.serial.to_string())],
            ));
        }
        let (dek, retired) = self.open_record(staying, pin)?;
        self.session.dek = Some(dek);
        self.session.retired = retired;
        self.session.generation = doc.generation;
        self.session.replacing = Some(remove);
        Ok(())
    }

    fn finish_replace(&mut self, remove: u32, pin: &str) -> Result<u32, KeyStoreError> {
        check_pin(pin)?;
        if self.session.replacing != Some(remove) || self.session.dek.is_none() {
            return Err(plain("wallet.yubi.always_two"));
        }
        let doc = read_doc(self.path)?;
        self.require_pair(&doc)?;
        if !cache_matches(self.session, &doc) {
            forget_cache(self.session);
            return Err(KeyStoreError::Locked);
        }
        if !doc.keys.iter().any(|key| key.serial == remove) {
            return Err(plain("wallet.yubi.not_enrolled"));
        }
        let staying = doc
            .keys
            .iter()
            .find(|key| key.serial != remove)
            .ok_or_else(|| plain("wallet.yubi.malformed"))?
            .clone();
        let connected = self.piv.connected()?;
        let mut candidates: Vec<u32> = connected
            .into_iter()
            .filter(|serial| *serial != staying.serial)
            .collect();
        candidates.sort_unstable();
        candidates.dedup();
        let new_serial = match candidates.as_slice() {
            [] => return Err(plain("wallet.yubi.insert_new")),
            [serial] => *serial,
            _ => return Err(plain("wallet.yubi.many")),
        };
        let public = self.public_key(new_serial, pin)?;
        let dek = self.session.dek.clone().ok_or(KeyStoreError::Locked)?;
        let retired = self.session.retired.clone();
        let body = SecretBytes(bundle(&dek, &retired));
        let staying_wrapped = kek::seal(&staying.public, &body.0)?;
        let new_wrapped = kek::seal(&public, &body.0)?;
        let mut next = doc.clone();
        next.keys = vec![
            Record {
                serial: staying.serial,
                public: staying.public,
                wrapped: staying_wrapped,
            },
            Record {
                serial: new_serial,
                public,
                wrapped: new_wrapped,
            },
        ];
        next.pending.clear();
        next.generation = bump(doc.generation)?;
        write_doc(self.path, &next)?;
        self.session.generation = next.generation;
        self.session.replacing = None;
        self.session.dek = Some(dek);
        self.session.retired = retired;
        Ok(new_serial)
    }

    fn switch_to_keyring(&mut self, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let doc = read_doc(self.path)?;
        self.require_pair(&doc)?;
        let serial = connected_enrolled(self.piv, &doc)?;
        let record = doc
            .keys
            .iter()
            .find(|key| key.serial == serial)
            .ok_or_else(|| plain("wallet.yubi.not_enrolled"))?
            .clone();
        let (dek, retired) = self.open_record(&record, pin)?;
        self.desktop.store_key(&dek)?;
        self.desktop.store_retired(&retired)?;
        let loaded = self
            .desktop
            .load_key()?
            .ok_or_else(|| plain("wallet.yubi.unwrap"))?;
        if loaded.as_bytes() != dek.as_bytes() {
            return Err(plain("wallet.yubi.unwrap"));
        }
        let loaded_retired = self.desktop.load_retired()?;
        if !same_retired(&loaded_retired, &retired) {
            return Err(plain("wallet.yubi.unwrap"));
        }
        let mut next = doc.clone();
        next.mechanism = Mechanism::Keyring;
        next.keys.clear();
        next.pending.clear();
        next.keyring_cleared = true;
        next.generation = bump(doc.generation)?;
        write_doc(self.path, &next)?;
        forget_cache(self.session);
        self.session.generation = next.generation;
        Ok(())
    }

    #[cfg(test)]
    fn load_cached(&mut self) -> Result<Option<Aes256Key>, KeyStoreError> {
        let doc = read_doc(self.path)?;
        if doc.mechanism != Mechanism::YubiKey {
            return self.desktop.load_key();
        }
        session_dek(self.session, &doc).map(Some)
    }

    fn finish_clearance(&mut self, mut doc: Doc) -> Result<(), KeyStoreError> {
        self.desktop.delete_secrets()?;
        doc.keyring_cleared = true;
        doc.generation = bump(doc.generation)?;
        if write_doc(self.path, &doc).is_ok() {
            self.session.generation = doc.generation;
        }
        Ok(())
    }

    fn public_key(&mut self, serial: u32, pin: &str) -> Result<[u8; 65], KeyStoreError> {
        match self.piv.enroll(serial, pin) {
            Ok(public) => {
                self.remember(serial, public);
                Ok(public)
            }
            Err(PivError::Busy(found)) => match (found, self.saved_public(serial)) {
                (Some(on_device), Some(saved)) if on_device == saved => Ok(saved),
                (None, Some(saved)) => Ok(saved),
                _ => Err(KeyStoreError::SlotBusy),
            },
            Err(PivError::Store(err)) => Err(err),
        }
    }

    fn remember(&mut self, serial: u32, public: [u8; 65]) {
        self.session.last_enrolled = Some((serial, public));
        self.session.pending_new = Some((serial, public));
    }

    fn saved_public(&self, serial: u32) -> Option<[u8; 65]> {
        [self.session.pending_new, self.session.last_enrolled]
            .into_iter()
            .flatten()
            .find(|(found, _)| *found == serial)
            .map(|(_, public)| public)
    }

    fn open_record(
        &mut self,
        record: &Record,
        pin: &str,
    ) -> Result<(Aes256Key, Vec<RetiredKey>), KeyStoreError> {
        let ephemeral = ephemeral_point(&record.wrapped)?;
        let shared = self.piv.shared_secret(record.serial, pin, &ephemeral)?;
        unbundle(kek::open(&shared, &record.wrapped)?)
    }

    fn require_pair(&self, doc: &Doc) -> Result<(), KeyStoreError> {
        if doc.mechanism == Mechanism::YubiKey && doc.keys.len() == 2 {
            Ok(())
        } else {
            Err(plain("wallet.yubi.malformed"))
        }
    }
}

fn one_connected(piv: &mut impl Piv) -> Result<u32, KeyStoreError> {
    let connected = piv.connected()?;
    match connected.as_slice() {
        [] => Err(plain("wallet.yubi.none")),
        [serial] => {
            if *serial == 0 {
                Err(plain_args("wallet.yubi.device", &[("message", "0")]))
            } else {
                Ok(*serial)
            }
        }
        _ => Err(plain("wallet.yubi.many")),
    }
}

fn connected_enrolled(piv: &mut impl Piv, doc: &Doc) -> Result<u32, KeyStoreError> {
    let connected = piv.connected()?;
    if connected.is_empty() {
        return Err(plain("wallet.yubi.none"));
    }
    let hits: Vec<u32> = doc
        .keys
        .iter()
        .map(|key| key.serial)
        .filter(|serial| connected.contains(serial))
        .collect();
    match hits.as_slice() {
        [] => Err(plain("wallet.yubi.not_enrolled")),
        [serial] => Ok(*serial),
        _ => Err(plain("wallet.yubi.many")),
    }
}

fn cache_matches(session: &Session, doc: &Doc) -> bool {
    session.generation == doc.generation && session.dek.is_some()
}

fn forget_cache(session: &mut Session) {
    session.dek = None;
    session.retired.clear();
    session.replacing = None;
}

fn session_dek(session: &mut Session, doc: &Doc) -> Result<Aes256Key, KeyStoreError> {
    if doc.mechanism != Mechanism::YubiKey || !cache_matches(session, doc) {
        forget_cache(session);
        return Err(KeyStoreError::Locked);
    }
    session.dek.clone().ok_or(KeyStoreError::Locked)
}

fn rewrap_key_at(path: &Path, session: &mut Session, key: &Aes256Key) -> Result<(), KeyStoreError> {
    let doc = read_doc(path)?;
    let _ = session_dek(session, &doc)?;
    let retired = session.retired.clone();
    let next = rewrap_doc(&doc, key, &retired)?;
    write_doc(path, &next)?;
    session.dek = Some(key.clone());
    session.generation = next.generation;
    Ok(())
}

fn rewrap_retired_at(
    path: &Path,
    session: &mut Session,
    retired: &[RetiredKey],
) -> Result<(), KeyStoreError> {
    let doc = read_doc(path)?;
    let dek = session_dek(session, &doc)?;
    let next = rewrap_doc(&doc, &dek, retired)?;
    write_doc(path, &next)?;
    session.retired = retired.to_vec();
    session.generation = next.generation;
    Ok(())
}

fn rewrap_doc(doc: &Doc, dek: &Aes256Key, retired: &[RetiredKey]) -> Result<Doc, KeyStoreError> {
    if doc.keys.len() != 2 {
        return Err(plain("wallet.yubi.malformed"));
    }
    let body = SecretBytes(bundle(dek, retired));
    let mut keys = Vec::with_capacity(doc.keys.len());
    for key in &doc.keys {
        keys.push(Record {
            serial: key.serial,
            public: key.public,
            wrapped: kek::seal(&key.public, &body.0)?,
        });
    }
    let mut next = doc.clone();
    next.keys = keys;
    next.generation = bump(doc.generation)?;
    Ok(next)
}

fn bundle(dek: &Aes256Key, retired: &[RetiredKey]) -> Vec<u8> {
    let mut plain = Vec::new();
    plain.extend_from_slice(MAGIC);
    plain.push(1);
    plain.extend_from_slice(dek.as_bytes());
    plain.extend(encode_retired(retired));
    plain
}

fn unbundle(mut bytes: Vec<u8>) -> Result<(Aes256Key, Vec<RetiredKey>), KeyStoreError> {
    let result = (|| {
        if bytes.len() < 4 + 1 + 32 || &bytes[..4] != MAGIC || bytes[4] != 1 {
            return Err(plain("wallet.yubi.unwrap"));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&bytes[5..37]);
        let retired =
            decode_retired(bytes[37..].to_vec()).map_err(|_| plain("wallet.yubi.unwrap"))?;
        Ok((Aes256Key::from_bytes(dek), retired))
    })();
    bytes.zeroize();
    result
}

fn same_retired(left: &[RetiredKey], right: &[RetiredKey]) -> bool {
    left.len() == right.len()
        && left.iter().zip(right).all(|(one, other)| {
            one.expires_at == other.expires_at && one.key.as_bytes() == other.key.as_bytes()
        })
}

fn check_pin(pin: &str) -> Result<(), KeyStoreError> {
    if pin.bytes().any(|byte| !byte.is_ascii_digit()) {
        return Err(plain("wallet.yubi.pin_digits"));
    }
    if pin.len() < 6 {
        return Err(plain("wallet.yubi.pin_short"));
    }
    if pin.len() > 8 {
        return Err(plain("wallet.yubi.pin_long"));
    }
    Ok(())
}

fn bump(generation: u64) -> Result<u64, KeyStoreError> {
    generation
        .checked_add(1)
        .ok_or_else(|| plain("wallet.yubi.malformed"))
}

fn plain(key: &str) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t(key))
}

fn plain_args(key: &str, args: &[(&str, &str)]) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t_args(key, args))
}

fn file_err(err: io::Error) -> KeyStoreError {
    plain_args("wallet.yubi.file", &[("error", &err.to_string())])
}

fn read_doc(path: &Path) -> Result<Doc, KeyStoreError> {
    match fs::read_to_string(path) {
        Ok(text) => parse_doc(&text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Doc::keyring()),
        Err(err) => Err(file_err(err)),
    }
}

fn parse_doc(text: &str) -> Result<Doc, KeyStoreError> {
    let value = Json::parse(text).map_err(|_| plain("wallet.yubi.malformed"))?;
    let mechanism = match value.get("mechanism").and_then(Json::as_str) {
        Some("keyring") => Mechanism::Keyring,
        Some("yubikey") => Mechanism::YubiKey,
        _ => return Err(plain("wallet.yubi.malformed")),
    };
    let generation = match value.get("generation") {
        None => 0,
        Some(number) => number
            .as_u64()
            .ok_or_else(|| plain("wallet.yubi.malformed"))?,
    };
    let keyring_cleared = match value.get("keyring_cleared") {
        None => mechanism != Mechanism::YubiKey,
        Some(Json::Bool(flag)) => *flag,
        Some(_) => return Err(plain("wallet.yubi.malformed")),
    };
    let pending = match value.get("pending") {
        None => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(parse_pending)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(plain("wallet.yubi.malformed")),
    };
    let keys = match value.get("keys") {
        None => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(parse_record)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(plain("wallet.yubi.malformed")),
    };
    if !distinct_nonzero(pending.iter().map(|item| item.serial))
        || !distinct_nonzero(keys.iter().map(|item| item.serial))
    {
        return Err(plain("wallet.yubi.malformed"));
    }
    match mechanism {
        Mechanism::YubiKey if keys.len() == 2 && pending.is_empty() => {}
        Mechanism::Keyring if keys.is_empty() && pending.len() <= 2 => {}
        _ => return Err(plain("wallet.yubi.malformed")),
    }
    Ok(Doc {
        mechanism,
        generation,
        keyring_cleared,
        keys,
        pending,
    })
}

fn parse_pending(value: &Json) -> Result<Pending, KeyStoreError> {
    let serial = required_serial(value)?;
    let public = required_point(value)?;
    Ok(Pending { serial, public })
}

fn parse_record(value: &Json) -> Result<Record, KeyStoreError> {
    let serial = required_serial(value)?;
    let public = required_point(value)?;
    let wrapped_text = value
        .get("wrapped")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.yubi.malformed"))?;
    let wrapped = b64_decode(wrapped_text).ok_or_else(|| plain("wallet.yubi.malformed"))?;
    if wrapped.len() < 65 + 12 + 16 {
        return Err(plain("wallet.yubi.malformed"));
    }
    Ok(Record {
        serial,
        public,
        wrapped,
    })
}

fn required_serial(value: &Json) -> Result<u32, KeyStoreError> {
    let serial = value
        .get("serial")
        .and_then(Json::as_u64)
        .ok_or_else(|| plain("wallet.yubi.malformed"))?;
    u32::try_from(serial).map_err(|_| plain("wallet.yubi.malformed"))
}

fn required_point(value: &Json) -> Result<[u8; 65], KeyStoreError> {
    let text = value
        .get("public")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.yubi.malformed"))?;
    let bytes = b64_decode(text).ok_or_else(|| plain("wallet.yubi.malformed"))?;
    let point: [u8; 65] = bytes
        .try_into()
        .map_err(|_| plain("wallet.yubi.malformed"))?;
    if point[0] != 0x04 || p256::PublicKey::from_sec1_bytes(&point).is_err() {
        return Err(plain("wallet.yubi.malformed"));
    }
    Ok(point)
}

fn distinct_nonzero(serials: impl Iterator<Item = u32>) -> bool {
    let mut seen = Vec::new();
    for serial in serials {
        if serial == 0 || seen.contains(&serial) {
            return false;
        }
        seen.push(serial);
    }
    true
}

fn write_doc(path: &Path, doc: &Doc) -> Result<(), KeyStoreError> {
    let mut text = encode_doc(doc);
    text.push('\n');
    write_bytes(path, text.as_bytes())
}

fn encode_doc(doc: &Doc) -> String {
    let mechanism = match doc.mechanism {
        Mechanism::Keyring => "keyring",
        Mechanism::YubiKey => "yubikey",
    };
    let pending = Json::Array(
        doc.pending
            .iter()
            .map(|item| {
                Json::Object(vec![
                    ("serial".to_string(), Json::Number(item.serial.to_string())),
                    ("public".to_string(), Json::String(b64_encode(&item.public))),
                ])
            })
            .collect(),
    );
    let keys = Json::Array(
        doc.keys
            .iter()
            .map(|item| {
                Json::Object(vec![
                    ("serial".to_string(), Json::Number(item.serial.to_string())),
                    ("public".to_string(), Json::String(b64_encode(&item.public))),
                    (
                        "wrapped".to_string(),
                        Json::String(b64_encode(&item.wrapped)),
                    ),
                ])
            })
            .collect(),
    );
    Json::Object(vec![
        ("mechanism".to_string(), Json::String(mechanism.to_string())),
        (
            "generation".to_string(),
            Json::Number(doc.generation.to_string()),
        ),
        (
            "keyring_cleared".to_string(),
            Json::Bool(doc.keyring_cleared),
        ),
        ("pending".to_string(), pending),
        ("keys".to_string(), keys),
    ])
    .to_string()
}

fn write_bytes(path: &Path, bytes: &[u8]) -> Result<(), KeyStoreError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(0o700);
            builder.create(parent).map_err(file_err)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(file_err)?;
        }
    }
    let temporary = path.with_extension("json.new");
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(file_err)?;
        file.write_all(bytes).map_err(file_err)?;
        file.sync_all().map_err(file_err)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(file_err)?;
        fs::rename(&temporary, path).map_err(file_err)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(file_err)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn restore_bytes(path: &Path, previous: Option<&[u8]>) -> Result<(), KeyStoreError> {
    match previous {
        Some(bytes) => write_bytes(path, bytes),
        None => fs::remove_file(path).map_err(file_err),
    }
}

/// The desktop half of key protection. YubiKey mode calls these instead of
/// [`super::key_store::EncryptionKeyStore`], which would recurse.
pub(super) trait DesktopSecrets {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError>;
    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError>;
    fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError>;
    fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError>;
    fn delete_secrets(&self) -> Result<(), KeyStoreError>;
}

impl DesktopSecrets for DesktopKeyStore {
    fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
        self.load_desktop_key()
    }

    fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        self.store_desktop_key(key)
    }

    fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
        self.load_desktop_retired()
    }

    fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
        self.store_desktop_retired(keys)
    }

    fn delete_secrets(&self) -> Result<(), KeyStoreError> {
        self.delete_desktop_secrets()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wallet::piv::SoftwarePiv;
    use std::time::{SystemTime, UNIX_EPOCH};

    struct MemState {
        key: Option<Aes256Key>,
        retired: Vec<RetiredKey>,
        fail_delete: bool,
    }

    struct MemDesktop {
        inner: Mutex<MemState>,
    }

    impl MemDesktop {
        fn new() -> Self {
            Self {
                inner: Mutex::new(MemState {
                    key: None,
                    retired: Vec::new(),
                    fail_delete: false,
                }),
            }
        }

        fn fail_delete(&self) {
            self.inner.lock().unwrap().fail_delete = true;
        }
    }

    impl DesktopSecrets for MemDesktop {
        fn load_key(&self) -> Result<Option<Aes256Key>, KeyStoreError> {
            Ok(self.inner.lock().unwrap().key.clone())
        }

        fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
            self.inner.lock().unwrap().key = Some(key.clone());
            Ok(())
        }

        fn load_retired(&self) -> Result<Vec<RetiredKey>, KeyStoreError> {
            Ok(self.inner.lock().unwrap().retired.clone())
        }

        fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
            self.inner.lock().unwrap().retired = keys.to_vec();
            Ok(())
        }

        fn delete_secrets(&self) -> Result<(), KeyStoreError> {
            let mut state = self.inner.lock().unwrap();
            if state.fail_delete {
                return Err(KeyStoreError::Plain("delete failed".to_string()));
            }
            state.key = None;
            state.retired.clear();
            Ok(())
        }
    }

    struct Lab {
        path: PathBuf,
        root: PathBuf,
        piv: SoftwarePiv,
        desktop: MemDesktop,
        session: Session,
    }

    impl Lab {
        fn new(name: &str) -> Self {
            let root = std::env::temp_dir().join(format!(
                "oid4vc-wallet-{name}-{}-{}",
                std::process::id(),
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_millis()
            ));
            Self {
                path: root.join(FILE_NAME),
                root,
                piv: SoftwarePiv::new(),
                desktop: MemDesktop::new(),
                session: Session::empty(),
            }
        }

        fn work(&mut self) -> Work<'_, SoftwarePiv, MemDesktop> {
            Work {
                piv: &mut self.piv,
                desktop: &self.desktop,
                session: &mut self.session,
                path: &self.path,
            }
        }
    }

    impl Drop for Lab {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn message(key: &str) -> String {
        crate::i18n::t(key)
    }

    #[test]
    fn a_short_or_non_digit_pin_is_refused_before_a_key_exists() {
        let mut lab = Lab::new("yubi-pin");
        lab.piv.set_connected(&[11]);
        let short = lab.work().enroll("12345").unwrap_err();
        assert_eq!(short.to_string(), message("wallet.yubi.pin_short"));
        let letters = lab.work().enroll("12345a").unwrap_err();
        assert_eq!(letters.to_string(), message("wallet.yubi.pin_digits"));
        let long = lab.work().enroll("123456789").unwrap_err();
        assert_eq!(long.to_string(), message("wallet.yubi.pin_long"));
        let empty = lab.work().enroll("").unwrap_err();
        assert_eq!(empty.to_string(), message("wallet.yubi.pin_short"));
        assert!(!lab.piv.has_secret(11));
        assert!(read_doc(&lab.path).unwrap().pending.is_empty());
    }

    #[test]
    fn two_keys_unwrap_the_same_storage_key_and_one_is_not_enough() {
        let mut lab = Lab::new("yubi-two");
        let dek = Aes256Key::from_bytes([0x11; 32]);
        lab.desktop.store_key(&dek).unwrap();
        lab.piv.set_connected(&[11]);
        assert_eq!(lab.work().enroll("111111").unwrap(), 11);
        let err = lab.work().activate().unwrap_err();
        assert_eq!(err.to_string(), message("wallet.yubi.need_two"));
        assert_eq!(read_doc(&lab.path).unwrap().mechanism, Mechanism::Keyring);
        lab.piv.set_connected(&[22]);
        assert_eq!(lab.work().enroll("222222").unwrap(), 22);
        let again = lab.work().enroll("222222").unwrap_err();
        assert_eq!(again.to_string(), message("wallet.yubi.already"));
        lab.work().activate().unwrap();
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.mechanism, Mechanism::YubiKey);
        assert_eq!(doc.keys.len(), 2);
        assert_ne!(doc.keys[0].wrapped, doc.keys[1].wrapped);
        assert!(doc.keyring_cleared);
        assert!(lab.desktop.load_key().unwrap().is_none());
        let mode = fs::metadata(&lab.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let first = lab.work().load_cached().unwrap().unwrap();
        assert_eq!(first.as_bytes(), dek.as_bytes());
        lab.session.dek = None;
        lab.piv.set_connected(&[22]);
        lab.work().unlock("222222").unwrap();
        let second = lab.work().load_cached().unwrap().unwrap();
        assert_eq!(second.as_bytes(), dek.as_bytes());
        lab.session.dek = None;
        lab.piv.set_connected(&[11]);
        lab.work().unlock("111111").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn replace_keeps_two_keys_and_the_removed_one_cannot_unwrap() {
        let mut lab = Lab::new("yubi-replace");
        let dek = Aes256Key::from_bytes([0x22; 32]);
        lab.desktop.store_key(&dek).unwrap();
        lab.piv.set_connected(&[11]);
        lab.work().enroll("111111").unwrap();
        lab.piv.set_connected(&[22]);
        lab.work().enroll("222222").unwrap();
        lab.work().activate().unwrap();
        let err = lab.work().finish_replace(11, "333333").unwrap_err();
        assert_eq!(err.to_string(), message("wallet.yubi.always_two"));
        lab.piv.set_connected(&[22]);
        lab.work().begin_replace(11, "222222").unwrap();
        let only_staying = lab.work().finish_replace(11, "333333").unwrap_err();
        assert_eq!(only_staying.to_string(), message("wallet.yubi.insert_new"));
        lab.piv.set_connected(&[33]);
        assert_eq!(lab.work().finish_replace(11, "333333").unwrap(), 33);
        let doc = read_doc(&lab.path).unwrap();
        let serials: Vec<u32> = doc.keys.iter().map(|key| key.serial).collect();
        assert_eq!(serials, vec![22, 33]);
        for key in &doc.keys {
            let point = ephemeral_point(&key.wrapped).unwrap();
            let shared = lab.piv.shared_secret(11, "111111", &point).unwrap();
            assert!(kek::open(&shared, &key.wrapped).is_err());
        }
        lab.session.dek = None;
        lab.piv.set_connected(&[22]);
        lab.work().unlock("222222").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
        lab.session.dek = None;
        lab.piv.set_connected(&[33]);
        lab.work().unlock("333333").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn switching_back_stores_the_key_and_clears_the_wraps() {
        let mut lab = Lab::new("yubi-back");
        let dek = Aes256Key::from_bytes([0x33; 32]);
        lab.desktop.store_key(&dek).unwrap();
        lab.desktop
            .store_retired(&[RetiredKey {
                key: Aes256Key::from_bytes([0x44; 32]),
                expires_at: 90,
            }])
            .unwrap();
        lab.piv.set_connected(&[11]);
        lab.work().enroll("111111").unwrap();
        lab.piv.set_connected(&[22]);
        lab.work().enroll("222222").unwrap();
        lab.work().activate().unwrap();
        assert!(lab.desktop.load_key().unwrap().is_none());
        lab.piv.set_connected(&[22]);
        lab.work().switch_to_keyring("222222").unwrap();
        let loaded = lab.desktop.load_key().unwrap().unwrap();
        assert_eq!(loaded.as_bytes(), dek.as_bytes());
        let retired = lab.desktop.load_retired().unwrap();
        assert_eq!(retired.len(), 1);
        assert_eq!(retired[0].expires_at, 90);
        assert_eq!(retired[0].key.as_bytes(), &[0x44; 32]);
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.mechanism, Mechanism::Keyring);
        assert!(doc.keys.is_empty());
        assert!(lab.session.dek.is_none());
        assert!(lab.piv.has_secret(11));
        assert!(lab.piv.has_secret(22));
    }

    #[test]
    fn a_generation_change_locks_the_cache() {
        let mut lab = Lab::new("yubi-gen");
        lab.piv.set_connected(&[11]);
        lab.work().enroll("111111").unwrap();
        lab.piv.set_connected(&[22]);
        lab.work().enroll("222222").unwrap();
        lab.work().activate().unwrap();
        assert!(lab.work().load_cached().unwrap().is_some());
        let mut doc = read_doc(&lab.path).unwrap();
        doc.generation += 1;
        write_doc(&lab.path, &doc).unwrap();
        let err = lab.work().load_cached().unwrap_err();
        assert!(matches!(err, KeyStoreError::Locked));
    }

    #[test]
    fn discard_drops_pending_keys_and_a_busy_slot_can_be_reused() {
        let mut lab = Lab::new("yubi-pending");
        lab.piv.set_connected(&[11]);
        lab.work().enroll("111111").unwrap();
        let mut doc = read_doc(&lab.path).unwrap();
        let public = doc.pending[0].public;
        doc.pending.clear();
        write_doc(&lab.path, &doc).unwrap();
        lab.work().enroll("111111").unwrap();
        let restored = read_doc(&lab.path).unwrap();
        assert_eq!(restored.pending[0].public, public);
        assert_eq!(restored.mechanism, Mechanism::Keyring);
        lab.work().discard().unwrap();
        assert!(read_doc(&lab.path).unwrap().pending.is_empty());
    }

    #[test]
    fn a_foreign_slot_is_not_reused() {
        let mut lab = Lab::new("yubi-foreign");
        lab.piv.occupy_foreign(11);
        lab.piv.set_connected(&[11]);
        let err = lab.work().enroll("111111").unwrap_err();
        assert!(matches!(err, KeyStoreError::SlotBusy), "{err}");
        assert!(read_doc(&lab.path).unwrap().pending.is_empty());
    }

    #[test]
    fn a_failed_desktop_delete_rolls_the_file_back() {
        let mut lab = Lab::new("yubi-rollback");
        let dek = Aes256Key::from_bytes([0x55; 32]);
        lab.desktop.store_key(&dek).unwrap();
        lab.piv.set_connected(&[11]);
        lab.work().enroll("111111").unwrap();
        lab.piv.set_connected(&[22]);
        lab.work().enroll("222222").unwrap();
        lab.desktop.fail_delete();
        let err = lab.work().activate().unwrap_err();
        assert_eq!(err.to_string(), "delete failed");
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.mechanism, Mechanism::Keyring);
        assert_eq!(doc.pending.len(), 2);
        assert_eq!(
            lab.desktop.load_key().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
        assert!(lab.session.dek.is_none());
    }

    #[test]
    fn the_same_serial_can_be_enrolled_again_after_its_slot_is_cleared() {
        let mut lab = Lab::new("yubi-reset");
        lab.desktop
            .store_key(&Aes256Key::from_bytes([0x66; 32]))
            .unwrap();
        lab.piv.set_connected(&[11]);
        lab.work().enroll("111111").unwrap();
        lab.piv.set_connected(&[22]);
        lab.work().enroll("222222").unwrap();
        lab.work().activate().unwrap();
        lab.piv.set_connected(&[22]);
        lab.work().begin_replace(11, "222222").unwrap();
        lab.piv.reset_slot(11);
        lab.piv.set_connected(&[11]);
        assert_eq!(lab.work().finish_replace(11, "111111").unwrap(), 11);
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.keys.len(), 2);
        lab.session.dek = None;
        lab.piv.set_connected(&[11]);
        lab.work().unlock("111111").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            &[0x66; 32]
        );
    }
}
