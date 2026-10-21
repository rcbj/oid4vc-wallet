//! Where the AES-256 storage key is kept.
//!
//! The desktop key ring is the default. FIDO protection replaces that with
//! the hmac-secret of two authenticators and deletes the desktop copy only
//! after both wrapped copies are on disk. Either authenticator can unwrap
//! the storage key. Replacing one checks the one that stays, then enrolls
//! the new one, so the file never holds fewer than two.
//!
//! The HMAC output cannot be recomputed from the stored public key, so this
//! process caches it. A later launch asks for a PIN again. Rotating the
//! storage key reseals both copies, so both outputs have to be cached.
//! Tests pass their own session, file, and software authenticators, so they
//! do not touch this cache, the real key ring, or a USB device.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use zeroize::Zeroize;

use crate::protocol::Json;

use super::b64::{b64_decode, b64_encode};
use super::fido::{Enrollment, Fido, HardwareFido};
use super::kek;
use super::key_store::{
    decode_retired, encode_retired, DesktopKeyStore, KeyStoreError, RetiredKey,
};
use super::seal::Aes256Key;

const FILE_NAME: &str = "key-protection.json";
const MAGIC: &[u8; 4] = b"O4FK";
const MAX_ID: usize = 1024;
const MAX_PUBLIC: usize = 512;
const MAX_LABEL: usize = 80;

static SESSION: Mutex<Session> = Mutex::new(Session::empty());

/// Which store currently protects the storage key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Keyring,
    Fido,
}

/// One authenticator the Security tab can name.
///
/// `id` is the base64 credential id. The label is what the person sees.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuthenticatorRef {
    pub id: String,
    pub label: String,
}

/// What Settings → Security shows, and what the credential list consults.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectionStatus {
    pub mechanism: Mechanism,
    pub enrolled: Vec<AuthenticatorRef>,
    pub pending: Vec<AuthenticatorRef>,
    pub unlocked: bool,
    /// FIDO mode is on, and a desktop copy could not be deleted yet.
    pub keyring_pending_removal: bool,
    /// Unlocked, and one enrolled HMAC output is not cached yet.
    ///
    /// A restart learns one output per unlock. Rotating the storage key
    /// reseals both copies, so the other authenticator has to be unlocked
    /// in this same process.
    pub other_needed: bool,
}

struct CachedKek {
    id: Vec<u8>,
    kek: [u8; 32],
}

impl Drop for CachedKek {
    fn drop(&mut self) {
        self.kek.zeroize();
    }
}

struct Session {
    dek: Option<Aes256Key>,
    retired: Vec<RetiredKey>,
    generation: u64,
    keks: Vec<CachedKek>,
    replacing: Option<Vec<u8>>,
}

impl Session {
    const fn empty() -> Self {
        Self {
            dek: None,
            retired: Vec::new(),
            generation: 0,
            keks: Vec::new(),
            replacing: None,
        }
    }
}

#[derive(Clone)]
struct Record {
    id: Vec<u8>,
    public_key: Vec<u8>,
    salt: [u8; 32],
    label: String,
    wrapped: Vec<u8>,
}

#[derive(Clone)]
struct Pending {
    id: Vec<u8>,
    public_key: Vec<u8>,
    salt: [u8; 32],
    label: String,
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
struct Work<'a, F, D> {
    fido: &'a mut F,
    desktop: &'a D,
    session: &'a mut Session,
    path: &'a Path,
}

/// Read `$XDG_DATA_HOME/oid4vc-wallet/key-protection.json` and the cache.
///
/// # Errors
///
/// The protection file cannot be read or is malformed, or the session lock is
/// poisoned.
pub fn protection_status() -> Result<ProtectionStatus, KeyStoreError> {
    with_global(|mut work| work.status())
}

/// True when a credential command must ask for a FIDO2 PIN before it can read.
///
/// # Errors
///
/// The protection file cannot be read or is malformed, or the session lock is
/// poisoned.
pub fn fido_locked() -> Result<bool, KeyStoreError> {
    let doc = read_doc(&default_path()?)?;
    if doc.mechanism != Mechanism::Fido {
        return Ok(false);
    }
    let session = lock_session()?;
    Ok(!cache_matches(&session, &doc))
}

/// Enroll the one connected authenticator. The storage key stays in the key
/// ring until [`activate_fido`]. The returned text is the label.
///
/// # Errors
///
/// The PIN is too short or too long, not exactly one authenticator is
/// connected, it lacks `hmac-secret` or a PIN, it is already pending, two are
/// already pending, the device refuses, or the protection file cannot be
/// written.
pub fn enroll_fido(pin: &str) -> Result<String, KeyStoreError> {
    with_global(|mut work| work.enroll(pin))
}

/// Wrap the storage key to the two enrolled authenticators and remove the desktop copy.
///
/// # Errors
///
/// Two authenticators are not pending, this process no longer holds both HMAC
/// outputs, the desktop key cannot be read, or the protection file or the
/// desktop delete fails.
pub fn activate_fido() -> Result<(), KeyStoreError> {
    with_global(|mut work| work.activate())
}

/// Forget authenticators enrolled while the key ring is still in use.
///
/// # Errors
///
/// Security keys are already in use, or the protection file cannot be read or
/// written.
pub fn discard_pending() -> Result<(), KeyStoreError> {
    with_global(|mut work| work.discard())
}

/// Unwrap with one connected enrolled authenticator and cache the storage key.
///
/// # Errors
///
/// The PIN is refused, not exactly one authenticator is connected, it holds no
/// enrolled credential, or the wrapped key does not open.
pub fn unlock_fido(pin: &str) -> Result<(), KeyStoreError> {
    with_global(|mut work| work.unlock(pin))
}

/// Cache the HMAC output of the enrolled authenticator this session has not
/// unlocked yet. The storage key is already unwrapped.
///
/// # Errors
///
/// Security keys are not in use, the storage key is not unwrapped, not exactly
/// one authenticator is connected, or the connected one is already unlocked.
pub fn unlock_other_fido(pin: &str) -> Result<(), KeyStoreError> {
    with_global(|mut work| work.unlock_other(pin))
}

/// Check the authenticator that will stay, before the other one is replaced.
///
/// `remove_id` is the base64 credential id from [`ProtectionStatus`].
///
/// # Errors
///
/// The PIN is refused, not exactly one authenticator is connected, or it does
/// not hold the credential that stays.
pub fn begin_replace(remove_id: &str, staying_pin: &str) -> Result<(), KeyStoreError> {
    with_global(|mut work| work.begin_replace(remove_id, staying_pin))
}

/// Enroll the new authenticator and drop `remove_id` from the protection file.
///
/// # Errors
///
/// [`begin_replace`] was not called for `remove_id`, the protection file
/// changed since, the connected authenticator is the one that stays, the device
/// refuses, or the protection file cannot be written.
pub fn finish_replace(remove_id: &str, pin: &str) -> Result<String, KeyStoreError> {
    with_global(|mut work| work.finish_replace(remove_id, pin))
}

/// Stop a replacement without changing the enrolled authenticators.
///
/// # Errors
///
/// The protection file has no location, or the session lock is poisoned.
pub fn cancel_replace() -> Result<(), KeyStoreError> {
    with_global(|work| {
        work.session.replacing = None;
        Ok(())
    })
}

/// Unwrap with an authenticator, store that key in the desktop key ring, and
/// stop using the authenticators. The FIDO credentials stay on the devices.
///
/// # Errors
///
/// The PIN is refused, not exactly one enrolled authenticator is connected, the
/// desktop store refuses the key or reads back something else, or the
/// protection file cannot be written.
pub fn switch_to_keyring(pin: &str) -> Result<(), KeyStoreError> {
    with_global(|mut work| work.switch_to_keyring(pin))
}

pub(super) fn protects_with_fido() -> Result<bool, KeyStoreError> {
    Ok(read_doc(&default_path()?)?.mechanism == Mechanism::Fido)
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

// `body` takes the `Work` by value. With `&mut Work<'_, ..>` clippy asks for
// `Work::status` in place of `|work| work.status()`, and a method path is
// not general over the borrowed lifetime, so that suggestion does not compile.
fn with_global<T>(
    body: impl FnOnce(Work<'_, HardwareFido, DesktopKeyStore>) -> Result<T, KeyStoreError>,
) -> Result<T, KeyStoreError> {
    let mut session = lock_session()?;
    let path = default_path()?;
    let mut fido = HardwareFido;
    let desktop = DesktopKeyStore::wallet();
    body(Work {
        fido: &mut fido,
        desktop: &desktop,
        session: &mut session,
        path: &path,
    })
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

impl<F: Fido, D: DesktopSecrets> Work<'_, F, D> {
    fn status(&mut self) -> Result<ProtectionStatus, KeyStoreError> {
        let doc = read_doc(self.path)?;
        let unlocked = doc.mechanism != Mechanism::Fido || cache_matches(self.session, &doc);
        Ok(ProtectionStatus {
            mechanism: doc.mechanism,
            enrolled: doc
                .keys
                .iter()
                .map(|key| authenticator_ref(&key.id, &key.label))
                .collect(),
            pending: doc
                .pending
                .iter()
                .map(|key| authenticator_ref(&key.id, &key.label))
                .collect(),
            unlocked,
            keyring_pending_removal: doc.mechanism == Mechanism::Fido && !doc.keyring_cleared,
            other_needed: unlocked && missing_kek(self.session, &doc).is_some(),
        })
    }

    fn enroll(&mut self, pin: &str) -> Result<String, KeyStoreError> {
        check_pin(pin)?;
        let mut doc = read_doc(self.path)?;
        if doc.mechanism != Mechanism::Keyring {
            return Err(plain("wallet.fido.always_two"));
        }
        match self.fido.device_count()? {
            0 => return Err(plain("wallet.fido.none")),
            1 => {}
            _ => return Err(plain("wallet.fido.many")),
        }
        // A key that is already pending says so even when two are waiting,
        // so the person is not told the list is full for a key they enrolled.
        let pending_ids: Vec<Vec<u8>> = doc.pending.iter().map(|item| item.id.clone()).collect();
        if let Some(id) = self.fido.holds(&pending_ids)? {
            if cached_kek(self.session, &id).is_some() {
                return Err(plain("wallet.fido.already"));
            }
            // A restart dropped this key's output, and activate cannot wrap
            // without it. The stored credential and salt give the same
            // output again, so relearn it instead of leaving a dead end.
            let Some(item) = doc.pending.iter().find(|item| item.id == id) else {
                return Err(plain("wallet.fido.malformed"));
            };
            let kek = self
                .fido
                .hmac(&item.id, &item.public_key, &item.salt, pin)?;
            remember_kek(self.session, &item.id, kek);
            return Ok(item.label.clone());
        }
        if doc.pending.len() >= 2 {
            return Err(plain("wallet.fido.pending_full"));
        }
        let enrollment = self.fido.enroll(pin)?;
        let (pending, mut kek) = pending_of(&enrollment);
        let label = pending.label.clone();
        doc.pending.push(pending);
        doc.generation = match bump(doc.generation) {
            Ok(generation) => generation,
            Err(err) => {
                kek.zeroize();
                return Err(err);
            }
        };
        if let Err(err) = write_doc(self.path, &doc) {
            kek.zeroize();
            return Err(err);
        }
        let id = doc
            .pending
            .last()
            .map(|item| item.id.clone())
            .unwrap_or_default();
        remember_kek(self.session, &id, kek);
        Ok(label)
    }

    fn activate(&mut self) -> Result<(), KeyStoreError> {
        let doc = read_doc(self.path)?;
        if doc.mechanism == Mechanism::Fido {
            if doc.keys.len() != 2 {
                return Err(plain("wallet.fido.malformed"));
            }
            if !doc.keyring_cleared {
                let _ = self.finish_clearance(doc);
            }
            return Ok(());
        }
        if doc.pending.len() != 2 {
            return Err(plain("wallet.fido.need_two"));
        }
        // The HMAC output is not on disk. A restarted process has to enroll
        // again rather than write a wrap it can never open.
        if doc
            .pending
            .iter()
            .any(|item| cached_kek(self.session, &item.id).is_none())
        {
            return Err(plain("wallet.fido.session"));
        }
        let dek = match self.desktop.load_key()? {
            Some(key) => key,
            None => Aes256Key::generate(),
        };
        let retired = self.desktop.load_retired()?;
        let body = SecretBytes(bundle(&dek, &retired));
        let mut keys = Vec::with_capacity(2);
        for pending in &doc.pending {
            let kek = cached_kek(self.session, &pending.id)
                .ok_or_else(|| plain("wallet.fido.session"))?;
            keys.push(Record {
                id: pending.id.clone(),
                public_key: pending.public_key.clone(),
                salt: pending.salt,
                label: pending.label.clone(),
                wrapped: kek::seal(kek, &body.0)?,
            });
        }
        if keys.len() != 2 || keys[0].id == keys[1].id {
            return Err(plain("wallet.fido.malformed"));
        }
        let previous = fs::read(self.path).ok();
        let mut next = doc.clone();
        next.mechanism = Mechanism::Fido;
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
            return Err(plain("wallet.fido.always_two"));
        }
        doc.pending.clear();
        doc.generation = bump(doc.generation)?;
        write_doc(self.path, &doc)?;
        self.session.keks.clear();
        Ok(())
    }

    fn unlock(&mut self, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let doc = read_doc(self.path)?;
        require_pair(&doc)?;
        let ids: Vec<Vec<u8>> = doc.keys.iter().map(|key| key.id.clone()).collect();
        let held = self
            .fido
            .holds(&ids)?
            .ok_or_else(|| plain("wallet.fido.not_enrolled"))?;
        let record = doc
            .keys
            .iter()
            .find(|key| key.id == held)
            .ok_or_else(|| plain("wallet.fido.not_enrolled"))?;
        let (dek, retired, kek) = self.open_record(record, pin)?;
        remember_kek(self.session, &record.id, kek);
        self.session.dek = Some(dek);
        self.session.retired = retired;
        self.session.generation = doc.generation;
        self.session.replacing = None;
        if !doc.keyring_cleared {
            let _ = self.finish_clearance(doc);
        }
        Ok(())
    }

    fn unlock_other(&mut self, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let doc = read_doc(self.path)?;
        require_pair(&doc)?;
        if !cache_matches(self.session, &doc) {
            return Err(KeyStoreError::Locked);
        }
        let Some(needed) = missing_kek(self.session, &doc) else {
            return Err(plain("wallet.fido.other"));
        };
        let needed = needed.to_vec();
        let ids: Vec<Vec<u8>> = doc.keys.iter().map(|key| key.id.clone()).collect();
        let held = self
            .fido
            .holds(&ids)?
            .ok_or_else(|| plain("wallet.fido.not_enrolled"))?;
        if held != needed {
            return Err(plain("wallet.fido.other"));
        }
        let record = doc
            .keys
            .iter()
            .find(|key| key.id == needed)
            .ok_or_else(|| plain("wallet.fido.not_enrolled"))?;
        let kek = self
            .fido
            .hmac(&record.id, &record.public_key, &record.salt, pin)?;
        remember_kek(self.session, &record.id, kek);
        Ok(())
    }

    fn begin_replace(&mut self, remove_id: &str, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let remove = decode_id(remove_id)?;
        let doc = read_doc(self.path)?;
        require_pair(&doc)?;
        if !doc.keys.iter().any(|key| key.id == remove) {
            return Err(plain("wallet.fido.not_enrolled"));
        }
        let staying = doc
            .keys
            .iter()
            .find(|key| key.id != remove)
            .ok_or_else(|| plain("wallet.fido.malformed"))?;
        let held = self.fido.holds(std::slice::from_ref(&staying.id))?;
        if held.is_none() {
            return Err(plain("wallet.fido.missing"));
        }
        let (dek, retired, kek) = self.open_record(staying, pin)?;
        remember_kek(self.session, &staying.id, kek);
        self.session.dek = Some(dek);
        self.session.retired = retired;
        self.session.generation = doc.generation;
        self.session.replacing = Some(remove);
        Ok(())
    }

    fn finish_replace(&mut self, remove_id: &str, pin: &str) -> Result<String, KeyStoreError> {
        check_pin(pin)?;
        let remove = decode_id(remove_id)?;
        if self.session.replacing.as_deref() != Some(remove.as_slice())
            || self.session.dek.is_none()
        {
            return Err(plain("wallet.fido.always_two"));
        }
        let doc = read_doc(self.path)?;
        require_pair(&doc)?;
        if !cache_matches(self.session, &doc) {
            forget_cache(self.session);
            return Err(KeyStoreError::Locked);
        }
        if !doc.keys.iter().any(|key| key.id == remove) {
            return Err(plain("wallet.fido.not_enrolled"));
        }
        let staying = doc
            .keys
            .iter()
            .find(|key| key.id != remove)
            .ok_or_else(|| plain("wallet.fido.malformed"))?
            .clone();
        let Some(staying_kek) = cached_kek(self.session, &staying.id).copied() else {
            return Err(plain("wallet.fido.both"));
        };
        let mut staying_kek = zeroize::Zeroizing::new(staying_kek);
        let held = self.fido.holds(&[staying.id.clone(), remove.clone()])?;
        if held.as_deref() == Some(staying.id.as_slice()) {
            return Err(plain("wallet.fido.same"));
        }
        let enrollment = self.fido.enroll(pin)?;
        let (pending, mut new_kek) = pending_of(&enrollment);
        let label = pending.label.clone();
        let dek = self.session.dek.clone().ok_or(KeyStoreError::Locked)?;
        let retired = self.session.retired.clone();
        let body = SecretBytes(bundle(&dek, &retired));
        let staying_wrapped = match kek::seal(&staying_kek, &body.0) {
            Ok(wrapped) => wrapped,
            Err(err) => {
                new_kek.zeroize();
                return Err(err);
            }
        };
        let new_wrapped = match kek::seal(&new_kek, &body.0) {
            Ok(wrapped) => wrapped,
            Err(err) => {
                new_kek.zeroize();
                return Err(err);
            }
        };
        staying_kek.zeroize();
        let mut next = doc.clone();
        next.keys = vec![
            Record {
                id: staying.id,
                public_key: staying.public_key,
                salt: staying.salt,
                label: staying.label,
                wrapped: staying_wrapped,
            },
            Record {
                id: pending.id.clone(),
                public_key: pending.public_key,
                salt: pending.salt,
                label: pending.label,
                wrapped: new_wrapped,
            },
        ];
        next.pending.clear();
        next.generation = match bump(doc.generation) {
            Ok(generation) => generation,
            Err(err) => {
                new_kek.zeroize();
                return Err(err);
            }
        };
        if let Err(err) = write_doc(self.path, &next) {
            new_kek.zeroize();
            return Err(err);
        }
        let new_id = pending.id;
        self.session.keks.retain(|item| item.id != remove);
        remember_kek(self.session, &new_id, new_kek);
        self.session.generation = next.generation;
        self.session.replacing = None;
        self.session.dek = Some(dek);
        self.session.retired = retired;
        Ok(label)
    }

    fn switch_to_keyring(&mut self, pin: &str) -> Result<(), KeyStoreError> {
        check_pin(pin)?;
        let doc = read_doc(self.path)?;
        require_pair(&doc)?;
        let ids: Vec<Vec<u8>> = doc.keys.iter().map(|key| key.id.clone()).collect();
        let held = self
            .fido
            .holds(&ids)?
            .ok_or_else(|| plain("wallet.fido.not_enrolled"))?;
        let record = doc
            .keys
            .iter()
            .find(|key| key.id == held)
            .ok_or_else(|| plain("wallet.fido.not_enrolled"))?
            .clone();
        let (dek, retired, mut kek) = self.open_record(&record, pin)?;
        kek.zeroize();
        self.desktop.store_key(&dek)?;
        self.desktop.store_retired(&retired)?;
        let loaded = self
            .desktop
            .load_key()?
            .ok_or_else(|| plain("wallet.fido.unwrap"))?;
        if loaded.as_bytes() != dek.as_bytes() {
            return Err(plain("wallet.fido.unwrap"));
        }
        let loaded_retired = self.desktop.load_retired()?;
        if !same_retired(&loaded_retired, &retired) {
            return Err(plain("wallet.fido.unwrap"));
        }
        let mut next = doc.clone();
        next.mechanism = Mechanism::Keyring;
        next.keys.clear();
        next.pending.clear();
        next.keyring_cleared = true;
        next.generation = bump(doc.generation)?;
        write_doc(self.path, &next)?;
        forget_cache(self.session);
        self.session.keks.clear();
        self.session.generation = next.generation;
        Ok(())
    }

    #[cfg(test)]
    fn load_cached(&mut self) -> Result<Option<Aes256Key>, KeyStoreError> {
        let doc = read_doc(self.path)?;
        if doc.mechanism != Mechanism::Fido {
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

    fn open_record(
        &mut self,
        record: &Record,
        pin: &str,
    ) -> Result<(Aes256Key, Vec<RetiredKey>, [u8; 32]), KeyStoreError> {
        let kek = zeroize::Zeroizing::new(self.fido.hmac(
            &record.id,
            &record.public_key,
            &record.salt,
            pin,
        )?);
        let opened = kek::open(&kek, &record.wrapped)?;
        let (dek, retired) = unbundle(opened)?;
        Ok((dek, retired, *kek))
    }
}

fn require_pair(doc: &Doc) -> Result<(), KeyStoreError> {
    if doc.mechanism == Mechanism::Fido && doc.keys.len() == 2 {
        Ok(())
    } else {
        Err(plain("wallet.fido.malformed"))
    }
}

fn pending_of(enrollment: &Enrollment) -> (Pending, [u8; 32]) {
    let pending = Pending {
        id: enrollment.id.clone(),
        public_key: enrollment.public_key.clone(),
        salt: enrollment.salt,
        label: enrollment.label.clone(),
    };
    let kek = enrollment.kek;
    (pending, kek)
}

fn authenticator_ref(id: &[u8], label: &str) -> AuthenticatorRef {
    AuthenticatorRef {
        id: b64_encode(id),
        label: label.to_string(),
    }
}

fn remember_kek(session: &mut Session, id: &[u8], mut kek: [u8; 32]) {
    if let Some(found) = session.keks.iter_mut().find(|item| item.id == id) {
        found.kek.zeroize();
        found.kek = kek;
        kek.zeroize();
        return;
    }
    session.keks.push(CachedKek {
        id: id.to_vec(),
        kek,
    });
}

fn cached_kek<'a>(session: &'a Session, id: &[u8]) -> Option<&'a [u8; 32]> {
    session
        .keks
        .iter()
        .find(|item| item.id == id)
        .map(|item| &item.kek)
}

fn missing_kek<'a>(session: &Session, doc: &'a Doc) -> Option<&'a [u8]> {
    if doc.mechanism != Mechanism::Fido {
        return None;
    }
    doc.keys
        .iter()
        .find(|key| cached_kek(session, &key.id).is_none())
        .map(|key| key.id.as_slice())
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
    if doc.mechanism != Mechanism::Fido || !cache_matches(session, doc) {
        forget_cache(session);
        if doc.mechanism != Mechanism::Fido {
            session.keks.clear();
        }
        return Err(KeyStoreError::Locked);
    }
    session.dek.clone().ok_or(KeyStoreError::Locked)
}

fn rewrap_key_at(path: &Path, session: &mut Session, key: &Aes256Key) -> Result<(), KeyStoreError> {
    let doc = read_doc(path)?;
    let _ = session_dek(session, &doc)?;
    let retired = session.retired.clone();
    let next = rewrap_doc(&doc, session, key, &retired)?;
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
    let next = rewrap_doc(&doc, session, &dek, retired)?;
    write_doc(path, &next)?;
    session.retired = retired.to_vec();
    session.generation = next.generation;
    Ok(())
}

fn rewrap_doc(
    doc: &Doc,
    session: &Session,
    dek: &Aes256Key,
    retired: &[RetiredKey],
) -> Result<Doc, KeyStoreError> {
    if doc.keys.len() != 2 {
        return Err(plain("wallet.fido.malformed"));
    }
    let body = SecretBytes(bundle(dek, retired));
    let mut keys = Vec::with_capacity(doc.keys.len());
    for key in &doc.keys {
        let kek = cached_kek(session, &key.id).ok_or_else(|| plain("wallet.fido.both"))?;
        keys.push(Record {
            id: key.id.clone(),
            public_key: key.public_key.clone(),
            salt: key.salt,
            label: key.label.clone(),
            wrapped: kek::seal(kek, &body.0)?,
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
            return Err(plain("wallet.fido.unwrap"));
        }
        let mut dek = [0u8; 32];
        dek.copy_from_slice(&bytes[5..37]);
        let retired =
            decode_retired(bytes[37..].to_vec()).map_err(|_| plain("wallet.fido.unwrap"))?;
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
    // FIDO counts UTF-8 bytes. The device enforces its own minimum, which
    // defaults to 4. Letters are allowed. 63 is the CTAP maximum.
    let len = pin.len();
    if len < 4 {
        return Err(plain("wallet.fido.pin_short"));
    }
    if len > 63 {
        return Err(plain("wallet.fido.pin_long"));
    }
    Ok(())
}

fn bump(generation: u64) -> Result<u64, KeyStoreError> {
    generation
        .checked_add(1)
        .ok_or_else(|| plain("wallet.fido.malformed"))
}

fn plain(key: &str) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t(key))
}

fn plain_args(key: &str, args: &[(&str, &str)]) -> KeyStoreError {
    KeyStoreError::Plain(crate::i18n::t_args(key, args))
}

fn file_err(err: &io::Error) -> KeyStoreError {
    plain_args("wallet.fido.file", &[("error", &err.to_string())])
}

fn decode_id(text: &str) -> Result<Vec<u8>, KeyStoreError> {
    let bytes = b64_decode(text).ok_or_else(|| plain("wallet.fido.not_enrolled"))?;
    if bytes.is_empty() || bytes.len() > MAX_ID {
        return Err(plain("wallet.fido.malformed"));
    }
    Ok(bytes)
}

fn read_doc(path: &Path) -> Result<Doc, KeyStoreError> {
    match fs::read_to_string(path) {
        Ok(text) => parse_doc(&text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Doc::keyring()),
        Err(err) => Err(file_err(&err)),
    }
}

fn parse_doc(text: &str) -> Result<Doc, KeyStoreError> {
    let value = Json::parse(text).map_err(|_| plain("wallet.fido.malformed"))?;
    // An old PIV file is refused before the rest of the parse, so a person
    // who still has one is not told the file is merely malformed.
    if value.get("mechanism").and_then(Json::as_str) == Some("yubikey") {
        return Err(plain("wallet.fido.retired_piv"));
    }
    let mechanism = match value.get("mechanism").and_then(Json::as_str) {
        Some("keyring") => Mechanism::Keyring,
        Some("fido") => Mechanism::Fido,
        _ => return Err(plain("wallet.fido.malformed")),
    };
    let generation = match value.get("generation") {
        None => 0,
        Some(number) => number
            .as_u64()
            .ok_or_else(|| plain("wallet.fido.malformed"))?,
    };
    let keyring_cleared = match value.get("keyring_cleared") {
        None => mechanism != Mechanism::Fido,
        Some(Json::Bool(flag)) => *flag,
        Some(_) => return Err(plain("wallet.fido.malformed")),
    };
    let pending = match value.get("pending") {
        None => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(parse_pending)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(plain("wallet.fido.malformed")),
    };
    let keys = match value.get("keys") {
        None => Vec::new(),
        Some(Json::Array(items)) => items
            .iter()
            .map(parse_record)
            .collect::<Result<Vec<_>, _>>()?,
        Some(_) => return Err(plain("wallet.fido.malformed")),
    };
    if !distinct_ids(pending.iter().map(|item| item.id.as_slice()))
        || !distinct_ids(keys.iter().map(|item| item.id.as_slice()))
    {
        return Err(plain("wallet.fido.malformed"));
    }
    match mechanism {
        Mechanism::Fido if keys.len() == 2 && pending.is_empty() => {}
        Mechanism::Keyring if keys.is_empty() && pending.len() <= 2 => {}
        _ => return Err(plain("wallet.fido.malformed")),
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
    let id = required_id(value)?;
    let public_key = required_public(value)?;
    let salt = required_salt(value)?;
    let label = required_label(value)?;
    Ok(Pending {
        id,
        public_key,
        salt,
        label,
    })
}

fn parse_record(value: &Json) -> Result<Record, KeyStoreError> {
    let id = required_id(value)?;
    let public_key = required_public(value)?;
    let salt = required_salt(value)?;
    let label = required_label(value)?;
    let wrapped_text = value
        .get("wrapped")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.fido.malformed"))?;
    let wrapped = b64_decode(wrapped_text).ok_or_else(|| plain("wallet.fido.malformed"))?;
    if wrapped.len() < 12 + 16 {
        return Err(plain("wallet.fido.malformed"));
    }
    Ok(Record {
        id,
        public_key,
        salt,
        label,
        wrapped,
    })
}

fn required_id(value: &Json) -> Result<Vec<u8>, KeyStoreError> {
    let text = value
        .get("id")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.fido.malformed"))?;
    let bytes = b64_decode(text).ok_or_else(|| plain("wallet.fido.malformed"))?;
    if bytes.is_empty() || bytes.len() > MAX_ID {
        return Err(plain("wallet.fido.malformed"));
    }
    Ok(bytes)
}

fn required_public(value: &Json) -> Result<Vec<u8>, KeyStoreError> {
    let text = value
        .get("public")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.fido.malformed"))?;
    let bytes = b64_decode(text).ok_or_else(|| plain("wallet.fido.malformed"))?;
    if bytes.is_empty() || bytes.len() > MAX_PUBLIC {
        return Err(plain("wallet.fido.malformed"));
    }
    Ok(bytes)
}

fn required_salt(value: &Json) -> Result<[u8; 32], KeyStoreError> {
    let text = value
        .get("salt")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.fido.malformed"))?;
    let bytes = b64_decode(text).ok_or_else(|| plain("wallet.fido.malformed"))?;
    bytes.try_into().map_err(|_| plain("wallet.fido.malformed"))
}

fn required_label(value: &Json) -> Result<String, KeyStoreError> {
    let label = value
        .get("label")
        .and_then(Json::as_str)
        .ok_or_else(|| plain("wallet.fido.malformed"))?;
    if label.is_empty() || label.chars().count() > MAX_LABEL || label.chars().any(char::is_control)
    {
        return Err(plain("wallet.fido.malformed"));
    }
    Ok(label.to_string())
}

fn distinct_ids<'a>(ids: impl Iterator<Item = &'a [u8]>) -> bool {
    let mut seen = Vec::new();
    for id in ids {
        if id.is_empty() || seen.iter().any(|found: &Vec<u8>| found.as_slice() == id) {
            return false;
        }
        seen.push(id.to_vec());
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
        Mechanism::Fido => "fido",
    };
    let pending = Json::Array(
        doc.pending
            .iter()
            .map(|item| {
                Json::Object(vec![
                    ("id".to_string(), Json::String(b64_encode(&item.id))),
                    (
                        "public".to_string(),
                        Json::String(b64_encode(&item.public_key)),
                    ),
                    ("salt".to_string(), Json::String(b64_encode(&item.salt))),
                    ("label".to_string(), Json::String(item.label.clone())),
                ])
            })
            .collect(),
    );
    let keys = Json::Array(
        doc.keys
            .iter()
            .map(|item| {
                Json::Object(vec![
                    ("id".to_string(), Json::String(b64_encode(&item.id))),
                    (
                        "public".to_string(),
                        Json::String(b64_encode(&item.public_key)),
                    ),
                    ("salt".to_string(), Json::String(b64_encode(&item.salt))),
                    ("label".to_string(), Json::String(item.label.clone())),
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
            builder.create(parent).map_err(|err| file_err(&err))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| file_err(&err))?;
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
            .map_err(|err| file_err(&err))?;
        file.write_all(bytes).map_err(|err| file_err(&err))?;
        file.sync_all().map_err(|err| file_err(&err))?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|err| file_err(&err))?;
        fs::rename(&temporary, path).map_err(|err| file_err(&err))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| file_err(&err))?;
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
        None => fs::remove_file(path).map_err(|err| file_err(&err)),
    }
}

/// The desktop half of key protection. FIDO mode calls these instead of
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
    use crate::wallet::fido::SoftwareFido;
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
        fido: SoftwareFido,
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
                fido: SoftwareFido::new(),
                desktop: MemDesktop::new(),
                session: Session::empty(),
            }
        }

        fn work(&mut self) -> Work<'_, SoftwareFido, MemDesktop> {
            Work {
                fido: &mut self.fido,
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

    fn enroll_pair(lab: &mut Lab) {
        lab.fido.set_connected(&[11]);
        lab.work().enroll("1111").unwrap();
        lab.fido.set_connected(&[22]);
        lab.work().enroll("2222").unwrap();
    }

    #[test]
    fn a_short_or_overlong_pin_is_refused_before_a_key_exists() {
        let mut lab = Lab::new("fido-pin");
        lab.fido.set_connected(&[11]);
        let short = lab.work().enroll("abc").unwrap_err();
        assert_eq!(short.to_string(), message("wallet.fido.pin_short"));
        let empty = lab.work().enroll("").unwrap_err();
        assert_eq!(empty.to_string(), message("wallet.fido.pin_short"));
        let long = lab.work().enroll(&"a".repeat(64)).unwrap_err();
        assert_eq!(long.to_string(), message("wallet.fido.pin_long"));
        assert_eq!(lab.fido.credential_count(11), 0);
        assert!(read_doc(&lab.path).unwrap().pending.is_empty());
        let letters = lab.work().enroll("12345a").unwrap();
        assert!(letters.starts_with("Security key "));
        assert_eq!(lab.fido.credential_count(11), 1);
    }

    #[test]
    fn two_keys_unwrap_the_same_storage_key_and_one_is_not_enough() {
        let mut lab = Lab::new("fido-two");
        let dek = Aes256Key::from_bytes([0x11; 32]);
        lab.desktop.store_key(&dek).unwrap();
        lab.fido.set_connected(&[11]);
        lab.work().enroll("1111").unwrap();
        let err = lab.work().activate().unwrap_err();
        assert_eq!(err.to_string(), message("wallet.fido.need_two"));
        assert_eq!(read_doc(&lab.path).unwrap().mechanism, Mechanism::Keyring);
        lab.fido.set_connected(&[22]);
        lab.work().enroll("2222").unwrap();
        let again = lab.work().enroll("2222").unwrap_err();
        assert_eq!(again.to_string(), message("wallet.fido.already"));
        lab.fido.set_connected(&[33]);
        let full = lab.work().enroll("3333").unwrap_err();
        assert_eq!(full.to_string(), message("wallet.fido.pending_full"));
        assert_eq!(lab.fido.credential_count(33), 0);
        lab.work().activate().unwrap();
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.mechanism, Mechanism::Fido);
        assert_eq!(doc.keys.len(), 2);
        assert_ne!(doc.keys[0].wrapped, doc.keys[1].wrapped);
        assert_ne!(doc.keys[0].id, doc.keys[1].id);
        assert!(doc.keyring_cleared);
        assert!(lab.desktop.load_key().unwrap().is_none());
        let mode = fs::metadata(&lab.path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let first = lab.work().load_cached().unwrap().unwrap();
        assert_eq!(first.as_bytes(), dek.as_bytes());
        lab.session.dek = None;
        lab.fido.set_connected(&[22]);
        lab.work().unlock("2222").unwrap();
        let second = lab.work().load_cached().unwrap().unwrap();
        assert_eq!(second.as_bytes(), dek.as_bytes());
        lab.session.dek = None;
        lab.fido.set_connected(&[11]);
        lab.work().unlock("1111").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn replace_keeps_two_keys_and_the_removed_one_cannot_unwrap() {
        let mut lab = Lab::new("fido-replace");
        let dek = Aes256Key::from_bytes([0x22; 32]);
        lab.desktop.store_key(&dek).unwrap();
        enroll_pair(&mut lab);
        lab.work().activate().unwrap();
        let doc = read_doc(&lab.path).unwrap();
        let removed = doc.keys[0].clone();
        let remove_id = b64_encode(&removed.id);
        let err = lab.work().finish_replace(&remove_id, "3333").unwrap_err();
        assert_eq!(err.to_string(), message("wallet.fido.always_two"));
        lab.fido.set_connected(&[22]);
        lab.work().begin_replace(&remove_id, "2222").unwrap();
        let same = lab.work().finish_replace(&remove_id, "3333").unwrap_err();
        assert_eq!(same.to_string(), message("wallet.fido.same"));
        assert_eq!(lab.fido.credential_count(22), 1);
        lab.fido.set_connected(&[33]);
        let label = lab.work().finish_replace(&remove_id, "3333").unwrap();
        assert!(label.starts_with("Security key "));
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.keys.len(), 2);
        assert!(doc.keys.iter().all(|key| key.id != removed.id));
        lab.fido.set_connected(&[11]);
        let old_kek = lab
            .fido
            .hmac(&removed.id, &removed.public_key, &removed.salt, "1111")
            .unwrap();
        for key in &doc.keys {
            assert!(kek::open(&old_kek, &key.wrapped).is_err());
        }
        lab.session.dek = None;
        lab.fido.set_connected(&[22]);
        lab.work().unlock("2222").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
        lab.session.dek = None;
        lab.fido.set_connected(&[33]);
        lab.work().unlock("3333").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            dek.as_bytes()
        );
    }

    #[test]
    fn switching_back_stores_the_key_and_leaves_the_credentials() {
        let mut lab = Lab::new("fido-back");
        let dek = Aes256Key::from_bytes([0x33; 32]);
        lab.desktop.store_key(&dek).unwrap();
        lab.desktop
            .store_retired(&[RetiredKey {
                key: Aes256Key::from_bytes([0x44; 32]),
                expires_at: 90,
            }])
            .unwrap();
        enroll_pair(&mut lab);
        lab.work().activate().unwrap();
        let ids: Vec<Vec<u8>> = read_doc(&lab.path)
            .unwrap()
            .keys
            .iter()
            .map(|key| key.id.clone())
            .collect();
        assert!(lab.desktop.load_key().unwrap().is_none());
        lab.fido.set_connected(&[22]);
        lab.work().switch_to_keyring("2222").unwrap();
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
        assert!(lab.session.keks.is_empty());
        assert!(lab.fido.has_credential(11, &ids[0]));
        assert!(lab.fido.has_credential(22, &ids[1]));
    }

    #[test]
    fn a_generation_change_locks_the_cache_and_keeps_the_wrap_keys() {
        let mut lab = Lab::new("fido-gen");
        enroll_pair(&mut lab);
        lab.work().activate().unwrap();
        assert!(lab.work().load_cached().unwrap().is_some());
        assert_eq!(lab.session.keks.len(), 2);
        let mut doc = read_doc(&lab.path).unwrap();
        doc.generation += 1;
        write_doc(&lab.path, &doc).unwrap();
        let err = lab.work().load_cached().unwrap_err();
        assert!(matches!(err, KeyStoreError::Locked));
        assert!(lab.session.dek.is_none());
        assert_eq!(lab.session.keks.len(), 2);
    }

    #[test]
    fn discard_forgets_a_pending_key_and_the_same_device_can_enroll_again() {
        let mut lab = Lab::new("fido-pending");
        lab.fido.set_connected(&[11]);
        lab.work().enroll("1111").unwrap();
        let again = lab.work().enroll("1111").unwrap_err();
        assert_eq!(again.to_string(), message("wallet.fido.already"));
        lab.work().discard().unwrap();
        assert!(read_doc(&lab.path).unwrap().pending.is_empty());
        assert!(lab.session.keks.is_empty());
        lab.work().enroll("1111").unwrap();
        assert_eq!(read_doc(&lab.path).unwrap().pending.len(), 1);
        assert_eq!(lab.fido.credential_count(11), 2);
    }

    #[test]
    fn a_failed_desktop_delete_rolls_the_file_back() {
        let mut lab = Lab::new("fido-rollback");
        let dek = Aes256Key::from_bytes([0x55; 32]);
        lab.desktop.store_key(&dek).unwrap();
        enroll_pair(&mut lab);
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
    fn activate_without_cached_wrap_keys_does_not_write_fido_mode() {
        let mut lab = Lab::new("fido-session");
        lab.desktop
            .store_key(&Aes256Key::from_bytes([0x66; 32]))
            .unwrap();
        enroll_pair(&mut lab);
        lab.session.keks.clear();
        let err = lab.work().activate().unwrap_err();
        assert_eq!(err.to_string(), message("wallet.fido.session"));
        let doc = read_doc(&lab.path).unwrap();
        assert_eq!(doc.mechanism, Mechanism::Keyring);
        assert_eq!(doc.pending.len(), 2);
    }

    #[test]
    fn enrolling_a_pending_key_after_a_restart_relearns_its_wrap_key() {
        let mut lab = Lab::new("fido-relearn");
        let dek = Aes256Key::from_bytes([0x67; 32]);
        lab.desktop.store_key(&dek).unwrap();
        enroll_pair(&mut lab);
        lab.session.keks.clear();
        lab.fido.set_connected(&[11]);
        lab.work().enroll("1111").unwrap();
        let err = lab.work().activate().unwrap_err();
        assert_eq!(err.to_string(), message("wallet.fido.session"));
        lab.fido.set_connected(&[22]);
        lab.work().enroll("2222").unwrap();
        assert_eq!(lab.fido.credential_count(11), 1);
        assert_eq!(lab.fido.credential_count(22), 1);
        assert_eq!(read_doc(&lab.path).unwrap().pending.len(), 2);
        lab.work().activate().unwrap();
        lab.session.dek = None;
        lab.fido.set_connected(&[11]);
        lab.work().unlock("1111").unwrap();
        assert_eq!(lab.session.dek.as_ref().unwrap().as_bytes(), dek.as_bytes());
    }

    #[test]
    fn rotating_needs_both_wrap_keys_and_the_other_unlock_restores_them() {
        let mut lab = Lab::new("fido-both");
        let dek = Aes256Key::from_bytes([0x77; 32]);
        lab.desktop.store_key(&dek).unwrap();
        enroll_pair(&mut lab);
        lab.work().activate().unwrap();
        let saved = lab.session.dek.take();
        lab.fido.set_connected(&[22]);
        let locked = lab.work().unlock_other("2222").unwrap_err();
        assert!(matches!(locked, KeyStoreError::Locked));
        lab.session.dek = saved;
        lab.session.keks.pop();
        let changed = Aes256Key::from_bytes([0x78; 32]);
        let err = rewrap_key_at(&lab.path, &mut lab.session, &changed).unwrap_err();
        assert_eq!(err.to_string(), message("wallet.fido.both"));
        assert_eq!(
            read_doc(&lab.path).unwrap().generation,
            lab.session.generation
        );
        lab.fido.set_connected(&[11]);
        let wrong = lab.work().unlock_other("1111").unwrap_err();
        assert_eq!(wrong.to_string(), message("wallet.fido.other"));
        lab.fido.set_connected(&[22]);
        lab.work().unlock_other("2222").unwrap();
        rewrap_key_at(&lab.path, &mut lab.session, &changed).unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            changed.as_bytes()
        );
        lab.session.dek = None;
        lab.fido.set_connected(&[11]);
        lab.work().unlock("1111").unwrap();
        assert_eq!(
            lab.work().load_cached().unwrap().unwrap().as_bytes(),
            changed.as_bytes()
        );
    }

    #[test]
    fn an_old_piv_file_is_refused_before_it_is_called_malformed() {
        let lab = Lab::new("fido-piv");
        fs::create_dir_all(lab.path.parent().unwrap()).unwrap();
        fs::write(&lab.path, "{\"mechanism\":\"yubikey\"}\n").unwrap();
        let Err(err) = read_doc(&lab.path) else {
            panic!("an old PIV file was opened");
        };
        assert_eq!(err.to_string(), message("wallet.fido.retired_piv"));
    }
}
