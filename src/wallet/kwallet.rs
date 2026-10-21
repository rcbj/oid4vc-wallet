//! KWallet, the KDE credential store.
//!
//! KWallet is reached on the session bus as `org.kde.kwalletd6`,
//! `org.kde.kwalletd5`, or the older `org.kde.kwalletd`. The key is a binary
//! entry in the network wallet. A random AES-256 key is not text, so it is
//! stored with `writeEntry` rather than `writePassword`.
//!
//! Calling a method on a name nobody owns starts that service when a service
//! file exists. The quiet path only uses `NameHasOwner`, so a GNOME session
//! that happens to have KWallet installed does not launch it.

use std::time::Duration;

use dbus::blocking::Connection;
use zeroize::Zeroize;

use super::key_store::{
    decode_retired, encode_retired, key_from_store, KeyStoreError, Probe, RetiredKey,
    KEY_HISTORY_USER, KEY_SERVICE, KEY_USER,
};
use super::seal::Aes256Key;

const INTERFACE: &str = "org.kde.KWallet";
const APP_ID: &str = KEY_SERVICE;
/// `EntryType::Stream` in KWallet. The shorter `writeEntry` stores this type.
const STREAM: i32 = 2;
const QUICK: Duration = Duration::from_secs(5);
/// `open` waits while the user answers the unlock dialog.
const UNLOCK: Duration = Duration::from_secs(120);

/// Newest first. Plasma 6 registers the 6 and 5 names on one daemon.
const DAEMONS: [Daemon; 3] = [
    Daemon {
        service: "org.kde.kwalletd6",
        path: "/modules/kwalletd6",
    },
    Daemon {
        service: "org.kde.kwalletd5",
        path: "/modules/kwalletd5",
    },
    Daemon {
        service: "org.kde.kwalletd",
        path: "/modules/kwalletd",
    },
];

#[derive(Clone, Copy)]
struct Daemon {
    service: &'static str,
    path: &'static str,
}

/// Whether a locked wallet may show its unlock dialog.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Prompt {
    /// Read only a wallet the session already unlocked.
    Never,
    /// Ask KWallet to open, which prompts when the wallet is locked.
    IfLocked,
}

pub(super) struct KWalletKeyStore {
    folder: String,
    entry: String,
}

impl KWalletKeyStore {
    pub(super) fn wallet() -> Self {
        Self {
            folder: KEY_SERVICE.to_string(),
            entry: KEY_USER.to_string(),
        }
    }

    pub(super) fn probe(&self, prompt: Prompt) -> Probe {
        match Session::open(prompt) {
            Ok(session) => session.read(&self.folder, &self.entry),
            Err(probe) => probe,
        }
    }

    pub(super) fn store_key(&self, key: &Aes256Key) -> Result<(), KeyStoreError> {
        let session = match Session::open(Prompt::IfLocked) {
            Ok(session) => session,
            Err(Probe::Absent) => return Err(KeyStoreError::Unavailable),
            Err(Probe::Failed(err)) => return Err(err),
            Err(Probe::Empty | Probe::Found(_)) => {
                return Err(KeyStoreError::Store(crate::i18n::t(
                    "wallet.keystore.kwallet_closed",
                )))
            }
        };
        session.write(&self.folder, &self.entry, key)
    }

    pub(super) fn load_retired(&self, prompt: Prompt) -> Result<Vec<RetiredKey>, KeyStoreError> {
        let session = match Session::open(prompt) {
            Ok(session) => session,
            Err(Probe::Absent) => return Err(KeyStoreError::Unavailable),
            Err(Probe::Failed(err)) => return Err(err),
            Err(Probe::Empty | Probe::Found(_)) => {
                return Err(KeyStoreError::Store(crate::i18n::t(
                    "wallet.keystore.kwallet_closed",
                )))
            }
        };
        session.read_history(&self.folder, KEY_HISTORY_USER)
    }

    pub(super) fn store_retired(&self, keys: &[RetiredKey]) -> Result<(), KeyStoreError> {
        let session = match Session::open(Prompt::IfLocked) {
            Ok(session) => session,
            Err(Probe::Absent) => return Err(KeyStoreError::Unavailable),
            Err(Probe::Failed(err)) => return Err(err),
            Err(Probe::Empty | Probe::Found(_)) => {
                return Err(KeyStoreError::Store(crate::i18n::t(
                    "wallet.keystore.kwallet_closed",
                )))
            }
        };
        let mut secret = encode_retired(keys);
        let result = session.write_bytes(&self.folder, KEY_HISTORY_USER, &secret);
        secret.zeroize();
        result
    }

    /// Remove the history entry, then the key entry.
    ///
    /// History goes first so removing the key does not drop the folder while
    /// the other entry is still in it. A missing daemon is success. A closed
    /// wallet on the quiet path is success and deletes nothing: that probe
    /// does not show whether the key is there.
    pub(super) fn delete_secrets(&self, prompt: Prompt) -> Result<(), KeyStoreError> {
        let session = match Session::open(prompt) {
            Ok(session) => session,
            Err(Probe::Absent) => return Ok(()),
            Err(Probe::Empty) if prompt == Prompt::Never => return Ok(()),
            Err(Probe::Empty | Probe::Found(_)) => {
                return Err(KeyStoreError::Store(crate::i18n::t(
                    "wallet.keystore.kwallet_closed",
                )))
            }
            Err(Probe::Failed(err)) => return Err(err),
        };
        session.remove(&self.folder, KEY_HISTORY_USER)?;
        session.remove(&self.folder, &self.entry)
    }

    /// Remove the entry and, when the folder is then empty, the folder.
    #[cfg(test)]
    fn delete(&self) -> Result<(), KeyStoreError> {
        self.delete_secrets(Prompt::Never)
    }

    /// True when a daemon is running and its network wallet is already open.
    /// This does not start KWallet and does not prompt.
    #[cfg(test)]
    fn already_open() -> bool {
        let Ok(conn) = Connection::new_session() else {
            return false;
        };
        let Ok(Some(daemon)) = reach(&conn, Prompt::Never) else {
            return false;
        };
        let Ok(wallet) = network_wallet(&conn, daemon) else {
            return false;
        };
        is_open(&conn, daemon, &wallet).unwrap_or(false)
    }
}

struct Session {
    conn: Connection,
    daemon: Daemon,
    wallet: String,
    handle: i32,
}

impl Session {
    fn open(prompt: Prompt) -> Result<Self, Probe> {
        let conn = match Connection::new_session() {
            Ok(conn) => conn,
            Err(err) => return Err(dbus_probe(&err)),
        };
        let daemon = match reach(&conn, prompt) {
            Ok(Some(daemon)) => daemon,
            Ok(None) => return Err(Probe::Absent),
            Err(err) => return Err(dbus_probe(&err)),
        };
        let wallet = match network_wallet(&conn, daemon) {
            Ok(wallet) => wallet,
            Err(err) => return Err(dbus_probe(&err)),
        };
        if prompt == Prompt::Never {
            match is_open(&conn, daemon, &wallet) {
                Ok(true) => {}
                Ok(false) => return Err(Probe::Empty),
                Err(err) => return Err(dbus_probe(&err)),
            }
        }
        let handle = match open_handle(&conn, daemon, &wallet) {
            Ok(handle) if handle >= 0 => handle,
            Ok(_) => {
                return Err(Probe::Failed(KeyStoreError::Store(crate::i18n::t(
                    "wallet.keystore.kwallet_closed",
                ))))
            }
            Err(err) => return Err(dbus_probe(&err)),
        };
        Ok(Self {
            conn,
            daemon,
            wallet,
            handle,
        })
    }

    fn read(&self, folder: &str, entry: &str) -> Probe {
        let has = match call::<(bool,)>(
            &self.conn,
            self.daemon,
            "hasEntry",
            (self.handle, folder, entry, APP_ID),
            QUICK,
        ) {
            Ok((has,)) => has,
            Err(probe) => return probe,
        };
        if !has {
            return Probe::Empty;
        }
        match call::<(Vec<u8>,)>(
            &self.conn,
            self.daemon,
            "readEntry",
            (self.handle, folder, entry, APP_ID),
            QUICK,
        ) {
            Ok((bytes,)) => match key_from_store(bytes) {
                Ok(key) => Probe::Found(key),
                Err(err) => Probe::Failed(err),
            },
            Err(probe) => probe,
        }
    }

    fn write(&self, folder: &str, entry: &str, key: &Aes256Key) -> Result<(), KeyStoreError> {
        self.write_bytes(folder, entry, key.as_bytes())
    }

    fn read_history(&self, folder: &str, entry: &str) -> Result<Vec<RetiredKey>, KeyStoreError> {
        let has = match call::<(bool,)>(
            &self.conn,
            self.daemon,
            "hasEntry",
            (self.handle, folder, entry, APP_ID),
            QUICK,
        ) {
            Ok((has,)) => has,
            Err(probe) => return Err(probe_error(probe)),
        };
        if !has {
            return Ok(Vec::new());
        }
        let bytes = match call::<(Vec<u8>,)>(
            &self.conn,
            self.daemon,
            "readEntry",
            (self.handle, folder, entry, APP_ID),
            QUICK,
        ) {
            Ok((bytes,)) => bytes,
            Err(probe) => return Err(probe_error(probe)),
        };
        decode_retired(bytes)
    }

    fn write_bytes(&self, folder: &str, entry: &str, bytes: &[u8]) -> Result<(), KeyStoreError> {
        self.ensure_folder(folder)?;
        let written: Result<(i32,), dbus::Error> = proxy(&self.conn, self.daemon, QUICK)
            .method_call(
                INTERFACE,
                "writeEntry",
                (self.handle, folder, entry, bytes, APP_ID),
            );
        let (code,): (i32,) = match written {
            Ok(code) => code,
            Err(err) if signature_mismatch(&err) => proxy(&self.conn, self.daemon, QUICK)
                .method_call(
                    INTERFACE,
                    "writeEntry",
                    (self.handle, folder, entry, bytes, STREAM, APP_ID),
                )?,
            Err(err) => return Err(dbus_error(&err)),
        };
        if code != 0 {
            return Err(rejected(&code.to_string()));
        }
        Ok(())
    }

    fn remove(&self, folder: &str, entry: &str) -> Result<(), KeyStoreError> {
        let (has,): (bool,) = call(
            &self.conn,
            self.daemon,
            "hasEntry",
            (self.handle, folder, entry, APP_ID),
            QUICK,
        )
        .map_err(probe_error)?;
        if has {
            let (code,): (i32,) = call(
                &self.conn,
                self.daemon,
                "removeEntry",
                (self.handle, folder, entry, APP_ID),
                QUICK,
            )
            .map_err(probe_error)?;
            if code != 0 {
                return Err(rejected(&code.to_string()));
            }
        }
        let (names,): (Vec<String>,) = call(
            &self.conn,
            self.daemon,
            "entryList",
            (self.handle, folder, APP_ID),
            QUICK,
        )
        .map_err(probe_error)?;
        if names.is_empty() {
            let (removed,): (bool,) = call(
                &self.conn,
                self.daemon,
                "removeFolder",
                (self.handle, folder, APP_ID),
                QUICK,
            )
            .map_err(probe_error)?;
            if !removed {
                let (still,): (bool,) = call(
                    &self.conn,
                    self.daemon,
                    "hasFolder",
                    (self.handle, folder, APP_ID),
                    QUICK,
                )
                .map_err(probe_error)?;
                if still {
                    return Err(rejected("removeFolder"));
                }
            }
        }
        Ok(())
    }

    fn ensure_folder(&self, folder: &str) -> Result<(), KeyStoreError> {
        let (exists,): (bool,) = call(
            &self.conn,
            self.daemon,
            "hasFolder",
            (self.handle, folder, APP_ID),
            QUICK,
        )
        .map_err(probe_error)?;
        if exists {
            return Ok(());
        }
        let (created,): (bool,) = call(
            &self.conn,
            self.daemon,
            "createFolder",
            (self.handle, folder, APP_ID),
            QUICK,
        )
        .map_err(probe_error)?;
        if created {
            Ok(())
        } else {
            Err(rejected("createFolder"))
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        close_handle(&self.conn, self.daemon, self.handle, APP_ID, &self.wallet);
    }
}

fn reach(conn: &Connection, prompt: Prompt) -> Result<Option<Daemon>, dbus::Error> {
    match prompt {
        Prompt::Never => {
            let Some(daemon) = owned_daemon(conn)? else {
                return Ok(None);
            };
            if is_enabled(conn, daemon)? {
                Ok(Some(daemon))
            } else {
                Ok(None)
            }
        }
        Prompt::IfLocked => {
            for daemon in DAEMONS {
                match is_enabled(conn, daemon) {
                    Ok(true) => return Ok(Some(daemon)),
                    Ok(false) => return Ok(None),
                    Err(err) if dbus_is_absent(&err) => {}
                    Err(err) => return Err(err),
                }
            }
            Ok(None)
        }
    }
}

fn owned_daemon(conn: &Connection) -> Result<Option<Daemon>, dbus::Error> {
    let bus = conn.with_proxy("org.freedesktop.DBus", "/org/freedesktop/DBus", QUICK);
    for daemon in DAEMONS {
        let (owned,): (bool,) =
            bus.method_call("org.freedesktop.DBus", "NameHasOwner", (daemon.service,))?;
        if owned {
            return Ok(Some(daemon));
        }
    }
    Ok(None)
}

fn is_enabled(conn: &Connection, daemon: Daemon) -> Result<bool, dbus::Error> {
    let (enabled,): (bool,) = proxy(conn, daemon, QUICK).method_call(INTERFACE, "isEnabled", ())?;
    Ok(enabled)
}

fn network_wallet(conn: &Connection, daemon: Daemon) -> Result<String, dbus::Error> {
    let (wallet,): (String,) =
        proxy(conn, daemon, QUICK).method_call(INTERFACE, "networkWallet", ())?;
    Ok(wallet)
}

fn is_open(conn: &Connection, daemon: Daemon, wallet: &str) -> Result<bool, dbus::Error> {
    let (open,): (bool,) =
        proxy(conn, daemon, QUICK).method_call(INTERFACE, "isOpen", (wallet,))?;
    Ok(open)
}

/// Current KWallet takes the window id as `x` (int64). Older daemons take `q`
/// (uint16). A signature miss is the only reason to try the older call.
fn open_handle(conn: &Connection, daemon: Daemon, wallet: &str) -> Result<i32, dbus::Error> {
    let proxy = proxy(conn, daemon, UNLOCK);
    let opened: Result<(i32,), dbus::Error> =
        proxy.method_call(INTERFACE, "open", (wallet, 0i64, APP_ID));
    let (handle,): (i32,) = match opened {
        Ok(handle) => handle,
        Err(err) if signature_mismatch(&err) => {
            proxy.method_call(INTERFACE, "open", (wallet, 0u16, APP_ID))?
        }
        Err(err) => return Err(err),
    };
    Ok(handle)
}

fn close_handle(conn: &Connection, daemon: Daemon, handle: i32, app_id: &str, wallet: &str) {
    let proxy = proxy(conn, daemon, QUICK);
    let closed: Result<(i32,), dbus::Error> =
        proxy.method_call(INTERFACE, "close", (handle, false, app_id));
    if let Err(err) = closed {
        if signature_mismatch(&err) {
            let _: Result<(i32,), dbus::Error> =
                proxy.method_call(INTERFACE, "close", (wallet, false));
        }
    }
}

fn call<R>(
    conn: &Connection,
    daemon: Daemon,
    method: &str,
    args: impl dbus::arg::AppendAll,
    timeout: Duration,
) -> Result<R, Probe>
where
    R: dbus::arg::ReadAll,
{
    proxy(conn, daemon, timeout)
        .method_call(INTERFACE, method, args)
        .map_err(|err| dbus_probe(&err))
}

fn proxy(
    conn: &Connection,
    daemon: Daemon,
    timeout: Duration,
) -> dbus::blocking::Proxy<'_, &Connection> {
    conn.with_proxy(daemon.service, daemon.path, timeout)
}

fn signature_mismatch(err: &dbus::Error) -> bool {
    matches!(
        err.name(),
        Some("org.freedesktop.DBus.Error.UnknownMethod" | "org.freedesktop.DBus.Error.InvalidArgs")
    )
}

pub(super) fn dbus_is_absent(err: &dbus::Error) -> bool {
    if matches!(
        err.name(),
        Some(
            "org.freedesktop.DBus.Error.ServiceUnknown"
                | "org.freedesktop.DBus.Error.NameHasNoOwner"
        )
    ) {
        return true;
    }
    let message = err.message().unwrap_or("").to_ascii_lowercase();
    message.contains("failed to connect")
        || message.contains("no such file or directory")
        || message.contains("cannot autolaunch")
}

fn dbus_probe(err: &dbus::Error) -> Probe {
    if dbus_is_absent(err) {
        Probe::Absent
    } else {
        Probe::Failed(KeyStoreError::Store(err.to_string()))
    }
}

fn dbus_error(err: &dbus::Error) -> KeyStoreError {
    match dbus_probe(err) {
        Probe::Failed(err) => err,
        Probe::Absent | Probe::Empty | Probe::Found(_) => KeyStoreError::Unavailable,
    }
}

fn probe_error(probe: Probe) -> KeyStoreError {
    match probe {
        Probe::Failed(err) => err,
        Probe::Absent | Probe::Empty | Probe::Found(_) => KeyStoreError::Unavailable,
    }
}

fn rejected(code: &str) -> KeyStoreError {
    KeyStoreError::Store(crate::i18n::t_args(
        "wallet.keystore.kwallet_rejected",
        &[("code", code)],
    ))
}

impl From<dbus::Error> for KeyStoreError {
    fn from(err: dbus::Error) -> Self {
        dbus_error(&err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_kwallet_name_is_absence_and_a_refusal_is_not() {
        let missing = dbus::Error::new_custom(
            "org.freedesktop.DBus.Error.ServiceUnknown",
            "The name org.kde.kwalletd6 was not provided by any .service files",
        );
        assert!(dbus_is_absent(&missing));
        let bus = dbus::Error::new_failed(
            "Failed to connect to socket /run/user/1000/bus: No such file or directory",
        );
        assert!(dbus_is_absent(&bus));
        let refused = dbus::Error::new_custom(
            "org.freedesktop.DBus.Error.AccessDenied",
            "KWallet refused the call",
        );
        assert!(!dbus_is_absent(&refused));
    }

    #[test]
    fn kwallet_round_trip_when_the_wallet_is_already_open() {
        let store = KWalletKeyStore {
            folder: format!("org.rcbj.oid4vc-wallet.test.{}", std::process::id()),
            entry: KEY_USER.to_string(),
        };
        assert_ne!(store.folder, KEY_SERVICE);
        if !KWalletKeyStore::already_open() {
            eprintln!("KWallet is not open, skipping");
            return;
        }
        let key = Aes256Key::generate();
        store
            .store_key(&key)
            .unwrap_or_else(|err| panic!("open KWallet did not store the test key: {err}"));
        let _cleanup = RemoveItem(&store);
        let loaded = store
            .probe(Prompt::Never)
            .into_key()
            .unwrap_or_else(|err| panic!("stored key could not be read back: {err}"));
        let loaded = loaded.expect("the key was just stored");
        assert_eq!(loaded.as_bytes(), key.as_bytes());
        store.delete().expect("test key could not be removed");
        assert!(store.probe(Prompt::Never).into_key().unwrap().is_none());
    }

    struct RemoveItem<'a>(&'a KWalletKeyStore);

    impl Drop for RemoveItem<'_> {
        fn drop(&mut self) {
            let _ = self.0.delete();
        }
    }
}
