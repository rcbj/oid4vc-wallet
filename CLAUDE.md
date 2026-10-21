# OID4VC Wallet — notes for agents

Linux native wallet for OpenID4VCI, OpenID4VP, and SIOPv2. Crate `oid4vc-wallet` 0.1.0, library `oid4vc_wallet`, binary `oid4vc-wallet`. Rust 2021, `rust-version` 1.95, `rust-toolchain.toml` channel `stable`. License BUSL-1.1 (see `LICENSE` and the README license section). `publish = false`. Repository https://github.com/rcbj/oid4vc-wallet. Used to exercise [iya-sts](https://github.com/rcbj/iya-sts).

People using the window follow `docs/guide.md` (published at https://rcbj.github.io/oid4vc-wallet/). Builders follow `README.md`. This file is the map of invariants that are expensive to rediscover. When this file and the code disagree, trust the code and update this file.

The UI is native egui (`eframe` 0.37). It is not a web app. Do not verify it in a browser. `./install/test.sh` does not open the window and does not touch a real YubiKey, the user's keyring, or the user's wallet files. Say that when you report tests.

## Hard rules

- OpenID4VCI, OpenID4VP, SIOPv2, SD-JWT, and JOSE are implemented in this crate. Do not add a crate whose job is to implement them. The allowed signature and TLS crates are listed in the `Cargo.toml` header. `p256` is for proofs of possession and for the YubiKey key-encryption key. `yubikey` 0.8 with feature `untested` is the PC/SC client; that feature is the crate's gate for PIV decipher.
- Protocol JSON is `protocol::Json` (`src/protocol/json.rs`). Numbers stay as their literal text. There is no serde. `Json::get` returns the last duplicate key. There is no `as_bool`; match `Json::Bool`. `as_u64` accepts only a base-10 integer literal that fits in `u64`.
- User-visible sentences go through `i18n::t` / `t_args`. Catalog keys in `locales/wallet/*.json` omit the `wallet.` prefix. Call sites use `wallet.<key>`.
- Comments and module docs say why a constraint exists. Do not restate what the next line does.
- `./install/test.sh` runs `cargo test --all-targets` and `cargo clippy --all-targets -- -D warnings`. Fix warnings. Do not `allow` them. Keep the tree `cargo fmt` clean.
- Private files are mode `0600`. Private directories are mode `0700`. Writes that must not leave a partial file use a temp file and rename.
- Do not `sudo`. On this workstation sudo asks for a password and there is no TTY.
- Do not run `ykman`. Do not reset the PIV applet. Do not delete PIV keys when switching back to the key ring. Do not call `MgmKey::set_default`, `get_protected`, or `reset_device`.
- Do not commit a machine-specific `.cargo/config.toml` or the `/tmp/oid4vc-pcsc` pkg-config stub.
- Do not change the `ldd` exclusion list in `install/appimage.sh`. `libpcsclite.so.1` is copied because it is not on that list. `pcscd` stays a host daemon. Linking is a normal dynamic link through the `yubikey` crate, not `dlopen`.
- Do not add tests that call `DesktopKeyStore::load_key`. That talks to the real desktop stores.

## Layout

| Path | Role |
|---|---|
| `src/lib.rs` | Library. Public modules: `i18n`, `linux`, `protocol`, `wallet`, `xdg`. |
| `src/main.rs` | Binary. Modules `browser`, `single`, `ui` live here, not in the library. |
| `src/ui.rs` | The `--ui` egui window. |
| `src/browser.rs` | Opens the verifier's return page in the browser that already holds the binding cookie. `xdg-open` is the wrong browser. |
| `src/single.rs` | One `--ui` window. Socket `ui.sock` plus advisory `ui.lock`. |
| `src/protocol/` | Offer and authorization-request parsing. No HTTP. |
| `src/wallet/` | Inbox, redeem, present, validate, seal, key stores, YubiKey wrap. |
| `src/i18n/` | Catalogs, negotiation, the saved language. |
| `src/linux/` | Desktop Entry and `mimeapps.list`. |
| `src/xdg.rs` | `data_home()` and `config_home()`. Empty XDG variables count as unset. |
| `locales/` | Same catalog layout as iya-sts. Embedded by `build.rs` into `OUT_DIR/locales_gen.rs`. |
| `install/test.sh` | Headless suite. Sets a throwaway `HOME` and the XDG dirs, unsets `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY`, and `WAYLAND_DISPLAY`. |
| `install/install.sh` | Release build, then `oid4vc-wallet install`. |
| `install/appimage.sh` | x86_64 AppImage. |
| `docs/guide.md` | End-user guide, including the Security / YubiKey section. |
| `.github/workflows/ci.yml` | `./install/test.sh` on ubuntu-latest. Apt-installs `libpcsclite-dev` and the X11/font libraries. |
| `.github/workflows/appimage.yml` | AppImage artifact `oid4vc-wallet-x86_64`, built on Ubuntu 22.04. Also installs `libpcsclite-dev`. |
| `.github/workflows/pages.yml` | Publishes `docs/` the same way iya-sts does. |

`src/wallet/` modules, in the order declared in `mod.rs`: `anchors`, `b64`, `certs`, `consent`, `credentials`, `http`, `inbox`, `jws`, `kek`, `key_store`, `kwallet`, `piv`, `portable`, `present`, `proof`, `protection`, `redeem`, `seal`, `secret_service`, `subject`, `trust`, `validate`. The protection API is re-exported from `wallet`.

`src/protocol/` modules: `http_url`, `json`, `percent`, `query`, `uri`, and public `invocation`, `offer`, `request`. Fetching an offer by reference is not implemented. Redeeming a pre-authorized offer is `wallet::redeem_pre_authorized`. Answering a same-device presentation is `wallet::present_same_device`. Checking an issued credential is `wallet::validate_stored`.

## Build on this workstation

`pkg-config --exists libpcsclite` fails here. The runtime library is present (`/usr/lib/x86_64-linux-gnu/libpcsclite.so.1` → `libpcsclite.so.1.0.0`). `winscard.h` is not installed, and `sudo apt-get install libpcsclite-dev pcscd` cannot be run from this agent. CI installs `libpcsclite-dev`, so CI does not need the stub.

Local compiles use a stub that is outside the repo and must stay there: `/tmp/oid4vc-pcsc`. It contains `libpcsclite.pc` (Version 1.9.5, `Libs: -L${libdir} -lpcsclite`) and a symlink `lib/libpcsclite.so` → the system `libpcsclite.so.1`. The include directory can be empty; `pcsc-sys` did not require `winscard.h` under this `PKG_CONFIG_PATH`.

```sh
PKG_CONFIG_PATH=/tmp/oid4vc-pcsc ./install/test.sh
```

`install/test.sh` does not set `PKG_CONFIG_PATH`. A plain `./install/test.sh` fails to link on this machine until the development package exists. `--offline` is valid only after `yubikey` 0.8 is already in the cargo cache. The first fetch of that crate must be online.

`pcscd` is required only when YubiKey protection is actually used. The desktop key ring does not need it.

## Commands

`oid4vc-wallet --ui` opens the window and takes the single-instance lock. A later `--ui` hands its URIs to the running window and exits. The command line without `--ui` does not take that lock. `--ui install` is rejected.

Commands in `main.rs` `run()`: `install`, `uninstall`, `inbox`, `credentials`, `credential` (`add`, `show`, `delete`, `list`), `language` (`set`, `clear`), `handle`, or a positional URI containing `://`. `help` and no arguments print usage. `--json` prints one JSON object. `--no-save` parses without writing the inbox. `--lang` applies to the current run.

`open_vault` is only the credential commands. If `yubikey_locked()` is `Ok(true)` it prompts on `/dev/tty` (not stdin; stdin may be the credential document), turns echo off with `stty -echo` pointed at that tty, then `unlock_yubikey`. No tty or an `stty` failure returns `wallet.yubi.tty`, which has no `{error}` placeholder — call `t`, not `t_args`. `EchoGuard` restores echo on drop. The PIN is `zeroize`d. A malformed protection file fails `open_vault` instead of prompting, because `yubikey_locked` returns `Result`. The window does not use this prompt.

Desktop registration: user scope is `~/.local/bin/oid4vc-wallet`, `~/.local/share/applications/org.rcbj.oid4vc-wallet.desktop`, and `~/.config/mimeapps.list`. System scope is `/usr/local/bin`, `/usr/share/applications`, and `/etc/xdg/mimeapps.list`. `Exec` is `oid4vc-wallet --ui %u`. `Icon=org.rcbj.oid4vc-wallet` (a hicolor name, not a path). Default schemes: `openid-credential-offer`, `siopv2`, `openid4vp`. `--haip` also registers `haip-vci` and `haip-vp`. App id `org.rcbj.oid4vc-wallet`.

## Where files live

All under `oid4vc-wallet/` in the XDG directory named below. `$XDG_DATA_HOME` defaults to `~/.local/share`. `$XDG_CONFIG_HOME` defaults to `~/.config`. `$XDG_CACHE_HOME` defaults to `~/.cache`.

| File or directory | Home | What it is |
|---|---|---|
| `credentials/` | data | Sealed credential files. |
| `inbox/` | data | Raw invocation URIs. |
| `key-protection.json` | data | Sibling of `credentials/`. YubiKey wrap metadata. Missing file means the desktop key ring. |
| `trust-anchors/` | config | Uploaded DER anchors, one file per cert, name is hex SHA-256. |
| `trusted-issuers` | config | Issuer URL, tab, hex SHA-256 of the leaf key. |
| `presentation-approvals` | config | One credential id per line. Those skip the present-again prompt. |
| `self-issued-subject` | config | How an ID Token names its subject. |
| `language` | config | Saved locale tag. |
| runtime socket dir | `$XDG_RUNTIME_DIR/oid4vc-wallet`, else `$XDG_CACHE_HOME/oid4vc-wallet/runtime` | `ui.sock` and `ui.lock`. |

## Language

English (`locales/wallet/en.json`) is the source catalog. `build.rs` embeds every `locales/*/*.json` plus `locales/catalogs.json`.

Base catalogs, which must contain every English key: `en`, `fr`, `es`, `zh-Hans`, `zh-Hant`, `fil`, `sv`. Override catalogs, which must stay strictly smaller and may only contain keys that also exist in English: `fr-CA` (base `fr`), `es-ES` (base `es`), `zh-Hant-HK` (base `zh-Hant`). Do not add a new key to an override unless that region's wording differs. Every non-English catalog is `machine-unreviewed`.

Offered tags (what `language set` and the window accept) are not the file tags: `en`, `fr-FR`, `fr-CA`, `es-MX`, `es-PA`, `es-ES`, `zh-CN`, `zh-HK`, `zh-TW`, `fil-PH`, `sv-SE`. `zh-HK` reads Traditional Chinese. `tl` is read as Filipino.

`src/i18n/mod.rs` test `catalogs_have_the_english_keys_and_placeholders` compares placeholder names as a vector in appearance order, not as a set. `{old}` then `{new}` is a different message from `{new}` then `{old}`. Insert new keys in alphabetical order and do not reformat the JSON.

Resolution order: `--lang`, then `ui_locales` on the invocation being shown, then the saved language, then `LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, `LANG`, then English.

## Credential seal and the desktop key ring

`Aes256Key` in `src/wallet/seal.rs` is 32 bytes, zeroized on drop, cloned by copying the bytes, and redacted in `Debug`. Each credential file has its own 12-byte nonce. Magic is `O4W1`. Associated data starts with `oid4vc-wallet credential v1\n`. The format, issuer, time, and document are inside the ciphertext. Document cap is 2 MiB.

The key is created the first time a credential is stored (`CredentialVault::key_for_write`). `load_key` returning `Ok(None)` is the only signal to generate. `Err` must not look like "no key", or a second key is created and existing credentials are orphaned. After a generate, the code reads the store again in case another process won the race.

`EncryptionKeyStore` (`src/wallet/key_store.rs`): `load_key`, `store_key`, `load_retired`, `store_retired`. `DesktopKeyStore` probes Secret Service first (`org.freedesktop.secrets`), then KWallet. Item name `org.rcbj.oid4vc-wallet` / `credential-encryption-key`. History item `credential-encryption-key-history`. KeePassXC is used when it owns the Secret Service. KWallet is `org.kde.kwalletd6`, then `kwalletd5`, then `kwalletd`, network wallet, folder `org.rcbj.oid4vc-wallet`, binary `writeEntry` (`EntryType::Stream` = 2). A quiet probe uses `NameHasOwner` so a GNOME session does not launch KWallet. A locked Secret Service is an error (`Probe::Failed` → deny), so the wallet does not create a second key in KWallet while the first store may still hold the real one.

`Probe` is `Found`, `Empty`, `Absent`, `Failed`. Plans: `plan_load`, `plan_store`, `plan_quiet`, `plan_prompt`. Do not change those for the desktop path.

Retired keys live 90 days (`RETIRED_KEY_SECS`). `encode_retired` / `decode_retired` are `pub(super)` and are the bytes inside the YubiKey bundle as well as the desktop history item. `CredentialVault::rotate` stores the retired key before the new key. The cache must still hold the old current key when retired is stored.

`KeyStoreError`: `Store(String)` displays with the `wallet.keystore.unusable` prefix, so a sentence that is already the message to show is `Plain(String)`. `Unavailable` means neither store is running. `WrongLength`. `Locked` means YubiKey mode and this process has not unwrapped the key (`is_locked()`). `SlotBusy` is a foreign PIV slot 82 (`wallet.yubi.slot_busy`). Poisoned session mutex is `Plain(t("wallet.keystore.poisoned"))`, not `Store`.

`VaultError::{Message, Key, Seal, Io}`. `VaultError::is_locked` matches `Key(err)` when `err.is_locked()`. `load_credentials` in the window returns `String`, so the window detects lock by comparing that string to `KeyStoreError::Locked.to_string()`. It does not call `is_locked`. A locked load sets `yubi_locked`, shows an unlock row on the credential page, and returns before the empty-wallet message and before `fail()`.

`DesktopKeyStore`'s `EncryptionKeyStore` impl dispatches: if `protection::protects_with_yubikey()` then `cached_key` / `rewrap_stored_key` / `cached_retired` / `rewrap_stored_retired`; otherwise the `load_desktop_*` / `store_desktop_*` methods. Do not call `EncryptionKeyStore::load_key` while holding the session mutex (deadlock). YubiKey mode must not call `load_desktop_key` to decide whether a key exists.

### Deleting the desktop copies

`delete_desktop_secrets` removes only the store the load would have used. History is removed before the key so `remove` does not delete the folder while the other entry remains. `NoEntry` is success.

- Secret Service `Denied` → error.
- Secret Service `Found` → delete Secret Service history and key. Do not touch KWallet.
- Secret Service `Empty` → delete Secret Service history and key, then quiet-probe KWallet (`Prompt::Never`). Delete KWallet only when that probe is `Found`. `Empty` and `Absent` are success. A failed quiet probe is an error, so a refusal is not treated as "key gone".
- Secret Service `Absent` → `kwallet.delete_secrets(Prompt::IfLocked)`. Absent daemon is success. `Prompt::Never` plus `Empty` deletes nothing: a closed wallet is not proof the key is absent. `IfLocked` plus empty or found-without-session is `wallet.keystore.kwallet_closed` (user cancel is a failure).

`secret_service::delete` clones the user string before `delete_user` (avoids a double borrow). `delete_retired` deletes `KEY_HISTORY_USER`. keyring features: `sync-secret-service`, `crypto-rust`, `vendored`. dbus feature `vendored`. No separate `libdbus-dev`.

## YubiKey protection

This path is the YubiKey PIV applet, reached through the `yubikey` 0.8 crate. A PC/SC reader that is not a YubiKey is skipped. `YubiKey::try_from` selects the PIV applet and then requires the Yubico version and serial commands (a YubiKey 4 switches to the OTP applet for the serial). A card that fails that handshake never appears in `connected()`. Identity in `key-protection.json` is that `u32` serial.

Enrollment also requires the YubiKey management key at `MgmKey::default()` (3DES, bytes `010203040506070801020304050607080102030405060708`) and Yubico key-generation tags `0xAA` (PIN policy) and `0xAB` (touch policy). `YubiKey::authenticate` always sends algorithm 3DES. Firmware 5.7 and later stores that same default value as AES-192, so the challenge fails and the wallet reports `yubi.mgmt` ("not the factory key") even when the value is still the default. The public steps are in `docs/guide.md`. Slot occupancy uses Yubico GET METADATA (`INS 0xF7`), which YubiKey firmware before 5.2.3 answers with `NotSupported`; the wallet then refuses (`yubi.firmware`). A NIST PIV or CAC, or another vendor's PIV applet, will not enroll: the holder usually cannot generate a key, the card-management key is not the YubiKey factory key, and there is no Yubico serial. A token that clones those Yubico commands might get further. Nothing else has been tried.

The private-key operation itself is PIV key establishment: GENERAL AUTHENTICATE, algorithm ECC P-256, key reference `0x82` (the first retired key-management slot in SP 800-73). The PIN length of 6 to 8 digits matches FIPS 201 and the YubiKey PIV PIN. The host HKDF salt and info, and the `O4YK` bundle, are this wallet's wrap. Another program cannot open the file by implementing PIV alone.

Settings → Security chooses the desktop key ring or two YubiKeys. The radio is user intent (`ProtectionChoice` in `ui.rs`). It is not reset every frame. `reload_protection(true)` runs on the Security tab click, on the first load (`protection_loaded` is false), and after activate or switch-back. Enroll and the other in-tab actions call `reload_protection(false)`. Do not reload the status every frame. Do not call `warn()` for `keyring_pending_removal` every frame; show the label `wallet.ui.yubi_keyring_copy`.

The section is `yubi_section`, after `storage_key_section`, inside the existing scroll. The rotate-key section stays. Radio labels: key ring is `wallet.ui.yubi_keyring`, YubiKey is `wallet.ui.yubi_title`. One PIN field, `TextEdit::singleline(...).password(true)`, cleared with `zeroize` after use.

| Mechanism now | Radio | What the tab shows |
|---|---|---|
| Key ring | Key ring | Status. Pending serials, discard, and activate when two are pending. No enroll PIN. |
| Key ring | YubiKey | Steps, PIN, enroll, pending serials, discard, activate once two are pending. |
| YubiKey | YubiKey | Status, unlock row when locked, key-ring-copy warning when removal is still pending, enrolled serials, replace flow. |
| YubiKey | Key ring | PIN and the button that calls `switch_to_keyring`. |

Public API (`src/wallet/protection.rs`, re-exported from `wallet`): `protection_status`, `yubikey_locked() -> Result<bool, KeyStoreError>`, `enroll_yubikey(pin) -> serial`, `activate_yubikeys`, `discard_pending`, `unlock_yubikey(pin)`, `begin_replace(remove_serial, staying_pin)`, `finish_replace(remove_serial, pin) -> new_serial`, `cancel_replace`, `switch_to_keyring(pin)`. Types: `Mechanism::{Keyring, YubiKey}`, `ProtectionStatus { mechanism, enrolled, pending, unlocked, keyring_pending_removal }`. Production wrappers use `DesktopKeyStore` + `HardwarePiv` + the global `SESSION` + the default path. Tests pass `SoftwarePiv`, `MemDesktop`, and a private `Session`. `Work::load_cached` is `#[cfg(test)]` because only tests call it and clippy denies dead code.

### Two keys, always

The mode is inactive until two YubiKeys are enrolled. There is no path that activates with one. After that, one key may be replaced at a time and the file always holds exactly two, distinct, non-zero serials. Pending enrollments exist only while the mechanism is still `keyring`. At most two pending. `discard_pending` only applies in that state.

Enroll, while the mechanism is still the key ring, requires exactly one connected YubiKey (`yubi.none` / `yubi.many`). Check order inside `enroll`, after the client PIN check and the mechanism check: `one_connected`, then `yubi.already` if that serial is already pending, then `yubi.pending_full` if two are already waiting. The same-serial check is first so re-enrolling a pending serial still says `already` when two are pending. The test `two_keys_unwrap_the_same_storage_key_and_one_is_not_enough` depends on that order.

Unlock uses a connected serial that is enrolled. Several enrolled keys plugged in at once returns `yubi.many`, so a wrong guess does not burn a PIN try. One enrolled key among strangers uses that one. None of the connected keys enrolled: `yubi.not_enrolled`. Nothing connected: `yubi.none`.

`begin_replace(remove_serial, staying_pin)` unwraps with the other key and sets `replacing`. It does not write the file. It opens the staying key by serial even when both keys are plugged in (`yubi.missing_serial` if the staying key is absent). The removed key does not have to be unplugged. `finish_replace` requires that flag, a matching generation, and the session key. The new device is the single connected serial that is not the staying serial. That may be the old serial after its slot was cleared, or a third key. It must not be the staying key. Only the staying key connected: `yubi.insert_new`. More than one non-staying key: `yubi.many`. The file is rewritten as staying then new. Finish without begin: `yubi.always_two`. A normal unlock clears `replacing`. Cancel clears the flag and may leave the session unlocked. The window is two steps (pick the serial to remove, verify the key being kept, then enroll the new one) and it clears the shared PIN between steps. After verify it shows `t("wallet.yubi.insert_new")`.

### PIN

The client rejects the PIN before any device call. Non-digit is checked first (`yubi.pin_digits`, so `12345a` says digits). Length under 6, including empty, is `yubi.pin_short`. Length over 8 is `yubi.pin_long` (PIV maximum is 8). Then `verify_pin` immediately followed by `decrypt_data` on the same `YubiKey` value. `PinPolicy::Always` must not see intervening APDUs, including metadata. Dropping `YubiKey` resets the card, so those two calls cannot be on different values. `yubikey::Error::WrongPin { tries: u8 }` maps to `yubi.wrong_pin` with `{tries}`. `PinLocked` maps to `yubi.pin_blocked`. `AuthenticationError` from decrypt after a successful verify maps to `yubi.pin_again`. The software PIV double uses `yubi.wrong_pin_plain` and does not invent a retry count. The factory PIN is 123456; the guide tells the user to change it with `ykman piv access change-pin`. This program does not run `ykman`.

### Slot 82 and key generation

PIV retired slot `SlotId::Retired(RetiredSlotId::R1)` (`0x82`). Not slot `9d`. Not RSA-OAEP. `AlgorithmId::EccP256`, `PinPolicy::Always`, `TouchPolicy::Never`. `PinPolicy` and `TouchPolicy` are at `yubikey::`, not under `piv`.

`piv::generate` returns `Result<SubjectPublicKeyInfoOwned, _>`. Management-key authentication uses `MgmKey::default()` (the 3DES factory key) and only for generation. If that authenticate fails with `AuthenticationError`, the error is `yubi.mgmt`. That also covers a YubiKey 5.7+ whose factory management key is AES. Decrypt requires the PIN only. Enroll order on the device: client PIN check, `open_by_serial`, `verify_pin`, `authenticate(MgmKey::default())`, then metadata and maybe generate.

Slot occupancy is `piv::metadata`:

- `Ok` and `public.is_some()` → occupied. Refuse unless the point is one this session just generated (`PivError::Busy(Option<[u8; 65]>)`).
- `Ok` and public is `None`: a certificate in the slot → `Busy(None)`; no certificate → generate.
- `GenericError` after a successful management-key auth, and `YubiKey::piv_keys()` shows no certificate in that slot (`Key::slot()`, `Key::certificate()`) → treat as empty and generate.
- `GenericError` and `piv_keys` itself errors → return that error. Do not treat the slot as empty.
- `GenericError` and a certificate is present → `Busy(None)`.
- `Error::NotSupported` (firmware before the metadata command, pre-5.2.3) → `yubi.firmware`. Do not generate.

`yubikey::Error` is `#[non_exhaustive]`. Every match needs a wildcard. `map_yubi` sends other errors to `yubi.device` with `{message}` from `err.to_string()`. `PcscError` is `yubi.pcsc`.

On an occupied slot, return the on-device public when metadata has it. Protection reuses that public only when the session already stored that exact public for that serial (`last_enrolled` or `pending_new`). `Busy(Some(other))` is `KeyStoreError::SlotBusy`. `Busy(None)` with a session public for that serial reuses the session public. A foreign slot is never reused. The second enroll of an existing software key returns `Busy(Some(existing point))`. `SoftwarePiv::reset_slot` clears the secret (`foreign = false`). `occupy_foreign` plants a point the session must not accept.

An enroll that dies after `generate` and before the file write is recoverable in-process because `last_enrolled` and `pending_new` are stored before the write. A restarted process cannot know the public, and the wallet will not overwrite slot 82. The error text may mention `ykman piv keys delete 82`. The program must not run that command.

### Readers

`yubikey::reader::Context::open()`, then `iter(&mut self) -> Result<Iter>` where the item is `Reader`, not `Result`. `YubiKey::try_from(&reader)`. `Serial(pub u32)` with `From<u32>` and `From<Serial> for u32`. `YubiKey::open()` errors when more than one key is present; `open_by_serial(Serial)` is the opener. Skip readers that are not YubiKeys, serial 0, and duplicate serials.

`piv::decrypt_data` is behind the crate's `untested` feature. `Buffer` is `Zeroizing<Vec<u8>>`.

### Wrap (DEK + KEK)

The AES-256 storage key is the DEK. The KEK never leaves the YubiKey. Host wrap is ECIES-style in `src/wallet/kek.rs`: ephemeral P-256, ECDH, HKDF-SHA256, AES-256-GCM. Use `SharedSecret::extract::<sha2::Sha256>` then `Hkdf::expand`. Do not hand-roll HMAC. Salt is `b"oid4vc-wallet kek salt v1"`. Info is `b"oid4vc-wallet yubikey dek v1"`. `SharedSecret` is not re-exported from `p256::ecdh`; use `p256::elliptic_curve::ecdh::SharedSecret`. Reconstruct with `impl<C: Curve> From<FieldBytes<C>> for SharedSecret<C>`. Uncompressed points go through `ToEncodedPoint` with `compress = false` (65 bytes, leading `0x04`).

Blob layout: 65-byte uncompressed ephemeral point, 12-byte nonce, ciphertext and tag. The card's decipher of a 65-byte point returns the shared X. `shared_x_from_card` also accepts a 65-byte uncompressed point (bytes 1..33) or a shorter integer left-padded to 32 bytes. Software ECDH may use `raw_secret_bytes` only to supply that X. It is not the KEK. `kek::open` runs HKDF.

SPKI in `piv.rs` `point_of`: `p256::pkcs8::spki::SubjectPublicKeyInfoOwned`, `BitString::raw_bytes()`. If those bytes are 65 and start with `0x04`, copy them. Otherwise `PublicKey::from_sec1_bytes` and `uncompressed_point`. There is no direct `der` crate dependency.

Inside the AES-GCM plaintext, magic `O4YK` (do not reuse the seal magic `O4W1`), version byte 1, the 32-byte DEK, then `encode_retired` bytes, which may be empty. Both the current key and the retired keys are wrapped. Zeroize the plaintext. Empty AAD is acceptable. Failures in `kek.rs` are `KeyStoreError::Plain(t("wallet.yubi.unwrap"))`. The `unbundle` parameter is named `bytes` because a parameter named `plain` would shadow `fn plain`.

### Protection file

`$XDG_DATA_HOME/oid4vc-wallet/key-protection.json`. Mode `0600`, parent `0700`, temp file then rename. Parsed with `protocol::Json`. `generation` is a `u64` bumped on every successful write (`checked_add`; overflow is `yubi.malformed`).

```json
{
  "mechanism": "keyring",
  "generation": 0,
  "keyring_cleared": true,
  "pending": [{ "serial": 1, "public": "<b64>" }],
  "keys": [{ "serial": 1, "public": "<b64>", "wrapped": "<b64>" }]
}
```

`mechanism` is `keyring` or `yubikey`. Public and wrapped fields use `b64::b64_encode` / `b64_decode`. Unknown extra fields are ignored. A missing file is the key ring, generation 0, `keyring_cleared` true, no pending, and is not an error. A missing `generation` is 0. A missing `keyring_cleared` is false when the mechanism is `yubikey` and true otherwise. When the mechanism is `yubikey`, there are exactly two key records and `pending` is empty. Anything else that does not match is `yubi.malformed`.

### Activate, unlock, switch back

Activate loads the desktop key. `Ok(None)` generates a DEK in memory only and never writes it to the key ring first, then loads retired keys. `Err` from the load fails activate before the YubiKey file is written. Both publics are wrapped. The file is written with `keyring_cleared: false` and generation + 1. Then the desktop secrets are deleted.

Roll the file back to the previous bytes, and clear the session DEK, only when the delete failed and the desktop key is still present (`desktop.load_key()` is `Ok(Some(_))` and the restore succeeds). If the delete already removed the key, do not roll back. Leave the YubiKey file (`keyring_cleared: false`, status `keyring_pending_removal`) and return the delete error. On full success set `keyring_cleared`, bump generation, and update the session generation so the session that just unlocked is not immediately `Locked`. If the flag write fails after a successful delete, still return `Ok`. A later unlock retries the idempotent delete. Do not fail unlock when that cleanup fails. After a failed flag write the session generation must match the file generation that was actually written (`cleared` still false). `finish_clearance` is used when activate finds the mechanism already `yubikey`, and by unlock. Callers ignore its error (`let _ =`).

Unlock caches the DEK, the retired keys, and the generation, and clears `replacing`. `load_key` in YubiKey mode returns `Ok(Some(cached))` when the generation matches, otherwise `KeyStoreError::Locked`. It must not return `Ok(None)`. A generation mismatch clears the cache and returns `Locked`. `store_key` / `store_retired` rewrap with the stored public keys and do not touch the device, and only while the session is unlocked. The file is written first, then the session is updated.

Switching back unwraps with either enrolled key and the PIN (exactly one enrolled key connected), stores the key and the retired keys in the desktop store, reads them back, compares, and only then writes mechanism `keyring` and clears the wraps and the cache. If that file write fails, the file still says `yubikey`. The PIV key pairs stay on the devices.

### Session

`static SESSION: Mutex<Session>` is const-initialized in `protection.rs`. Unit tests do not use it. Fields: `dek`, `retired`, `generation`, `last_enrolled`, `pending_new`, `replacing`.

### Strings already in the catalogs

`keystore.locked`. `yubi.activated`, `already`, `always_two`, `device` (`{message}`), `enrolled` (`{serial}`), `file` (`{error}`), `firmware`, `insert_new`, `malformed`, `many`, `mgmt`, `missing_serial` (`{serial}`), `need_two`, `none`, `not_enrolled`, `now_keyring`, `pcsc`, `pending_full`, `pin_again`, `pin_blocked`, `pin_digits`, `pin_long`, `pin_short`, `prompt`, `replaced` (`{old}` then `{new}`), `slot_busy`, `tty`, `unlocked`, `unwrap`, `wrong_pin` (`{tries}`), `wrong_pin_plain`.

`ui.yubi_activate`, `cancel_replace`, `choice`, `choice_help`, `discard`, `enroll`, `finish_replace`, `help`, `keyring`, `keyring_copy`, `keyring_help`, `pin`, `replace`, `replace_help` (`{keep}`, not `{serial}`), `serial` (`{serial}`), `status_keyring`, `status_pending` (`{serials}`), `status_yubi`, `step1`, `step2`, `title`, `to_keyring`, `to_keyring_help`, `unlock`, `verify_keep`.

`usage.crypto` in all seven base catalogs mentions the YubiKey alternative and has no new placeholders. The user-facing steps are in `docs/guide.md` under Security, before "Move credentials to another computer".

## Window

`Section`: Credentials, Inbox, Accept, Settings. `SettingsTab`: Language, Registration, Trust, Security, ImportExport, About. `NAV` is that section order. Default viewport is 1080×720, title `wallet.desktop.name`, app id `org.rcbj.oid4vc-wallet`. A socket error must not stop the window. The command line never claims the single-instance lock.

Self-issued subject radios: JWK thumbprint with `sub_jwk` (default), `did:jwk`, `did:key`, `did:web`. Encodings live in `src/wallet/subject.rs` (base58btc and the multicodec `p256-pub` prefix for `did:key`). For `did:web` the tab shows the DID document to publish and the URL it must be served at. If the verifier's `subject_syntax_types_supported` does not list the chosen kind, the wallet sends `subject_syntax_types_not_supported` and signs nothing. A request that asks for both a presentation and an ID Token sends both, signed by the presented holder key, and that ID Token uses the JWK thumbprint.

Validate checks the issuer signature. Algorithms: ES256, ES384, ES512, ES256K, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA, ML-DSA-44/65/87, the twelve SLH-DSA parameter sets, and the six ML-DSA composite signatures iya-sts publishes. Published keys come from JWT VC Issuer Metadata at `/.well-known/jwt-vc-issuer` (`jwks`, or `jwks_uri` when `jwks` is absent). An `x5c` chain is completed from the RFC 5280 AIA `caIssuers` URL. A self-signed root that was only embedded in the credential is not a published anchor. The TLS certificate the issuer presented can anchor the same chain. Trusting an issuer writes `trusted-issuers`, keyed by issuer URL and the SHA-256 of the leaf key.

HTTPS is `src/wallet/http.rs` on rustls. User-Agent `oid4vc-wallet`. A loopback issuer (`localhost`, `127.0.0.1`, `::1`) is accepted even when the system store does not know its CA, so a local iya-sts process CA works. Any other host must chain to the system store, the webpki roots, or a certificate on the Trust anchors tab. Body cap 2 MiB.

Import and export (`wallet::portable`) seal a copy with a fresh AES-256 key that is shown once. That key is not the storage key. The export selector offers `oid4vc-credentials.oid4vc`.

## Tests

Temp directories follow the `credentials.rs` pattern: `oid4vc-wallet-{name}-{pid}-{millis}`, removed on drop. YubiKey tests construct `SoftwarePiv` (`new`, `set_connected`, `reset_slot`, `occupy_foreign`, `has_secret`) and `MemDesktop`. They never touch `SESSION`, the XDG protection file, the desktop keyring, or a reader.

Covered invariants worth not re-breaking: short, empty, non-digit, and long PINs are refused before a key exists; two keys unwrap the same storage key and one is not enough; a duplicate pending serial is `already` even when two are pending; replace keeps two and the removed key cannot unwrap; switching back stores the key, clears wraps, and keeps the retired key; a generation change locks the cache; discard drops pending and a busy slot can be reused after `reset_slot`; a foreign slot is `SlotBusy`; a failed desktop delete rolls the file back only while the desktop key is still there; the same serial can be enrolled again after its slot is cleared.

`install/test.sh` last known green run, with `PKG_CONFIG_PATH=/tmp/oid4vc-pcsc`: 150 library tests, 20 binary tests, clippy clean. That run did not open the window and did not use a YubiKey.
