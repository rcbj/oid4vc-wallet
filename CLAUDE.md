# OID4VC Wallet — notes for agents

Linux native wallet for OpenID4VCI, OpenID4VP, and SIOPv2. Crate `oid4vc-wallet` 0.1.0, library `oid4vc_wallet`, binary `oid4vc-wallet`. Rust 2021, `rust-version` 1.95, `rust-toolchain.toml` channel `stable`. License BUSL-1.1 (see `LICENSE` and the README license section). `publish = false`. Repository https://github.com/rcbj/oid4vc-wallet. Used to exercise [iya-sts](https://github.com/rcbj/iya-sts).

People using the window follow `docs/guide.md` (published at https://rcbj.github.io/oid4vc-wallet/). Builders follow `README.md`. This file is the map of invariants that are expensive to rediscover. When this file and the code disagree, trust the code and update this file.

The UI is native egui (`eframe` 0.37). It is not a web app. Do not verify it in a browser. `./install/test.sh` does not open the window and does not touch a real security key, the user's keyring, or the user's wallet files. Say that when you report tests.

## Hard rules

- OpenID4VCI, OpenID4VP, SIOPv2, SD-JWT, and JOSE are implemented in this crate. Do not add a crate whose job is to implement them. The allowed signature and TLS crates are listed in the `Cargo.toml` header. `p256` with the `ecdh` feature is for proofs of possession (`present.rs`). `ctap-fido2` 0.1.3 speaks CTAP2 over USB HID and returns the hmac-secret. Do not add the `yubikey` crate or a PIV client.
- Protocol JSON is `protocol::Json` (`src/protocol/json.rs`). Numbers stay as their literal text. There is no serde. `Json::get` returns the last duplicate key. There is no `as_bool`; match `Json::Bool`. `as_u64` accepts only a base-10 integer literal that fits in `u64`.
- User-visible sentences go through `i18n::t` / `t_args`. Catalog keys in `locales/wallet/*.json` omit the `wallet.` prefix. Call sites use `wallet.<key>`.
- Comments and module docs say why a constraint exists. Do not restate what the next line does.
- `./install/test.sh` runs `cargo test --all-targets` and `cargo clippy --all-targets -- -D warnings`. Fix warnings. Do not `allow` them. Keep the tree `cargo fmt` clean.
- Clippy runs with `clippy::pedantic` on. `Cargo.toml` `[lints.clippy]` turns the group on, so every `cargo clippy`, `./install/test.sh`, and CI use it with no extra flags. `clippy.toml` holds `doc-valid-idents` (protocol and product names such as SIOPv2 and KWallet, plus `..` for clippy's defaults) and `max-struct-bools = 11` (the CLI options, the window state, and a parsed request hold independent switches). Do not lower the group, raise a threshold, or add an `allow` to get past a lint. A public function returning `Result` needs a `# Errors` section that says when it fails. Truncating casts use `try_from` or `to_be_bytes`, not `as`.
- `with_global` in `protection.rs` passes `Work` by value. With `&mut Work<'_, ..>`, clippy's `redundant_closure_for_method_calls` suggestion (`Work::status`) does not compile, because a method path is not general over the borrowed lifetime.
- Private files are mode `0600`. Private directories are mode `0700`. Writes that must not leave a partial file use a temp file and rename.
- Do not `sudo`. On this workstation sudo asks for a password and there is no TTY.
- Do not call `authenticatorReset`. Do not delete FIDO credentials when switching back to the key ring. Do not send a PIN until exactly one authenticator is connected, and do not fan one PIN across devices. Do not open the user's key or call `makeCredential` unless they can touch it.
- Do not commit a machine-specific `.cargo/config.toml` or the `/tmp/oid4vc-libudev` tree.
- Do not change the `ldd` exclusion list in `install/appimage.sh`. `libudev.so.1` is copied because it is not on that list. Linking is a normal dynamic link through hidapi, not `dlopen`. hidapi's build accepts exactly one Linux backend. `ctap-fido2` turns on the default, `linux-static-hidraw`. Do not enable a second one.
- Do not add tests that call `DesktopKeyStore::load_key`. That talks to the real desktop stores.

## Layout

| Path | Role |
|---|---|
| `src/lib.rs` | Library. Public modules: `i18n`, `linux`, `protocol`, `version`, `wallet`, `xdg`. |
| `src/main.rs` | Binary. Modules `browser`, `single`, `ui` live here, not in the library. |
| `src/ui.rs` | The `--ui` egui window. |
| `src/browser.rs` | Opens the verifier's return page in the browser that already holds the binding cookie. `xdg-open` is the wrong browser. |
| `src/single.rs` | One `--ui` window. Socket `ui.sock` plus advisory `ui.lock`. |
| `src/protocol/` | Offer and authorization-request parsing. No HTTP. |
| `src/wallet/` | Inbox, redeem, present, validate, seal, key stores, FIDO2 wrap. |
| `src/i18n/` | Catalogs, negotiation, the saved language. |
| `src/linux/` | Desktop Entry and `mimeapps.list`. |
| `src/version.rs` | The build's `M.N.O`, from env vars `build.rs` sets. |
| `VERSION` | `M.N`, the release. |
| `src/xdg.rs` | `data_home()` and `config_home()`. Empty XDG variables count as unset. |
| `locales/` | Same catalog layout as iya-sts. Embedded by `build.rs` into `OUT_DIR/locales_gen.rs`. |
| `install/test.sh` | Headless suite. Sets a throwaway `HOME` and the XDG dirs, unsets `DBUS_SESSION_BUS_ADDRESS`, `DISPLAY`, and `WAYLAND_DISPLAY`. |
| `install/install.sh` | Release build, then `oid4vc-wallet install`. |
| `install/appimage.sh` | x86_64 AppImage. |
| `docs/guide.md` | End-user guide, including the Security / security-key section. |
| `.github/workflows/ci.yml` | `./install/test.sh` on ubuntu-latest. Apt-installs `libudev-dev` and the X11/font libraries. |
| `.github/workflows/appimage.yml` | AppImage artifact `oid4vc-wallet-x86_64`, built on Ubuntu 22.04. Also installs `libudev-dev`. |
| `.github/workflows/pages.yml` | Publishes `docs/` the same way iya-sts does. |

`src/wallet/` modules, in the order declared in `mod.rs`: `anchors`, `b64`, `certs`, `consent`, `credentials`, `fido`, `http`, `inbox`, `jws`, `kek`, `key_store`, `kwallet`, `portable`, `present`, `proof`, `protection`, `redeem`, `seal`, `secret_service`, `subject`, `trust`, `validate`. The protection API is re-exported from `wallet`.

`src/protocol/` modules: `http_url`, `json`, `percent`, `query`, `uri`, and public `invocation`, `offer`, `request`. Fetching an offer by reference is not implemented. Redeeming a pre-authorized offer is `wallet::redeem_pre_authorized`. Answering a same-device presentation is `wallet::present_same_device`. Checking an issued credential is `wallet::validate_stored`.

## Build on this workstation

`pkg-config --exists libudev` fails here. The runtime library is present (`/lib/x86_64-linux-gnu/libudev.so.1`). `libudev.h` and the `libudev.so` linker name are not installed, and `sudo apt-get install libudev-dev` cannot be run from this agent. CI installs `libudev-dev`, so CI does not need a local tree.

Local compiles use a tree that is outside the repo and must stay there: `/tmp/oid4vc-libudev`. It is the `libudev-dev` package extracted without root, plus `libudev.pc` whose `prefix` points at that extract, and `libudev.so` symlinked to the system `libudev.so.1`. hidapi compiles `hid.c` with `cc` and does not pass pkg-config's include path to the compiler, so `libudev.h` also has to be on `C_INCLUDE_PATH`.

```sh
export PKG_CONFIG_PATH=/tmp/oid4vc-libudev
export C_INCLUDE_PATH=/tmp/oid4vc-libudev/root/usr/include
export LIBRARY_PATH=/tmp/oid4vc-libudev/root/usr/lib/x86_64-linux-gnu
./install/test.sh
```

`install/test.sh` does not set those variables. A plain `./install/test.sh` fails to compile hidapi on this machine until `libudev-dev` exists. `--offline` is valid only after `ctap-fido2` 0.1.3 is already in the cargo cache. The first fetch of that crate must be online. Running the wallet does not need `pcscd`.

## Version

`M.N.O`, the scheme iya-sts (`common/version.js`) and id-proto-debugger (`client/version.js`) use (issue #2). `M.N` is the repo-root `VERSION` file, now `0.1`. `O` is the UTC build instant `YYYYMMDDHHMMSS`, or `BUILD_NUMBER` when that is set and has no control characters. `build.rs` sets `OID4VC_WALLET_{VERSION,MAJOR_MINOR,BUILD,BUILT_AT,COMMIT}` with `rustc-env`. `src/version.rs` exposes them as constants. The number is fixed when the binary is built, not when it starts. `COMMIT` is `GIT_COMMIT` or `git rev-parse --short=12 HEAD`, and empty without history. `build.rs` lists `src`, `VERSION`, `Cargo.toml`, and `build.rs` in `rerun-if-changed`. Without them, an explicit rerun list (the locales) would leave a stale build number. A missing or malformed `VERSION` is a `cargo:warning` and `0.0`, never a build failure. `Cargo.toml` is `M.N.0`. The test `cargo_version_is_the_version_file_plus_zero` fails when the two drift, so a bump edits both. The About tab shows `wallet.ui.about_version` with `about_built` / `about_built_commit` as hover text. `--version` (or `-V`) prints `oid4vc-wallet M.N.O`. With `--json` it prints `version`, `major_minor`, `build`, `built_at`, and `commit` (`null` without history). It runs before `--ui`, and only `--help` takes precedence over it. `install/appimage.sh` still names the file from `Cargo.toml` (`M.N.0`).

## Commands

`oid4vc-wallet --ui` opens the window and takes the single-instance lock. A later `--ui` hands its URIs to the running window and exits. The command line without `--ui` does not take that lock. `--ui install` is rejected.

Commands in `main.rs` `run()`: `install`, `uninstall`, `inbox`, `credentials`, `credential` (`add`, `show`, `delete`, `list`), `language` (`set`, `clear`), `handle`, or a positional URI containing `://`. `help` and no arguments print usage. `--version` prints the version. `--json` prints one JSON object. `--no-save` parses without writing the inbox. `--lang` applies to the current run.

`open_vault` is only the credential commands. If `fido_locked()` is `Ok(true)` it prompts on `/dev/tty` (not stdin; stdin may be the credential document), turns echo off with `stty -echo` pointed at that tty, then `unlock_fido`. No tty or an `stty` failure returns `wallet.fido.tty`, which has no `{error}` placeholder — call `t`, not `t_args`. `EchoGuard` restores echo on drop. The PIN is `zeroize`d. A malformed protection file fails `open_vault` instead of prompting, because `fido_locked` returns `Result`. The window does not use this prompt.

Desktop registration: user scope is `~/.local/bin/oid4vc-wallet`, `~/.local/share/applications/org.rcbj.oid4vc-wallet.desktop`, and `~/.config/mimeapps.list`. System scope is `/usr/local/bin`, `/usr/share/applications`, and `/etc/xdg/mimeapps.list`. `Exec` is `oid4vc-wallet --ui %u`. `Icon=org.rcbj.oid4vc-wallet` (a hicolor name, not a path). Default schemes: `openid-credential-offer`, `siopv2`, `openid4vp`. `--haip` also registers `haip-vci` and `haip-vp`. App id `org.rcbj.oid4vc-wallet`.

## Where files live

All under `oid4vc-wallet/` in the XDG directory named below. `$XDG_DATA_HOME` defaults to `~/.local/share`. `$XDG_CONFIG_HOME` defaults to `~/.config`. `$XDG_CACHE_HOME` defaults to `~/.cache`.

| File or directory | Home | What it is |
|---|---|---|
| `credentials/` | data | Sealed credential files. |
| `inbox/` | data | Raw invocation URIs. |
| `key-protection.json` | data | Sibling of `credentials/`. FIDO2 wrap metadata. Missing file means the desktop key ring. |
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

Retired keys live 90 days (`RETIRED_KEY_SECS`). `encode_retired` / `decode_retired` are `pub(super)` and are the bytes inside the FIDO bundle as well as the desktop history item. `CredentialVault::rotate` stores the retired key before the new key. The cache must still hold the old current key when retired is stored, and both hmac-secret outputs must already be cached, because both copies are resealed.

`KeyStoreError`: `Store(String)` displays with the `wallet.keystore.unusable` prefix, so a sentence that is already the message to show is `Plain(String)`. `Unavailable` means neither store is running. `WrongLength`. `Locked` means FIDO mode and this process has not unwrapped the key (`is_locked()`). Poisoned session mutex is `Plain(t("wallet.keystore.poisoned"))`, not `Store`.

`VaultError::{Message, Key, Seal, Io}`. `VaultError::is_locked` matches `Key(err)` when `err.is_locked()`. `load_credentials` in the window returns `String`, so the window detects lock by comparing that string to `KeyStoreError::Locked.to_string()`. It does not call `is_locked`. A locked load sets `fido_locked`, shows an unlock row on the credential page, and returns before the empty-wallet message and before `fail()`.

`DesktopKeyStore`'s `EncryptionKeyStore` impl dispatches: if `protection::protects_with_fido()` then `cached_key` / `rewrap_stored_key` / `cached_retired` / `rewrap_stored_retired`; otherwise the `load_desktop_*` / `store_desktop_*` methods. Do not call `EncryptionKeyStore::load_key` while holding the session mutex (deadlock). FIDO mode must not call `load_desktop_key` to decide whether a key exists.

### Deleting the desktop copies

`delete_desktop_secrets` removes only the store the load would have used. History is removed before the key so `remove` does not delete the folder while the other entry remains. `NoEntry` is success.

- Secret Service `Denied` → error.
- Secret Service `Found` → delete Secret Service history and key. Do not touch KWallet.
- Secret Service `Empty` → delete Secret Service history and key, then quiet-probe KWallet (`Prompt::Never`). Delete KWallet only when that probe is `Found`. `Empty` and `Absent` are success. A failed quiet probe is an error, so a refusal is not treated as "key gone".
- Secret Service `Absent` → `kwallet.delete_secrets(Prompt::IfLocked)`. Absent daemon is success. `Prompt::Never` plus `Empty` deletes nothing: a closed wallet is not proof the key is absent. `IfLocked` plus empty or found-without-session is `wallet.keystore.kwallet_closed` (user cancel is a failure).

`secret_service::delete` clones the user string before `delete_user` (avoids a double borrow). `delete_retired` deletes `KEY_HISTORY_USER`. keyring features: `sync-secret-service`, `crypto-rust`, `vendored`. dbus feature `vendored`. No separate `libdbus-dev`.

## FIDO2 security keys

This path is CTAP2 over USB HID, through `ctap-fido2` 0.1.3. The crate's `list_devices` already keeps only authenticators that advertise `hmac-secret`. A key without that extension looks like none. The relying party id is the stable string `oid4vc-wallet`. CTAP hashes it. It is not fetched. The credential is not discoverable. `pin` is always `Some`: `None` disables user verification and produces a different hmac-secret. Do not set `cred_protect`, `cred_blob`, `large_blob_key`, or `min_pin_length`. Touch cannot be turned off. The UI says to touch the key when it blinks, and the HID call blocks the window.

`HardwareFido` in `src/wallet/fido.rs` is the device. `SoftwareFido` is the test double. Tests never open `/dev/hidraw`. `Error` lives at `ctap_fido2::error::Error`, not the crate root. Match a wildcard. `PinInvalid` then `pin_retries()` is `fido.wrong_pin` with `{tries}`; a retry-count failure is `fido.wrong_pin_plain`. `PinBlocked` and `PinAuthBlocked` are `fido.pin_blocked`. `MissingExtension` takes a `&'static str`. `ChannelBusy` and `Hid` are `fido.hid`. The software double uses `fido.wrong_pin_plain` and does not invent a retry count.

Before a PIN, `prepare` reads GetInfo. No `hmac-secret` is `fido.no_extension`. `clientPin` unset is `fido.pin_not_set` (the wallet does not set the PIN). PIN protocol v2 is not implemented. `supports_pin_protocol_v1` treats a CTAP2.0 device that omits `pinProtocols` as v1. A v2-only device is `fido.pin_protocol`. Exactly one device, deduplicated by hidraw path: zero is `fido.none`, more than one is `fido.many`. A PIN is never sent while the count is not one.

`probe_credential` is silent (`up=false`, no PIN, no touch) and returns the matching credential id, or `None` for `NoCredentials`. Only `Error::Ctap` falls back to `probe_credential_with_touch`. Do not fall back on `Hid` or `Io`. `holds` probes one id at a time: a YubiKey answers an id minted by another authenticator with `InvalidCredential` (0x22, `CtapStatus::Other(0x22)`) rather than `NoCredentials`, so 0x22 means "not this id", and one foreign id in a list would hide the device's own.

Identity is the credential id, not a serial and not the AAGUID. The same model shares an AAGUID, and this user's keys have an empty iSerial. The label is the product string, or `Security key` when that string is empty, plus the hex of the first four credential-id bytes (`fingerprint`). Persist the credential id, the COSE public key (`as_cose_bytes` / `from_cose_bytes`), a random 32-byte salt, the wrapped bundle, and the label. The public key is what verifies the assertion. The salt is not the secret. Reject an empty, control-character, or longer-than-80 label, a credential id over 1024 bytes, and a public key over 512 bytes.

Settings → Security chooses the desktop key ring or two security keys. The radio is user intent (`ProtectionChoice` in `ui.rs`). It is not reset every frame. `reload_protection(true)` runs on the Security tab click, on the first load (`protection_loaded` is false), and after activate or switch-back. Enroll and the other in-tab actions call `reload_protection(false)`. Do not reload the status every frame. Do not call `warn()` for `keyring_pending_removal` every frame; show `wallet.ui.fido_keyring_copy`.

The section is `fido_section`, after `storage_key_section`, inside the existing scroll. The rotate-key section stays. Radio labels: key ring is `wallet.ui.fido_keyring`, security key is `wallet.ui.fido_title`. One PIN field, `TextEdit::singleline(...).password(true)`, cleared with `zeroize` after use. `replacing` is `Option<String>` of the base64 credential id. The other-key row and the replace PIN share `fido_pin` and are not on screen together.

| Mechanism now | Radio | What the tab shows |
|---|---|---|
| Key ring | Key ring | Status. Pending labels, discard, and activate when two are pending. |
| Key ring | Security key | Steps, PIN, enroll, pending labels, discard, activate once two are pending. |
| Security key | Security key | Status, unlock row when locked, other-key row when `other_needed` and not replacing, key-ring-copy warning when removal is still pending, enrolled labels, replace flow. |
| Security key | Key ring | PIN and the button that calls `switch_to_keyring`. |

Public API (`src/wallet/protection.rs`, re-exported from `wallet`): `protection_status`, `fido_locked() -> Result<bool, KeyStoreError>`, `enroll_fido(pin) -> label`, `activate_fido`, `discard_pending`, `unlock_fido(pin)`, `unlock_other_fido(pin)`, `begin_replace(remove_id, staying_pin)`, `finish_replace(remove_id, pin) -> new label`, `cancel_replace`, `switch_to_keyring(pin)`. Types: `Mechanism::{Keyring, Fido}`, `AuthenticatorRef { id, label }`, `ProtectionStatus { mechanism, enrolled, pending, unlocked, keyring_pending_removal, other_needed }`. `id` is the base64 credential id. Production wrappers use `DesktopKeyStore` + `HardwareFido` + the global `SESSION` + the default path. Tests pass `SoftwareFido`, `MemDesktop`, and a private `Session`. `Work::load_cached` is `#[cfg(test)]` because only tests call it and clippy denies dead code.

### Two keys, always

The mode is inactive until two authenticators are enrolled. There is no path that activates with one. After that, one key may be replaced at a time and the file always holds exactly two distinct credential ids. Pending enrollments exist only while the mechanism is still `keyring`. At most two pending. `discard_pending` only applies in that state. Discard forgets the ids, so the same device can enroll again and gets a second non-discoverable credential. Do not delete the credential on the device.

Enroll, while the mechanism is still the key ring, requires exactly one connected authenticator (`fido.none` / `fido.many`). Check order inside `enroll`, after the client PIN check and the mechanism check: device count, then `fido.already` if `holds` finds a pending credential on that device, then `fido.pending_full` if two are already waiting. The already check is first so re-enrolling a pending key still says `already` when two are pending. The test `two_keys_unwrap_the_same_storage_key_and_one_is_not_enough` depends on that order. Enroll then calls `makeCredential` and immediately `get_hmac_secret` (a second touch) and caches that output before the key is unplugged.

Unlock requires exactly one device, probes which enrolled credential it holds, and remembers that output without clearing the other. None of the enrolled ids: `fido.not_enrolled`. Several devices: `fido.many`.

`begin_replace(remove_id, staying_pin)` requires exactly one device and that it holds the staying credential (`fido.missing` otherwise). It caches that output and sets `replacing`. It does not write the file. `finish_replace` requires that flag, a matching generation, and the session key. If the one connected device holds the staying credential, refuse with `fido.same` rather than creating a second credential on the key being kept. A device that holds the removed credential, or neither, may `makeCredential`. Finish without begin: `fido.always_two`. A normal unlock clears `replacing`. Cancel clears the flag and may leave the session unlocked. The window clears the shared PIN between the two steps and shows `wallet.fido.insert_new` after verify. `{old}` and `{new}` are labels, not ids.

### PIN

The client checks the PIN before any device call. FIDO counts UTF-8 bytes. Under 4, including empty, is `fido.pin_short`. Over 63 is `fido.pin_long`. Letters are allowed, so `12345a` is accepted by this check. The device enforces its own minimum, which defaults to 4. This wallet does not set or change the PIN.

### Wrap (DEK + KEK)

The AES-256 storage key is the DEK. The 32-byte hmac-secret output is the KEK. Use those bytes directly. Do not HKDF. `kek.rs` is AES-256-GCM: 12-byte nonce, then ciphertext and tag. Shorter than 12+16 is refused. Empty AAD is acceptable. Failures are `KeyStoreError::Plain(t("wallet.fido.unwrap"))`. The `unbundle` parameter is named `bytes` because a parameter named `plain` would shadow `fn plain`.

Inside the plaintext, magic `O4FK` (do not reuse the seal magic `O4W1` or the old PIV magic `O4YK`), version byte 1, the 32-byte DEK, then `encode_retired` bytes, which may be empty. Both the current key and the retired keys are wrapped. Zeroize the plaintext.

The HMAC output cannot be recomputed from the stored public key. Cache both outputs in the process (`CachedKek`, zeroized on drop) after enroll, unlock, `begin_replace`, and `finish_replace`. `rewrap_stored_key` and `rewrap_stored_retired` use the cache and do not touch the device, and only while the session is unlocked. A missing output is `fido.both`. Do not reseal only one copy. `forget_cache` drops the DEK and keeps the outputs. `switch_to_keyring` and `discard_pending` clear the outputs. Unlocking one device must not wipe the other output. `session_dek` on a generation mismatch forgets the DEK and keeps the outputs while the mechanism is still `fido`; if the mechanism is no longer `fido`, it clears the outputs too.

Activate uses the cached outputs and takes no PIN. If a process restart dropped them, return `fido.session` and do not write mechanism `fido`. The person enrolls again: `enroll` on a pending key whose output is not cached calls `hmac` with the stored credential and salt, caches the output, and returns the label without creating a credential. A pending key whose output is cached is still `fido.already`. Do not persist the KEK. After a restart, one unlock learns one output. `unlock_other_fido` requires fido mode, an unlocked session, and exactly one device holding the enrolled credential whose output is not cached. The already-cached device is `fido.other`. `other_needed` is what the Security tab shows. The same session after enroll and activate has both outputs, so rotate works. After a restart, rotate needs `unlock_other_fido` first.

### Protection file

`$XDG_DATA_HOME/oid4vc-wallet/key-protection.json`. Mode `0600`, parent `0700`, temp file then rename. Parsed with `protocol::Json`. `generation` is a `u64` bumped on every successful write (`checked_add`; overflow is `fido.malformed`).

```json
{
  "mechanism": "keyring",
  "generation": 0,
  "keyring_cleared": true,
  "pending": [{ "id": "<b64>", "public": "<b64>", "salt": "<b64>", "label": "Security key abcd" }],
  "keys": [{ "id": "<b64>", "public": "<b64>", "salt": "<b64>", "label": "Security key abcd", "wrapped": "<b64>" }]
}
```

`mechanism` is `keyring` or `fido`. A file whose mechanism is `yubikey` is `fido.retired_piv`, checked before the other fields, so an old PIV file is not called malformed. There is no migration. Fields use `b64::b64_encode` / `b64_decode`. Unknown extra fields are ignored. A missing file is the key ring, generation 0, `keyring_cleared` true, no pending, and is not an error. A missing `generation` is 0. A missing `keyring_cleared` is false when the mechanism is `fido` and true otherwise. When the mechanism is `fido`, there are exactly two key records and `pending` is empty. Pending records have no `wrapped`. Anything else that does not match is `fido.malformed`.

### Activate, unlock, switch back

Activate loads the desktop key. `Ok(None)` generates a DEK in memory only and never writes it to the key ring first, then loads retired keys. `Err` from the load fails activate before the file is written. The missing-KEK check happens before that load and before any mechanism-`fido` write. Both outputs wrap the bundle. The file is written with `keyring_cleared: false` and generation + 1. Then the desktop secrets are deleted.

Roll the file back to the previous bytes, and clear the session DEK, only when the delete failed and the desktop key is still present (`desktop.load_key()` is `Ok(Some(_))` and the restore succeeds). If the delete already removed the key, do not roll back. Leave the file (`keyring_cleared: false`, status `keyring_pending_removal`) and return the delete error. On full success set `keyring_cleared`, bump generation, and update the session generation so the session that just unlocked is not immediately `Locked`. If the flag write fails after a successful delete, still return `Ok`. A later unlock retries the idempotent delete. Do not fail unlock when that cleanup fails. After a failed flag write the session generation must match the file generation that was actually written (`cleared` still false). `finish_clearance` is used when activate finds the mechanism already `fido`, and by unlock. Callers ignore its error (`let _ =`).

Unlock caches the DEK, the retired keys, the generation, and that one hmac output, and clears `replacing`. `load_key` in FIDO mode returns `Ok(Some(cached))` when the generation matches, otherwise `KeyStoreError::Locked`. It must not return `Ok(None)`. `store_key` / `store_retired` rewrap from the cached outputs and do not touch the device. The file is written first, then the session is updated.

Switching back unwraps with either enrolled key and the PIN (exactly one enrolled key connected), stores the key and the retired keys in the desktop store, reads them back, compares, and only then writes mechanism `keyring` and clears the wraps and the cache. If that file write fails, the file still says `fido`. The FIDO credentials stay on the devices.

### Session

`static SESSION: Mutex<Session>` is const-initialized in `protection.rs`. Unit tests do not use it. Fields: `dek`, `retired`, `generation`, `keks`, `replacing`. `keks` is the cached hmac outputs. `replacing` is the credential id being removed.

### Strings already in the catalogs

`keystore.locked`. `fido.activated`, `already`, `always_two`, `both`, `denied`, `device` (`{message}`), `enrolled` (`{label}`), `file` (`{error}`), `hid`, `insert_new`, `malformed`, `many`, `missing`, `need_two`, `no_extension`, `none`, `not_enrolled`, `now_keyring`, `other`, `pending_full`, `pin_blocked`, `pin_long`, `pin_not_set`, `pin_policy`, `pin_protocol`, `pin_short`, `prompt`, `replaced` (`{old}` then `{new}`), `retired_piv`, `same`, `session`, `timeout`, `tty`, `unlocked`, `unwrap`, `wrong_pin` (`{tries}`), `wrong_pin_plain`.

`ui.fido_activate`, `cancel_replace`, `choice`, `discard`, `enroll`, `finish_replace`, `help`, `keyring`, `keyring_copy`, `keyring_help`, `label` (`{label}`), `other`, `other_help`, `pin`, `replace`, `replace_help` (`{keep}`), `status_fido`, `status_keyring`, `status_pending` (`{labels}`), `step1`, `step2`, `title`, `to_keyring`, `to_keyring_help`, `touch`, `unlock`, `verify_keep`.

`usage.crypto` in all seven base catalogs mentions the hmac-secret alternative and has no new placeholders. Override catalogs were not given these keys. The user-facing steps are in `docs/guide.md` under Security, before "Move credentials to another computer".


## Window

`Section`: Credentials, Inbox, Accept, Settings. `SettingsTab`: Language, Registration, Trust, Security, ImportExport, About. `NAV` is that section order. Default viewport is 1080×720, title `wallet.desktop.name`, app id `org.rcbj.oid4vc-wallet`. A socket error must not stop the window. The command line never claims the single-instance lock.

Self-issued subject radios: JWK thumbprint with `sub_jwk` (default), `did:jwk`, `did:key`, `did:web`. Encodings live in `src/wallet/subject.rs` (base58btc and the multicodec `p256-pub` prefix for `did:key`). For `did:web` the tab shows the DID document to publish and the URL it must be served at. If the verifier's `subject_syntax_types_supported` does not list the chosen kind, the wallet sends `subject_syntax_types_not_supported` and signs nothing. A request that asks for both a presentation and an ID Token sends both, signed by the presented holder key, and that ID Token uses the JWK thumbprint.

Validate checks the issuer signature. Algorithms: ES256, ES384, ES512, ES256K, RS256, RS384, RS512, PS256, PS384, PS512, EdDSA, ML-DSA-44/65/87, the twelve SLH-DSA parameter sets, and the six ML-DSA composite signatures iya-sts publishes. Published keys come from JWT VC Issuer Metadata at `/.well-known/jwt-vc-issuer` (`jwks`, or `jwks_uri` when `jwks` is absent). An `x5c` chain is completed from the RFC 5280 AIA `caIssuers` URL. A self-signed root that was only embedded in the credential is not a published anchor. The TLS certificate the issuer presented can anchor the same chain. Trusting an issuer writes `trusted-issuers`, keyed by issuer URL and the SHA-256 of the leaf key.

HTTPS is `src/wallet/http.rs` on rustls. User-Agent `oid4vc-wallet`. A loopback issuer (`localhost`, `127.0.0.1`, `::1`) is accepted even when the system store does not know its CA, so a local iya-sts process CA works. Any other host must chain to the system store, the webpki roots, or a certificate on the Trust anchors tab. Body cap 2 MiB.

Import and export (`wallet::portable`) seal a copy with a fresh AES-256 key that is shown once. That key is not the storage key. The export selector offers `oid4vc-credentials.oid4vc`.

## Tests

Temp directories follow the `credentials.rs` pattern: `oid4vc-wallet-{name}-{pid}-{millis}`, removed on drop. FIDO tests construct `SoftwareFido` (`new`, `set_connected`, `credential_count`, `has_credential`) and `MemDesktop`. They never touch `SESSION`, the XDG protection file, the desktop keyring, or `/dev/hidraw`.

Covered invariants worth not re-breaking: a PIN shorter than 4 bytes, including empty, and one longer than 63 bytes are refused before a credential exists, and a letter PIN is accepted; two keys unwrap the same storage key and one is not enough; a pending key is `already` even when two are pending, and a third device is `pending_full` with no credential created; replace keeps two, the key being kept is `fido.same`, and the removed credential cannot unwrap; switching back stores the key, clears the cached outputs, and leaves the credentials on the devices; a generation change locks the cache and keeps the outputs; discard forgets the pending id and the same device can enroll again; a failed desktop delete rolls the file back only while the desktop key is still there; activate with no cached outputs returns `fido.session` and does not write mechanism `fido`; rotate without both outputs is `fido.both`, and `unlock_other_fido` of the missing device restores it; mechanism `yubikey` is `fido.retired_piv`.

`install/test.sh` last known green run: 2026-10-20, rustc 1.99.1, with the `/tmp/oid4vc-libudev` variables above. 154 library tests and 21 binary tests passed, and clippy with `-D warnings` and the pedantic group was clean. That run did not open the window and did not use a security key.
