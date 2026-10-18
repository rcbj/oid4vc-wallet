# OID4VC Wallet

A Linux wallet for [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) credential offers and [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) / [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) requests. It is a native program. The installer registers it with the desktop, so a browser or an issuer page that opens `openid-credential-offer://` or `siopv2://` starts this wallet.

The OpenID messages are implemented in this repository. `src/protocol` does not use another crate, and the wallet does not use a library that implements OpenID4VCI, OpenID4VP, SIOPv2, SD-JWT or JOSE. AES-256-GCM, the Secret Service client, and the KWallet client are the only dependencies. They seal credentials at rest. They do not implement the protocols.

This wallet is used to exercise [iya-sts](https://github.com/rcbj/iya-sts). iya-sts hands a wallet three URIs:

| What iya-sts is doing | Scheme |
|---|---|
| Credential Offer, by value or by reference | `openid-credential-offer://` |
| Presentation request | `openid4vp://` |
| ID Token request (SIOPv2) | `siopv2://` |

`openid4vp://` is registered alongside the two schemes above because that is the presentation scheme iya-sts uses unless it is configured for HAIP. Pass `--haip` to the installer to also register `haip-vci://` and `haip-vp://`.

## What this version does

It parses an invocation, prints what the issuer or verifier asked, and stores the raw URI in an inbox that only the owner can read. A pre-authorized code is a bearer credential, so the inbox directory is mode `0700` and each file is mode `0600`.

A credential added with `credential add` is sealed with AES-256-GCM before it is written. Each file under `$XDG_DATA_HOME/oid4vc-wallet/credentials` is mode `0600`, and that directory is mode `0700`. The file holds a nonce and ciphertext. The format, issuer, time, and credential document are inside the ciphertext. The inbox stays a separate directory of raw invocation URIs.

The 256-bit key is created the first time a credential is stored. GNOME Keyring holds it when the Secret Service (`org.freedesktop.secrets`) is available. The item is `org.rcbj.oid4vc-wallet` / `credential-encryption-key`, and the key is encrypted while it crosses the session bus. KeePassXC is used in that same way when its Secret Service integration is turned on and it owns the service. On a KDE session that does not provide the Secret Service, the key is a binary entry in KWallet (`org.kde.kwalletd6` or `org.kde.kwalletd5`), in the network wallet, folder `org.rcbj.oid4vc-wallet`. The login keyring or KWallet needs to be unlocked, which it is in a normal desktop session. A locked GNOME Keyring is reported as an error, so the wallet does not create a second key in KWallet while the first store may still hold the real one.

It does not yet fetch an offer or a request by reference, redeem a pre-authorized code, or return a presentation or an ID Token. Those steps stay in this crate, without an OpenID library, when they are built.

## Build

Install a stable Rust toolchain, then:

```sh
cargo test
cargo build --release
```

## AppImage

`install/appimage.sh` builds one self-contained x86_64 executable:

```sh
./install/appimage.sh
./dist/OID4VC_Wallet-0.1.0-x86_64.AppImage --help
```

The file contains the wallet and the libraries it needs besides the system C library, including libgcc. The image uses the glibc of the machine that builds it. GitHub Actions builds on Ubuntu 22.04, so that copy runs on Ubuntu 22.04 and newer. The workflow uploads it as an artifact named `oid4vc-wallet-x86_64`.

```sh
./dist/OID4VC_Wallet-0.1.0-x86_64.AppImage install
```

That registers the AppImage itself for `openid-credential-offer://`, `siopv2://`, and `openid4vp://`. On a machine without FUSE, run it with `APPIMAGE_EXTRACT_AND_RUN=1`.

## Install

For the current user, which is the usual way to test against iya-sts on the same machine:

```sh
./install/install.sh
```

That builds the release binary, copies it to `~/.local/bin/oid4vc-wallet`, and registers the protocol handlers. The registration is two files:

* `~/.local/share/applications/org.rcbj.oid4vc-wallet.desktop`, a Desktop Entry whose `MimeType` lists `x-scheme-handler/openid-credential-offer`, `x-scheme-handler/siopv2` and `x-scheme-handler/openid4vp`, and whose `Exec` line receives the URI as `%u`.
* `~/.config/mimeapps.list`, where those types name this desktop file as the default application.

The installer also runs `update-desktop-database` and `xdg-mime default` when those tools are on `PATH`. The files above are the registration either way.

For every user on the machine:

```sh
sudo ./install/install.sh --system
```

That writes `/usr/local/bin/oid4vc-wallet`, `/usr/share/applications/org.rcbj.oid4vc-wallet.desktop` and `/etc/xdg/mimeapps.list`.

Remove the registration with `oid4vc-wallet uninstall` or `oid4vc-wallet uninstall --system`.

The desktop file sets `Terminal=true`, so accepting an offer opens a terminal with the parsed request. A graphical window is not part of this version.

## Try an invocation

```sh
oid4vc-wallet 'openid-credential-offer://?credential_offer=…'
oid4vc-wallet 'siopv2://?client_id=…&request_uri=…&request_uri_method=get'
oid4vc-wallet inbox
```

`--json` prints one JSON object on stdout. `--no-save` parses without writing the inbox.

Store a credential the wallet already holds, for example an SD-JWT from a test issuer:

```sh
oid4vc-wallet credential add \
  --format dc+sd-jwt \
  --issuer https://sts.example \
  --document-file credential.txt
oid4vc-wallet credentials
oid4vc-wallet credential show <id>
```

`--document` passes the credential text on the command line. `--document-file -` reads it from stdin. `credential delete <id>` removes the file and leaves the AES-256 key in GNOME Keyring or KWallet.

With the wallet installed, an iya-sts page that offers **Open in a wallet on this device** launches this program. A wallet sign-in whose request is an ID Token alone uses `siopv2://`. A presentation request uses `openid4vp://`.

## Language

Display text uses the same languages iya-sts ships. That includes help, prompts, summaries, and error messages. English is the source catalog. Every other catalog was machine-written and has not been reviewed by a native speaker. Each catalog's status is `machine-unreviewed` in `locales/catalogs.json`.

| Language | Locales you can select | Catalogs |
|---|---|---|
| English | `en` | `en` |
| French | `fr-FR`, `fr-CA` | `fr`, and `fr-CA` where Canadian wording differs |
| Spanish | `es-MX`, `es-PA`, `es-ES` | `es` (Latin American), and `es-ES` where Spanish wording differs |
| Chinese (Simplified) | `zh-CN` | `zh-Hans` |
| Chinese (Traditional) | `zh-HK`, `zh-TW` | `zh-Hant`, and `zh-Hant-HK` where Hong Kong wording differs |
| Filipino (Tagalog) | `fil-PH` | `fil` |
| Swedish | `sv-SE` | `sv` |

```sh
oid4vc-wallet language
oid4vc-wallet language set fr-FR
oid4vc-wallet language clear
oid4vc-wallet --lang sv-SE help
```

`language` lists those locales and marks the one in use. `language set` saves one for later runs in `$XDG_CONFIG_HOME/oid4vc-wallet/language`. That file is mode `0600`. `language clear` removes it. `--lang` applies to the current run, and the tag is one of the locales in the table.

The wallet chooses a language in this order:

1. `--lang`, when the tag is one the wallet offers.
2. `ui_locales` on the invocation being shown, for that invocation's text.
3. The saved language.
4. `LANGUAGE`, then `LC_ALL`, `LC_MESSAGES`, and `LANG`.
5. English.

A language with no catalog is skipped, and the next preference is used. `zh-HK` reads Traditional Chinese, and `tl` is read as Filipino. JSON field names, protocol identifiers, the issuer's transaction-code text, and the operating system's own error text stay as they were received. The desktop file keeps an English `Name`, `GenericName`, and `Comment`, and adds those three keys for every locale in the table.

## Layout

| Path | What it is |
|---|---|
| `src/protocol` | Credential Offer and authorization-request parsing |
| `src/linux` | Desktop Entry, `mimeapps.list`, and the installer |
| `src/wallet` | The inbox, and the AES-256 credential vault |
| `src/i18n` | Catalog lookup, language choice, and message formatting |
| `locales` | Message catalogs, in the same layout iya-sts uses |
| `install/install.sh` | Build, then `oid4vc-wallet install` |

## License

Copyright 2026 rcbj

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
