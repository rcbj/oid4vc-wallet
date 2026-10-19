# OID4VC Wallet

People using the wallet follow the guide on the documentation site: <https://rcbj.github.io/oid4vc-wallet/>. That site is written for someone at the window. This file is for building and installing the program.

A Linux wallet for [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) credential offers and [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) / [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) requests. It is a native program. The installer registers it with the desktop, so a browser or an issuer page that opens `openid-credential-offer://` or `siopv2://` starts this wallet.

The OpenID messages are implemented in this repository. `src/protocol` does not use another crate, and the wallet does not use a library that implements OpenID4VCI, OpenID4VP, SIOPv2, SD-JWT or JOSE. Credentials are sealed with AES-256-GCM. The key is stored through the Secret Service client or the KWallet client. `oid4vc-wallet --ui` opens one window. A later `--ui` start focuses that window and hands it the new URI. The command line without `--ui` does not take that lock. How to use each page is in [docs/guide.md](docs/guide.md). `.github/workflows/pages.yml` publishes `docs/` to GitHub Pages the same way iya-sts does. After the Pages site exists and that workflow has run on `main`, the guide is at <https://rcbj.github.io/oid4vc-wallet/>.

This wallet is used to exercise [iya-sts](https://github.com/rcbj/iya-sts). iya-sts hands a wallet three URIs:

| What iya-sts is doing | Scheme |
|---|---|
| Credential Offer, by value or by reference | `openid-credential-offer://` |
| Presentation request | `openid4vp://` |
| ID Token request (SIOPv2) | `siopv2://` |

`openid4vp://` is registered alongside the two schemes above because that is the presentation scheme iya-sts uses unless it is configured for HAIP. Pass `--haip` to the installer to also register `haip-vci://` and `haip-vp://`.

## What this version does

It parses an invocation, prints what the issuer or verifier asked, and stores the raw URI in an inbox that only the owner can read. A pre-authorized code is a bearer credential, so the inbox directory is mode `0700` and each file is mode `0600`. The Inbox page can delete one entry. `oid4vc-wallet --ui` opens a window that lists stored credentials and can accept an invocation and read the inbox. The Settings page has Language, Registration, Trust anchors, Security, and Import and export tabs. Trust anchors stores a PEM root or CA chain you supply and uses it when a published chain is incomplete. Security rotates the AES-256 storage key, re-encrypts every credential, and keeps the previous key for 90 days. Import and export writes the credentials you check, or all of them, to a file you choose in the file selector. The list stays in a fixed window and scrolls. The export selector offers the name `oid4vc-credentials.oid4vc`. The file is sealed with a fresh key that is shown once, and that file can be imported on another device. When the window is opened with a pre-authorized credential offer, the Accept page asks for the transaction code the issuer is showing and redeems the offer: the token endpoint, the nonce endpoint, and a credential request signed with an ES256 proof of possession. When the issuer advertises a batch size, the request carries one proof for each copy. Every credential in the response is sealed, each with the key it is bound to, and appears in the credential list. Those private keys are not shown. When that window is opened with a presentation request, it opens the credential list, fetches the request, and selects a stored credential that matches the verifier, the credential type, and the requested claims. A presentation or self-issued sign-in asks before it uses a credential's key. The dialog shows the credential id, format, issuer, and received time. You can choose not to be asked again for that credential. The first request always asks. It then submits the presentation and opens the verifier's redirect. A `siopv2://` request asks before it creates a key, builds an ID Token, stores a self-issued credential, and a later `siopv2://` sign-in reuses that subject. A request that asks for both a presentation and an ID Token sends both, signed by the presented holder key.

Validate checks the issuer signature on a stored credential. The algorithms are the JOSE signatures ES256, ES384, ES512, ES256K, RS256, RS384, RS512, PS256, PS384, PS512, and EdDSA, plus ML-DSA-44, ML-DSA-65, ML-DSA-87, the twelve SLH-DSA parameter sets, and the six ML-DSA composite signatures iya-sts publishes. Published keys are read from JWT VC Issuer Metadata at `/.well-known/jwt-vc-issuer` (the `jwks` member, or `jwks_uri` when that member is absent). An `x5c` chain is completed from the RFC 5280 Authority Information Access `caIssuers` URL, which is the spec's way to retrieve a parent the credential itself did not carry. A self-signed root that was only embedded in the credential is not treated as a published anchor. When the signature checks and that chain cannot be completed, the window asks whether to trust the issuer at that URL. The TLS certificate presented by the issuer can anchor the same chain; the window says when that fallback was used. A chain with a bad signature, a name mismatch, or a date outside its validity is reported as an error. An acceptance is stored at `$XDG_CONFIG_HOME/oid4vc-wallet/trusted-issuers`, mode `0600`, keyed by the issuer URL and the SHA-256 of the leaf key, so a different key is asked again.

A credential added with `credential add` is sealed with AES-256-GCM before it is written. Each file under `$XDG_DATA_HOME/oid4vc-wallet/credentials` is mode `0600`, and that directory is mode `0700`. The file holds a nonce and ciphertext. The format, issuer, time, and credential document are inside the ciphertext. The inbox stays a separate directory of raw invocation URIs.

The 256-bit key is created the first time a credential is stored. GNOME Keyring holds it when the Secret Service (`org.freedesktop.secrets`) is available. The item is `org.rcbj.oid4vc-wallet` / `credential-encryption-key`, and the key is encrypted while it crosses the session bus. KeePassXC is used in that same way when its Secret Service integration is turned on and it owns the service. On a KDE session that does not provide the Secret Service, the key is a binary entry in KWallet (`org.kde.kwalletd6` or `org.kde.kwalletd5`), in the network wallet, folder `org.rcbj.oid4vc-wallet`. The login keyring or KWallet needs to be unlocked, which it is in a normal desktop session. A locked GNOME Keyring is reported as an error, so the wallet does not create a second key in KWallet while the first store may still hold the real one.

An offer by reference is not fetched. An ID Token is built for a `siopv2://` request and for a presentation that also asks for an ID Token. An ordinary presentation sends the presentation only. A same-device presentation request is fetched and answered in this crate, without an OpenID library.

A loopback issuer (`localhost`, `127.0.0.1`, or `::1`) whose certificate is not in the system trust store is still accepted, so a local iya-sts process CA works. Any other issuer must chain to a CA the system store or the public web roots trust, or to a certificate you stored on the Trust anchors tab.

## Build

Install a stable Rust toolchain, then:

```sh
cargo build --release
```

## Tests

The suite is headless. It does not open a window, and it does not use this user's wallet files or the desktop key store. The same script runs locally and in GitHub Actions (`.github/workflows/ci.yml`) on every push and pull request. The Actions job installs the X11 and font libraries the binary links, then runs the script. `--offline` uses crates already in the local Cargo cache. Any further arguments are a `cargo test` filter.

```sh
./install/test.sh
./install/test.sh --offline
./install/test.sh --offline wallet::present
```

## AppImage

`install/appimage.sh` builds one self-contained x86_64 executable:

```sh
./install/appimage.sh
./dist/OID4VC_Wallet-0.1.0-x86_64.AppImage --help
```

The file contains the wallet and the libraries it needs besides the system C library and the host OpenGL loader, including libgcc. The window needs `libGL` from the desktop, which loads the GPU driver. The image uses the glibc of the machine that builds it. GitHub Actions builds on Ubuntu 22.04, so that copy runs on Ubuntu 22.04 and newer. The workflow uploads it as an artifact named `oid4vc-wallet-x86_64`.

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

* `~/.local/share/applications/org.rcbj.oid4vc-wallet.desktop`, a Desktop Entry whose `MimeType` lists `x-scheme-handler/openid-credential-offer`, `x-scheme-handler/siopv2` and `x-scheme-handler/openid4vp`, and whose `Exec` line is `oid4vc-wallet --ui` plus the URI as `%u`. `Icon=org.rcbj.oid4vc-wallet` is the hicolor icon name. The installer writes that PNG under `~/.local/share/icons/hicolor/` at the sizes the application grid asks for. GNOME Shell shows a generic icon when `Icon` is a file path.
* `~/.config/mimeapps.list`, where those types name this desktop file as the default application.

The installer also runs `update-desktop-database` and `xdg-mime default` when those tools are on `PATH`. The files above are the registration either way.

For every user on the machine:

```sh
sudo ./install/install.sh --system
```

That writes `/usr/local/bin/oid4vc-wallet`, `/usr/share/applications/org.rcbj.oid4vc-wallet.desktop` and `/etc/xdg/mimeapps.list`.

Remove the registration with `oid4vc-wallet uninstall` or `oid4vc-wallet uninstall --system`.

The desktop file sets `Terminal=false`. Clicking the application opens the window on the credential list. A protocol link that carries a pre-authorized offer opens the Accept page and asks for the transaction code. Another protocol link opens that same window and shows the parsed request. The command line is still there when you leave off `--ui`: `oid4vc-wallet help` prints the commands, and a URI on the command line parses it without opening the window.

## Try an invocation

```sh
oid4vc-wallet --ui
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

With the wallet installed, an iya-sts page that offers **Open a wallet on this device** launches this program on the Accept page. Type the transaction code the page shows. A wallet sign-in whose request is an ID Token alone uses `siopv2://`. A presentation request uses `openid4vp://`. The first time either request would use a credential's key, the window asks.

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
| `src/wallet` | The inbox, redemption of a pre-authorized offer, credential signature checks, and the AES-256 credential vault |
| `src/i18n` | Catalog lookup, language choice, and message formatting |
| `locales` | Message catalogs, in the same layout iya-sts uses |
| `install/install.sh` | Build, then `oid4vc-wallet install` |

## License

Copyright 2026 Iya CyberSecurity Solutions, LLC

The [Business Source License 1.1](LICENSE) applies to this repository. You may copy, modify, and make non-production use of oid4vc-wallet. Production use requires a commercial license, which Iya CyberSecurity Solutions, LLC grants only as part of a paid support subscription. Each version becomes available under the MIT License four years after it is published. Revisions already published under the Apache License, Version 2.0 remain under that license. See [LICENSE](LICENSE).
