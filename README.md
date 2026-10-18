# OID4VC Wallet

A Linux wallet for [OpenID4VCI](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html) credential offers and [OpenID4VP](https://openid.net/specs/openid-4-verifiable-presentations-1_0.html) / [SIOPv2](https://openid.net/specs/openid-connect-self-issued-v2-1_0.html) requests. It is a native program. The installer registers it with the desktop, so a browser or an issuer page that opens `openid-credential-offer://` or `siopv2://` starts this wallet.

The OpenID messages are implemented in this repository. The crate has no dependencies, and it does not use a library that implements OpenID4VCI, OpenID4VP, SIOPv2, SD-JWT or JOSE. `src/protocol` is the protocol code.

This wallet is used to exercise [iya-sts](https://github.com/rcbj/iya-sts). iya-sts hands a wallet three URIs:

| What iya-sts is doing | Scheme |
|---|---|
| Credential Offer, by value or by reference | `openid-credential-offer://` |
| Presentation request | `openid4vp://` |
| ID Token request (SIOPv2) | `siopv2://` |

`openid4vp://` is registered alongside the two schemes above because that is the presentation scheme iya-sts uses unless it is configured for HAIP. Pass `--haip` to the installer to also register `haip-vci://` and `haip-vp://`.

## What this version does

It parses an invocation, prints what the issuer or verifier asked, and stores the raw URI in an inbox that only the owner can read. A pre-authorized code is a bearer credential, so the inbox directory is mode `0700` and each file is mode `0600`.

It does not yet fetch an offer or a request by reference, redeem a pre-authorized code, or return a presentation or an ID Token. Those steps stay in this crate, without an OpenID library, when they are built.

## Build

Install a stable Rust toolchain, then:

```sh
cargo test
cargo build --release
```

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

With the wallet installed, an iya-sts page that offers **Open in a wallet on this device** launches this program. A wallet sign-in whose request is an ID Token alone uses `siopv2://`. A presentation request uses `openid4vp://`.

## Layout

| Path | What it is |
|---|---|
| `src/protocol` | Credential Offer and authorization-request parsing |
| `src/linux` | Desktop Entry, `mimeapps.list`, and the installer |
| `src/wallet` | The inbox |
| `install/install.sh` | Build, then `oid4vc-wallet install` |

## License

Copyright 2026 rcbj

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
