---
title: How to use the wallet
---

# OID4VC Wallet

This guide is for a person using the OID4VC Wallet with iya-sts on the same machine. The wallet stores credentials, accepts credential offers, and answers same-device requests from iya-sts. It is a native Linux program. The window title is OID4VC Wallet.

The installed command is `~/.local/bin/oid4vc-wallet`. Open the window with:

```sh
oid4vc-wallet --ui
```

The desktop starts the same window with `oid4vc-wallet --ui %u`. `%u` is the URI the browser or iya-sts page handed over. Clicking the application, with no URI, opens the credential list.

A command without `--ui` parses an invocation and stores it. It does not fetch anything, and it does not present a credential. `oid4vc-wallet help` lists those commands.

## After an upgrade

Close an already-open wallet window and start it again after an upgrade. The running process keeps the old program. A new install does not replace the copy that is already on screen.

## Pages

The window has four pages: Credentials, Inbox, Accept, and Settings.

### Credentials

The list shows each stored credential. Select a row to read that credential. The detail shows the id, the format, the issuer, the time it was received, and the document. A JSON checkbox shows the stored record as JSON. Copy copies the id only.

Refresh reloads the list. Add credential stores a document you already have. The dialog asks for the format (for example `dc+sd-jwt`), the issuer URL, and the document. You can type the document or load it from a file, then choose Store credential.

Validate checks the issuer signature and the trust chain of the selected credential. When the signature checks and the chain cannot be completed from what the issuer published, a prompt asks before the wallet trusts that unknown chain. Trust this issuer records the decision for that issuer and that key. A different key is asked again. If the wallet used the issuer's TLS certificate because the published anchors could not be retrieved, the message says that this fallback was used. A bad signature, a name mismatch, or a date outside the certificate's validity is an error.

Delete asks you to confirm, then removes that credential. The AES-256 storage key stays in the desktop key store.

The holder private key is never shown. A credential received from an issuer keeps that key sealed with the credential. You can read the document. You cannot read the key.

You can also export and import from this page. That is described under Import and export.

### Inbox

Inbox lists invocations the desktop handed the wallet. Each entry is the raw URI. Select a row to read it. Refresh reloads the list. Delete removes one entry, and only after you confirm.

An inbox file can contain a pre-authorized code. That code is enough to ask the issuer for the credential, so treat the inbox as private and delete an entry when you no longer need it.

The command line writes the same inbox when you pass a URI without `--ui`. The window and the command line are looking at one inbox.

### Accept

Paste an invocation URI. The schemes iya-sts uses are:

| What iya-sts is doing | Scheme |
|---|---|
| Credential offer, by value or by reference | `openid-credential-offer://` |
| Presentation request | `openid4vp://` |
| ID Token request (SIOPv2) | `siopv2://` |

Two checkboxes apply to that paste. Do not write the inbox parses the URI and does not store it. JSON applies to that paste as well. Choose Accept when the URI is filled in.

After a parse, the page has two tabs. One tab is the formatted JSON. The other is a table of field name and field value.

A by-value pre-authorized offer then asks for the transaction code. Type the code the issuer page is showing and choose Redeem. The wallet takes the code to the issuer, receives the credential, and puts it in the credential list. The holder private key is stored with that credential and is not shown. Use a different invocation leaves the code prompt and returns to the paste box.

If the offer does not ask for a transaction code, Redeem is available without one.

An offer by reference is not fetched. Pasting that URI only parses and, unless you unchecked the inbox, stores the URI.

### Settings

Settings has four tabs: Language, Registration, Trust anchors, and Security.

**Language.** This is the set of languages iya-sts uses. Pick one and choose Save language. The choice is kept for later runs. Use the session language forgets that choice and follows the language of this desktop session. A `--lang` tag on the command that starts the wallet applies to that run only.

The languages you can select are:

| Language | Tags |
|---|---|
| English | `en` |
| French | `fr-FR`, `fr-CA` |
| Spanish | `es-MX`, `es-PA`, `es-ES` |
| Chinese (Simplified) | `zh-CN` |
| Chinese (Traditional) | `zh-HK`, `zh-TW` |
| Filipino (Tagalog) | `fil-PH` |
| Swedish | `sv-SE` |

English is the source. The other catalogs were machine-written and have not been reviewed by a native speaker. Protocol field names, the issuer's own transaction-code text, and operating-system errors stay as they were received.

The wallet picks a language in this order: `--lang` for this run, `ui_locales` on the invocation being shown, the saved language, then `LANGUAGE`, `LC_ALL`, `LC_MESSAGES`, and `LANG`, then English.

**Registration.** This tab registers or removes the protocol handlers. For this user is the usual choice and matches `./install/install.sh`. For every user on this machine writes the system-wide registration. Also register haip-vci:// and haip-vp:// adds the HAIP schemes iya-sts uses when it is configured for HAIP. Register this wallet writes the desktop file. Remove registration takes it away. The desktop file's launch line is `oid4vc-wallet --ui` plus the URI.

**Trust anchors.** Paste a PEM root or CA chain, or load one from a file, then choose Save certificates. After that, validation trusts that chain. Use this when iya-sts, or another issuer you mean to trust, signs with a CA that is not in the system store and is not a public web root. Loopback is separate: see Local iya-sts below. Remove drops one stored certificate by its fingerprint.

**Security.** Rotate encryption key generates a new AES-256 storage key and re-encrypts every credential. The previous key is kept for 90 days so a rotation that was interrupted can be finished. The new key is the storage key. It is not an export key, and it is not a holder key. The key lives in the desktop key store: GNOME Keyring when the Secret Service is available, KeePassXC when it provides that service, or KWallet on a KDE session that does not. The keyring or wallet needs to be unlocked, which it is in a normal desktop session. The holder private key is still never shown.

## Use the wallet with iya-sts

### Receive a credential

On the issuer page, start the same-device wallet handoff for a pre-authorized offer. The desktop opens this wallet on Accept and asks for the transaction code that page is showing. Redeem stores the credential and selects it on Credentials.

You can paste the same `openid-credential-offer://` URI yourself on Accept. The offer has to be by value. A by-reference offer is stored as a URI and is not fetched.

### Same-device presentation

On iya-sts, Open your wallet on this device on `/authn/wallet/wait` opens this wallet on the credential list. The wallet fetches the request, selects a stored credential that matches the verifier, the credential type, and the claims, sends the presentation, and returns the browser to the verifier.

If nothing matches, the verifier is told and the browser still returns. The wallet does not invent a credential for an ordinary presentation. An ID Token is not sent for an ordinary presentation request. When the request asks for both a presentation and an ID Token, the wallet sends both, and the ID Token is signed by the holder key of the credential that was presented.

The command line does not present. A URI passed without `--ui` is parsed and stored only.

### Self-issued identity

A `siopv2://` request is an ID Token request, not an ordinary presentation. The wallet creates a self-issued credential, sends an ID Token back to iya-sts, and stores the credential. The ID Token carries the subject and the public key. The private key stays in the wallet.

A later `siopv2://` sign-in sends the same subject. iya-sts can then authenticate the person who enrolled that key. You do not type the subject or the key. Do not expect to see the private key on Credentials.

### Import and export

Export writes the selected credential, or all of them, to a file you can move to another device. Each export generates a new encryption key. The screen warns that if that key is lost the file cannot be read. Keep the key with the file only as carefully as you would keep the credentials themselves. Copy it somewhere you can get it back. The wallet does not store that export key for you.

Import asks for the file and that key. It opens the file with the export key and stores the credentials in this wallet under this wallet's own storage key. The export key is not the wallet's storage key. Rotating the AES-256 key does not rotate keys inside old export files. An export file is read with the key that was shown when that file was written.

### One window

Starting the UI again focuses the window that is already open and hands it the new URI. A second window is not opened. A presentation URI is handled from the credential list of that window. A pre-authorized offer is handled on Accept in that window.

The command line without `--ui` does not do this. It does not look for an open window, and it does not present.

## What this wallet will not do

- It does not fetch an offer by reference.
- It does not send an ID Token for an ordinary presentation request. A `siopv2://` ID Token request, and a request that asks for both a presentation and an ID Token, are the exceptions described above.
- The command line does not present, and it does not redeem an offer. Redemption and presentation run in the window.
- It does not show the holder private key.

## Local iya-sts

Loopback TLS (localhost) is accepted for a local iya-sts. The issuer's certificate does not have to be in the system trust store when the host is localhost. Any other host must chain to a CA the system store trusts, a public web root, or a chain you added on the Trust anchors tab.

## Command line, short

These do not open the window:

```sh
oid4vc-wallet 'openid-credential-offer://?credential_offer=…'
oid4vc-wallet inbox
oid4vc-wallet credentials
oid4vc-wallet language
oid4vc-wallet language set fr-FR
```

`--json` prints one JSON object. `--no-save` parses without writing the inbox. `credential add` seals a document you already have. `credential delete` removes one credential and leaves the AES-256 storage key in place.

None of those commands fetch an offer, redeem one, or present a credential.
