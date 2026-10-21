---
title: How to use the wallet
---

# How to use the wallet

This guide is for a person using the OID4VC Wallet with iya-sts on the same computer. The wallet stores credentials, takes a credential the issuer is offering, and answers when a site asks you to sign in or to present a credential.

The window has four pages: **Credentials**, **Inbox**, **Accept**, and **Settings**. A message at the top of the window reports what the last action did.

## Open the wallet {#open}

The installed command is `oid4vc-wallet`. Open the window with:

```sh
oid4vc-wallet --ui
```

You can also click **OID4VC Wallet** in the application menu. That opens the credential list.

When a site hands the computer a wallet link, the desktop starts the same window and passes the link in. A pre-authorized offer opens **Accept** and asks for the transaction code. A sign-in or presentation opens **Credentials**.

Close an already-open wallet window and start it again after an update. The window that is already on screen keeps the old program. A new install does not change that copy.

A second start does not open a second window. It brings the open window forward and gives it the new link.

## Read a stored credential {#read}

1. Open **Credentials**.
2. Click a row in the list. The row shows the issuer, the time the credential arrived, the format, and the id.
3. The detail on the right shows:
   - **Id**
   - **Format**
   - **Issuer**
   - **Signature algorithm**, the kind of signature named in the credential. The line says **unknown** when the credential does not name one.
   - **Received**
   - **Document**, the credential itself

**JSON** shows the stored record as JSON. Leave it unchecked to read the credential document.

**Copy** on this page copies the id only. The message says **Copied** and then the id.

**Refresh** reloads the list.

The private key that belongs to a credential is never shown. You can read the document. You cannot read the key.

The same lines appear when you ask the command line to show one credential: `oid4vc-wallet credential show`, followed by the id. That command prints the id, the format, the issuer, the signature algorithm, the time, and the document.

## Look at the issuer's certificates {#certificates}

The **Certificate chain** button is on the credential detail, under **Copy**.

1. Select the credential.
2. Choose **Certificate chain**.
3. A window opens with the certificates that were included with that credential. They are numbered. Number 1 is the signer's certificate. Each certificate after it is the one that stands behind the one before it.
4. Click a certificate in the list.

The window has two tabs:

- **Fields** is a table. **Field** is the name, and **Value** is what the certificate says. The field names stay in English when the rest of the wallet is in another language, because they are the standard certificate names.
- **Raw** shows that certificate as text.

**Copy** puts that certificate text on the clipboard, so you can paste it into a file or another program. The message at the top of the wallet says **Copied the certificate.** The certificate text stays in the certificate window.

Close the certificate window with its close button. You can resize it. Choosing **Certificate chain** again for the same credential keeps the certificate and the tab you were looking at. Choosing it for a different credential starts at the first certificate on **Fields**.

The window shows the certificates that came inside the credential. It does not go online to fetch another certificate.

A sign-in credential this wallet created includes one certificate for its own key. That certificate is the whole chain, and it is stored in the credential. An older sign-in credential receives that certificate the next time the wallet reads it.

Some other credentials have no signer certificate. The window then says **This credential does not include a signer certificate.** There is no **Copy** button in that case.

## Add a credential you already have {#add}

On **Credentials**, choose **Add credential**. The dialog asks for:

- **Format**, for example `dc+sd-jwt`
- **Issuer URL**
- **Document**, which you can type, or load with **Load file** after choosing **Document file**

Choose **Store credential**. **Cancel** closes the dialog without storing.

## Check a credential {#check}

Select a credential and choose **Validate**. The wallet checks the issuer's signature and the chain of trust.

A credential this wallet created for a sign-in names its own key. **Validate** checks the signature against that key. It does not contact a website for that credential.

When the signature checks and the chain cannot be finished from what the issuer published, a prompt asks before the wallet trusts that chain. **Trust this issuer** remembers the decision for that issuer and that key. A different key is asked again.

If the wallet used the issuer's own connection certificate because the published certificates could not be retrieved, the message says that this fallback was used.

A bad signature, a name that does not match, or a date outside the certificate's validity is an error.

## Remove a credential {#remove}

Select a credential and choose **Delete**. Confirm the prompt. The credential is removed. The storage key stays.

## The inbox {#inbox}

**Inbox** lists the links the desktop handed the wallet. Each entry is the link itself.

1. Click a row to read it.
2. **Refresh** reloads the list.
3. **Delete** removes one entry after you confirm.

An inbox entry can contain a transaction code. That code is enough to ask the issuer for the credential, so treat the inbox as private and delete an entry when you no longer need it. Only your user can read those files.

A link you pass on the command line, without `--ui`, is written to this same inbox. The window and the command line are looking at one inbox.

## Accept a link {#accept}

**Accept** is where you paste a link yourself.

1. Paste the link into **Invocation URI**.
2. **Do not write the inbox** reads the link and leaves the inbox unchanged. Leave it unchecked to save the link in the inbox.
3. **JSON** writes the summary as JSON. Leave it unchecked for the usual sentences.
4. Choose **Accept**.

The links iya-sts uses are:

| What iya-sts is doing | What the link starts with |
|---|---|
| Offering a credential | `openid-credential-offer://` |
| Asking you to present a credential | `openid4vp://` |
| Asking you to sign in | `siopv2://` |

After the wallet reads the link, the summary appears, and under it two tabs. **JSON** is the full information. **Fields** is a table of name and value.

A link that only points at an offer, and does not contain the offer itself, is saved as a link. The wallet does not go and fetch it.

## Receive a credential {#receive}

On the issuer page, start the same-device handoff for an offer that is ready to redeem. The desktop opens this wallet on **Accept** and shows **Redeem**.

1. Read the issuer and the credential names on that prompt.
2. If the page asks for a transaction code, type the code the issuer page is showing. The box is labeled **Transaction code**.
3. Choose **Redeem**.
4. The wallet stores every credential the issuer returns. When there is one, the message names that credential. When there are several, the message says how many were stored. The first one is selected on **Credentials**.

Some issuers give you several credentials for one code. iya-sts usually gives four. The wallet creates one key for each and stores each credential with the key that belongs to it. Those keys are not shown.

If the offer does not ask for a transaction code, **Redeem** is available without one.

**Use a different invocation** leaves the code prompt and returns to the paste box.

You can paste the same offer link yourself on **Accept**. The offer has to be included in the link.

## Approve a sign-in or a presentation {#present}

On iya-sts, **Open your wallet on this device** opens this wallet on the credential list. The wallet fetches the request and selects a stored credential that matches the site, the kind of credential, and the information the site asked for.

Before the key is used, a dialog asks **Use this credential?**

The dialog shows:

- who is asking, next to **Verifier**
- the credential id, the format, the issuer, and the time you received it

Choose **Allow** to sign and send the answer. Choose **Cancel**, or close the dialog, to stop. The key is not used, and the site is told that you declined.

**Do not ask again for this credential** is unchecked at first. Check it when you want later requests for that same credential to skip the dialog. The first request for a credential always asks. The checkbox is remembered when you choose **Allow**.

After you allow a presentation, the wallet opens the site's next page as a new tab in the browser you were already using for that site. The sign-in stays in that browser. A program outside the browser cannot switch the tab that is already open.

Opening the same link again in this window does not send it a second time. iya-sts answers a sign-in once.

If none of your credentials fit the request, the wallet tells the site, and the browser can still return. The wallet does not invent a credential for an ordinary presentation.

An ordinary presentation sends the presentation. A request that asks for a presentation and a sign-in together sends both, after you allow it, and the sign-in uses the key of the credential you presented.

The command line does not present. A link passed without `--ui` is read and stored only.

## Create a sign-in identity {#identity}

A `siopv2://` link is a sign-in request. The first time, the dialog says that a new self-issued credential will be created and that its key will be used.

1. Choose **Allow** to create the credential, send the sign-in, and store the credential.
2. Check **Do not ask again for this credential** if a later sign-in with that credential should skip the question.
3. Choose **Cancel**, or close the dialog, to create nothing.

The sign-in carries the subject and the public key. The private key stays in the wallet. You do not type the subject or the key, and you will not see the private key on **Credentials**.

A later `siopv2://` sign-in sends the same subject, so iya-sts can recognize the person who enrolled that key. The wallet asks again unless you checked the box the first time.

The subject is the key's JWK thumbprint unless you chose another one on [Security](#security). There it can be a `did:jwk`, a `did:key`, or a `did:web` of the same key. The sign-in then names the DID, says which of its keys signed, and does not carry the public key separately. A verifier that enrolled one identifier does not recognize another, so after a change, enrol the new one with that verifier.

A verifier can say which kinds of subject it accepts. When it does, and your choice is not one of them, the wallet signs nothing. It tells the verifier, and the message names your choice and the kinds the verifier accepts. The wallet never sends another kind of subject in its place.

A request that asks for a presentation and a sign-in together always uses the JWK thumbprint of the presented credential's key. The DID you chose names the self-issued key, not that one.

## Settings {#settings}

**Settings** has six tabs: **Language**, **Registration**, **Trust anchors**, **Security**, **Import and export**, and **About**.

### Language {#language}

Pick a language and choose **Save language**. The choice is kept for later runs. **Use the session language** forgets that choice and follows the language of this desktop session.

A `--lang` tag on the command that starts the wallet applies to that run only.

| Language | Tags |
|---|---|
| English | `en` |
| French | `fr-FR`, `fr-CA` |
| Spanish | `es-MX`, `es-PA`, `es-ES` |
| Chinese (Simplified) | `zh-CN` |
| Chinese (Traditional) | `zh-HK`, `zh-TW` |
| Filipino (Tagalog) | `fil-PH` |
| Swedish | `sv-SE` |

English is the source. The other languages were machine-written and have not been reviewed by a native speaker. Names that come from the issuer, the transaction-code text the issuer wrote, and messages from the operating system stay as they were received.

The wallet picks a language in this order: `--lang` for this run, the language asked for on the link being shown, the saved language, then the language of this desktop session, then English.

### Registration {#registration}

This tab tells the desktop to open this wallet when a site uses a wallet link.

- **For this user** is the usual choice.
- **For every user on this machine** writes the registration for the whole computer.
- **Also register haip-vci:// and haip-vp://** adds the extra link types iya-sts uses when it is set up for HAIP.

**Register this wallet** writes the desktop file. **Remove registration** takes it away.

### Trust anchors {#trust}

Use this when an issuer you mean to trust signs with a certificate that this computer does not already trust.

The box is labeled **Certificates (PEM)**. Paste the certificate text there. You can also type a file path under **Certificate file** and choose **Load**. Then choose **Save certificates**. After that, **Validate** can trust a chain that ends at one of those certificates.

The list shows each saved certificate's name and a long fingerprint. Click one, then choose **Remove**.

An issuer running on this same computer is covered under [A local iya-sts](#local).

### Security {#security}

**Self-issued ID subject** says how a `siopv2://` sign-in names you. Each choice names the same self-issued key.

- **JWK thumbprint (default)**: the subject is the key's RFC 7638 thumbprint, and the sign-in carries the public key in `sub_jwk`. This is what the wallet always did.
- **did:jwk**: the subject is the public key itself, base64url encoded. A verifier reads the key from the identifier. Nothing has to be published.
- **did:key**: the subject is the compressed public key with its multicodec prefix, base58btc encoded (`did:key:zDn…`). A verifier reads the key from the identifier. Nothing has to be published.
- **did:web**: the subject is a DID on a web site you control. Type it in the box, for example `did:web:example.com` or `did:web:example.com:users:alice`. A port is written `%3A`, as in `did:web:example.com%3A8443`.

Choose **Save subject**. A malformed `did:web` is refused, and the earlier choice stays.

Below the choices, the tab shows the subject a sign-in sends now. If there is no self-issued key yet, it says so: the first `siopv2://` sign-in creates one. Saving **did:web** creates one at once, because the document has to name a key before you can publish it.

For **did:web**, the tab shows the DID document and the address it must be served at. `did:web:example.com` is `https://example.com/.well-known/did.json`, and `did:web:example.com:users:alice` is `https://example.com/users/alice/did.json`. **Copy document** copies it. Serve it over https, with no redirect. The document lists the key for `authentication`, which is what a verifier checks a sign-in against. A verifier fetches the document when you enrol and pins the key. If the self-issued key changes, for example because you removed that credential, publish the new document and enrol again.

Changing the choice changes the identifier a verifier sees. A verifier that enrolled the old one has to enrol the new one.

**Rotate encryption key** makes a new storage key and locks every stored credential with it. The previous key is kept for 90 days, so a rotation that was interrupted can be finished.

The new key is the storage key. It is not the key shown after an export, and it is not a credential's private key. With the desktop key ring selected, it lives in GNOME Keyring when that service is available, in KeePassXC when KeePassXC provides that service, or in KWallet on a KDE session that does not. That store needs to be unlocked, which it is in a normal desktop session. With security-key protection selected, the new key is wrapped to the two enrolled keys. Unlock the wallet on this tab first. Rotating it also needs the other enrolled key unlocked in this same run.

**How the storage key is protected** chooses that desktop key ring, or two security keys. The desktop key ring is the usual choice.

**Security key protection** wraps the same storage key with the FIDO2 hmac-secret of each of two security keys. Either key can unlock the wallet. The wallet speaks the FIDO CTAP2 messages over USB HID. A key from another vendor works when it supports the hmac-secret extension and has a FIDO2 PIN. The key does not need a PIV application.

The PIN is the FIDO2 PIN you set in the key's own tool. It can contain letters. It is at least 4 bytes and at most 63 bytes. This wallet does not set or change that PIN. Leave only one security key plugged in for each step. Touch the key when it blinks. Enrollment touches the key twice.

To enroll, choose **Security key protection**. Insert the first key, enter its FIDO2 PIN, and choose **Enroll this security key**. Remove it, insert the second key, and enroll that one too. Then choose **Protect the storage key with these security keys** before you quit this window. That writes both wrapped copies and then removes the storage key from the desktop key ring. The wrap key is kept only until that step finishes. If you quit first, enroll both keys again.

To replace a key, choose **Replace** next to the one you want to remove. Enter the PIN of the key you are keeping and touch it when it blinks. Then remove that key, insert the new one, and choose **Enroll the new security key**. Two keys stay enrolled. You replace one at a time, and you cannot leave only one.

**Move the storage key back to the key ring** unwraps it with either enrolled security key and stores it in the desktop key ring again. The FIDO credentials stay on the security keys.

After you start the wallet again, one enrolled key unlocks it. **Unlock the other security key** is what lets a rotation reseal both copies. The command line asks for the PIN in the terminal. The window asks on **Credentials** and on this tab. The unwrapped key stays available until the program exits. The next launch asks again.

A protection file from the older PIV wrap is not opened. Move the storage key back with that older version, or start again from the desktop key ring. Building the program needs the `libudev-dev` package. Running it does not need `pcscd`.

### Move credentials to another computer {#move}

Open **Settings**, then **Import and export**.

The stored credentials sit in a fixed box on this tab. The list scrolls inside that box when there are more credentials than the box can show. A checkbox on a row here does not change the credential selected on **Credentials**.

The tab warns: **This encryption key opens the export. If the key is lost, the file cannot be read.**

To write a file:

1. Check the credentials you want to take with you. Skip this step if you want every credential.
2. Next to **Export file**, choose **Choose file**. The save window suggests the name `oid4vc-credentials.oid4vc`. You can change it. The file types are **OID4VC export** and **All files**.
3. Choose **Export** to write the checked credentials. **Export** stays unavailable until a file is chosen and at least one box is checked.
4. Choose **Export all** to write every stored credential. That button stays unavailable until a file is chosen and the wallet has at least one credential.

Each export makes a new encryption key. After the file is written, that key appears at the top of the tab in **Encryption key**, with **Copy** beside it. The message says **Encryption key copied.** The key is not written into that message. The wallet does not store the export key. Copy it and keep it with the same care you would give the credentials.

To bring a file onto this computer:

1. Next to **Import file**, choose **Choose file** and pick the export file.
2. Type the export key into **Encryption key for this file**.
3. Choose **Import**. The button stays unavailable until both the file and the key are filled in.

The wallet opens the file with that export key and stores the credentials under this computer's own storage key. After a successful import, the key box is emptied.

The export key is not the storage key. **Rotate encryption key** does not change the key inside an export file you already wrote. An old file still opens with the key that was shown when that file was written.

### About {#about}

**About** shows the wallet's version, for example `Version 0.1.20261020143205`. The first two numbers are the release. The last is the build, which is the UTC date and time the program was built. Hover over the version to see the build time and commit. Include the version when you ask for help. In a terminal, `oid4vc-wallet --version` prints the same number. **About** also shows Copyright 2026 Iya CyberSecurity Solutions, LLC, and it opens the documentation for this wallet, the GitHub page where you can ask for help, and the Business Source License.

## One window {#one-window}

Starting the wallet window again brings the open window forward and hands it the new link. A presentation link is handled from **Credentials** in that window. An offer that is ready to redeem is handled on **Accept** in that window.

The command line without `--ui` does not look for an open window, and it does not present a credential or redeem an offer.

## What the wallet leaves alone {#limits}

- A link that only points at an offer is saved. The offer itself has to be inside the link before the wallet can redeem it.
- An ordinary presentation sends the presentation. A sign-in link, and a request that asks for both a presentation and a sign-in, also send the sign-in. Those cases are described above.
- Redeem and present run in the window. A command without `--ui` reads a link and can store it.
- The private key of a credential is never shown.

## A local iya-sts {#local}

When iya-sts is on this same computer, at `localhost`, the wallet accepts its certificate.

An issuer on another computer needs a certificate the system already trusts, a public certificate the wallet already knows, or a certificate you added on **Trust anchors**.

## Commands, if you were asked to type one {#commands}

These do not open the window:

```sh
oid4vc-wallet 'openid-credential-offer://?credential_offer=…'
oid4vc-wallet inbox
oid4vc-wallet credentials
oid4vc-wallet credential show <id>
oid4vc-wallet language
oid4vc-wallet language set fr-FR
```

`--json` prints one JSON object. `--no-save` reads a link without writing the inbox. `credential add` stores a document you already have. `credential delete` removes one credential and leaves the storage key in place.

`oid4vc-wallet help` lists the commands. None of those commands fetch an offer, redeem one, or present a credential.
