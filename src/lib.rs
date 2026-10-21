//! Verifiable credential wallet for Linux.
//!
//! The OpenID4VCI, OpenID4VP and SIOPv2 messages are implemented in
//! [`protocol`]. That code does not use an OpenID library. Stored credentials
//! are sealed with AES-256-GCM. The key is kept in GNOME Keyring, or in
//! KWallet when the Secret Service is not running. It can instead be wrapped
//! to two FIDO2 security keys with the hmac-secret extension. Display text uses the
//! languages iya-sts ships. [`i18n`] is that catalog. The
//! `oid4vc-wallet --ui` command opens a window for the same operations. A
//! pre-authorized offer in that window asks for the transaction code and
//! redeems the credential from the issuer. A same-device presentation request
//! opens the credential list, selects a matching stored credential, and
//! returns the browser to the verifier. Validate checks the issuer signature
//! on a stored credential, including the published key and certificate chain.
//! An inbox entry can be deleted on its own. [`version`] is the build's
//! M.N.O version.

pub mod i18n;
pub mod linux;
pub mod protocol;
pub mod version;
pub mod wallet;
pub mod xdg;
