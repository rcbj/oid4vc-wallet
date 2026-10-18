//! Verifiable credential wallet for Linux.
//!
//! The OpenID4VCI, OpenID4VP and SIOPv2 messages are implemented in
//! [`protocol`]. That code does not use an OpenID library. Stored credentials
//! are sealed with AES-256-GCM. The key is kept in GNOME Keyring, or in
//! KWallet when the Secret Service is not running. Display text uses the
//! languages iya-sts ships. [`i18n`] is that catalog. The
//! `oid4vc-wallet --ui` command opens a window for the same operations.

pub mod i18n;
pub mod linux;
pub mod protocol;
pub mod wallet;
pub mod xdg;
