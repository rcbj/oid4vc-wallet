//! Verifiable credential wallet for Linux.
//!
//! The OpenID4VCI, OpenID4VP and SIOPv2 messages are implemented in
//! [`protocol`]. That code uses the Rust standard library only.

pub mod linux;
pub mod protocol;
pub mod wallet;
pub mod xdg;
