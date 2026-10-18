//! Registration with the Linux desktop.
//!
//! The installer writes a Desktop Entry whose `MimeType` lists
//! `x-scheme-handler/<scheme>` and sets those types as the default in
//! `mimeapps.list`. A browser that follows `openid-credential-offer://` or
//! `siopv2://` then starts this wallet.

mod desktop;

pub use desktop::{
    install_handlers, uninstall_handlers, CommandRunner, InstallError, InstallReport, Layout,
    SystemRunner, ALL_SCHEMES, DEFAULT_SCHEMES, DESKTOP_FILE_NAME,
};
