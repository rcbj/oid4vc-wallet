//! The inbox of invocations the desktop handed this process, and the
//! credentials the wallet stores.
//!
//! Invocations stay as the raw URI. Credentials are sealed with AES-256-GCM.
//! The key is read from GNOME Keyring, or from KWallet when the Secret
//! Service is not running.

mod credentials;
mod inbox;
mod key_store;
mod kwallet;
mod seal;
mod secret_service;

pub use credentials::{Credential, CredentialVault, NewCredential, VaultError};
pub use inbox::{Inbox, InboxEntry};
pub use key_store::{DesktopKeyStore, EncryptionKeyStore, KeyStoreError};
pub use seal::SealError;
pub use secret_service::SecretServiceKeyStore;

use crate::protocol::invocation::{self, Invocation, ParseError};

/// An invocation that parsed, and where it was stored when an inbox was given.
pub struct Accepted {
    pub invocation: Invocation,
    pub summary: String,
    pub json: String,
    pub saved: Option<std::path::PathBuf>,
}

/// Parse `uri`. When `inbox` is set, store the raw URI and the summary in it.
pub fn accept(uri: &str, inbox: Option<&Inbox>) -> Result<Accepted, AcceptError> {
    let invocation = invocation::parse(uri).map_err(AcceptError::Parse)?;
    let summary = invocation::summary(&invocation);
    let json = invocation::to_json(&invocation);
    let saved = match inbox {
        Some(inbox) => Some(inbox.save(uri, &summary).map_err(AcceptError::Store)?),
        None => None,
    };
    Ok(Accepted {
        invocation,
        summary,
        json,
        saved,
    })
}

/// A parse failure, or a failure to write the inbox.
#[derive(Debug)]
pub enum AcceptError {
    Parse(ParseError),
    Store(std::io::Error),
}

impl std::fmt::Display for AcceptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse(err) => write!(f, "{err}"),
            Self::Store(err) => f.write_str(&crate::i18n::t_args(
                "wallet.accept.store",
                &[("error", &err.to_string())],
            )),
        }
    }
}

impl std::error::Error for AcceptError {}
