//! The inbox of invocations the desktop handed this process, and the
//! credentials the wallet stores.
//!
//! Invocations stay as the raw URI. Credentials are sealed with AES-256-GCM.
//! The key is read from GNOME Keyring, or from KWallet when the Secret
//! Service is not running. [`validate_stored`] checks an issued credential's
//! signature. One inbox entry can be removed with [`Inbox::delete`].
//! [`present_same_device`] fetches a same-device presentation request,
//! selects a stored credential, and posts the answer. [`prepare_presentation`]
//! stops before a holder key is used so the window can ask first.
//! [`remember_presentation`] records a credential that should not be asked
//! again. An `id_token` request is answered with a self-issued ID Token.
//! [`export_credentials`] copies credentials into a file sealed with a new
//! AES-256 key, so they can move to another device. [`import_credentials`]
//! opens that file. The new key is not the wallet's storage key.

mod anchors;
mod b64;
mod certs;
mod consent;
mod credentials;
mod http;
mod inbox;
mod jws;
mod key_store;
mod kwallet;
mod portable;
mod present;
mod proof;
mod redeem;
mod seal;
mod secret_service;
mod trust;
mod validate;

pub use anchors::{
    default_dir as trust_anchors_dir, install_pem as import_anchors, list as list_anchors,
    remove as delete_anchor, StoredAnchor as AnchorInfo,
};
pub use certs::{signer_certificates, SignerCertificate};
pub use consent::{
    approved_ids as presentation_approvals, default_path as presentation_approval_path,
    remember as remember_presentation,
};
pub use credentials::{Credential, CredentialVault, NewCredential, RotateReport, VaultError};
pub use inbox::{Inbox, InboxEntry};
pub use jws::signature_algorithm;
pub use key_store::{DesktopKeyStore, EncryptionKeyStore, KeyStoreError, RetiredKey};
pub use portable::{export_credentials, import_credentials, PortableError, PortableExport};
pub use present::{
    approve_presentation, ensure_self_issued_certificate, prepare_presentation,
    present_same_device, refuse_presentation, PendingPresentation, Presentation,
    PresentationSummary, Presented,
};
pub use redeem::{redeem_pre_authorized, RedeemError, Redeemed};
pub use seal::{Aes256Key, SealError};
pub use secret_service::SecretServiceKeyStore;
pub use validate::{remember_trust, validate_stored, Outcome, ValidateError};

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
