//! The local record of invocations the desktop handed this process.

mod inbox;

pub use inbox::{Inbox, InboxEntry};

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
            Self::Store(err) => write!(f, "could not store the invocation: {err}"),
        }
    }
}

impl std::error::Error for AcceptError {}
