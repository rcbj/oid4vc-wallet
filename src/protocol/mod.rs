//! OpenID4VCI credential offers and OpenID4VP / SIOPv2 authorization requests.
//!
//! Nothing in this module calls another crate. Parsing, validation and the
//! summaries a person reads are all first-party code. Fetching an offer or a
//! request by reference, and redeeming or answering one, are later steps:
//! this module stops once the invocation the desktop handed over is understood.

mod http_url;
mod json;
mod percent;
mod query;
mod uri;

pub mod invocation;
pub mod offer;
pub mod request;

pub use http_url::is_http_url;
pub use invocation::{parse, ui_locales_of_uri, Invocation, ParseError};
pub use json::Json;
pub use percent::{encode_uri_component, form_decode};
pub use uri::CustomUri;
