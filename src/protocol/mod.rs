//! OpenID4VCI credential offers and OpenID4VP / SIOPv2 authorization requests.
//!
//! Nothing in this module calls another crate. Parsing, validation and the
//! summaries a person reads are all first-party code. Fetching an offer by
//! reference stays outside this module. Answering a same-device presentation
//! request is `wallet::present_same_device`. Redeeming a pre-authorized offer
//! is `wallet::redeem`. Checking an issued credential's signature is
//! `wallet::validate_stored`.

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
