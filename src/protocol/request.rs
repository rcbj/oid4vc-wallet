//! An OpenID4VP 1.0 or SIOPv2 authorization request, the document carried by
//! `openid4vp://`, `siopv2://` and `haip-vp://`.
//!
//! iya-sts puts a request by reference on the URI: `client_id`, `request_uri`
//! and `request_uri_method=get`. A request by value carries the parameters
//! themselves, with `dcql_query` and `client_metadata` as JSON. An ID Token
//! alone uses `siopv2://` and `response_type=id_token`. A presentation uses
//! `openid4vp://`.

use super::http_url::is_http_url;
use super::json::{Json, JsonError};
use super::query::{values, QueryParam};

/// Which custom scheme delivered the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestScheme {
    /// SIOPv2 section 7.2. iya-sts uses this for an ID Token alone.
    SiopV2,
    /// OpenID4VP 1.0. iya-sts uses this for a presentation request.
    OpenId4Vp,
    /// OpenID4VC HAIP 1.0 section 5.1.
    HaipVp,
}

impl RequestScheme {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SiopV2 => "siopv2",
            Self::OpenId4Vp => "openid4vp",
            Self::HaipVp => "haip-vp",
        }
    }

    #[must_use]
    pub fn parse(scheme: &str) -> Option<Self> {
        match scheme {
            "siopv2" => Some(Self::SiopV2),
            "openid4vp" => Some(Self::OpenId4Vp),
            "haip-vp" => Some(Self::HaipVp),
            _ => None,
        }
    }
}

/// A presentation or self-issued request the wallet was asked to answer.
#[derive(Debug, Clone, PartialEq)]
pub struct AuthorizationRequest {
    pub scheme: RequestScheme,
    pub client_id: String,
    /// Set when the signed Request Object is fetched from `request_uri`.
    /// This build records the URI and does not fetch it.
    pub request_uri: Option<String>,
    /// `get` or `post`. Absent means `get`, which is what iya-sts sends.
    pub request_uri_method: Option<String>,
    /// A Request Object JWT passed by value. Not verified in this build.
    pub request: Option<String>,
    pub response_type: Option<String>,
    pub response_mode: Option<String>,
    pub response_uri: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub nonce: Option<String>,
    pub state: Option<String>,
    pub dcql_query: Option<Json>,
    pub client_metadata: Option<Json>,
    pub presentation_definition: Option<Json>,
    pub presentation_definition_uri: Option<String>,
    /// OpenID Connect `ui_locales`, space-separated, best first.
    pub ui_locales: Option<String>,
    /// Parameter names this wallet does not act on yet.
    pub unknown_parameters: Vec<String>,
}

impl AuthorizationRequest {
    #[must_use]
    pub fn by_reference(&self) -> bool {
        self.request_uri.is_some()
    }
}

/// Why a presentation or SIOPv2 invocation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RequestError {
    Message(String),
}

impl std::fmt::Display for RequestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for RequestError {}

/// Read the request from the query of a `siopv2://`, `openid4vp://` or
/// `haip-vp://` URI.
///
/// # Errors
///
/// A parameter is repeated, a required parameter is missing, or a value is not
/// one this wallet accepts.
pub fn from_query(
    scheme: RequestScheme,
    params: &[QueryParam],
) -> Result<AuthorizationRequest, RequestError> {
    let mut client_id = None;
    let mut request_uri = None;
    let mut request_uri_method = None;
    let mut request = None;
    let mut response_type = None;
    let mut response_mode = None;
    let mut response_uri = None;
    let mut redirect_uri = None;
    let mut scope = None;
    let mut nonce = None;
    let mut state = None;
    let mut dcql_query = None;
    let mut client_metadata = None;
    let mut presentation_definition = None;
    let mut presentation_definition_uri = None;
    let mut ui_locales = None;
    let mut unknown_parameters = Vec::new();

    for param in params {
        if values(params, &param.name).len() > 1 {
            return Err(tra(
                "wallet.request.duplicate",
                &[("name", param.name.as_str())],
            ));
        }
        let value = param.value.as_str();
        match param.name.as_str() {
            "client_id" => client_id = Some(require_token(value, "client_id")?),
            "request_uri" => {
                if !is_http_url(value) {
                    return Err(tr("wallet.request.request_uri_http"));
                }
                request_uri = Some(value.to_string());
            }
            "request_uri_method" => {
                let method = value.to_ascii_lowercase();
                if method != "get" && method != "post" {
                    return Err(tr("wallet.request.request_uri_method"));
                }
                request_uri_method = Some(method);
            }
            "request" => request = Some(require_token(value, "request")?),
            "response_type" => response_type = Some(require_text(value, "response_type")?),
            "response_mode" => response_mode = Some(require_token(value, "response_mode")?),
            "response_uri" => {
                response_uri = Some(require_http(value, "response_uri")?);
            }
            "redirect_uri" => {
                redirect_uri = Some(require_http(value, "redirect_uri")?);
            }
            "scope" => scope = Some(require_text(value, "scope")?),
            "nonce" => nonce = Some(require_token(value, "nonce")?),
            "state" => state = Some(require_token(value, "state")?),
            "dcql_query" => dcql_query = Some(require_json_object(value, "dcql_query")?),
            "client_metadata" => {
                client_metadata = Some(require_json_object(value, "client_metadata")?);
            }
            "presentation_definition" => {
                presentation_definition =
                    Some(require_json_object(value, "presentation_definition")?);
            }
            "presentation_definition_uri" => {
                presentation_definition_uri =
                    Some(require_http(value, "presentation_definition_uri")?);
            }
            "ui_locales" => ui_locales = Some(require_text(value, "ui_locales")?),
            other => unknown_parameters.push(other.to_string()),
        }
    }

    let client_id = client_id.ok_or_else(|| tr("wallet.request.missing_client"))?;
    if request_uri.is_none() && response_type.is_none() && request.is_none() {
        return Err(tr("wallet.request.nothing"));
    }
    Ok(AuthorizationRequest {
        scheme,
        client_id,
        request_uri,
        request_uri_method,
        request,
        response_type,
        response_mode,
        response_uri,
        redirect_uri,
        scope,
        nonce,
        state,
        dcql_query,
        client_metadata,
        presentation_definition,
        presentation_definition_uri,
        ui_locales,
        unknown_parameters,
    })
}

fn require_token(value: &str, field: &str) -> Result<String, RequestError> {
    if value.is_empty() || value.chars().any(|c| c.is_ascii_whitespace()) {
        return Err(tra("wallet.request.token", &[("field", field)]));
    }
    Ok(value.to_string())
}

/// `response_type` and `scope` are space-separated lists (`vp_token id_token`,
/// `openid`).
fn require_text(value: &str, field: &str) -> Result<String, RequestError> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return Err(tra("wallet.request.text", &[("field", field)]));
    }
    Ok(trimmed.to_string())
}

fn require_http(value: &str, field: &str) -> Result<String, RequestError> {
    if !is_http_url(value) {
        return Err(tra("wallet.request.http", &[("field", field)]));
    }
    Ok(value.to_string())
}

fn require_json_object(value: &str, field: &str) -> Result<Json, RequestError> {
    let parsed = Json::parse(value).map_err(|error: JsonError| {
        tra(
            "wallet.request.not_json",
            &[("field", field), ("error", &error.to_string())],
        )
    })?;
    if parsed.as_object().is_none() {
        return Err(tra("wallet.request.not_json_object", &[("field", field)]));
    }
    Ok(parsed)
}

fn err(message: impl Into<String>) -> RequestError {
    RequestError::Message(message.into())
}

fn tr(key: &str) -> RequestError {
    err(crate::i18n::t(key))
}

fn tra(key: &str, args: &[(&str, &str)]) -> RequestError {
    err(crate::i18n::t_args(key, args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::uri::{build_uri, parse_uri};

    #[test]
    fn parses_the_siopv2_reference_iya_sts_uses_for_an_id_token() {
        let uri = build_uri(
            "siopv2",
            &[
                ("client_id", "x509_hash:abc"),
                ("request_uri", "https://sts.example/oid4vp/request/id"),
                ("request_uri_method", "get"),
            ],
        );
        let parsed = parse_uri(&uri).unwrap();
        let request = from_query(RequestScheme::SiopV2, &parsed.query).unwrap();
        assert!(request.by_reference());
        assert_eq!(request.client_id, "x509_hash:abc");
        assert_eq!(
            request.request_uri.as_deref(),
            Some("https://sts.example/oid4vp/request/id")
        );
        assert_eq!(request.request_uri_method.as_deref(), Some("get"));
    }

    #[test]
    fn parses_an_openid4vp_request_by_value() {
        let uri = build_uri(
            "openid4vp",
            &[
                (
                    "client_id",
                    "redirect_uri:https://sts.example/oid4vp/response",
                ),
                ("response_type", "vp_token"),
                ("response_mode", "direct_post.jwt"),
                ("response_uri", "https://sts.example/oid4vp/response"),
                ("nonce", "n-1"),
                ("state", "s-1"),
                (
                    "dcql_query",
                    r#"{"credentials":[{"id":"identity","format":"dc+sd-jwt"}]}"#,
                ),
            ],
        );
        let parsed = parse_uri(&uri).unwrap();
        let request = from_query(RequestScheme::OpenId4Vp, &parsed.query).unwrap();
        assert!(!request.by_reference());
        assert_eq!(request.response_type.as_deref(), Some("vp_token"));
        let combined = build_uri(
            "siopv2",
            &[
                ("client_id", "https://sts.example"),
                ("response_type", "vp_token id_token"),
                ("scope", "openid"),
                ("nonce", "n-1"),
                ("response_mode", "direct_post"),
            ],
        );
        let parsed = parse_uri(&combined).unwrap();
        let combined = from_query(RequestScheme::SiopV2, &parsed.query).unwrap();
        assert_eq!(combined.response_type.as_deref(), Some("vp_token id_token"));
        assert_eq!(combined.scope.as_deref(), Some("openid"));
        assert_eq!(request.response_mode.as_deref(), Some("direct_post.jwt"));
        assert!(request.dcql_query.unwrap().get("credentials").is_some());
    }

    #[test]
    fn refuses_a_request_with_nothing_to_answer() {
        let params = crate::protocol::query::parse_query("client_id=only").unwrap();
        assert!(from_query(RequestScheme::SiopV2, &params).is_err());
    }
}
