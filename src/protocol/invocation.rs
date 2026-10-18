//! The invocation a desktop session hands this wallet: one custom-scheme URI.

use super::json::Json;
use super::offer::{OfferPassing, PRE_AUTHORIZED_CODE_GRANT};
use super::request::{from_query, AuthorizationRequest, RequestError, RequestScheme};
use super::uri::{parse_uri, UriError};

/// One launch of the wallet.
#[derive(Debug, Clone, PartialEq)]
pub enum Invocation {
    /// `openid-credential-offer://` or `haip-vci://`.
    CredentialOffer { scheme: String, offer: OfferPassing },
    /// `siopv2://`, `openid4vp://` or `haip-vp://`.
    Presentation(Box<AuthorizationRequest>),
}

/// Why the text the desktop passed is not an invocation this wallet accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseError {
    Uri(UriError),
    Message(String),
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Uri(err) => write!(f, "{err}"),
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Parse a wallet invocation URI.
pub fn parse(input: &str) -> Result<Invocation, ParseError> {
    let uri = parse_uri(input).map_err(ParseError::Uri)?;
    match uri.scheme.as_str() {
        "openid-credential-offer" | "haip-vci" => {
            let offer = OfferPassing::from_query(&uri.query)
                .map_err(|err| ParseError::Message(err.to_string()))?;
            Ok(Invocation::CredentialOffer {
                scheme: uri.scheme,
                offer,
            })
        }
        "siopv2" | "openid4vp" | "haip-vp" => {
            let scheme = RequestScheme::parse(&uri.scheme).expect("scheme was just matched");
            let request = from_query(scheme, &uri.query).map_err(request_error)?;
            Ok(Invocation::Presentation(Box::new(request)))
        }
        other => Err(ParseError::Message(format!(
            "scheme {other} is not a credential offer or a presentation request this wallet registers for"
        ))),
    }
}

fn request_error(err: RequestError) -> ParseError {
    ParseError::Message(err.to_string())
}

/// A short report for the terminal the desktop opens.
pub fn summary(invocation: &Invocation) -> String {
    match invocation {
        Invocation::CredentialOffer { scheme, offer } => summarize_offer(scheme, offer),
        Invocation::Presentation(request) => summarize_request(request),
    }
}

/// The same report as one JSON object, for a harness.
pub fn to_json(invocation: &Invocation) -> String {
    json_value(invocation).to_string()
}

fn summarize_offer(scheme: &str, offer: &OfferPassing) -> String {
    let mut lines = Vec::new();
    match offer {
        OfferPassing::ByValue(offer) => {
            lines.push(format!("Credential offer ({scheme}, by value)"));
            lines.push(format!("Issuer: {}", offer.credential_issuer));
            lines.push(format!(
                "Configurations: {}",
                offer.credential_configuration_ids.join(", ")
            ));
            if let Some(grant) = &offer.grants.authorization_code {
                lines.push("Grant: authorization code".to_string());
                if let Some(state) = &grant.issuer_state {
                    lines.push(format!("Issuer state: {state}"));
                }
                if let Some(server) = &grant.authorization_server {
                    lines.push(format!("Authorization server: {server}"));
                }
            }
            if let Some(grant) = &offer.grants.pre_authorized_code {
                lines.push("Grant: pre-authorized code".to_string());
                lines.push(format!(
                    "Pre-authorized code: {}",
                    grant.pre_authorized_code
                ));
                if let Some(tx) = &grant.tx_code {
                    let mode = tx.input_mode.as_deref().unwrap_or("unspecified");
                    let length = tx
                        .length
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "unspecified".to_string());
                    lines.push(format!("Transaction code: {mode}, length {length}"));
                    if let Some(description) = &tx.description {
                        lines.push(format!("Transaction code prompt: {description}"));
                    }
                }
                if let Some(interval) = grant.interval {
                    lines.push(format!("Interval: {interval}"));
                }
            }
            if offer.grants.authorization_code.is_none()
                && offer.grants.pre_authorized_code.is_none()
            {
                lines.push("Grant: none".to_string());
            }
            for name in &offer.grants.other {
                lines.push(format!("Other grant: {name}"));
            }
            if !offer.unknown_members.is_empty() {
                lines.push(format!(
                    "Ignored offer members: {}",
                    offer.unknown_members.join(", ")
                ));
            }
            lines.push("This build stores the offer. It does not redeem it yet.".to_string());
        }
        OfferPassing::ByReference {
            credential_offer_uri,
        } => {
            lines.push(format!("Credential offer ({scheme}, by reference)"));
            lines.push(format!("Offer URL: {credential_offer_uri}"));
            lines.push("This build stores the URL. It does not fetch the offer yet.".to_string());
        }
    }
    lines.join("\n")
}

fn summarize_request(request: &AuthorizationRequest) -> String {
    let passing = if request.by_reference() {
        "by reference"
    } else {
        "by value"
    };
    let mut lines = vec![
        format!(
            "Presentation request ({}, {passing})",
            request.scheme.as_str()
        ),
        format!("Client: {}", request.client_id),
    ];
    if let Some(uri) = &request.request_uri {
        let method = request.request_uri_method.as_deref().unwrap_or("get");
        lines.push(format!("Request URI: {uri}"));
        lines.push(format!("Request URI method: {method}"));
        lines.push(
            "This build stores the request URI. It does not fetch the request object yet."
                .to_string(),
        );
    }
    if let Some(value) = &request.response_type {
        lines.push(format!("Response type: {value}"));
    }
    if let Some(value) = &request.response_mode {
        lines.push(format!("Response mode: {value}"));
    }
    if let Some(value) = &request.response_uri {
        lines.push(format!("Response URI: {value}"));
    }
    if let Some(value) = &request.redirect_uri {
        lines.push(format!("Redirect URI: {value}"));
    }
    if let Some(value) = &request.scope {
        lines.push(format!("Scope: {value}"));
    }
    if let Some(value) = &request.nonce {
        lines.push(format!("Nonce: {value}"));
    }
    if let Some(value) = &request.state {
        lines.push(format!("State: {value}"));
    }
    if request.dcql_query.is_some() {
        lines.push("DCQL query: present".to_string());
    }
    if request.client_metadata.is_some() {
        lines.push("Client metadata: present".to_string());
    }
    if !request.unknown_parameters.is_empty() {
        lines.push(format!(
            "Ignored parameters: {}",
            request.unknown_parameters.join(", ")
        ));
    }
    if !request.by_reference() {
        lines.push(
            "This build stores the request. It does not build a presentation or an ID Token yet."
                .to_string(),
        );
    }
    lines.join("\n")
}

fn json_value(invocation: &Invocation) -> Json {
    match invocation {
        Invocation::CredentialOffer { scheme, offer } => match offer {
            OfferPassing::ByValue(offer) => {
                let mut grants = Vec::new();
                if offer.grants.authorization_code.is_some() {
                    grants.push(Json::String("authorization_code".to_string()));
                }
                if offer.grants.pre_authorized_code.is_some() {
                    grants.push(Json::String(PRE_AUTHORIZED_CODE_GRANT.to_string()));
                }
                Json::Object(vec![
                    (
                        "kind".to_string(),
                        Json::String("credential-offer".to_string()),
                    ),
                    ("scheme".to_string(), Json::String(scheme.clone())),
                    ("passing".to_string(), Json::String("by-value".to_string())),
                    (
                        "credential_issuer".to_string(),
                        Json::String(offer.credential_issuer.clone()),
                    ),
                    (
                        "credential_configuration_ids".to_string(),
                        Json::Array(
                            offer
                                .credential_configuration_ids
                                .iter()
                                .cloned()
                                .map(Json::String)
                                .collect(),
                        ),
                    ),
                    ("grants".to_string(), Json::Array(grants)),
                ])
            }
            OfferPassing::ByReference {
                credential_offer_uri,
            } => Json::Object(vec![
                (
                    "kind".to_string(),
                    Json::String("credential-offer".to_string()),
                ),
                ("scheme".to_string(), Json::String(scheme.clone())),
                (
                    "passing".to_string(),
                    Json::String("by-reference".to_string()),
                ),
                (
                    "credential_offer_uri".to_string(),
                    Json::String(credential_offer_uri.clone()),
                ),
            ]),
        },
        Invocation::Presentation(request) => {
            let mut members = vec![
                (
                    "kind".to_string(),
                    Json::String("presentation-request".to_string()),
                ),
                (
                    "scheme".to_string(),
                    Json::String(request.scheme.as_str().to_string()),
                ),
                (
                    "passing".to_string(),
                    Json::String(
                        if request.by_reference() {
                            "by-reference"
                        } else {
                            "by-value"
                        }
                        .to_string(),
                    ),
                ),
                (
                    "client_id".to_string(),
                    Json::String(request.client_id.clone()),
                ),
            ];
            push_opt(&mut members, "request_uri", request.request_uri.clone());
            push_opt(
                &mut members,
                "request_uri_method",
                request.request_uri_method.clone(),
            );
            push_opt(&mut members, "response_type", request.response_type.clone());
            push_opt(&mut members, "response_mode", request.response_mode.clone());
            push_opt(&mut members, "nonce", request.nonce.clone());
            push_opt(&mut members, "state", request.state.clone());
            Json::Object(members)
        }
    }
}

fn push_opt(members: &mut Vec<(String, Json)>, name: &str, value: Option<String>) {
    if let Some(value) = value {
        members.push((name.to_string(), Json::String(value)));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::uri::build_uri;

    #[test]
    fn iya_sts_offer_and_both_presentation_schemes() {
        let offer = build_uri(
            "openid-credential-offer",
            &[(
                "credential_offer",
                r#"{"credential_issuer":"https://sts.example","credential_configuration_ids":["identity"],"grants":{"authorization_code":{"issuer_state":"s"}}}"#,
            )],
        );
        let parsed = parse(&offer).unwrap();
        let text = summary(&parsed);
        assert!(text.contains("by value"));
        assert!(text.contains("https://sts.example"));
        let json = to_json(&parsed);
        assert!(json.contains("\"kind\":\"credential-offer\""));

        let siop = build_uri(
            "siopv2",
            &[
                ("client_id", "x509_hash:abc"),
                ("request_uri", "http://localhost:8080/oid4vp/request/1"),
                ("request_uri_method", "get"),
            ],
        );
        let parsed = parse(&siop).unwrap();
        assert!(summary(&parsed).contains("siopv2"));
        assert!(to_json(&parsed).contains("\"scheme\":\"siopv2\""));

        let vp = build_uri(
            "openid4vp",
            &[
                ("client_id", "x509_hash:abc"),
                ("request_uri", "https://sts.example/oid4vp/request/1"),
                ("request_uri_method", "get"),
            ],
        );
        assert!(summary(&parse(&vp).unwrap()).contains("openid4vp"));
    }

    #[test]
    fn refuses_an_https_page() {
        let err = parse("https://sts.example/issuer").unwrap_err();
        assert!(err.to_string().contains("scheme"));
    }
}
