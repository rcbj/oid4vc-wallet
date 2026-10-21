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
///
/// # Errors
///
/// `input` is not a URI, its scheme is not one this wallet handles, or its
/// offer or request parameters are invalid.
pub fn parse(input: &str) -> Result<Invocation, ParseError> {
    let uri = parse_uri(input).map_err(ParseError::Uri)?;
    if let Some(scheme) = RequestScheme::parse(&uri.scheme) {
        let request = from_query(scheme, &uri.query).map_err(|err| request_error(&err))?;
        return Ok(Invocation::Presentation(Box::new(request)));
    }
    match uri.scheme.as_str() {
        "openid-credential-offer" | "haip-vci" => {
            let offer = OfferPassing::from_query(&uri.query)
                .map_err(|err| ParseError::Message(err.to_string()))?;
            Ok(Invocation::CredentialOffer {
                scheme: uri.scheme,
                offer,
            })
        }
        other => Err(ParseError::Message(crate::i18n::t_args(
            "wallet.invocation.unknown_scheme",
            &[("scheme", other)],
        ))),
    }
}

fn request_error(err: &RequestError) -> ParseError {
    ParseError::Message(err.to_string())
}

/// `ui_locales` from a URI, when the query can be read. A URI that cannot be
/// read leaves the caller's language alone.
#[must_use]
pub fn ui_locales_of_uri(uri: &str) -> Vec<String> {
    let Ok(parsed) = parse_uri(uri) else {
        return Vec::new();
    };
    let Some(value) = parsed
        .query
        .iter()
        .find(|param| param.name == "ui_locales")
        .map(|param| param.value.as_str())
    else {
        return Vec::new();
    };
    crate::i18n::ui_locales(value)
}

/// A short report for the terminal the desktop opens.
#[must_use]
pub fn summary(invocation: &Invocation) -> String {
    match invocation {
        Invocation::CredentialOffer { scheme, offer } => summarize_offer(scheme, offer),
        Invocation::Presentation(request) => summarize_request(request),
    }
}

/// The same report as one JSON object, for a harness.
#[must_use]
pub fn to_json(invocation: &Invocation) -> String {
    json_value(invocation).to_string()
}

fn summarize_offer(scheme: &str, offer: &OfferPassing) -> String {
    let mut lines = Vec::new();
    match offer {
        OfferPassing::ByValue(offer) => {
            lines.push(line(
                "wallet.summary.offer",
                &[
                    ("scheme", scheme),
                    ("passing", &crate::i18n::t("wallet.summary.by_value")),
                ],
            ));
            lines.push(line(
                "wallet.summary.issuer",
                &[("issuer", offer.credential_issuer.as_str())],
            ));
            lines.push(line(
                "wallet.summary.configurations",
                &[("list", &offer.credential_configuration_ids.join(", "))],
            ));
            if let Some(grant) = &offer.grants.authorization_code {
                lines.push(crate::i18n::t("wallet.summary.grant_authorization_code"));
                if let Some(state) = &grant.issuer_state {
                    lines.push(line("wallet.summary.issuer_state", &[("state", state)]));
                }
                if let Some(server) = &grant.authorization_server {
                    lines.push(line(
                        "wallet.summary.authorization_server",
                        &[("server", server)],
                    ));
                }
            }
            if let Some(grant) = &offer.grants.pre_authorized_code {
                lines.push(crate::i18n::t("wallet.summary.grant_pre_authorized"));
                lines.push(line(
                    "wallet.summary.pre_authorized_code",
                    &[("code", grant.pre_authorized_code.as_str())],
                ));
                if let Some(tx) = &grant.tx_code {
                    let mode = tx
                        .input_mode
                        .clone()
                        .unwrap_or_else(|| crate::i18n::t("wallet.summary.unspecified"));
                    let length = tx.length.map_or_else(
                        || crate::i18n::t("wallet.summary.unspecified"),
                        |n| n.to_string(),
                    );
                    lines.push(line(
                        "wallet.summary.tx_code",
                        &[("mode", mode.as_str()), ("length", length.as_str())],
                    ));
                    if let Some(description) = &tx.description {
                        lines.push(line(
                            "wallet.summary.tx_prompt",
                            &[("description", description)],
                        ));
                    }
                }
                if let Some(interval) = grant.interval {
                    lines.push(line(
                        "wallet.summary.interval",
                        &[("interval", &interval.to_string())],
                    ));
                }
            }
            if offer.grants.authorization_code.is_none()
                && offer.grants.pre_authorized_code.is_none()
            {
                lines.push(crate::i18n::t("wallet.summary.grant_none"));
            }
            for name in &offer.grants.other {
                lines.push(line("wallet.summary.other_grant", &[("name", name)]));
            }
            if !offer.unknown_members.is_empty() {
                lines.push(line(
                    "wallet.summary.ignored_members",
                    &[("list", &offer.unknown_members.join(", "))],
                ));
            }
            lines.push(crate::i18n::t("wallet.summary.stores_offer"));
        }
        OfferPassing::ByReference {
            credential_offer_uri,
        } => {
            lines.push(line(
                "wallet.summary.offer",
                &[
                    ("scheme", scheme),
                    ("passing", &crate::i18n::t("wallet.summary.by_reference")),
                ],
            ));
            lines.push(line(
                "wallet.summary.offer_url",
                &[("url", credential_offer_uri.as_str())],
            ));
            lines.push(crate::i18n::t("wallet.summary.stores_url"));
        }
    }
    lines.join("\n")
}

fn summarize_request(request: &AuthorizationRequest) -> String {
    let passing = if request.by_reference() {
        crate::i18n::t("wallet.summary.by_reference")
    } else {
        crate::i18n::t("wallet.summary.by_value")
    };
    let mut lines = vec![
        line(
            "wallet.summary.request",
            &[
                ("scheme", request.scheme.as_str()),
                ("passing", passing.as_str()),
            ],
        ),
        line(
            "wallet.summary.client",
            &[("client", request.client_id.as_str())],
        ),
    ];
    if let Some(uri) = &request.request_uri {
        let method = request.request_uri_method.as_deref().unwrap_or("get");
        lines.push(line("wallet.summary.request_uri", &[("uri", uri)]));
        lines.push(line(
            "wallet.summary.request_uri_method",
            &[("method", method)],
        ));
        lines.push(crate::i18n::t("wallet.summary.stores_request_uri"));
    }
    if let Some(value) = &request.response_type {
        lines.push(line("wallet.summary.response_type", &[("value", value)]));
    }
    if let Some(value) = &request.response_mode {
        lines.push(line("wallet.summary.response_mode", &[("value", value)]));
    }
    if let Some(value) = &request.response_uri {
        lines.push(line("wallet.summary.response_uri", &[("value", value)]));
    }
    if let Some(value) = &request.redirect_uri {
        lines.push(line("wallet.summary.redirect_uri", &[("value", value)]));
    }
    if let Some(value) = &request.scope {
        lines.push(line("wallet.summary.scope", &[("value", value)]));
    }
    if let Some(value) = &request.nonce {
        lines.push(line("wallet.summary.nonce", &[("value", value)]));
    }
    if let Some(value) = &request.state {
        lines.push(line("wallet.summary.state", &[("value", value)]));
    }
    if request.dcql_query.is_some() {
        lines.push(crate::i18n::t("wallet.summary.dcql"));
    }
    if request.client_metadata.is_some() {
        lines.push(crate::i18n::t("wallet.summary.client_metadata"));
    }
    if !request.unknown_parameters.is_empty() {
        lines.push(line(
            "wallet.summary.ignored_parameters",
            &[("list", &request.unknown_parameters.join(", "))],
        ));
    }
    if !request.by_reference() {
        lines.push(crate::i18n::t("wallet.summary.stores_request"));
    }
    lines.join("\n")
}

fn line(key: &str, args: &[(&str, &str)]) -> String {
    crate::i18n::t_args(key, args)
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
            push_opt(&mut members, "ui_locales", request.ui_locales.clone());
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
