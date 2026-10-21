//! An OpenID4VCI 1.0 Credential Offer, the document carried by
//! `openid-credential-offer://` (section 4.1).
//!
//! iya-sts mints the same document: `credential_issuer`,
//! `credential_configuration_ids`, and either an `authorization_code` grant
//! (same-device) or a `pre-authorized_code` grant whose `tx_code` describes
//! the digits the issuer showed the person (cross-device and deferred).

use super::http_url::is_http_url;
use super::json::{Json, JsonError};
use super::query::{values, QueryParam};

/// The grant name OpenID4VCI 1.0 uses for a pre-authorized code.
pub const PRE_AUTHORIZED_CODE_GRANT: &str = "urn:ietf:params:oauth:grant-type:pre-authorized_code";

/// How the offer was passed on the invocation URI.
#[derive(Debug, Clone, PartialEq)]
pub enum OfferPassing {
    /// `credential_offer`, the offer object itself.
    ByValue(Box<CredentialOffer>),
    /// `credential_offer_uri`, an `http` or `https` URL the wallet still has
    /// to fetch. This build records the URL and does not fetch it.
    ByReference { credential_offer_uri: String },
}

/// A Credential Offer (OpenID4VCI 1.0 section 4.1.1).
#[derive(Debug, Clone, PartialEq)]
pub struct CredentialOffer {
    pub credential_issuer: String,
    pub credential_configuration_ids: Vec<String>,
    pub grants: Grants,
    /// Member names this wallet does not act on. OpenID4VCI says a wallet
    /// ignores members it does not understand; they are kept so a test can
    /// see them.
    pub unknown_members: Vec<String>,
}

/// The grants on an offer. Both may be present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grants {
    pub authorization_code: Option<AuthorizationCodeGrant>,
    pub pre_authorized_code: Option<PreAuthorizedCodeGrant>,
    /// Grant names other than the two OpenID4VCI 1.0 defines.
    pub other: Vec<String>,
}

/// The authorization-code grant inside a Credential Offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCodeGrant {
    pub issuer_state: Option<String>,
    pub authorization_server: Option<String>,
    pub unknown_members: Vec<String>,
}

/// The pre-authorized-code grant inside a Credential Offer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreAuthorizedCodeGrant {
    pub pre_authorized_code: String,
    pub tx_code: Option<TxCode>,
    pub authorization_server: Option<String>,
    /// Present in some drafts. OpenID4VCI 1.0 section 4.1.1 does not define
    /// it on this grant; iya-sts does not send it. Kept when an issuer does.
    pub interval: Option<u64>,
    pub unknown_members: Vec<String>,
}

/// What the issuer tells the wallet to ask the person to type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxCode {
    /// `numeric` or `text`.
    pub input_mode: Option<String>,
    pub length: Option<u64>,
    pub description: Option<String>,
    pub unknown_members: Vec<String>,
}

/// Why an offer invocation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OfferError {
    Message(String),
}

impl std::fmt::Display for OfferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Message(message) => write!(f, "{message}"),
        }
    }
}

impl std::error::Error for OfferError {}

impl OfferPassing {
    /// Read the offer from the query of an
    /// `openid-credential-offer://` or `haip-vci://` URI.
    ///
    /// # Errors
    ///
    /// `credential_offer` or `credential_offer_uri` is repeated, both or
    /// neither are present, the offer is not a valid Credential Offer, or the
    /// offer URI is not HTTP(S).
    pub fn from_query(params: &[QueryParam]) -> Result<Self, OfferError> {
        let by_value = values(params, "credential_offer");
        let by_reference = values(params, "credential_offer_uri");
        if by_value.len() > 1 {
            return Err(tr("wallet.offer.duplicate_offer"));
        }
        if by_reference.len() > 1 {
            return Err(tr("wallet.offer.duplicate_uri"));
        }
        match (by_value.first(), by_reference.first()) {
            (Some(_), Some(_)) => Err(tr("wallet.offer.both")),
            (None, None) => Err(tr("wallet.offer.neither")),
            (Some(offer), None) => Ok(Self::ByValue(Box::new(parse_offer_json(offer)?))),
            (None, Some(uri)) => {
                if !is_http_url(uri) {
                    return Err(tr("wallet.offer.offer_uri_http"));
                }
                Ok(Self::ByReference {
                    credential_offer_uri: (*uri).to_string(),
                })
            }
        }
    }
}

/// Parse a Credential Offer object.
///
/// # Errors
///
/// `text` is not a JSON object, or it lacks or misuses a member a Credential
/// Offer requires.
pub fn parse_offer_json(text: &str) -> Result<CredentialOffer, OfferError> {
    let value = Json::parse(text).map_err(|error: JsonError| {
        tra(
            "wallet.offer.not_object_error",
            &[("error", &error.to_string())],
        )
    })?;
    let members = value
        .as_object()
        .ok_or_else(|| tr("wallet.offer.not_object"))?;
    let mut unknown_members = Vec::new();
    let mut credential_issuer = None;
    let mut configuration_ids = None;
    let mut grants = None;
    for (name, member) in members {
        match name.as_str() {
            "credential_issuer" => {
                credential_issuer = Some(require_string(member, "credential_issuer")?);
            }
            "credential_configuration_ids" => {
                configuration_ids = Some(require_string_array(
                    member,
                    "credential_configuration_ids",
                )?);
            }
            "grants" => grants = Some(parse_grants(member)?),
            "credentials" => {
                return Err(tr("wallet.offer.old_credentials"));
            }
            other => unknown_members.push(other.to_string()),
        }
    }
    let credential_issuer = credential_issuer.ok_or_else(|| tr("wallet.offer.missing_issuer"))?;
    if !is_http_url(&credential_issuer) {
        return Err(tr("wallet.offer.issuer_http"));
    }
    let credential_configuration_ids =
        configuration_ids.ok_or_else(|| tr("wallet.offer.missing_configs"))?;
    if credential_configuration_ids.is_empty() {
        return Err(tr("wallet.offer.configs_empty"));
    }
    Ok(CredentialOffer {
        credential_issuer,
        credential_configuration_ids,
        grants: grants.unwrap_or(Grants {
            authorization_code: None,
            pre_authorized_code: None,
            other: Vec::new(),
        }),
        unknown_members,
    })
}

fn parse_grants(value: &Json) -> Result<Grants, OfferError> {
    let members = value
        .as_object()
        .ok_or_else(|| tr("wallet.offer.grants_object"))?;
    let mut authorization_code = None;
    let mut pre_authorized_code = None;
    let mut other = Vec::new();
    for (name, member) in members {
        match name.as_str() {
            "authorization_code" => {
                authorization_code = Some(parse_authorization_code(member)?);
            }
            PRE_AUTHORIZED_CODE_GRANT => {
                pre_authorized_code = Some(parse_pre_authorized(member)?);
            }
            other_name => other.push(other_name.to_string()),
        }
    }
    Ok(Grants {
        authorization_code,
        pre_authorized_code,
        other,
    })
}

fn parse_authorization_code(value: &Json) -> Result<AuthorizationCodeGrant, OfferError> {
    let members = value
        .as_object()
        .ok_or_else(|| tr("wallet.offer.auth_code_object"))?;
    let mut issuer_state = None;
    let mut authorization_server = None;
    let mut unknown_members = Vec::new();
    for (name, member) in members {
        match name.as_str() {
            "issuer_state" => {
                issuer_state = Some(require_string(
                    member,
                    "grants.authorization_code.issuer_state",
                )?);
            }
            "authorization_server" => {
                let server =
                    require_string(member, "grants.authorization_code.authorization_server")?;
                if !is_http_url(&server) {
                    return Err(tr("wallet.offer.auth_server_http"));
                }
                authorization_server = Some(server);
            }
            other => unknown_members.push(other.to_string()),
        }
    }
    Ok(AuthorizationCodeGrant {
        issuer_state,
        authorization_server,
        unknown_members,
    })
}

fn parse_pre_authorized(value: &Json) -> Result<PreAuthorizedCodeGrant, OfferError> {
    let members = value
        .as_object()
        .ok_or_else(|| tr("wallet.offer.preauth_object"))?;
    let mut pre_authorized_code = None;
    let mut tx_code = None;
    let mut authorization_server = None;
    let mut interval = None;
    let mut unknown_members = Vec::new();
    for (name, member) in members {
        match name.as_str() {
            "pre-authorized_code" => {
                let code = require_string(member, "pre-authorized_code")?;
                if code.is_empty() {
                    return Err(tr("wallet.offer.preauth_empty"));
                }
                pre_authorized_code = Some(code);
            }
            "tx_code" => tx_code = Some(parse_tx_code(member)?),
            "authorization_server" => {
                let server = require_string(member, "pre-authorized grant authorization_server")?;
                if !is_http_url(&server) {
                    return Err(tr("wallet.offer.preauth_server_http"));
                }
                authorization_server = Some(server);
            }
            "interval" => {
                interval = Some(member.as_u64().ok_or_else(|| tr("wallet.offer.interval"))?);
            }
            other => unknown_members.push(other.to_string()),
        }
    }
    let pre_authorized_code =
        pre_authorized_code.ok_or_else(|| tr("wallet.offer.preauth_missing"))?;
    Ok(PreAuthorizedCodeGrant {
        pre_authorized_code,
        tx_code,
        authorization_server,
        interval,
        unknown_members,
    })
}

fn parse_tx_code(value: &Json) -> Result<TxCode, OfferError> {
    let members = value
        .as_object()
        .ok_or_else(|| tr("wallet.offer.tx_object"))?;
    let mut input_mode = None;
    let mut length = None;
    let mut description = None;
    let mut unknown_members = Vec::new();
    for (name, member) in members {
        match name.as_str() {
            "input_mode" => {
                let mode = require_string(member, "tx_code.input_mode")?;
                if mode != "numeric" && mode != "text" {
                    return Err(tr("wallet.offer.tx_mode"));
                }
                input_mode = Some(mode);
            }
            "length" => {
                let digits = member
                    .as_u64()
                    .ok_or_else(|| tr("wallet.offer.tx_length"))?;
                if digits == 0 {
                    return Err(tr("wallet.offer.tx_length"));
                }
                length = Some(digits);
            }
            "description" => {
                description = Some(require_string(member, "tx_code.description")?);
            }
            other => unknown_members.push(other.to_string()),
        }
    }
    Ok(TxCode {
        input_mode,
        length,
        description,
        unknown_members,
    })
}

fn require_string(value: &Json, field: &str) -> Result<String, OfferError> {
    value
        .as_str()
        .filter(|text| !text.is_empty())
        .map(str::to_string)
        .ok_or_else(|| tra("wallet.offer.field_string", &[("field", field)]))
}

fn require_string_array(value: &Json, field: &str) -> Result<Vec<String>, OfferError> {
    let items = value
        .as_array()
        .ok_or_else(|| tra("wallet.offer.field_array", &[("field", field)]))?;
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let text = item
            .as_str()
            .ok_or_else(|| tra("wallet.offer.field_array_items", &[("field", field)]))?;
        if text.is_empty() {
            return Err(tra("wallet.offer.field_array_items", &[("field", field)]));
        }
        out.push(text.to_string());
    }
    Ok(out)
}

fn err(message: impl Into<String>) -> OfferError {
    OfferError::Message(message.into())
}

fn tr(key: &str) -> OfferError {
    err(crate::i18n::t(key))
}

fn tra(key: &str, args: &[(&str, &str)]) -> OfferError {
    err(crate::i18n::t_args(key, args))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::uri::build_uri;

    fn iya_pre_authorized() -> &'static str {
        r#"{"credential_issuer":"https://sts.example","credential_configuration_ids":["identity"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc+def/ghi=","tx_code":{"input_mode":"numeric","length":5,"description":"Type the 5-digit code shown by the issuer."}}}}"#
    }

    #[test]
    fn parses_the_offer_iya_sts_puts_on_a_cross_device_link() {
        let uri = build_uri(
            "openid-credential-offer",
            &[("credential_offer", iya_pre_authorized())],
        );
        let parsed = crate::protocol::uri::parse_uri(&uri).unwrap();
        let OfferPassing::ByValue(offer) = OfferPassing::from_query(&parsed.query).unwrap() else {
            panic!("by value");
        };
        assert_eq!(offer.credential_issuer, "https://sts.example");
        assert_eq!(offer.credential_configuration_ids, vec!["identity"]);
        let grant = offer.grants.pre_authorized_code.unwrap();
        assert_eq!(grant.pre_authorized_code, "abc+def/ghi=");
        let tx = grant.tx_code.unwrap();
        assert_eq!(tx.input_mode.as_deref(), Some("numeric"));
        assert_eq!(tx.length, Some(5));
        assert!(tx.description.unwrap().contains("5-digit"));
    }

    #[test]
    fn parses_a_same_device_offer_and_a_reference() {
        let text = r#"{"credential_issuer":"http://localhost:8080","credential_configuration_ids":["identity","another"],"grants":{"authorization_code":{"issuer_state":"state-1"}}}"#;
        let offer = parse_offer_json(text).unwrap();
        assert_eq!(
            offer
                .grants
                .authorization_code
                .unwrap()
                .issuer_state
                .as_deref(),
            Some("state-1")
        );
        let params = crate::protocol::query::parse_query(
            "credential_offer_uri=https%3A%2F%2Fsts.example%2Foid4vci%2Fcredential-offer%2Fid",
        )
        .unwrap();
        let OfferPassing::ByReference {
            credential_offer_uri,
        } = OfferPassing::from_query(&params).unwrap()
        else {
            panic!("by reference");
        };
        assert_eq!(
            credential_offer_uri,
            "https://sts.example/oid4vci/credential-offer/id"
        );
    }

    #[test]
    fn refuses_both_forms_and_the_old_credentials_member() {
        let params = crate::protocol::query::parse_query(
            "credential_offer=%7B%7D&credential_offer_uri=https%3A%2F%2Fsts.example%2Fx",
        )
        .unwrap();
        assert!(OfferPassing::from_query(&params).is_err());
        let old = r#"{"credential_issuer":"https://sts.example","credentials":["a"]}"#;
        assert!(parse_offer_json(old)
            .unwrap_err()
            .to_string()
            .contains("credential_configuration_ids"));
    }
}
