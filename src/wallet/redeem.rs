//! Redeem an OpenID4VCI pre-authorized code.
//!
//! The wallet reads the credential-issuer metadata and the authorization
//! server metadata, sends the transaction code to the token endpoint with no
//! `client_id`, fetches a `c_nonce`, and asks for the credential with an
//! ES256 proof of possession. The messages are built in this crate.

use crate::i18n::{t, t_args};
use crate::protocol::offer::{CredentialOffer, PRE_AUTHORIZED_CODE_GRANT};
use crate::protocol::{encode_uri_component, is_http_url, Json};

use super::http;
use super::proof;

/// The credential the issuer returned, ready to seal.
pub struct Redeemed {
    pub format: String,
    pub issuer: String,
    pub document: String,
    /// Private JWK for the key the credential is bound to.
    pub holder_key: String,
}

/// Why redemption stopped. The message is already translated.
#[derive(Debug)]
pub struct RedeemError {
    message: String,
}

impl std::fmt::Display for RedeemError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for RedeemError {}

fn err(message: String) -> RedeemError {
    RedeemError { message }
}

/// What one HTTP call returned. Tests supply these instead of a live issuer.
pub struct Fetched {
    pub status: u16,
    pub body: String,
}

/// The calls redemption makes. The live issuer is [`LiveIssuer`].
pub trait IssuerHttp {
    fn get(&self, url: &str) -> Result<Fetched, RedeemError>;
    fn post(
        &self,
        url: &str,
        content_type: &str,
        authorization: Option<&str>,
        body: &str,
    ) -> Result<Fetched, RedeemError>;
}

/// Redeem `offer` at its issuer. `tx_code` is what the person typed. Pass
/// `None` only when the offer did not ask for one.
pub fn redeem_pre_authorized(
    offer: &CredentialOffer,
    tx_code: Option<&str>,
) -> Result<Redeemed, RedeemError> {
    redeem_with(offer, tx_code, &LiveIssuer, now_seconds())
}

pub(crate) fn redeem_with(
    offer: &CredentialOffer,
    tx_code: Option<&str>,
    http: &dyn IssuerHttp,
    now: u64,
) -> Result<Redeemed, RedeemError> {
    let grant = offer
        .grants
        .pre_authorized_code
        .as_ref()
        .ok_or_else(|| err(t("wallet.redeem.not_preauthorized")))?;
    let typed = checked_tx_code(grant.tx_code.as_ref(), tx_code)?;
    let issuer_metadata_url = well_known(&offer.credential_issuer, "openid-credential-issuer")?;
    let issuer_metadata = json_ok(
        &issuer_metadata_url,
        http.get(&issuer_metadata_url)?,
        "wallet.redeem.metadata",
    )?;
    let credential_issuer = required_string(&issuer_metadata, "credential_issuer")?;
    let credential_endpoint = required_http(&issuer_metadata, "credential_endpoint")?;
    let configuration = offer
        .credential_configuration_ids
        .first()
        .cloned()
        .ok_or_else(|| err(t("wallet.offer.configs_empty")))?;
    let format = configuration_format(&issuer_metadata, &configuration)?;
    let authorization_server = grant
        .authorization_server
        .clone()
        .or_else(|| first_string(issuer_metadata.get("authorization_servers")))
        .unwrap_or_else(|| credential_issuer.clone());
    if !is_http_url(&authorization_server) {
        return Err(err(t_args(
            "wallet.redeem.no_endpoint",
            &[("name", "authorization_servers")],
        )));
    }
    let as_metadata_url = well_known(&authorization_server, "oauth-authorization-server")?;
    let as_metadata = json_ok(
        &as_metadata_url,
        http.get(&as_metadata_url)?,
        "wallet.redeem.metadata",
    )?;
    let token_endpoint = required_http(&as_metadata, "token_endpoint")?;
    let mut form = format!(
        "grant_type={}&pre-authorized_code={}",
        encode_uri_component(PRE_AUTHORIZED_CODE_GRANT),
        encode_uri_component(&grant.pre_authorized_code)
    );
    if let Some(code) = &typed {
        form.push_str("&tx_code=");
        form.push_str(&encode_uri_component(code));
    }
    let token = json_ok(
        &token_endpoint,
        http.post(
            &token_endpoint,
            "application/x-www-form-urlencoded",
            None,
            &form,
        )?,
        "wallet.redeem.token",
    )?;
    let access_token = required_string(&token, "access_token")?;
    if access_token
        .bytes()
        .any(|byte| matches!(byte, b'\r' | b'\n' | 0))
    {
        return Err(err(t("wallet.redeem.bad_token")));
    }
    if let Some(token_type) = token.get("token_type").and_then(|value| value.as_str()) {
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(err(t_args(
                "wallet.redeem.token_type",
                &[("type", token_type)],
            )));
        }
    }
    let nonce = fetch_nonce(
        http,
        issuer_metadata.get("nonce_endpoint"),
        token.get("c_nonce"),
    )?;
    let identifier = granted_identifier(&token, &configuration)?;
    let proof = proof::sign_proof(&credential_issuer, &nonce, now);
    let mut body = Vec::new();
    if let Some(identifier) = identifier {
        body.push((
            "credential_identifier".to_string(),
            Json::String(identifier),
        ));
    } else {
        body.push((
            "credential_configuration_id".to_string(),
            Json::String(configuration),
        ));
    }
    body.push((
        "proofs".to_string(),
        Json::Object(vec![(
            "jwt".to_string(),
            Json::Array(vec![Json::String(proof.jwt)]),
        )]),
    ));
    let credential_http = http.post(
        &credential_endpoint,
        "application/json",
        Some(&access_token),
        &Json::Object(body).to_string(),
    )?;
    if credential_http.status == 202 {
        return Err(err(t("wallet.redeem.deferred")));
    }
    let credential_json = json_ok(
        &credential_endpoint,
        credential_http,
        "wallet.redeem.credential",
    )?;
    let document = credential_document(&credential_json)?;
    Ok(Redeemed {
        format,
        issuer: credential_issuer,
        document,
        holder_key: proof.private_jwk,
    })
}

fn checked_tx_code(
    spec: Option<&crate::protocol::offer::TxCode>,
    typed: Option<&str>,
) -> Result<Option<String>, RedeemError> {
    let Some(spec) = spec else {
        return Ok(None);
    };
    let code = typed.unwrap_or("").trim();
    if code.is_empty() {
        return Err(err(t("wallet.redeem.tx_required")));
    }
    if let Some(length) = spec.length {
        if code.chars().count() != length as usize {
            return Err(err(t_args(
                "wallet.redeem.tx_length",
                &[("length", &length.to_string())],
            )));
        }
    }
    let numeric = spec.input_mode.as_deref() != Some("text");
    if numeric && !code.chars().all(|ch| ch.is_ascii_digit()) {
        return Err(err(t("wallet.redeem.tx_numeric")));
    }
    Ok(Some(code.to_string()))
}

fn fetch_nonce(
    http: &dyn IssuerHttp,
    endpoint: Option<&Json>,
    token_nonce: Option<&Json>,
) -> Result<String, RedeemError> {
    if let Some(endpoint) = endpoint.and_then(|value| value.as_str()) {
        if !is_http_url(endpoint) {
            return Err(err(t_args(
                "wallet.redeem.no_endpoint",
                &[("name", "nonce_endpoint")],
            )));
        }
        let fetched = http.post(endpoint, "", None, "")?;
        let json = json_ok(endpoint, fetched, "wallet.redeem.nonce")?;
        return required_string(&json, "c_nonce");
    }
    match token_nonce.and_then(|value| value.as_str()) {
        Some(nonce) if !nonce.is_empty() => Ok(nonce.to_string()),
        _ => Err(err(t("wallet.redeem.no_nonce"))),
    }
}

fn granted_identifier(token: &Json, configuration: &str) -> Result<Option<String>, RedeemError> {
    let Some(details) = token
        .get("authorization_details")
        .and_then(|value| value.as_array())
    else {
        return Ok(None);
    };
    let mut any = false;
    for detail in details {
        let Some(identifiers) = detail
            .get("credential_identifiers")
            .and_then(|value| value.as_array())
        else {
            continue;
        };
        if identifiers.is_empty() {
            continue;
        }
        any = true;
        let named = detail
            .get("credential_configuration_id")
            .and_then(|value| value.as_str());
        if named == Some(configuration) {
            if let Some(identifier) = identifiers.first().and_then(|value| value.as_str()) {
                if !identifier.is_empty() {
                    return Ok(Some(identifier.to_string()));
                }
            }
        }
    }
    if any {
        return Err(err(t_args(
            "wallet.redeem.no_identifier",
            &[("configuration", configuration)],
        )));
    }
    Ok(None)
}

fn configuration_format(metadata: &Json, configuration: &str) -> Result<String, RedeemError> {
    let format = metadata
        .get("credential_configurations_supported")
        .and_then(|configs| configs.get(configuration))
        .and_then(|config| config.get("format"))
        .and_then(|format| format.as_str())
        .unwrap_or("");
    if format.is_empty() {
        return Err(err(t_args(
            "wallet.redeem.no_format",
            &[("configuration", configuration)],
        )));
    }
    Ok(format.to_string())
}

fn credential_document(body: &Json) -> Result<String, RedeemError> {
    if let Some(credentials) = body.get("credentials").and_then(|value| value.as_array()) {
        if let Some(first) = credentials.first() {
            if let Some(document) = first.get("credential").and_then(|value| value.as_str()) {
                if !document.is_empty() {
                    return Ok(document.to_string());
                }
            }
            if let Some(document) = first.as_str() {
                if !document.is_empty() {
                    return Ok(document.to_string());
                }
            }
        }
    }
    if let Some(document) = body.get("credential").and_then(|value| value.as_str()) {
        if !document.is_empty() {
            return Ok(document.to_string());
        }
    }
    Err(err(t("wallet.redeem.no_credential")))
}

fn json_ok(url: &str, fetched: Fetched, error_key: &str) -> Result<Json, RedeemError> {
    if !(200..300).contains(&fetched.status) {
        return Err(err(t_args(
            error_key,
            &[
                ("status", &fetched.status.to_string()),
                ("error", &oauth_error(&fetched.body)),
            ],
        )));
    }
    Json::parse(&fetched.body).map_err(|error| {
        err(t_args(
            "wallet.redeem.not_json",
            &[("url", url), ("error", &error.to_string())],
        ))
    })
}

fn oauth_error(body: &str) -> String {
    if let Ok(json) = Json::parse(body) {
        let code = json
            .get("error")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        let description = json
            .get("error_description")
            .and_then(|value| value.as_str())
            .unwrap_or("");
        if !code.is_empty() || !description.is_empty() {
            return match (code.is_empty(), description.is_empty()) {
                (false, false) => format!("{code}: {description}"),
                (false, true) => code.to_string(),
                _ => description.to_string(),
            };
        }
    }
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return t("wallet.redeem.empty");
    }
    trimmed.chars().take(300).collect()
}

fn required_string(json: &Json, name: &str) -> Result<String, RedeemError> {
    match json.get(name).and_then(|value| value.as_str()) {
        Some(value) if !value.is_empty() => Ok(value.to_string()),
        _ => Err(err(t_args("wallet.redeem.no_endpoint", &[("name", name)]))),
    }
}

fn required_http(json: &Json, name: &str) -> Result<String, RedeemError> {
    let value = required_string(json, name)?;
    if is_http_url(&value) {
        Ok(value)
    } else {
        Err(err(t_args("wallet.redeem.no_endpoint", &[("name", name)])))
    }
}

fn first_string(value: Option<&Json>) -> Option<String> {
    let array = value?.as_array()?;
    let text = array.first()?.as_str()?;
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// RFC 8414 and OpenID4VCI insert `/.well-known/{name}` before an issuer path.
pub(crate) fn well_known(issuer: &str, name: &str) -> Result<String, RedeemError> {
    if !is_http_url(issuer) {
        return Err(err(t_args("wallet.redeem.no_endpoint", &[("name", name)])));
    }
    let (scheme, rest) = issuer
        .split_once("://")
        .ok_or_else(|| err(t_args("wallet.redeem.no_endpoint", &[("name", name)])))?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], rest[index..].trim_matches('/')),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(err(t_args("wallet.redeem.no_endpoint", &[("name", name)])));
    }
    if path.is_empty() {
        Ok(format!("{scheme}://{authority}/.well-known/{name}"))
    } else {
        Ok(format!("{scheme}://{authority}/.well-known/{name}/{path}"))
    }
}

fn now_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// The issuer on the network.
pub struct LiveIssuer;

impl IssuerHttp for LiveIssuer {
    fn get(&self, url: &str) -> Result<Fetched, RedeemError> {
        call("GET", url, None, None, "")
    }

    fn post(
        &self,
        url: &str,
        content_type: &str,
        authorization: Option<&str>,
        body: &str,
    ) -> Result<Fetched, RedeemError> {
        let content_type = if content_type.is_empty() {
            None
        } else {
            Some(content_type)
        };
        call("POST", url, content_type, authorization, body)
    }
}

fn call(
    method: &str,
    url: &str,
    content_type: Option<&str>,
    authorization: Option<&str>,
    body: &str,
) -> Result<Fetched, RedeemError> {
    let response = http::exchange(method, url, content_type, authorization, body.as_bytes())
        .map_err(|error| {
            err(t_args(
                "wallet.redeem.http",
                &[("url", url), ("error", &error)],
            ))
        })?;
    let body = String::from_utf8(response.body).map_err(|_| {
        err(t_args(
            "wallet.redeem.not_json",
            &[("url", url), ("error", &t("wallet.redeem.not_utf8"))],
        ))
    })?;
    Ok(Fetched {
        status: response.status,
        body,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::offer::parse_offer_json;
    use std::sync::Mutex;

    struct Script {
        steps: Mutex<Vec<Fetched>>,
        seen: Mutex<Vec<(String, String, String, String)>>,
    }

    impl Script {
        fn new(steps: Vec<Fetched>) -> Self {
            Self {
                steps: Mutex::new(steps),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl IssuerHttp for Script {
        fn get(&self, url: &str) -> Result<Fetched, RedeemError> {
            self.seen.lock().unwrap().push((
                "GET".to_string(),
                url.to_string(),
                String::new(),
                String::new(),
            ));
            Ok(self.steps.lock().unwrap().remove(0))
        }

        fn post(
            &self,
            url: &str,
            content_type: &str,
            authorization: Option<&str>,
            body: &str,
        ) -> Result<Fetched, RedeemError> {
            self.seen.lock().unwrap().push((
                format!("POST {content_type}"),
                url.to_string(),
                body.to_string(),
                authorization.unwrap_or("").to_string(),
            ));
            Ok(self.steps.lock().unwrap().remove(0))
        }
    }

    fn offer() -> CredentialOffer {
        parse_offer_json(
            r#"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["IdentityCredential"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"code+/=","tx_code":{"input_mode":"numeric","length":5,"description":"Type the 5-digit code."}}}}"#,
        )
        .unwrap()
    }

    fn issuer_meta() -> String {
        r#"{"credential_issuer":"https://issuer.example","credential_endpoint":"https://issuer.example/oid4vci/credential","nonce_endpoint":"https://issuer.example/oid4vci/nonce","authorization_servers":["https://issuer.example"],"credential_configurations_supported":{"IdentityCredential":{"format":"dc+sd-jwt"}}}"#.to_string()
    }

    fn as_meta() -> String {
        r#"{"issuer":"https://issuer.example","token_endpoint":"https://issuer.example/oauth2/token"}"#.to_string()
    }

    #[test]
    fn a_transaction_code_redeems_and_the_proof_is_sent() {
        let script = Script::new(vec![
            Fetched {
                status: 200,
                body: issuer_meta(),
            },
            Fetched {
                status: 200,
                body: as_meta(),
            },
            Fetched {
                status: 200,
                body: r#"{"access_token":"access-1","token_type":"Bearer"}"#.to_string(),
            },
            Fetched {
                status: 200,
                body: r#"{"c_nonce":"nonce-9"}"#.to_string(),
            },
            Fetched {
                status: 200,
                body: r#"{"credentials":[{"credential":"header.payload.sig"}]}"#.to_string(),
            },
        ]);
        let redeemed = redeem_with(&offer(), Some("12345"), &script, 1_700_000_000).unwrap();
        assert_eq!(redeemed.format, "dc+sd-jwt");
        assert_eq!(redeemed.issuer, "https://issuer.example");
        assert_eq!(redeemed.document, "header.payload.sig");
        assert!(redeemed.holder_key.contains("\"d\""));
        let seen = script.seen.lock().unwrap();
        assert_eq!(
            seen[0].1,
            "https://issuer.example/.well-known/openid-credential-issuer"
        );
        assert_eq!(
            seen[1].1,
            "https://issuer.example/.well-known/oauth-authorization-server"
        );
        assert!(seen[2]
            .2
            .contains("grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Apre-authorized_code"));
        assert!(seen[2].2.contains("pre-authorized_code=code%2B%2F%3D"));
        assert!(seen[2].2.contains("tx_code=12345"));
        assert!(!seen[2].2.contains("client_id"));
        assert_eq!(seen[3].0, "POST ");
        assert!(seen[3].2.is_empty());
        assert!(seen[2].3.is_empty());
        assert_eq!(seen[4].3, "access-1");
        let request = Json::parse(&seen[4].2).unwrap();
        assert_eq!(
            request
                .get("credential_configuration_id")
                .and_then(|value| value.as_str()),
            Some("IdentityCredential")
        );
        let jwt = request
            .get("proofs")
            .unwrap()
            .get("jwt")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_str()
            .unwrap();
        assert_eq!(jwt.split('.').count(), 3);
        assert!(script.steps.lock().unwrap().is_empty());
    }

    #[test]
    fn a_short_code_does_not_call_the_issuer() {
        let script = Script::new(vec![]);
        let error = match redeem_with(&offer(), Some("12"), &script, 0) {
            Err(error) => error,
            Ok(_) => panic!("a short code must be refused before the issuer is called"),
        };
        assert!(error.message.contains('5'), "{}", error.message);
        assert!(script.seen.lock().unwrap().is_empty());
    }

    #[test]
    fn the_token_error_is_the_issuer_description() {
        let script = Script::new(vec![
            Fetched { status: 200, body: issuer_meta() },
            Fetched { status: 200, body: as_meta() },
            Fetched {
                status: 400,
                body: r#"{"error":"invalid_grant","error_description":"The Transaction Code is not correct."}"#.to_string(),
            },
        ]);
        let error = match redeem_with(&offer(), Some("00000"), &script, 0) {
            Err(error) => error,
            Ok(_) => panic!("the issuer error must be returned"),
        };
        assert!(error.message.contains("invalid_grant"), "{}", error.message);
        assert!(error.message.contains("not correct"), "{}", error.message);
    }

    #[test]
    fn a_granted_identifier_replaces_the_configuration_id() {
        let script = Script::new(vec![
            Fetched { status: 200, body: issuer_meta() },
            Fetched { status: 200, body: as_meta() },
            Fetched {
                status: 200,
                body: r#"{"access_token":"access-1","token_type":"bearer","authorization_details":[{"type":"openid_credential","credential_configuration_id":"IdentityCredential","credential_identifiers":["IdentityCredential:abc"]}]}"#.to_string(),
            },
            Fetched { status: 200, body: r#"{"c_nonce":"n"}"#.to_string() },
            Fetched { status: 200, body: r#"{"credential":"one"}"#.to_string() },
        ]);
        let redeemed = redeem_with(&offer(), Some("12345"), &script, 1).unwrap();
        assert_eq!(redeemed.document, "one");
        let body = Json::parse(&script.seen.lock().unwrap()[4].2).unwrap();
        assert!(body.get("credential_configuration_id").is_none());
        assert_eq!(
            body.get("credential_identifier")
                .and_then(|value| value.as_str()),
            Some("IdentityCredential:abc")
        );
    }

    #[test]
    fn a_deferred_credential_is_not_stored() {
        let script = Script::new(vec![
            Fetched {
                status: 200,
                body: issuer_meta(),
            },
            Fetched {
                status: 200,
                body: as_meta(),
            },
            Fetched {
                status: 200,
                body: r#"{"access_token":"access-1","token_type":"Bearer"}"#.to_string(),
            },
            Fetched {
                status: 200,
                body: r#"{"c_nonce":"n"}"#.to_string(),
            },
            Fetched {
                status: 202,
                body: r#"{"transaction_id":"later"}"#.to_string(),
            },
        ]);
        let error = match redeem_with(&offer(), Some("12345"), &script, 1) {
            Err(error) => error,
            Ok(_) => panic!("a deferred credential must not be stored"),
        };
        assert!(error.message.contains("later"), "{}", error.message);
    }

    #[test]
    fn an_issuer_path_is_inserted_after_well_known() {
        let url = well_known(
            "https://issuer.example/realm/acme",
            "oauth-authorization-server",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://issuer.example/.well-known/oauth-authorization-server/realm/acme"
        );
    }
}
