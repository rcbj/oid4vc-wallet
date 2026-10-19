//! A same-device OpenID4VP presentation.
//!
//! The verifier's same-device button is an `openid4vp://` URI whose request
//! is fetched from `request_uri` (OpenID4VP 1.0 section 5.10). The signed
//! Request Object is checked, a stored credential is selected for that
//! verifier, credential type, and claims, and the wallet posts the answer to
//! `response_uri` (section 8.2). `direct_post.jwt` encrypts that answer to
//! the request's ECDH-ES key (section 8.3.1, RFC 7518 section 4.6). The
//! verifier's `redirect_uri` is the page the browser is already waiting on.
//!
//! An offer by reference is not fetched here. A request whose `response_type`
//! contains `id_token` and not `vp_token` is answered with a self-issued ID
//! Token (SIOPv2 section 11). `vp_token id_token` sends both, signed by the
//! presented credential's holder key. `vp_token` alone is unchanged.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::SigningKey;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};

use crate::i18n::{t, t_args};
use crate::protocol::request::AuthorizationRequest;
use crate::protocol::{encode_uri_component, is_http_url, parse, Invocation, Json};

use super::b64;
use super::certs::{self, Chain, OwnedCert};
use super::http::RawResponse;
use super::jws::{self, IssuerJws};
use super::{Credential, NewCredential};

const WALLET_AUDIENCE: &str = "https://self-issued.me/v2";

/// What the window shows after a same-device presentation, and the page to open.
pub struct Presented {
    /// The stored credential that was selected, when one matched.
    pub credential_id: Option<String>,
    /// A self-issued credential to seal when this answer created its key.
    /// `None` when an existing key was reused or none was created.
    pub store: Option<NewCredential>,
    /// The verifier's `redirect_uri` when it names the same host.
    pub redirect_uri: Option<String>,
    /// A translated sentence for the banner.
    pub message: String,
    /// `true` when a presentation was accepted by the response endpoint.
    pub ok: bool,
}

fn refused(message: String) -> Box<Presented> {
    Box::new(Presented::bare(message))
}

impl Presented {
    fn bare(message: String) -> Self {
        Self {
            credential_id: None,
            store: None,
            redirect_uri: None,
            message,
            ok: false,
        }
    }
}

trait Transport {
    fn exchange(
        &self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<RawResponse, String>;
}

struct LiveHttp;

impl Transport for LiveHttp {
    fn exchange(
        &self,
        method: &str,
        url: &str,
        content_type: Option<&str>,
        body: &[u8],
    ) -> Result<RawResponse, String> {
        super::http::exchange(method, url, content_type, None, body)
    }
}

/// Fetch the request the desktop launched, present one matching credential,
/// and report the page the verifier asked the browser to open.
pub fn present_same_device(uri: &str, credentials: &[Credential]) -> Presented {
    present_with(uri, credentials, &LiveHttp, now_secs())
}

fn present_with<T: Transport>(
    uri: &str,
    credentials: &[Credential],
    http: &T,
    now: u64,
) -> Presented {
    let Some(request) = invocation_request(uri) else {
        return Presented::bare(t("wallet.present.unverified"));
    };
    let fetched = match fetch_jwt(http, &request) {
        Ok(fetched) => fetched,
        Err(done) => return *done,
    };
    let ready = match authorize(http, &request, &fetched, now) {
        Ok(ready) => ready,
        Err(done) => return *done,
    };
    if !ready.can_respond {
        return Presented::bare(t("wallet.present.unsupported"));
    }
    if ready.wants_id && !ready.wants_vp {
        return answer_self_issued(http, &ready, credentials, now);
    }
    if !ready.wants_vp {
        return respond(http, &ready, None, None, None, None, Answer::Unsupported);
    }
    let verifier_host = host_of(&ready.response_uri);
    match choose(&ready.dcql, credentials, verifier_host.as_deref()) {
        Some(choice) if choice.presentable => {
            let credential = &credentials[choice.index];
            let id_token = if ready.wants_id {
                id_token_for(credential, &ready, now)
            } else {
                None
            };
            if ready.wants_id && id_token.is_none() {
                return respond(
                    http,
                    &ready,
                    Some(credential.id.clone()),
                    None,
                    None,
                    None,
                    Answer::Cannot,
                );
            }
            match presentation_for(credential, &choice.query_id, &ready, now) {
                Some(vp) => respond(
                    http,
                    &ready,
                    Some(credential.id.clone()),
                    Some(vp),
                    id_token,
                    None,
                    Answer::Sent,
                ),
                None => respond(
                    http,
                    &ready,
                    Some(credential.id.clone()),
                    None,
                    None,
                    None,
                    Answer::Cannot,
                ),
            }
        }
        Some(choice) => respond(
            http,
            &ready,
            Some(credentials[choice.index].id.clone()),
            None,
            None,
            None,
            Answer::Cannot,
        ),
        None => respond(http, &ready, None, None, None, None, Answer::Declined),
    }
}

fn invocation_request(uri: &str) -> Option<AuthorizationRequest> {
    match parse(uri).ok()? {
        Invocation::Presentation(request)
            if request.request_uri.is_some() || request.request.is_some() =>
        {
            Some(*request)
        }
        _ => None,
    }
}

struct Fetched {
    jwt: String,
    peers: Vec<Vec<u8>>,
    request_host: Option<String>,
}

fn fetch_jwt<T: Transport>(
    http: &T,
    request: &AuthorizationRequest,
) -> Result<Fetched, Box<Presented>> {
    let Some(uri) = request.request_uri.as_deref() else {
        let jwt = request
            .request
            .clone()
            .ok_or_else(|| refused(t("wallet.present.unverified")))?;
        return Ok(Fetched {
            jwt,
            peers: Vec::new(),
            request_host: None,
        });
    };
    let post = request.request_uri_method.as_deref() == Some("post");
    let body = if post {
        format!("client_id={}", encode_uri_component(&request.client_id))
    } else {
        String::new()
    };
    let response = http
        .exchange(
            if post { "POST" } else { "GET" },
            uri,
            post.then_some("application/x-www-form-urlencoded"),
            body.as_bytes(),
        )
        .map_err(|err| {
            refused(t_args(
                "wallet.redeem.http",
                &[("url", uri), ("error", &err)],
            ))
        })?;
    if host_of(&response.final_url) != host_of(uri) {
        return Err(refused(t("wallet.present.unverified")));
    }
    if response.status != 200 {
        let status = response.status.to_string();
        return Err(refused(t_args(
            "wallet.present.http",
            &[("url", uri), ("status", &status)],
        )));
    }
    let text =
        String::from_utf8(response.body).map_err(|_| refused(t("wallet.present.unverified")))?;
    let jwt = text.trim().to_string();
    if jwt.is_empty() {
        return Err(refused(t("wallet.present.unverified")));
    }
    Ok(Fetched {
        jwt,
        peers: response.peer_certs,
        request_host: host_of(uri),
    })
}

struct Ready {
    client_id: String,
    nonce: String,
    state: String,
    response_uri: String,
    jwt_response: bool,
    dcql: Json,
    recipient: Option<Recipient>,
    enc: String,
    can_respond: bool,
    wants_vp: bool,
    wants_id: bool,
}

struct Recipient {
    kid: String,
    x: Vec<u8>,
    y: Vec<u8>,
}

fn authorize<T: Transport>(
    http: &T,
    outer: &AuthorizationRequest,
    fetched: &Fetched,
    now: u64,
) -> Result<Ready, Box<Presented>> {
    let unverified = || refused(t("wallet.present.unverified"));
    let jws = jws::open_issuer_jws("jwt", &fetched.jwt).map_err(|_| unverified())?;
    let header = jwt_json(&fetched.jwt, 0).ok_or_else(unverified)?;
    if header.get("typ").and_then(Json::as_str) != Some("oauth-authz-req+jwt")
        || header.get("crit").is_some()
    {
        return Err(unverified());
    }
    let payload = jwt_json(&fetched.jwt, 1).ok_or_else(unverified)?;
    let client_id = payload
        .get("iss")
        .and_then(Json::as_str)
        .ok_or_else(unverified)?;
    if client_id != outer.client_id
        || payload
            .get("client_id")
            .and_then(Json::as_str)
            .is_some_and(|value| value != client_id)
        || !audience_is_wallet(&payload)
    {
        return Err(unverified());
    }
    let exp = payload
        .get("exp")
        .and_then(Json::as_u64)
        .ok_or_else(unverified)?;
    if now >= exp {
        return Err(unverified());
    }
    if payload
        .get("iat")
        .and_then(Json::as_u64)
        .is_some_and(|iat| iat > now.saturating_add(300))
    {
        return Err(unverified());
    }
    let leaf = jws.x5c.first().ok_or_else(unverified)?;
    if !signature_ok(&jws) {
        return Err(unverified());
    }
    let response_uri = payload
        .get("response_uri")
        .and_then(Json::as_str)
        .filter(|uri| is_http_url(uri))
        .ok_or_else(unverified)?
        .to_string();
    if !client_binds(client_id, leaf, &response_uri) {
        return Err(unverified());
    }
    if fetched.request_host.as_deref() != host_of(&response_uri).as_deref()
        && fetched.request_host.is_some()
    {
        return Err(unverified());
    }
    let now_i64 = i64::try_from(now).unwrap_or(i64::MAX);
    if !anchored(http, &jws, &fetched.peers, now_i64) {
        return Err(unverified());
    }
    let nonce = required_token(&payload, "nonce").ok_or_else(unverified)?;
    let state = required_token(&payload, "state").ok_or_else(unverified)?;
    let response_type = payload
        .get("response_type")
        .and_then(Json::as_str)
        .unwrap_or("");
    let mode = payload
        .get("response_mode")
        .and_then(Json::as_str)
        .unwrap_or("");
    let metadata = payload
        .get("client_metadata")
        .cloned()
        .unwrap_or(Json::Null);
    let (recipient, enc) = encryption_key(&metadata);
    let jwt_response = mode == "direct_post.jwt";
    let direct = mode == "direct_post";
    let can_respond = direct || (jwt_response && recipient.is_some());
    let wants_vp = has_token(response_type, "vp_token");
    let wants_id = has_token(response_type, "id_token");
    let dcql = payload
        .get("dcql_query")
        .cloned()
        .filter(|value| value.as_object().is_some())
        .unwrap_or(Json::Object(Vec::new()));
    Ok(Ready {
        client_id: client_id.to_string(),
        nonce,
        state,
        response_uri,
        jwt_response,
        dcql,
        recipient,
        enc,
        can_respond,
        wants_vp,
        wants_id,
    })
}

fn signature_ok(jws: &IssuerJws) -> bool {
    let Some(der) = jws.x5c.first() else {
        return false;
    };
    let Some(cert) = OwnedCert::parse(der) else {
        return false;
    };
    jws::verifies(&jws.alg, &cert.key, &jws.signing_input, &jws.signature)
}

fn client_binds(client_id: &str, leaf: &[u8], response_uri: &str) -> bool {
    if let Some(hash) = client_id.strip_prefix("x509_hash:") {
        let digest = Sha256::digest(leaf);
        return !hash.is_empty() && hash == b64::b64url_encode(&digest);
    }
    if let Some(name) = client_id.strip_prefix("x509_san_dns:") {
        return !name.is_empty()
            && host_of(response_uri).as_deref() == Some(&name.to_ascii_lowercase())
            && san_has_dns(leaf, name);
    }
    false
}

fn san_has_dns(der: &[u8], name: &str) -> bool {
    let Ok((_, cert)) = x509_parser::parse_x509_certificate(der) else {
        return false;
    };
    let Ok(Some(san)) = cert.subject_alternative_name() else {
        return false;
    };
    san.value.general_names.iter().any(|general| {
        matches!(
            general,
            x509_parser::extensions::GeneralName::DNSName(dns)
                if dns.eq_ignore_ascii_case(name)
        )
    })
}

fn anchored<T: Transport>(http: &T, jws: &IssuerJws, peers: &[Vec<u8>], now: i64) -> bool {
    let peer_certs: Vec<OwnedCert> = peers
        .iter()
        .filter_map(|der| OwnedCert::parse(der))
        .collect();
    match certs::walk(&jws.x5c, now, |url| fetch_ders(http, url)) {
        Chain::Published { .. } => true,
        Chain::Incomplete(chain) => certs::tls_anchors(&chain, &peer_certs),
        Chain::Broken(_) => false,
    }
}

fn fetch_ders<T: Transport>(http: &T, url: &str) -> Option<Vec<Vec<u8>>> {
    let response = http.exchange("GET", url, None, &[]).ok()?;
    if response.status != 200 {
        return None;
    }
    let certs = certs::certificates_in(&response.body);
    if certs.is_empty() {
        None
    } else {
        Some(certs)
    }
}

fn audience_is_wallet(payload: &Json) -> bool {
    match payload.get("aud") {
        Some(Json::String(value)) => value == WALLET_AUDIENCE,
        Some(Json::Array(items)) => items
            .iter()
            .any(|item| item.as_str() == Some(WALLET_AUDIENCE)),
        _ => false,
    }
}

fn required_token(payload: &Json, name: &str) -> Option<String> {
    let value = payload.get(name).and_then(Json::as_str)?;
    if value.is_empty() || value.chars().any(char::is_whitespace) {
        None
    } else {
        Some(value.to_string())
    }
}

fn has_token(value: &str, token: &str) -> bool {
    value.split_whitespace().any(|one| one == token)
}

fn encryption_key(metadata: &Json) -> (Option<Recipient>, String) {
    let enc = content_enc(metadata);
    let Some(keys) = metadata
        .get("jwks")
        .and_then(|jwks| jwks.get("keys"))
        .and_then(Json::as_array)
    else {
        return (None, enc);
    };
    for key in keys {
        if key.get("alg").and_then(Json::as_str) != Some("ECDH-ES") {
            continue;
        }
        if key.get("kty").and_then(Json::as_str) != Some("EC")
            || key.get("crv").and_then(Json::as_str) != Some("P-256")
        {
            continue;
        }
        if key
            .get("use")
            .and_then(Json::as_str)
            .is_some_and(|use_| use_ != "enc")
        {
            continue;
        }
        let Some(kid) = key
            .get("kid")
            .and_then(Json::as_str)
            .filter(|kid| !kid.is_empty())
        else {
            continue;
        };
        let Some((x, y)) = coordinates(key) else {
            continue;
        };
        if x.len() == 32 && y.len() == 32 {
            return (
                Some(Recipient {
                    kid: kid.to_string(),
                    x,
                    y,
                }),
                enc,
            );
        }
    }
    (None, enc)
}

fn content_enc(metadata: &Json) -> String {
    let Some(items) = metadata
        .get("encrypted_response_enc_values_supported")
        .and_then(Json::as_array)
    else {
        return "A256GCM".to_string();
    };
    let names: Vec<&str> = items.iter().filter_map(Json::as_str).collect();
    if names.is_empty() || names.contains(&"A256GCM") {
        "A256GCM".to_string()
    } else if names.contains(&"A128GCM") {
        "A128GCM".to_string()
    } else {
        String::new()
    }
}

fn coordinates(jwk: &Json) -> Option<(Vec<u8>, Vec<u8>)> {
    let x = b64::b64_decode(jwk.get("x").and_then(Json::as_str)?)?;
    let y = b64::b64_decode(jwk.get("y").and_then(Json::as_str)?)?;
    Some((x, y))
}

struct Choice {
    index: usize,
    query_id: String,
    presentable: bool,
}

fn choose(dcql: &Json, credentials: &[Credential], verifier_host: Option<&str>) -> Option<Choice> {
    let queries = candidate_queries(dcql);
    let mut best: Option<Ranked> = None;
    for (index, credential) in credentials.iter().enumerate() {
        let Some(parsed) = sd_jwt(credential) else {
            continue;
        };
        for query in &queries {
            if !query_matches(credential, &parsed, query) {
                continue;
            }
            let presentable = holder_can_sign(&parsed.payload, credential.holder_key.as_deref());
            let host_match = verifier_host
                .is_some_and(|host| host_of(&credential.issuer).as_deref() == Some(host));
            let ranked = Ranked {
                presentable,
                host_match,
                received_at: credential.received_at.clone(),
                id: credential.id.clone(),
                choice: Choice {
                    index,
                    query_id: query.id.clone(),
                    presentable,
                },
            };
            if best.as_ref().is_none_or(|current| ranked.beats(current)) {
                best = Some(ranked);
            }
        }
    }
    best.map(|ranked| ranked.choice)
}

struct Ranked {
    presentable: bool,
    host_match: bool,
    received_at: String,
    id: String,
    choice: Choice,
}

impl Ranked {
    fn beats(&self, other: &Self) -> bool {
        (
            self.presentable,
            self.host_match,
            &self.received_at,
            &self.id,
        ) > (
            other.presentable,
            other.host_match,
            &other.received_at,
            &other.id,
        )
    }
}

struct Query {
    id: String,
    vcts: Option<Vec<String>>,
    claims: Vec<ClaimAsk>,
}

struct ClaimAsk {
    path: Vec<String>,
    usable: bool,
    values: Option<Vec<Json>>,
}

struct SdJwt {
    issuer: String,
    payload: Json,
    disclosures: Vec<Disclosure>,
}

struct Disclosure {
    name: String,
    value: Json,
}

fn candidate_queries(dcql: &Json) -> Vec<Query> {
    let Some(credentials) = dcql.get("credentials").and_then(Json::as_array) else {
        return Vec::new();
    };
    let allowed = allowed_ids(dcql, credentials);
    let mut queries = Vec::new();
    for credential in credentials {
        let Some(id) = credential.get("id").and_then(Json::as_str) else {
            continue;
        };
        if id.is_empty() || !allowed.iter().any(|one| one == id) {
            continue;
        }
        if !credential
            .get("format")
            .and_then(Json::as_str)
            .is_some_and(|format| format.eq_ignore_ascii_case("dc+sd-jwt"))
        {
            continue;
        }
        queries.push(Query {
            id: id.to_string(),
            vcts: vct_values(credential),
            claims: claim_asks(credential),
        });
    }
    queries
}

fn allowed_ids(dcql: &Json, credentials: &[Json]) -> Vec<String> {
    if let Some(sets) = dcql.get("credential_sets").and_then(Json::as_array) {
        let mut ids = Vec::new();
        for set in sets {
            let required = set
                .get("required")
                .and_then(|value| match value {
                    Json::Bool(flag) => Some(*flag),
                    _ => None,
                })
                .unwrap_or(true);
            if !required {
                continue;
            }
            let Some(options) = set.get("options").and_then(Json::as_array) else {
                continue;
            };
            for option in options {
                let Some(list) = option.as_array() else {
                    continue;
                };
                if list.len() == 1 {
                    if let Some(id) = list[0].as_str() {
                        if !id.is_empty() && !ids.iter().any(|one| one == id) {
                            ids.push(id.to_string());
                        }
                    }
                }
            }
        }
        return ids;
    }
    if credentials.len() == 1 {
        credentials
            .first()
            .and_then(|query| query.get("id"))
            .and_then(Json::as_str)
            .filter(|id| !id.is_empty())
            .map(|id| vec![id.to_string()])
            .unwrap_or_default()
    } else {
        Vec::new()
    }
}

fn vct_values(query: &Json) -> Option<Vec<String>> {
    let values = query.get("meta")?.get("vct_values")?.as_array()?;
    Some(
        values
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_string)
            .collect(),
    )
}

fn claim_asks(query: &Json) -> Vec<ClaimAsk> {
    let Some(items) = query.get("claims").and_then(Json::as_array) else {
        return Vec::new();
    };
    items
        .iter()
        .map(|claim| {
            let mut usable = true;
            let mut path = Vec::new();
            match claim.get("path").and_then(Json::as_array) {
                Some(segments) if !segments.is_empty() => {
                    for segment in segments {
                        match segment {
                            Json::String(name) if !name.is_empty() => path.push(name.clone()),
                            _ => usable = false,
                        }
                    }
                }
                _ => usable = false,
            }
            let values = claim
                .get("values")
                .and_then(Json::as_array)
                .map(|items| items.to_vec());
            ClaimAsk {
                path,
                usable,
                values,
            }
        })
        .collect()
}

fn query_matches(credential: &Credential, parsed: &SdJwt, query: &Query) -> bool {
    if !credential.format.eq_ignore_ascii_case("dc+sd-jwt") {
        return false;
    }
    if let Some(vcts) = &query.vcts {
        let vct = parsed
            .payload
            .get("vct")
            .and_then(Json::as_str)
            .unwrap_or("");
        if !vcts.iter().any(|one| one == vct) {
            return false;
        }
    }
    for claim in &query.claims {
        if !claim.usable {
            return false;
        }
        let Some(found) = walk_claim(&parsed.payload, &parsed.disclosures, &claim.path) else {
            return false;
        };
        if let Some(values) = &claim.values {
            if !values.iter().any(|value| json_same(&found, value)) {
                return false;
            }
        }
    }
    true
}

fn walk_claim(current: &Json, disclosures: &[Disclosure], path: &[String]) -> Option<Json> {
    if path.is_empty() {
        return Some(current.clone());
    }
    let name = &path[0];
    if let Some(child) = current.get(name) {
        if !matches!(child, Json::Null) {
            return walk_claim(child, disclosures, &path[1..]);
        }
    }
    for disclosure in disclosures {
        if &disclosure.name == name {
            return walk_claim(&disclosure.value, disclosures, &path[1..]);
        }
    }
    None
}

fn sd_jwt(credential: &Credential) -> Option<SdJwt> {
    let trimmed = credential.document.trim();
    let mut parts = trimmed.split('~');
    let issuer = parts.next().unwrap_or("").to_string();
    if issuer.split('.').count() != 3 {
        return None;
    }
    let payload = jwt_json(&issuer, 1)?;
    let mut disclosures = Vec::new();
    for part in parts {
        if part.is_empty() {
            continue;
        }
        let Some(bytes) = b64::b64_decode(part) else {
            continue;
        };
        let Ok(text) = std::str::from_utf8(&bytes) else {
            continue;
        };
        let Ok(value) = Json::parse(text) else {
            continue;
        };
        let Some(items) = value.as_array() else {
            continue;
        };
        if items.len() == 3 {
            if let Some(name) = items[1].as_str() {
                disclosures.push(Disclosure {
                    name: name.to_string(),
                    value: items[2].clone(),
                });
            }
        }
    }
    Some(SdJwt {
        issuer,
        payload,
        disclosures,
    })
}

fn holder_can_sign(payload: &Json, holder_key: Option<&str>) -> bool {
    let Some(holder) = holder_key.and_then(|text| Json::parse(text).ok()) else {
        return false;
    };
    let Some(cnf) = payload.get("cnf").and_then(|cnf| cnf.get("jwk")) else {
        return false;
    };
    let Some((left_x, left_y)) = coordinates(&holder) else {
        return false;
    };
    let Some((right_x, right_y)) = coordinates(cnf) else {
        return false;
    };
    left_x == right_x && left_y == right_y && holder_signing(&holder).is_some()
}

fn holder_signing(jwk: &Json) -> Option<SigningKey> {
    if jwk.get("kty").and_then(Json::as_str) != Some("EC")
        || jwk.get("crv").and_then(Json::as_str) != Some("P-256")
    {
        return None;
    }
    let d = b64::b64_decode(jwk.get("d").and_then(Json::as_str)?)?;
    if d.is_empty() || d.len() > 32 {
        return None;
    }
    let mut raw = [0u8; 32];
    raw[32 - d.len()..].copy_from_slice(&d);
    let field = p256::FieldBytes::from(raw);
    let secret = SecretKey::from_bytes(&field).ok()?;
    let bytes = secret.to_bytes();
    let signing = SigningKey::from_bytes(&bytes).ok()?;
    let point = signing.verifying_key().to_encoded_point(false);
    let (x, y) = coordinates(jwk)?;
    if point.x().map(|value| value.as_slice()) != Some(x.as_slice())
        || point.y().map(|value| value.as_slice()) != Some(y.as_slice())
    {
        return None;
    }
    Some(signing)
}

struct Vp {
    query_id: String,
    presentation: String,
}

fn presentation_for(
    credential: &Credential,
    query_id: &str,
    ready: &Ready,
    now: u64,
) -> Option<Vp> {
    let parsed = sd_jwt(credential)?;
    let holder = Json::parse(credential.holder_key.as_deref()?).ok()?;
    let signing = holder_signing(&holder)?;
    let disclosed = format!("{}~", parsed.issuer);
    let digest = Sha256::digest(disclosed.as_bytes());
    let sd_hash = b64::b64url_encode(&digest);
    let header = object(&[
        ("alg", Json::String("ES256".to_string())),
        ("typ", Json::String("kb+jwt".to_string())),
    ]);
    let payload = object(&[
        ("iat", Json::Number(now.to_string())),
        ("aud", Json::String(ready.client_id.clone())),
        ("nonce", Json::String(ready.nonce.clone())),
        ("sd_hash", Json::String(sd_hash)),
    ]);
    let kb = sign_compact(&signing, &header, &payload);
    Some(Vp {
        query_id: query_id.to_string(),
        presentation: format!("{disclosed}{kb}"),
    })
}

const THUMBPRINT_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

fn answer_self_issued<T: Transport>(
    http: &T,
    ready: &Ready,
    credentials: &[Credential],
    now: u64,
) -> Presented {
    if let Some(index) = newest_self_issued(credentials) {
        let credential = &credentials[index];
        let Some(id_token) = id_token_for(credential, ready, now) else {
            return respond(
                http,
                ready,
                Some(credential.id.clone()),
                None,
                None,
                None,
                Answer::Cannot,
            );
        };
        return respond(
            http,
            ready,
            Some(credential.id.clone()),
            None,
            Some(id_token),
            None,
            Answer::SiopSent,
        );
    }
    let Some(minted) = mint_self_issued(ready, now) else {
        return Presented::bare(t("wallet.present.unsupported"));
    };
    respond(
        http,
        ready,
        None,
        None,
        Some(minted.id_token),
        Some(minted.store),
        Answer::SiopCreated,
    )
}

/// The newest stored credential whose holder key is P-256 and whose SD-JWT
/// `iss` and `sub` are that key's RFC 7638 thumbprint URI.
fn newest_self_issued(credentials: &[Credential]) -> Option<usize> {
    let mut best: Option<(usize, &str, &str)> = None;
    for (index, credential) in credentials.iter().enumerate() {
        if self_issued_subject(credential).is_none() {
            continue;
        }
        let at = credential.received_at.as_str();
        let id = credential.id.as_str();
        let replace = match best {
            None => true,
            Some((_, best_at, best_id)) => (at, id) > (best_at, best_id),
        };
        if replace {
            best = Some((index, at, id));
        }
    }
    best.map(|(index, _, _)| index)
}

fn self_issued_subject(credential: &Credential) -> Option<String> {
    let holder = Json::parse(credential.holder_key.as_deref()?).ok()?;
    let signing = holder_signing(&holder)?;
    let (x, y) = encoded_xy(&signing)?;
    let subject = thumbprint_uri(&x, &y);
    let parsed = sd_jwt(credential)?;
    let iss = parsed.payload.get("iss").and_then(Json::as_str)?;
    let sub = parsed.payload.get("sub").and_then(Json::as_str)?;
    if iss == subject && sub == subject {
        Some(subject)
    } else {
        None
    }
}

fn thumbprint_uri(x: &str, y: &str) -> String {
    // RFC 7638: required members, lexicographic order, no whitespace.
    let canonical = format!(r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#);
    let digest = Sha256::digest(canonical.as_bytes());
    format!("{THUMBPRINT_PREFIX}{}", b64::b64url_encode(&digest))
}

fn public_jwk(x: &str, y: &str) -> Json {
    object(&[
        ("kty", Json::String("EC".to_string())),
        ("crv", Json::String("P-256".to_string())),
        ("x", Json::String(x.to_string())),
        ("y", Json::String(y.to_string())),
    ])
}

fn encoded_xy(signing: &SigningKey) -> Option<(String, String)> {
    let point = signing.verifying_key().to_encoded_point(false);
    Some((
        b64::b64url_encode(point.x()?.as_slice()),
        b64::b64url_encode(point.y()?.as_slice()),
    ))
}

fn private_jwk(signing: &SigningKey) -> Option<String> {
    let (x, y) = encoded_xy(signing)?;
    let d = b64::b64url_encode(signing.to_bytes().as_slice());
    Some(
        object(&[
            ("kty", Json::String("EC".to_string())),
            ("crv", Json::String("P-256".to_string())),
            ("x", Json::String(x)),
            ("y", Json::String(y)),
            ("d", Json::String(d)),
        ])
        .to_string(),
    )
}

fn sign_compact(signing: &SigningKey, header: &Json, payload: &Json) -> String {
    let signing_input = format!(
        "{}.{}",
        b64::b64url_encode(header.to_string().as_bytes()),
        b64::b64url_encode(payload.to_string().as_bytes())
    );
    let signature: p256::ecdsa::Signature = signing.sign(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        b64::b64url_encode(signature.to_bytes().as_slice())
    )
}

fn id_token_for(credential: &Credential, ready: &Ready, now: u64) -> Option<String> {
    let holder = Json::parse(credential.holder_key.as_deref()?).ok()?;
    let signing = holder_signing(&holder)?;
    id_token_from(&signing, ready, now)
}

fn id_token_from(signing: &SigningKey, ready: &Ready, now: u64) -> Option<String> {
    let (x, y) = encoded_xy(signing)?;
    let subject = thumbprint_uri(&x, &y);
    let header = object(&[
        ("alg", Json::String("ES256".to_string())),
        ("typ", Json::String("JWT".to_string())),
    ]);
    let payload = object(&[
        ("iss", Json::String(subject.clone())),
        ("sub", Json::String(subject)),
        ("sub_jwk", public_jwk(&x, &y)),
        ("aud", Json::String(ready.client_id.clone())),
        ("nonce", Json::String(ready.nonce.clone())),
        ("iat", Json::Number(now.to_string())),
        ("exp", Json::Number(now.saturating_add(600).to_string())),
    ]);
    Some(sign_compact(signing, &header, &payload))
}

struct Minted {
    id_token: String,
    store: NewCredential,
}

fn mint_self_issued(ready: &Ready, now: u64) -> Option<Minted> {
    let signing = SigningKey::random(&mut OsRng);
    let (x, y) = encoded_xy(&signing)?;
    let subject = thumbprint_uri(&x, &y);
    let header = object(&[
        ("alg", Json::String("ES256".to_string())),
        ("typ", Json::String("dc+sd-jwt".to_string())),
    ]);
    let payload = object(&[
        ("iss", Json::String(subject.clone())),
        ("sub", Json::String(subject.clone())),
        (
            "vct",
            Json::String("urn:idptools:sd-jwt-vc:identity".to_string()),
        ),
        ("cnf", object(&[("jwk", public_jwk(&x, &y))])),
        ("iat", Json::Number(now.to_string())),
    ]);
    let document = format!("{}~", sign_compact(&signing, &header, &payload));
    let holder_key = private_jwk(&signing)?;
    let id_token = id_token_from(&signing, ready, now)?;
    Some(Minted {
        id_token,
        store: NewCredential {
            format: "dc+sd-jwt".to_string(),
            issuer: subject,
            document,
            holder_key: Some(holder_key),
        },
    })
}

enum Answer {
    Sent,
    Declined,
    Cannot,
    Unsupported,
    SiopCreated,
    SiopSent,
}

enum Page {
    Open(String),
    Elsewhere,
    Nowhere,
}

fn respond<T: Transport>(
    http: &T,
    ready: &Ready,
    credential_id: Option<String>,
    vp: Option<Vp>,
    id_token: Option<String>,
    store: Option<NewCredential>,
    answer: Answer,
) -> Presented {
    let page = match post_response(http, ready, vp.as_ref(), id_token.as_deref()) {
        Ok(page) => page,
        Err(message) => {
            return Presented {
                credential_id,
                store,
                redirect_uri: None,
                message,
                ok: false,
            }
        }
    };
    narrate(answer, credential_id, page, store)
}

fn post_response<T: Transport>(
    http: &T,
    ready: &Ready,
    vp: Option<&Vp>,
    id_token: Option<&str>,
) -> Result<Page, String> {
    let response = if ready.jwt_response {
        let recipient = ready
            .recipient
            .as_ref()
            .ok_or_else(|| t("wallet.present.unsupported"))?;
        if ready.enc != "A256GCM" && ready.enc != "A128GCM" {
            return Err(t("wallet.present.unsupported"));
        }
        let plaintext = response_json(ready, vp, id_token).to_string();
        let compact = encrypt_ecdh_es(plaintext.as_bytes(), recipient, &ready.enc)
            .ok_or_else(|| t("wallet.present.unsupported"))?;
        post_form(http, &ready.response_uri, &[("response", compact.as_str())])?
    } else {
        let vp_body = vp.map(|one| vp_token_json(one).to_string());
        let mut fields: Vec<(&str, &str)> = Vec::new();
        if let Some(token) = vp_body.as_deref() {
            fields.push(("vp_token", token));
        }
        if let Some(token) = id_token {
            fields.push(("id_token", token));
        }
        if vp_body.is_none() && id_token.is_none() {
            fields.push(("error", "access_denied"));
        }
        fields.push(("state", ready.state.as_str()));
        post_form(http, &ready.response_uri, &fields)?
    };
    if response.status != 200 {
        let status = response.status.to_string();
        return Err(t_args(
            "wallet.present.http",
            &[("url", ready.response_uri.as_str()), ("status", &status)],
        ));
    }
    Ok(page_from(&response.body, &ready.response_uri))
}

fn response_json(ready: &Ready, vp: Option<&Vp>, id_token: Option<&str>) -> Json {
    let mut members = Vec::new();
    if let Some(vp) = vp {
        members.push(("vp_token".to_string(), vp_token_json(vp)));
    }
    if let Some(token) = id_token {
        members.push(("id_token".to_string(), Json::String(token.to_string())));
    }
    if vp.is_none() && id_token.is_none() {
        members.push((
            "error".to_string(),
            Json::String("access_denied".to_string()),
        ));
    }
    members.push(("state".to_string(), Json::String(ready.state.clone())));
    Json::Object(members)
}

fn vp_token_json(vp: &Vp) -> Json {
    object(&[(
        vp.query_id.as_str(),
        Json::Array(vec![Json::String(vp.presentation.clone())]),
    )])
}

fn post_form<T: Transport>(
    http: &T,
    url: &str,
    fields: &[(&str, &str)],
) -> Result<RawResponse, String> {
    let mut body = String::new();
    for (index, (name, value)) in fields.iter().enumerate() {
        if index > 0 {
            body.push('&');
        }
        body.push_str(&encode_uri_component(name));
        body.push('=');
        body.push_str(&encode_uri_component(value));
    }
    http.exchange(
        "POST",
        url,
        Some("application/x-www-form-urlencoded"),
        body.as_bytes(),
    )
    .map_err(|err| t_args("wallet.redeem.http", &[("url", url), ("error", &err)]))
}

fn page_from(body: &[u8], response_uri: &str) -> Page {
    let Ok(text) = std::str::from_utf8(body) else {
        return Page::Nowhere;
    };
    let Ok(json) = Json::parse(text.trim()) else {
        return Page::Nowhere;
    };
    let Some(redirect) = json.get("redirect_uri").and_then(Json::as_str) else {
        return Page::Nowhere;
    };
    if !is_http_url(redirect) {
        return Page::Nowhere;
    }
    if host_of(redirect) == host_of(response_uri) {
        Page::Open(redirect.to_string())
    } else {
        Page::Elsewhere
    }
}

fn narrate(
    answer: Answer,
    credential_id: Option<String>,
    page: Page,
    store: Option<NewCredential>,
) -> Presented {
    let created = store.as_ref().map(|item| item.issuer.clone());
    let id = match &answer {
        Answer::SiopCreated => created.as_deref().unwrap_or(""),
        _ => credential_id.as_deref().unwrap_or(""),
    };
    let message = match (&answer, &page) {
        (Answer::Sent, Page::Open(_)) => t_args("wallet.present.ok", &[("id", id)]),
        (Answer::Sent, Page::Elsewhere) => t_args("wallet.present.redirect_other", &[("id", id)]),
        (Answer::Sent, Page::Nowhere) => t_args("wallet.present.ok_no_page", &[("id", id)]),
        (Answer::Declined, Page::Open(_)) => t("wallet.present.declined"),
        (Answer::Declined, _) => t("wallet.present.declined_no_page"),
        (Answer::Cannot, Page::Open(_)) => t("wallet.present.cannot"),
        (Answer::Cannot, _) => t("wallet.present.cannot_no_page"),
        (Answer::Unsupported, _) => t("wallet.present.unsupported"),
        (Answer::SiopCreated, Page::Open(_)) => {
            t_args("wallet.present.siop_created", &[("id", id)])
        }
        (Answer::SiopCreated, _) => t_args("wallet.present.siop_created_no_page", &[("id", id)]),
        (Answer::SiopSent, Page::Open(_)) => t_args("wallet.present.siop_sent", &[("id", id)]),
        (Answer::SiopSent, _) => t_args("wallet.present.siop_sent_no_page", &[("id", id)]),
    };
    let redirect_uri = match page {
        Page::Open(url) => Some(url),
        Page::Elsewhere | Page::Nowhere => None,
    };
    Presented {
        credential_id,
        store,
        redirect_uri,
        message,
        ok: matches!(
            answer,
            Answer::Sent | Answer::SiopCreated | Answer::SiopSent
        ),
    }
}

fn encrypt_ecdh_es(plaintext: &[u8], recipient: &Recipient, enc: &str) -> Option<String> {
    let mut sec1 = vec![0x04];
    sec1.extend_from_slice(&recipient.x);
    sec1.extend_from_slice(&recipient.y);
    let public = PublicKey::from_sec1_bytes(&sec1).ok()?;
    let ephemeral = p256::ecdh::EphemeralSecret::random(&mut OsRng);
    let shared = ephemeral.diffie_hellman(&public);
    let point = ephemeral.public_key().to_encoded_point(false);
    let x = b64::b64url_encode(point.x()?.as_slice());
    let y = b64::b64url_encode(point.y()?.as_slice());
    let key_len = match enc {
        "A256GCM" => 32,
        "A128GCM" => 16,
        _ => return None,
    };
    let cek = concat_kdf(shared.raw_secret_bytes(), key_len, enc.as_bytes(), &[], &[]);
    let header = object(&[
        ("alg", Json::String("ECDH-ES".to_string())),
        ("enc", Json::String(enc.to_string())),
        ("typ", Json::String("JWT".to_string())),
        ("kid", Json::String(recipient.kid.clone())),
        (
            "epk",
            object(&[
                ("kty", Json::String("EC".to_string())),
                ("crv", Json::String("P-256".to_string())),
                ("x", Json::String(x)),
                ("y", Json::String(y)),
            ]),
        ),
    ]);
    let header_b64 = b64::b64url_encode(header.to_string().as_bytes());
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let sealed = seal_gcm(enc, &cek, &iv, header_b64.as_bytes(), plaintext)?;
    let (ciphertext, tag) = sealed.split_at(sealed.len().checked_sub(16)?);
    Some(format!(
        "{header_b64}..{}.{}.{}",
        b64::b64url_encode(&iv),
        b64::b64url_encode(ciphertext),
        b64::b64url_encode(tag)
    ))
}

fn seal_gcm(enc: &str, cek: &[u8], iv: &[u8], aad: &[u8], plaintext: &[u8]) -> Option<Vec<u8>> {
    let nonce = Nonce::from_slice(iv);
    let payload = Payload {
        msg: plaintext,
        aad,
    };
    match enc {
        "A256GCM" => Aes256Gcm::new_from_slice(cek)
            .ok()?
            .encrypt(nonce, payload)
            .ok(),
        "A128GCM" => Aes128Gcm::new_from_slice(cek)
            .ok()?
            .encrypt(nonce, payload)
            .ok(),
        _ => None,
    }
}

fn concat_kdf(z: &[u8], key_bytes: usize, alg_id: &[u8], apu: &[u8], apv: &[u8]) -> Vec<u8> {
    let mut info = Vec::new();
    info.extend_from_slice(&(alg_id.len() as u32).to_be_bytes());
    info.extend_from_slice(alg_id);
    info.extend_from_slice(&(apu.len() as u32).to_be_bytes());
    info.extend_from_slice(apu);
    info.extend_from_slice(&(apv.len() as u32).to_be_bytes());
    info.extend_from_slice(apv);
    info.extend_from_slice(&((key_bytes as u32).saturating_mul(8)).to_be_bytes());
    let rounds = key_bytes.div_ceil(32);
    let mut out = Vec::with_capacity(rounds * 32);
    for counter in 1..=rounds {
        let mut hasher = Sha256::new();
        hasher.update((counter as u32).to_be_bytes());
        hasher.update(z);
        hasher.update(&info);
        out.extend_from_slice(&hasher.finalize());
    }
    out.truncate(key_bytes);
    out
}

fn object(members: &[(&str, Json)]) -> Json {
    Json::Object(
        members
            .iter()
            .map(|(name, value)| ((*name).to_string(), value.clone()))
            .collect(),
    )
}

fn jwt_json(compact: &str, index: usize) -> Option<Json> {
    let part = compact.split('.').nth(index)?;
    let bytes = b64::b64_decode(part)?;
    Json::parse(std::str::from_utf8(&bytes).ok()?).ok()
}

fn host_of(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let authority = authority.rsplit('@').next().unwrap_or(authority);
    if authority.is_empty() {
        return None;
    }
    let host = if let Some(inner) = authority.strip_prefix('[') {
        inner.split(']').next()?
    } else {
        authority.split(':').next()?
    };
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn json_same(left: &Json, right: &Json) -> bool {
    match (left, right) {
        (Json::Null, Json::Null) => true,
        (Json::Bool(left), Json::Bool(right)) => left == right,
        (Json::Number(left), Json::Number(right)) => left == right,
        (Json::String(left), Json::String(right)) => left == right,
        (Json::Array(left), Json::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(one, other)| json_same(one, other))
        }
        (Json::Object(left), Json::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(name, value)| {
                    right
                        .iter()
                        .any(|(other, other_value)| other == name && json_same(value, other_value))
                })
        }
        _ => false,
    }
}

#[cfg(test)]
fn open_ecdh_es(compact: &str, secret: &SecretKey) -> Option<Vec<u8>> {
    let mut parts = compact.split('.');
    let header_b64 = parts.next()?;
    let encrypted_key = parts.next()?;
    let iv_b64 = parts.next()?;
    let ciphertext_b64 = parts.next()?;
    let tag_b64 = parts.next()?;
    if parts.next().is_some() || !encrypted_key.is_empty() {
        return None;
    }
    let header_bytes = b64::b64_decode(header_b64)?;
    let header = Json::parse(std::str::from_utf8(&header_bytes).ok()?).ok()?;
    if header.get("alg").and_then(Json::as_str) != Some("ECDH-ES") {
        return None;
    }
    let enc = header.get("enc").and_then(Json::as_str)?.to_string();
    let (x, y) = coordinates(header.get("epk")?)?;
    let mut sec1 = vec![0x04];
    sec1.extend(x);
    sec1.extend(y);
    let public = PublicKey::from_sec1_bytes(&sec1).ok()?;
    let shared = p256::ecdh::diffie_hellman(secret.to_nonzero_scalar(), public.as_affine());
    let key_len = match enc.as_str() {
        "A256GCM" => 32,
        "A128GCM" => 16,
        _ => return None,
    };
    let apu = party(&header, "apu")?;
    let apv = party(&header, "apv")?;
    let cek = concat_kdf(
        shared.raw_secret_bytes(),
        key_len,
        enc.as_bytes(),
        &apu,
        &apv,
    );
    let iv = b64::b64_decode(iv_b64)?;
    let mut sealed = b64::b64_decode(ciphertext_b64)?;
    sealed.extend(b64::b64_decode(tag_b64)?);
    open_gcm(&enc, &cek, &iv, header_b64.as_bytes(), &sealed)
}

#[cfg(test)]
fn party(header: &Json, name: &str) -> Option<Vec<u8>> {
    match header.get(name).and_then(Json::as_str) {
        Some(text) if !text.is_empty() => b64::b64_decode(text),
        _ => Some(Vec::new()),
    }
}

#[cfg(test)]
fn open_gcm(enc: &str, cek: &[u8], iv: &[u8], aad: &[u8], sealed: &[u8]) -> Option<Vec<u8>> {
    if iv.len() != 12 {
        return None;
    }
    let nonce = Nonce::from_slice(iv);
    let payload = Payload { msg: sealed, aad };
    match enc {
        "A256GCM" => Aes256Gcm::new_from_slice(cek)
            .ok()?
            .decrypt(nonce, payload)
            .ok(),
        "A128GCM" => Aes128Gcm::new_from_slice(cek)
            .ok()?
            .decrypt(nonce, payload)
            .ok(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::sync::Mutex;

    use p256::ecdsa::signature::{Signer, Verifier};
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };

    struct Script {
        gets: HashMap<String, RawResponse>,
        posts: Mutex<Vec<(String, String)>>,
        post_status: u16,
        post_body: Vec<u8>,
    }

    impl Transport for Script {
        fn exchange(
            &self,
            method: &str,
            url: &str,
            _content_type: Option<&str>,
            body: &[u8],
        ) -> Result<RawResponse, String> {
            if method.eq_ignore_ascii_case("POST") {
                self.posts
                    .lock()
                    .expect("posts")
                    .push((url.to_string(), String::from_utf8_lossy(body).into_owned()));
                return Ok(RawResponse {
                    status: self.post_status,
                    body: self.post_body.clone(),
                    peer_certs: Vec::new(),
                    final_url: url.to_string(),
                });
            }
            self.gets
                .get(url)
                .cloned()
                .ok_or_else(|| format!("no route {url}"))
        }
    }

    struct Fixture {
        script: Script,
        uri: String,
        recipient: SecretKey,
        holder_secret: String,
        client_id: String,
        nonce: String,
        same: Credential,
        other: Credential,
    }

    fn fixture(mode: &str, aia: bool) -> Fixture {
        fixture_request(mode, aia, "vp_token", "openid4vp")
    }

    fn fixture_request(mode: &str, aia: bool, response_type: &str, scheme: &str) -> Fixture {
        let now = now_secs();
        let (ca_key, ca_params, ca_cert) = ca("Verifier Root");
        let aia_url = "https://verifier.example/ca.cer";
        let (leaf_key, leaf_cert) = leaf("Verifier", &ca_params, &ca_key, aia.then_some(aia_url));
        let leaf_der = leaf_cert.der().to_vec();
        let signer = signer_of(&leaf_key);
        let client_id = format!(
            "x509_hash:{}",
            b64::b64url_encode(&Sha256::digest(&leaf_der))
        );
        let recipient = SecretKey::random(&mut OsRng);
        let recipient_point = recipient.public_key().to_encoded_point(false);
        let holder = SigningKey::random(&mut OsRng);
        let holder_point = holder.verifying_key().to_encoded_point(false);
        let holder_d = b64::b64url_encode(holder.to_bytes().as_slice());
        let dcql = sign_in_query();
        let payload = object(&[
            ("iss", Json::String(client_id.clone())),
            ("aud", Json::String(WALLET_AUDIENCE.to_string())),
            ("iat", Json::Number(now.to_string())),
            ("exp", Json::Number((now + 600).to_string())),
            ("client_id", Json::String(client_id.clone())),
            ("response_type", Json::String(response_type.to_string())),
            ("response_mode", Json::String(mode.to_string())),
            (
                "response_uri",
                Json::String("https://verifier.example/oid4vp/response".to_string()),
            ),
            ("nonce", Json::String("nonce-1".to_string())),
            ("state", Json::String("state-1".to_string())),
            ("dcql_query", dcql),
            (
                "client_metadata",
                object(&[
                    (
                        "jwks",
                        object(&[(
                            "keys",
                            Json::Array(vec![object(&[
                                ("kty", Json::String("EC".to_string())),
                                ("crv", Json::String("P-256".to_string())),
                                ("use", Json::String("enc".to_string())),
                                ("alg", Json::String("ECDH-ES".to_string())),
                                ("kid", Json::String("dpj-state-1".to_string())),
                                (
                                    "x",
                                    Json::String(b64::b64url_encode(
                                        recipient_point.x().unwrap().as_slice(),
                                    )),
                                ),
                                (
                                    "y",
                                    Json::String(b64::b64url_encode(
                                        recipient_point.y().unwrap().as_slice(),
                                    )),
                                ),
                            ])]),
                        )]),
                    ),
                    (
                        "encrypted_response_enc_values_supported",
                        Json::Array(vec![
                            Json::String("A128GCM".to_string()),
                            Json::String("A256GCM".to_string()),
                        ]),
                    ),
                ]),
            ),
        ]);
        let jwt = signed_jwt(&signer, &leaf_der, &payload.to_string());
        let request_uri = "https://verifier.example/oid4vp/request/1";
        let mut gets = HashMap::new();
        let peers = if aia {
            Vec::new()
        } else {
            vec![leaf_der.clone()]
        };
        gets.insert(
            request_uri.to_string(),
            http(request_uri, 200, jwt.as_bytes(), peers),
        );
        if aia {
            gets.insert(
                aia_url.to_string(),
                http(aia_url, 200, ca_cert.der().as_ref(), Vec::new()),
            );
        }
        let holder_secret = object(&[
            ("kty", Json::String("EC".to_string())),
            ("crv", Json::String("P-256".to_string())),
            (
                "x",
                Json::String(b64::b64url_encode(holder_point.x().unwrap().as_slice())),
            ),
            (
                "y",
                Json::String(b64::b64url_encode(holder_point.y().unwrap().as_slice())),
            ),
            ("d", Json::String(holder_d.clone())),
        ])
        .to_string();
        let same_doc = sd_document(&holder, "https://verifier.example", "same-host");
        let other_holder = SigningKey::random(&mut OsRng);
        let other_doc = sd_document(&other_holder, "https://other.example", "other-host");
        let other_point = other_holder.verifying_key().to_encoded_point(false);
        let other_secret = object(&[
            ("kty", Json::String("EC".to_string())),
            ("crv", Json::String("P-256".to_string())),
            (
                "x",
                Json::String(b64::b64url_encode(other_point.x().unwrap().as_slice())),
            ),
            (
                "y",
                Json::String(b64::b64url_encode(other_point.y().unwrap().as_slice())),
            ),
            (
                "d",
                Json::String(b64::b64url_encode(other_holder.to_bytes().as_slice())),
            ),
        ])
        .to_string();
        let redirect = br#"{"redirect_uri":"https://verifier.example/authn/wallet/wait?authn=1&state=state-1&response_code=code-1"}"#;
        Fixture {
            script: Script {
                gets,
                posts: Mutex::new(Vec::new()),
                post_status: 200,
                post_body: redirect.to_vec(),
            },
            uri: format!(
                "{scheme}://?client_id={}&request_uri={}&request_uri_method=get",
                encode_uri_component(&client_id),
                encode_uri_component(request_uri)
            ),
            recipient,
            holder_secret: holder_d,
            client_id,
            nonce: "nonce-1".to_string(),
            same: credential(
                "cred-same",
                "https://verifier.example",
                "20261018T120000.000Z",
                same_doc,
                holder_secret,
            ),
            other: credential(
                "cred-other",
                "https://other.example",
                "20261018T180000.000Z",
                other_doc,
                other_secret,
            ),
        }
    }

    fn sign_in_query() -> Json {
        object(&[
            (
                "credentials",
                Json::Array(vec![object(&[
                    ("id", Json::String("identity_credential".to_string())),
                    ("format", Json::String("dc+sd-jwt".to_string())),
                    (
                        "meta",
                        object(&[(
                            "vct_values",
                            Json::Array(vec![Json::String(
                                "urn:idptools:sd-jwt-vc:identity".to_string(),
                            )]),
                        )]),
                    ),
                    (
                        "claims",
                        Json::Array(vec![object(&[(
                            "path",
                            Json::Array(vec![Json::String("sub".to_string())]),
                        )])]),
                    ),
                ])]),
            ),
            (
                "credential_sets",
                Json::Array(vec![object(&[
                    (
                        "options",
                        Json::Array(vec![Json::Array(vec![Json::String(
                            "identity_credential".to_string(),
                        )])]),
                    ),
                    ("required", Json::Bool(true)),
                ])]),
            ),
        ])
    }

    fn sd_document(holder: &SigningKey, issuer: &str, sub: &str) -> String {
        let point = holder.verifying_key().to_encoded_point(false);
        let payload = object(&[
            ("iss", Json::String(issuer.to_string())),
            (
                "vct",
                Json::String("urn:idptools:sd-jwt-vc:identity".to_string()),
            ),
            ("sub", Json::String(sub.to_string())),
            (
                "cnf",
                object(&[(
                    "jwk",
                    object(&[
                        ("kty", Json::String("EC".to_string())),
                        ("crv", Json::String("P-256".to_string())),
                        (
                            "x",
                            Json::String(b64::b64url_encode(point.x().unwrap().as_slice())),
                        ),
                        (
                            "y",
                            Json::String(b64::b64url_encode(point.y().unwrap().as_slice())),
                        ),
                    ]),
                )]),
            ),
        ]);
        let header = r#"{"alg":"ES256"}"#;
        let input = format!(
            "{}.{}",
            b64::b64url_encode(header.as_bytes()),
            b64::b64url_encode(payload.to_string().as_bytes())
        );
        let signature: p256::ecdsa::Signature = holder.sign(input.as_bytes());
        let marker = b64::b64url_encode(signature.to_bytes().as_slice());
        format!("{input}.{marker}~ZGlzY2xvc3VyZS1tYXJrZXI")
    }

    fn credential(
        id: &str,
        issuer: &str,
        received_at: &str,
        document: String,
        holder_key: String,
    ) -> Credential {
        Credential {
            id: id.to_string(),
            format: "dc+sd-jwt".to_string(),
            issuer: issuer.to_string(),
            received_at: received_at.to_string(),
            document,
            holder_key: Some(holder_key),
        }
    }

    fn posted_plain(fixture: &Fixture) -> Json {
        let posts = fixture.script.posts.lock().expect("posts");
        assert_eq!(posts.len(), 1, "one response was posted");
        assert_eq!(posts[0].0, "https://verifier.example/oid4vp/response");
        let response = form_value(&posts[0].1, "response");
        let plain = open_ecdh_es(&response, &fixture.recipient).expect("the response opens");
        Json::parse(std::str::from_utf8(&plain).unwrap()).unwrap()
    }

    fn form_value(body: &str, name: &str) -> String {
        for pair in body.split('&') {
            let Some((key, value)) = pair.split_once('=') else {
                continue;
            };
            if crate::protocol::form_decode(key).ok().as_deref() == Some(name) {
                return crate::protocol::form_decode(value).unwrap();
            }
        }
        panic!("missing form field {name}");
    }

    #[test]
    fn presents_the_credential_for_this_verifier() {
        let fixture = fixture("direct_post.jwt", true);
        let outcome = present_with(
            &fixture.uri,
            std::slice::from_ref(&fixture.same),
            &fixture.script,
            now_secs(),
        );
        assert!(outcome.ok, "{}", outcome.message);
        assert!(outcome.store.is_none());
        assert_eq!(outcome.credential_id.as_deref(), Some("cred-same"));
        assert_eq!(
            outcome.redirect_uri.as_deref(),
            Some(
                "https://verifier.example/authn/wallet/wait?authn=1&state=state-1&response_code=code-1"
            )
        );
        let body = fixture.script.posts.lock().expect("posts")[0].1.clone();
        assert!(
            !body.contains(&fixture.holder_secret),
            "the holder key was posted"
        );
        let plain = posted_plain(&fixture);
        assert!(plain.get("id_token").is_none());
        let presentation = plain
            .get("vp_token")
            .unwrap()
            .get("identity_credential")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_str()
            .unwrap();
        assert_eq!(presentation.chars().filter(|ch| *ch == '~').count(), 1);
        assert!(!presentation.contains("ZGlzY2xvc3VyZS1tYXJrZXI"));
        let holder = holder_signing(&Json::parse(&jwk_with_d(&fixture)).unwrap()).unwrap();
        check_kb(presentation, &holder, &fixture.client_id, &fixture.nonce);
    }

    fn retarget_vct(document: &str) -> String {
        let (header, rest) = document.split_once('.').unwrap();
        let (payload, tail) = rest.split_once('.').unwrap();
        let mut text = String::from_utf8(b64::b64_decode(payload).unwrap()).unwrap();
        text = text.replace("urn:idptools:sd-jwt-vc:identity", "urn:example:other");
        format!("{header}.{}.{}", b64::b64url_encode(text.as_bytes()), tail)
    }

    fn jwk_with_d(fixture: &Fixture) -> String {
        // The stored credential's private JWK is what signed the KB-JWT.
        fixture.same.holder_key.clone().unwrap()
    }

    fn check_kb(presentation: &str, holder: &SigningKey, aud: &str, nonce: &str) {
        let (issuer, kb) = presentation.split_once('~').unwrap();
        assert!(!issuer.contains('~'));
        let digest = Sha256::digest(format!("{issuer}~").as_bytes());
        let payload = part_json(kb, 1);
        assert_eq!(
            payload.get("sd_hash").and_then(Json::as_str),
            Some(b64::b64url_encode(&digest).as_str())
        );
        assert_eq!(payload.get("aud").and_then(Json::as_str), Some(aud));
        assert_eq!(payload.get("nonce").and_then(Json::as_str), Some(nonce));
        let header = part_json(kb, 0);
        assert_eq!(header.get("typ").and_then(Json::as_str), Some("kb+jwt"));
        assert_eq!(header.get("alg").and_then(Json::as_str), Some("ES256"));
        let (input, signature) = kb.rsplit_once('.').unwrap();
        let signature =
            p256::ecdsa::Signature::from_slice(&b64::b64_decode(signature).unwrap()).unwrap();
        holder
            .verifying_key()
            .verify(input.as_bytes(), &signature)
            .unwrap();
    }

    fn part_json(compact: &str, index: usize) -> Json {
        jwt_json(compact, index).unwrap()
    }

    #[test]
    fn prefers_the_credential_from_the_verifier_host() {
        let fixture = fixture("direct_post.jwt", true);
        let outcome = present_with(
            &fixture.uri,
            &[fixture.other.clone(), fixture.same.clone()],
            &fixture.script,
            now_secs(),
        );
        assert!(outcome.ok, "{}", outcome.message);
        assert_eq!(outcome.credential_id.as_deref(), Some("cred-same"));
        let plain = posted_plain(&fixture);
        let presentation = plain
            .get("vp_token")
            .unwrap()
            .get("identity_credential")
            .unwrap()
            .as_array()
            .unwrap()[0]
            .as_str()
            .unwrap()
            .to_string();
        let issuer = presentation.split('~').next().unwrap();
        let payload = part_json(issuer, 1);
        assert_eq!(payload.get("sub").and_then(Json::as_str), Some("same-host"));
    }

    #[test]
    fn tells_the_verifier_when_nothing_matches() {
        let fixture = fixture("direct_post.jwt", true);
        let mut wrong = fixture.same.clone();
        wrong.document = retarget_vct(&wrong.document);
        let outcome = present_with(&fixture.uri, &[wrong], &fixture.script, now_secs());
        assert!(!outcome.ok, "{}", outcome.message);
        assert!(outcome.credential_id.is_none());
        assert!(outcome.redirect_uri.is_some());
        assert!(outcome.message.contains("No stored credential"));
        let plain = posted_plain(&fixture);
        assert_eq!(
            plain.get("error").and_then(Json::as_str),
            Some("access_denied")
        );
        assert!(plain.get("vp_token").is_none());
    }

    #[test]
    fn does_not_send_a_credential_when_the_request_is_not_signed() {
        let mut broken = fixture("direct_post.jwt", true);
        let mut text = String::from_utf8(
            broken
                .script
                .gets
                .get("https://verifier.example/oid4vp/request/1")
                .unwrap()
                .body
                .clone(),
        )
        .unwrap();
        let end = text.len();
        text.replace_range(end - 4..end, "AAAA");
        broken.script.gets.insert(
            "https://verifier.example/oid4vp/request/1".to_string(),
            http(
                "https://verifier.example/oid4vp/request/1",
                200,
                text.as_bytes(),
                Vec::new(),
            ),
        );
        let outcome = present_with(
            &broken.uri,
            std::slice::from_ref(&broken.same),
            &broken.script,
            now_secs(),
        );
        assert!(!outcome.ok, "{}", outcome.message);
        assert!(outcome.message.contains("could not be checked"));
        assert!(broken.script.posts.lock().expect("posts").is_empty());
        assert!(outcome.redirect_uri.is_none());
    }

    #[test]
    fn posts_a_plain_form_when_the_verifier_asks_for_direct_post() {
        let fixture = fixture("direct_post", true);
        let outcome = present_with(
            &fixture.uri,
            std::slice::from_ref(&fixture.same),
            &fixture.script,
            now_secs(),
        );
        assert!(outcome.ok, "{}", outcome.message);
        let posts = fixture.script.posts.lock().expect("posts");
        let token = form_value(&posts[0].1, "vp_token");
        let state = form_value(&posts[0].1, "state");
        assert_eq!(state, "state-1");
        assert!(!posts[0].1.contains("response="));
        assert!(!posts[0].1.contains("id_token="));
        let parsed = Json::parse(&token).unwrap();
        assert!(parsed.get("identity_credential").is_some());
    }

    #[test]
    fn a_tls_peer_anchors_a_request_whose_chain_was_not_fetched() {
        let fixture = fixture("direct_post.jwt", false);
        let outcome = present_with(
            &fixture.uri,
            std::slice::from_ref(&fixture.same),
            &fixture.script,
            now_secs(),
        );
        assert!(outcome.ok, "{}", outcome.message);
        assert_eq!(outcome.credential_id.as_deref(), Some("cred-same"));
    }

    fn held(id: &str, received_at: &str, new: NewCredential) -> Credential {
        Credential {
            id: id.to_string(),
            format: new.format,
            issuer: new.issuer,
            received_at: received_at.to_string(),
            document: new.document,
            holder_key: new.holder_key,
        }
    }

    fn posted_body(fixture: &Fixture) -> String {
        fixture.script.posts.lock().expect("posts")[0].1.clone()
    }

    fn id_subject(token: &str) -> String {
        part_json(token, 1)
            .get("sub")
            .and_then(Json::as_str)
            .unwrap()
            .to_string()
    }

    fn check_id_token(token: &str, aud: &str, nonce: &str, holder_jwk: &str, now: u64) {
        let header = part_json(token, 0);
        assert_eq!(header.get("alg").and_then(Json::as_str), Some("ES256"));
        assert_eq!(header.get("typ").and_then(Json::as_str), Some("JWT"));
        assert!(header.get("jwk").is_none());
        let payload_json =
            String::from_utf8(b64::b64_decode(token.split('.').nth(1).unwrap()).unwrap()).unwrap();
        assert!(!payload_json.contains("\"d\""));
        let payload = part_json(token, 1);
        let jwk = payload.get("sub_jwk").expect("sub_jwk");
        assert!(jwk.get("d").is_none());
        assert_eq!(jwk.keys(), vec!["kty", "crv", "x", "y"]);
        let x = jwk.get("x").and_then(Json::as_str).unwrap();
        let y = jwk.get("y").and_then(Json::as_str).unwrap();
        let subject = thumbprint_uri(x, y);
        assert_eq!(
            payload.get("iss").and_then(Json::as_str),
            Some(subject.as_str())
        );
        assert_eq!(
            payload.get("sub").and_then(Json::as_str),
            Some(subject.as_str())
        );
        assert_eq!(payload.get("aud").and_then(Json::as_str), Some(aud));
        assert_eq!(payload.get("nonce").and_then(Json::as_str), Some(nonce));
        let iat = payload.get("iat").and_then(Json::as_u64).unwrap();
        let exp = payload.get("exp").and_then(Json::as_u64).unwrap();
        assert_eq!(iat, now);
        assert_eq!(exp, iat.saturating_add(600));
        let holder = holder_signing(&Json::parse(holder_jwk).unwrap()).unwrap();
        let (left, signature) = token.rsplit_once('.').unwrap();
        let signature =
            p256::ecdsa::Signature::from_slice(&b64::b64_decode(signature).unwrap()).unwrap();
        holder
            .verifying_key()
            .verify(left.as_bytes(), &signature)
            .unwrap();
        let (hx, hy) = encoded_xy(&holder).unwrap();
        assert_eq!(x, hx);
        assert_eq!(y, hy);
    }

    fn check_self_issued_document(document: &str, subject: &str, holder_jwk: &str) {
        assert!(document.ends_with('~'));
        assert_eq!(document.matches('~').count(), 1);
        assert!(!document.contains("\"d\""));
        let issuer = document.trim_end_matches('~');
        let payload = part_json(issuer, 1);
        assert_eq!(payload.get("iss").and_then(Json::as_str), Some(subject));
        assert_eq!(payload.get("sub").and_then(Json::as_str), Some(subject));
        assert_eq!(
            payload.get("vct").and_then(Json::as_str),
            Some("urn:idptools:sd-jwt-vc:identity")
        );
        assert!(payload.get("iat").and_then(Json::as_u64).is_some());
        let jwk = payload.get("cnf").and_then(|cnf| cnf.get("jwk")).unwrap();
        assert!(jwk.get("d").is_none());
        let holder = holder_signing(&Json::parse(holder_jwk).unwrap()).unwrap();
        let (left, signature) = issuer.rsplit_once('.').unwrap();
        let signature =
            p256::ecdsa::Signature::from_slice(&b64::b64_decode(signature).unwrap()).unwrap();
        holder
            .verifying_key()
            .verify(left.as_bytes(), &signature)
            .unwrap();
    }

    fn assert_post_hides_key(body: &str, holder_jwk: &str) {
        assert!(
            !body.contains("\"d\""),
            "the posted body contains a private JWK member"
        );
        let scalar = Json::parse(holder_jwk)
            .unwrap()
            .get("d")
            .and_then(Json::as_str)
            .unwrap()
            .to_string();
        assert!(!scalar.is_empty());
        assert!(!body.contains(&scalar), "the private scalar was posted");
    }

    #[test]
    fn an_id_token_request_creates_a_self_issued_credential() {
        let now = now_secs();
        let fixture = fixture_request("direct_post.jwt", true, "id_token", "siopv2");
        let outcome = present_with(&fixture.uri, &[], &fixture.script, now);
        assert!(outcome.ok, "{}", outcome.message);
        assert!(outcome.credential_id.is_none());
        assert!(outcome.redirect_uri.is_some());
        assert!(outcome.message.contains("Created a self-issued credential"));
        let stored = outcome.store.expect("a new credential is returned");
        assert_eq!(stored.format, "dc+sd-jwt");
        assert!(stored.issuer.starts_with(THUMBPRINT_PREFIX));
        assert!(outcome.message.contains(&stored.issuer));
        let holder = stored.holder_key.clone().expect("holder key");
        check_self_issued_document(&stored.document, &stored.issuer, &holder);
        let plain = posted_plain(&fixture);
        assert!(plain.get("vp_token").is_none());
        assert!(plain.get("error").is_none());
        assert_eq!(plain.get("state").and_then(Json::as_str), Some("state-1"));
        let token = plain.get("id_token").and_then(Json::as_str).unwrap();
        check_id_token(token, &fixture.client_id, &fixture.nonce, &holder, now);
        assert_eq!(id_subject(token), stored.issuer);
        assert!(!plain.to_string().contains("\"d\""));
        assert_post_hides_key(&posted_body(&fixture), &holder);
    }

    #[test]
    fn an_id_token_request_can_post_a_plain_form() {
        let now = now_secs();
        let fixture = fixture_request("direct_post", true, "id_token", "siopv2");
        let outcome = present_with(
            &fixture.uri,
            std::slice::from_ref(&fixture.same),
            &fixture.script,
            now,
        );
        assert!(outcome.ok, "{}", outcome.message);
        assert!(outcome.store.is_some());
        let holder = outcome.store.unwrap().holder_key.unwrap();
        let posts = fixture.script.posts.lock().expect("posts");
        let token = form_value(&posts[0].1, "id_token");
        let state = form_value(&posts[0].1, "state");
        assert_eq!(state, "state-1");
        assert!(!posts[0].1.contains("vp_token="));
        assert!(!posts[0].1.contains("error="));
        assert_post_hides_key(&posts[0].1, &holder);
        drop(posts);
        check_id_token(&token, &fixture.client_id, &fixture.nonce, &holder, now);
    }

    #[test]
    fn a_later_id_token_reuses_the_stored_subject() {
        let now = now_secs();
        let first = fixture_request("direct_post.jwt", true, "id_token", "siopv2");
        let created = present_with(&first.uri, &[], &first.script, now);
        let subject = id_subject(
            posted_plain(&first)
                .get("id_token")
                .and_then(Json::as_str)
                .unwrap(),
        );
        let minted = created.store.expect("created");
        let holder = minted.holder_key.clone().expect("holder");
        let stored = held("cred-self", "20261018T120000.000Z", minted);
        let older = {
            let earlier = fixture_request("direct_post.jwt", true, "id_token", "siopv2");
            let made = present_with(&earlier.uri, &[], &earlier.script, now);
            held(
                "cred-older",
                "20261017T120000.000Z",
                made.store.expect("older"),
            )
        };
        let second = fixture_request("direct_post.jwt", true, "id_token", "siopv2");
        let outcome = present_with(&second.uri, &[older, stored], &second.script, now);
        assert!(outcome.ok, "{}", outcome.message);
        assert!(outcome.store.is_none());
        assert_eq!(outcome.credential_id.as_deref(), Some("cred-self"));
        assert!(outcome
            .message
            .contains("Sent the self-issued credential cred-self"));
        let plain = posted_plain(&second);
        assert!(plain.get("vp_token").is_none());
        assert!(plain.get("error").is_none());
        let token = plain
            .get("id_token")
            .and_then(Json::as_str)
            .unwrap()
            .to_string();
        assert_eq!(id_subject(&token), subject);
        check_id_token(&token, &second.client_id, &second.nonce, &holder, now);
        assert_post_hides_key(&posted_body(&second), &holder);
    }

    #[test]
    fn vp_token_and_id_token_share_the_holder_key() {
        let now = now_secs();
        let fixture = fixture_request("direct_post.jwt", true, "vp_token id_token", "openid4vp");
        let outcome = present_with(
            &fixture.uri,
            std::slice::from_ref(&fixture.same),
            &fixture.script,
            now,
        );
        assert!(outcome.ok, "{}", outcome.message);
        assert!(outcome.store.is_none());
        assert_eq!(outcome.credential_id.as_deref(), Some("cred-same"));
        let holder = fixture.same.holder_key.clone().unwrap();
        let plain = posted_plain(&fixture);
        assert!(plain
            .get("vp_token")
            .and_then(|token| token.get("identity_credential"))
            .is_some());
        assert!(plain.get("error").is_none());
        assert_eq!(plain.get("state").and_then(Json::as_str), Some("state-1"));
        let token = plain
            .get("id_token")
            .and_then(Json::as_str)
            .unwrap()
            .to_string();
        check_id_token(&token, &fixture.client_id, &fixture.nonce, &holder, now);
        assert!(!plain.to_string().contains("\"d\""));
        assert_post_hides_key(&posted_body(&fixture), &holder);
    }

    fn http(url: &str, status: u16, body: &[u8], peers: Vec<Vec<u8>>) -> RawResponse {
        RawResponse {
            status,
            body: body.to_vec(),
            peer_certs: peers,
            final_url: url.to_string(),
        }
    }

    fn signed_jwt(signing: &SigningKey, leaf: &[u8], payload: &str) -> String {
        let header = format!(
            r#"{{"alg":"ES256","typ":"oauth-authz-req+jwt","x5c":["{}"]}}"#,
            b64::b64_encode(leaf)
        );
        let input = format!(
            "{}.{}",
            b64::b64url_encode(header.as_bytes()),
            b64::b64url_encode(payload.as_bytes())
        );
        let signature: p256::ecdsa::Signature = signing.sign(input.as_bytes());
        format!(
            "{input}.{}",
            b64::b64url_encode(signature.to_bytes().as_slice())
        )
    }

    fn signer_of(key: &KeyPair) -> SigningKey {
        let secret = SecretKey::from_pkcs8_der(&key.serialize_der()).unwrap();
        let bytes = secret.to_bytes();
        SigningKey::from_bytes(&bytes).unwrap()
    }

    fn ca(cn: &str) -> (KeyPair, CertificateParams, rcgen::Certificate) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, cn);
        let cert = params.self_signed(&key).unwrap();
        (key, params, cert)
    }

    fn leaf(
        cn: &str,
        issuer_params: &CertificateParams,
        issuer_key: &KeyPair,
        aia: Option<&str>,
    ) -> (KeyPair, rcgen::Certificate) {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.distinguished_name.push(DnType::CommonName, cn);
        if let Some(url) = aia {
            params
                .custom_extensions
                .push(CustomExtension::from_oid_content(
                    &[1, 3, 6, 1, 5, 5, 7, 1, 1],
                    aia_der(url),
                ));
        }
        let issuer = Issuer::from_params(issuer_params, issuer_key);
        let cert = params.signed_by(&key, &issuer).unwrap();
        (key, cert)
    }

    fn aia_der(uri: &str) -> Vec<u8> {
        let oid = der_tlv(0x06, &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02]);
        let location = der_tlv(0x86, uri.as_bytes());
        let mut access = oid;
        access.extend(location);
        let description = der_tlv(0x30, &access);
        der_tlv(0x30, &description)
    }

    fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = body.len();
        if len < 128 {
            out.push(len as u8);
        } else if len < 256 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(body);
        out
    }
}
