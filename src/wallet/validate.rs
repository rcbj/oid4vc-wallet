//! Check an issued credential's signature and the chain behind it.
//!
//! Published keys come from JWT VC Issuer Metadata
//! (`/.well-known/jwt-vc-issuer`, draft-ietf-oauth-sd-jwt-vc). That document
//! carries a JWKS or a `jwks_uri`. A certificate chain in the JWS `x5c`
//! header is completed from the RFC 5280 Authority Information Access
//! `caIssuers` URL. A root that was only embedded in the credential was not
//! retrieved, so it is not a published anchor.
//!
//! When the signature checks against `x5c` and neither a published key nor a
//! fetched root is available, the TLS certificate of the issuer can anchor
//! the chain. That result says the fallback was used. Otherwise the caller
//! asks whether this issuer's key is trusted.

use std::cell::RefCell;
use std::path::Path;

use crate::i18n::{t, t_args};
use crate::protocol::Json;

use super::b64;
use super::certs::{self, Chain, ChainFault, OwnedCert};
use super::http::{self, RawResponse};
use super::jws::{self, KeyMaterial, OpenError, PublishedKey};
use super::trust;

/// What a successful check established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// The signature matches a published key or a key accepted earlier.
    Accepted(String),
    /// The issuer's TLS certificate anchored the chain.
    Fallback(String),
    /// The signature checks, and this key has not been accepted yet.
    Ask {
        message: String,
        issuer: String,
        fingerprint: String,
    },
}

/// Why a credential could not be checked.
#[derive(Debug)]
pub enum ValidateError {
    NotJws,
    Unsupported(String),
    IssuerMismatch { iss: String, issuer: String },
    NoIssuer,
    Metadata { url: String, error: String },
    NoKey,
    BadSignature,
    ChainBad,
    ChainName,
    ChainDate,
    TrustWrite(String),
}

impl std::fmt::Display for ValidateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::NotJws => t("wallet.validate.not_jws"),
            Self::Unsupported(algorithm) => {
                t_args("wallet.validate.unsupported", &[("algorithm", algorithm)])
            }
            Self::IssuerMismatch { iss, issuer } => t_args(
                "wallet.validate.issuer_mismatch",
                &[("iss", iss), ("issuer", issuer)],
            ),
            Self::NoIssuer => t("wallet.validate.no_issuer"),
            Self::Metadata { url, error } => t_args(
                "wallet.validate.metadata",
                &[("url", url), ("error", error)],
            ),
            Self::NoKey => t("wallet.validate.no_key"),
            Self::BadSignature => t("wallet.validate.bad_signature"),
            Self::ChainBad => t("wallet.validate.chain_bad"),
            Self::ChainName => t("wallet.validate.chain_name"),
            Self::ChainDate => t("wallet.validate.chain_date"),
            Self::TrustWrite(error) => t_args("wallet.validate.trust_write", &[("error", error)]),
        };
        f.write_str(&text)
    }
}

impl std::error::Error for ValidateError {}

/// Check the stored credential against the issuer on the network.
pub fn validate_stored(
    format: &str,
    issuer: &str,
    document: &str,
) -> Result<Outcome, ValidateError> {
    let path = trust::default_path().map_err(ValidateError::TrustWrite)?;
    let anchors = match super::anchors::default_dir() {
        Ok(dir) => super::anchors::anchor_ders(&dir),
        Err(_) => Vec::new(),
    };
    validate_anchored(
        format,
        issuer,
        document,
        &LiveFetch,
        &path,
        now_unix(),
        &anchors,
    )
}

/// Remember that `fingerprint` is trusted for `issuer`.
pub fn remember_trust(issuer: &str, fingerprint: &str) -> Result<(), ValidateError> {
    let path = trust::default_path().map_err(ValidateError::TrustWrite)?;
    trust::remember(&path, issuer, fingerprint).map_err(ValidateError::TrustWrite)
}

pub(crate) trait Fetch {
    fn get(&self, url: &str) -> Result<RawResponse, String>;
}

struct LiveFetch;

impl Fetch for LiveFetch {
    fn get(&self, url: &str) -> Result<RawResponse, String> {
        http::exchange("GET", url, None, None, b"")
    }
}

struct Session<'a, F> {
    fetch: &'a F,
    issuer_host: String,
    peers: RefCell<Vec<Vec<u8>>>,
}

impl<F: Fetch> Session<'_, F> {
    fn get(&self, url: &str) -> Result<RawResponse, String> {
        let response = self.fetch.get(url)?;
        if url_host(&response.final_url).as_deref() == Some(self.issuer_host.as_str()) {
            self.peers
                .borrow_mut()
                .extend(response.peer_certs.iter().cloned());
        }
        Ok(response)
    }
}

struct KeySet {
    keys: Vec<PublishedKey>,
    url: String,
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn validate_with<F: Fetch>(
    format: &str,
    stored_issuer: &str,
    document: &str,
    fetch: &F,
    trust_path: &Path,
    now: i64,
) -> Result<Outcome, ValidateError> {
    validate_anchored(format, stored_issuer, document, fetch, trust_path, now, &[])
}

pub(crate) fn validate_anchored<F: Fetch>(
    format: &str,
    stored_issuer: &str,
    document: &str,
    fetch: &F,
    trust_path: &Path,
    now: i64,
    anchors: &[Vec<u8>],
) -> Result<Outcome, ValidateError> {
    let jws = match jws::open_issuer_jws(format, document) {
        Ok(jws) => jws,
        Err(OpenError::NotJws) => return Err(ValidateError::NotJws),
        Err(OpenError::Unsupported(algorithm)) => {
            return Err(ValidateError::Unsupported(algorithm))
        }
    };
    let payload_iss = payload_issuer(&jws.payload);
    if let Some(iss) = payload_iss.as_ref() {
        if !stored_issuer.is_empty() && iss != stored_issuer {
            return Err(ValidateError::IssuerMismatch {
                iss: iss.clone(),
                issuer: stored_issuer.to_string(),
            });
        }
    }
    let issuer = payload_iss.unwrap_or_else(|| stored_issuer.to_string());
    if issuer.is_empty() {
        return Err(ValidateError::NoIssuer);
    }
    let session = Session {
        fetch,
        issuer_host: url_host(&issuer).unwrap_or_default(),
        peers: RefCell::new(Vec::new()),
    };
    let loaded = published_keys(&session, &issuer, jws.kid.as_deref());
    let (keys, publication_url, meta_failure) = match loaded {
        Ok(set) => (set.keys, set.url, None),
        Err((url, error)) => (Vec::new(), String::new(), Some((url, error))),
    };
    let (jwks_ok, mut saw_fail) = try_keys(&jws.alg, &keys, &jws.signing_input, &jws.signature);
    let leaf = jws.x5c.first().and_then(|der| OwnedCert::parse(der));
    let leaf_ok = match &leaf {
        Some(leaf) if compatible(&jws.alg, &leaf.key) => {
            let ok = jws::verifies(&jws.alg, &leaf.key, &jws.signing_input, &jws.signature);
            if !ok {
                saw_fail = true;
            }
            ok
        }
        _ => false,
    };
    if leaf_ok {
        let chain = certs::walk(&jws.x5c, now, |url| fetch_ders(&session, url));
        return match chain {
            Chain::Published { name, url } => Ok(Outcome::Accepted(t_args(
                "wallet.validate.ok",
                &[("algorithm", &jws.alg), ("name", &name), ("url", &url)],
            ))),
            Chain::Broken(fault) if !jwks_ok => Err(chain_error(fault)),
            Chain::Incomplete(certs) if !jwks_ok => {
                if let Some(name) = user_anchor(&certs, anchors) {
                    return Ok(Outcome::Accepted(t_args(
                        "wallet.validate.ok_anchor",
                        &[("name", &name)],
                    )));
                }
                unanchored(
                    &jws.alg,
                    &issuer,
                    &certs,
                    &session.peers.borrow(),
                    trust_path,
                )
            }
            Chain::Broken(_) | Chain::Incomplete(_) => Ok(Outcome::Accepted(ok_key(
                &jws.alg,
                &issuer,
                &publication_url,
            ))),
        };
    }
    if jwks_ok {
        return Ok(Outcome::Accepted(ok_key(
            &jws.alg,
            &issuer,
            &publication_url,
        )));
    }
    if saw_fail {
        return Err(ValidateError::BadSignature);
    }
    if jws.x5c.is_empty() {
        if let Some((url, error)) = meta_failure {
            return Err(ValidateError::Metadata { url, error });
        }
    }
    Err(ValidateError::NoKey)
}

fn user_anchor(certs: &[OwnedCert], anchors: &[Vec<u8>]) -> Option<String> {
    let parsed = anchors
        .iter()
        .filter_map(|der| OwnedCert::parse(der))
        .collect::<Vec<_>>();
    certs::anchored_by(certs, &parsed)
}

fn unanchored(
    algorithm: &str,
    issuer: &str,
    certs: &[OwnedCert],
    peers: &[Vec<u8>],
    trust_path: &Path,
) -> Result<Outcome, ValidateError> {
    let Some(leaf) = certs.first() else {
        return Err(ValidateError::NoKey);
    };
    if certs::tls_anchors(certs, &parse_peers(peers)) {
        return Ok(Outcome::Fallback(t_args(
            "wallet.validate.fallback",
            &[("algorithm", algorithm)],
        )));
    }
    let fingerprint = b64::sha256_hex(&leaf.spki_der);
    if trust::is_trusted(trust_path, issuer, &fingerprint) {
        return Ok(Outcome::Accepted(t_args(
            "wallet.validate.ok_trusted",
            &[("algorithm", algorithm), ("issuer", issuer)],
        )));
    }
    let name = if leaf.name.is_empty() {
        issuer.to_string()
    } else {
        leaf.name.clone()
    };
    Ok(Outcome::Ask {
        message: t_args(
            "wallet.ui.trust_prompt",
            &[("url", issuer), ("name", &name)],
        ),
        issuer: issuer.to_string(),
        fingerprint,
    })
}

fn published_keys<F: Fetch>(
    session: &Session<'_, F>,
    issuer: &str,
    kid: Option<&str>,
) -> Result<KeySet, (String, String)> {
    let meta_url = super::redeem::well_known(issuer, "jwt-vc-issuer")
        .map_err(|err| (issuer.to_string(), err.to_string()))?;
    let response = session
        .get(&meta_url)
        .map_err(|error| (meta_url.clone(), error))?;
    if response.status != 200 {
        return Err((meta_url, response.status.to_string()));
    }
    let Some(json) = json_body(&response.body) else {
        return Err((meta_url, "the response was not JSON".to_string()));
    };
    let meta_issuer = json
        .get("issuer")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    if meta_issuer != issuer {
        return Ok(KeySet {
            keys: Vec::new(),
            url: meta_url,
        });
    }
    let inline = json.get("jwks").map(keys_in).unwrap_or_default();
    if !inline.is_empty() {
        return Ok(KeySet {
            keys: prefer_kid(inline, kid),
            url: meta_url,
        });
    }
    let Some(jwks_uri) = json
        .get("jwks_uri")
        .and_then(|value| value.as_str())
        .filter(|uri| crate::protocol::is_http_url(uri))
    else {
        return Ok(KeySet {
            keys: Vec::new(),
            url: meta_url,
        });
    };
    let jwks_uri = jwks_uri.to_string();
    let response = session
        .get(&jwks_uri)
        .map_err(|error| (jwks_uri.clone(), error))?;
    if response.status != 200 {
        return Err((jwks_uri, response.status.to_string()));
    }
    let Some(json) = json_body(&response.body) else {
        return Err((jwks_uri, "the response was not JSON".to_string()));
    };
    Ok(KeySet {
        keys: prefer_kid(keys_in(&json), kid),
        url: jwks_uri,
    })
}

fn keys_in(jwks: &Json) -> Vec<PublishedKey> {
    jwks.get("keys")
        .and_then(|value| value.as_array())
        .map(|keys| keys.iter().filter_map(jws::key_from_jwk).collect())
        .unwrap_or_default()
}

fn prefer_kid(keys: Vec<PublishedKey>, kid: Option<&str>) -> Vec<PublishedKey> {
    let Some(kid) = kid else {
        return keys;
    };
    let mut matched = Vec::new();
    let mut rest = Vec::new();
    for key in keys {
        if key.kid.as_deref() == Some(kid) {
            matched.push(key);
        } else {
            rest.push(key);
        }
    }
    matched.extend(rest);
    matched
}

fn try_keys(
    alg: &str,
    keys: &[PublishedKey],
    signing_input: &[u8],
    signature: &[u8],
) -> (bool, bool) {
    let mut failed = false;
    for key in keys {
        if !compatible(alg, &key.key) {
            continue;
        }
        if jws::verifies(alg, &key.key, signing_input, signature) {
            return (true, failed);
        }
        failed = true;
    }
    (false, failed)
}

fn compatible(alg: &str, key: &KeyMaterial) -> bool {
    match (alg, key) {
        ("ES256", KeyMaterial::P256 { x, y }) => x.len() == 32 && y.len() == 32,
        ("ES384", KeyMaterial::P384 { x, y }) => x.len() == 48 && y.len() == 48,
        ("ES512", KeyMaterial::P521 { x, y }) => x.len() == 66 && y.len() == 66,
        ("ES256K", KeyMaterial::K256 { x, y }) => x.len() == 32 && y.len() == 32,
        ("RS256" | "RS384" | "RS512" | "PS256" | "PS384" | "PS512", KeyMaterial::Rsa { n, e }) => {
            !n.is_empty() && !e.is_empty()
        }
        ("EdDSA", KeyMaterial::Ed25519 { x }) => x.len() == 32,
        ("EdDSA", KeyMaterial::Ed448 { x }) => x.len() == 57,
        (
            alg,
            KeyMaterial::Akp {
                alg: key_alg,
                public,
            },
        ) => alg == key_alg && !public.is_empty(),
        _ => false,
    }
}

fn fetch_ders<F: Fetch>(session: &Session<'_, F>, url: &str) -> Option<Vec<Vec<u8>>> {
    let response = session.get(url).ok()?;
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

fn parse_peers(ders: &[Vec<u8>]) -> Vec<OwnedCert> {
    ders.iter()
        .filter_map(|der| OwnedCert::parse(der))
        .collect()
}

fn payload_issuer(payload: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(payload).ok()?;
    let json = Json::parse(text).ok()?;
    let iss = json.get("iss").and_then(|value| value.as_str())?;
    if iss.is_empty() {
        None
    } else {
        Some(iss.to_string())
    }
}

fn json_body(body: &[u8]) -> Option<Json> {
    let text = std::str::from_utf8(body).ok()?;
    Json::parse(text).ok()
}

fn ok_key(algorithm: &str, issuer: &str, url: &str) -> String {
    t_args(
        "wallet.validate.ok_key",
        &[("algorithm", algorithm), ("issuer", issuer), ("url", url)],
    )
}

fn chain_error(fault: ChainFault) -> ValidateError {
    match fault {
        ChainFault::Bad => ValidateError::ChainBad,
        ChainFault::Name => ValidateError::ChainName,
        ChainFault::Date => ValidateError::ChainDate,
    }
}

fn url_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
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

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::path::PathBuf;

    use p256::ecdsa::signature::Signer;
    use p256::pkcs8::DecodePrivateKey;
    use rcgen::{
        BasicConstraints, CertificateParams, CustomExtension, DnType, IsCa, Issuer, KeyPair,
        PKCS_ECDSA_P256_SHA256,
    };

    const ISSUER: &str = "https://issuer.example";
    const NOW: i64 = 1_700_000_000;

    #[derive(Clone)]
    struct Routes(HashMap<String, RawResponse>);

    impl Fetch for Routes {
        fn get(&self, url: &str) -> Result<RawResponse, String> {
            self.0
                .get(url)
                .cloned()
                .ok_or_else(|| format!("no route for {url}"))
        }
    }

    struct Boom;

    impl Fetch for Boom {
        fn get(&self, url: &str) -> Result<RawResponse, String> {
            Err(format!("fetched {url}"))
        }
    }

    fn meta() -> String {
        format!("{ISSUER}/.well-known/jwt-vc-issuer")
    }

    fn scratch(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-validate-{label}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    fn http(url: &str, status: u16, body: &[u8], peers: Vec<Vec<u8>>) -> RawResponse {
        RawResponse {
            status,
            body: body.to_vec(),
            peer_certs: peers,
            final_url: url.to_string(),
        }
    }

    fn signer_of(key: &KeyPair) -> p256::ecdsa::SigningKey {
        let secret = p256::SecretKey::from_pkcs8_der(&key.serialize_der()).unwrap();
        let bytes = secret.to_bytes();
        p256::ecdsa::SigningKey::from_bytes(&bytes).unwrap()
    }

    fn es256_jws(signing: &p256::ecdsa::SigningKey, issuer: &str, x5c: &[Vec<u8>]) -> String {
        let payload = if issuer.is_empty() {
            "not json".to_string()
        } else {
            format!(r#"{{"iss":"{issuer}"}}"#)
        };
        let mut header = r#"{"alg":"ES256""#.to_string();
        if !x5c.is_empty() {
            header.push_str(r#","x5c":["#);
            for (index, der) in x5c.iter().enumerate() {
                if index > 0 {
                    header.push(',');
                }
                header.push('"');
                header.push_str(&b64::b64_encode(der));
                header.push('"');
            }
            header.push(']');
        }
        header.push('}');
        let encoded_header = b64::b64url_encode(header.as_bytes());
        let encoded_payload = b64::b64url_encode(payload.as_bytes());
        let input = format!("{encoded_header}.{encoded_payload}");
        let signature: p256::ecdsa::Signature = signing.sign(input.as_bytes());
        format!("{input}.{}", b64::b64url_encode(&signature.to_bytes()))
    }

    fn jwks_body(signing: &p256::ecdsa::SigningKey) -> String {
        let point = signing.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        let x = b64::b64url_encode(&bytes[1..33]);
        let y = b64::b64url_encode(&bytes[33..65]);
        format!(
            r#"{{"issuer":"{ISSUER}","jwks":{{"keys":[{{"kty":"EC","crv":"P-256","use":"sig","kid":"1","x":"{x}","y":"{y}"}}]}}}}"#
        )
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

    /// Change the first character of the JWS signature. That character always
    /// carries signature bits. The final character of an ES256 signature often
    /// does not, so flipping it leaves a valid signature.
    fn flip_signature(document: &str) -> String {
        let at = document.rfind('.').expect("compact jws") + 1;
        let mut broken = document.to_string();
        let next = if broken.as_bytes()[at] == b'A' {
            "B"
        } else {
            "A"
        };
        broken.replace_range(at..at + 1, next);
        broken
    }

    fn check(
        routes: Routes,
        format: &str,
        issuer: &str,
        document: &str,
        trust_path: &std::path::Path,
    ) -> Result<Outcome, ValidateError> {
        validate_with(format, issuer, document, &routes, trust_path, NOW)
    }

    #[test]
    fn inline_jwks_accepts_the_published_key() {
        let root = scratch("jwks");
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let document = es256_jws(&signing, ISSUER, &[]);
        let body = jwks_body(&signing);
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url.clone(), http(&url, 200, body.as_bytes(), Vec::new()));
        let outcome = check(
            Routes(map),
            "dc+sd-jwt",
            ISSUER,
            &document,
            &root.join("trust"),
        )
        .unwrap();
        match outcome {
            Outcome::Accepted(text) => {
                assert!(text.contains("ES256"), "{text}");
                assert!(text.contains(&url), "{text}");
                assert!(text.contains(ISSUER), "{text}");
            }
            other => panic!("expected a published key, got {other:?}"),
        }
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_uploaded_root_anchors_an_incomplete_chain() {
        let root_dir = scratch("anchor");
        let (ca_key, ca_params, ca_cert) = ca("Uploaded Root");
        let (leaf_key, leaf_cert) = leaf("Example Leaf", &ca_params, &ca_key, None);
        let signing = signer_of(&leaf_key);
        let document = es256_jws(&signing, ISSUER, &[leaf_cert.der().to_vec()]);
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url, http(ISSUER, 404, b"", Vec::new()));
        let anchors = [ca_cert.der().to_vec()];
        let outcome = validate_anchored(
            "dc+sd-jwt",
            ISSUER,
            &document,
            &Routes(map.clone()),
            &root_dir.join("trust"),
            NOW,
            &anchors,
        )
        .unwrap();
        match outcome {
            Outcome::Accepted(text) => assert!(text.contains("Uploaded Root"), "{text}"),
            other => panic!("expected the uploaded anchor, got {other:?}"),
        }
        let bare = validate_with(
            "dc+sd-jwt",
            ISSUER,
            &document,
            &Routes(map),
            &root_dir.join("trust"),
            NOW,
        )
        .unwrap();
        assert!(matches!(bare, Outcome::Ask { .. }), "{bare:?}");

        let broken = flip_signature(&document);
        let err = validate_anchored(
            "dc+sd-jwt",
            ISSUER,
            &broken,
            &Routes(HashMap::new()),
            &root_dir.join("trust"),
            NOW,
            &anchors,
        )
        .unwrap_err();
        assert!(matches!(err, ValidateError::BadSignature), "{err}");
        std::fs::remove_dir_all(&root_dir).unwrap();
    }

    #[test]
    fn aia_root_is_a_published_anchor() {
        let root_dir = scratch("aia");
        let (ca_key, ca_params, ca_cert) = ca("Example Root");
        let aia = format!("{ISSUER}/root.cer");
        let (leaf_key, leaf_cert) = leaf("Example Leaf", &ca_params, &ca_key, Some(&aia));
        let signing = signer_of(&leaf_key);
        let document = es256_jws(&signing, ISSUER, &[leaf_cert.der().to_vec()]);
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url.clone(), http(&url, 404, b"", Vec::new()));
        map.insert(
            aia.clone(),
            http(&aia, 200, ca_cert.der().as_ref(), Vec::new()),
        );
        let outcome = check(
            Routes(map),
            "jwt_vc_json",
            ISSUER,
            &document,
            &root_dir.join("trust"),
        )
        .unwrap();
        match outcome {
            Outcome::Accepted(text) => {
                assert!(text.contains("ES256"), "{text}");
                assert!(text.contains("Example Root"), "{text}");
                assert!(text.contains(&aia), "{text}");
            }
            other => panic!("expected the fetched root, got {other:?}"),
        }
        std::fs::remove_dir_all(&root_dir).unwrap();
    }

    #[test]
    fn an_embedded_root_asks_instead_of_counting_as_published() {
        let root_dir = scratch("embedded");
        let (ca_key, ca_params, ca_cert) = ca("Example Root");
        let (leaf_key, leaf_cert) = leaf("Example Leaf", &ca_params, &ca_key, None);
        let signing = signer_of(&leaf_key);
        let document = es256_jws(
            &signing,
            ISSUER,
            &[leaf_cert.der().to_vec(), ca_cert.der().to_vec()],
        );
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url.clone(), http(&url, 404, b"", Vec::new()));
        let outcome = check(
            Routes(map),
            "dc+sd-jwt",
            ISSUER,
            &document,
            &root_dir.join("trust"),
        )
        .unwrap();
        match outcome {
            Outcome::Ask {
                message,
                issuer,
                fingerprint,
            } => {
                assert!(message.contains(ISSUER), "{message}");
                assert!(message.contains("Example Leaf"), "{message}");
                assert_eq!(issuer, ISSUER);
                assert_eq!(fingerprint.len(), 64);
            }
            other => panic!("expected a trust prompt, got {other:?}"),
        }
        std::fs::remove_dir_all(&root_dir).unwrap();
    }

    #[test]
    fn tls_peer_is_the_fallback_and_a_saved_answer_is_reused() {
        let root_dir = scratch("tls");
        let (ca_key, ca_params, ca_cert) = ca("Example Root");
        let (leaf_key, leaf_cert) = leaf("Example Leaf", &ca_params, &ca_key, None);
        let signing = signer_of(&leaf_key);
        let document = es256_jws(&signing, ISSUER, &[leaf_cert.der().to_vec()]);
        let url = meta();
        let trust = root_dir.join("trust");
        let mut map = HashMap::new();
        map.insert(
            url.clone(),
            http(&url, 404, b"", vec![ca_cert.der().to_vec()]),
        );
        let outcome = check(Routes(map), "dc+sd-jwt", ISSUER, &document, &trust).unwrap();
        match outcome {
            Outcome::Fallback(text) => {
                assert!(text.contains("ES256"), "{text}");
                assert!(text.to_ascii_lowercase().contains("fallback"), "{text}");
            }
            other => panic!("expected the TLS fallback, got {other:?}"),
        }
        let mut plain = HashMap::new();
        plain.insert(url.clone(), http(&url, 404, b"", Vec::new()));
        let asked = check(
            Routes(plain.clone()),
            "dc+sd-jwt",
            ISSUER,
            &document,
            &trust,
        )
        .unwrap();
        let Outcome::Ask { fingerprint, .. } = asked else {
            panic!("expected a prompt, got {asked:?}");
        };
        trust::remember(&trust, ISSUER, &fingerprint).unwrap();
        let again = check(Routes(plain), "dc+sd-jwt", ISSUER, &document, &trust).unwrap();
        match again {
            Outcome::Accepted(text) => assert!(text.contains(ISSUER), "{text}"),
            other => panic!("expected the saved trust decision, got {other:?}"),
        }
        std::fs::remove_dir_all(&root_dir).unwrap();
    }

    #[test]
    fn a_broken_link_is_an_error() {
        let root_dir = scratch("name");
        let (ca_key, ca_params, _) = ca("Example Root");
        let (leaf_key, leaf_cert) = leaf("Example Leaf", &ca_params, &ca_key, None);
        let (_, _, other) = ca("Other Root");
        let signing = signer_of(&leaf_key);
        let document = es256_jws(
            &signing,
            ISSUER,
            &[leaf_cert.der().to_vec(), other.der().to_vec()],
        );
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url, http(&meta(), 404, b"", Vec::new()));
        let outcome = check(
            Routes(map),
            "dc+sd-jwt",
            ISSUER,
            &document,
            &root_dir.join("trust"),
        );
        assert!(matches!(outcome, Err(ValidateError::ChainName)));
        std::fs::remove_dir_all(&root_dir).unwrap();
    }

    #[test]
    fn a_tampered_signature_is_rejected() {
        let root_dir = scratch("bad");
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let document = flip_signature(&es256_jws(&signing, ISSUER, &[]));
        let body = jwks_body(&signing);
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url.clone(), http(&url, 200, body.as_bytes(), Vec::new()));
        let outcome = check(
            Routes(map),
            "dc+sd-jwt",
            ISSUER,
            &document,
            &root_dir.join("trust"),
        );
        assert!(matches!(outcome, Err(ValidateError::BadSignature)));
        std::fs::remove_dir_all(&root_dir).unwrap();
    }

    #[test]
    fn the_stored_issuer_must_match_the_payload() {
        let root = scratch("mismatch");
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let document = es256_jws(&signing, ISSUER, &[]);
        let outcome = validate_with(
            "dc+sd-jwt",
            "https://other.example",
            &document,
            &Boom,
            &root.join("trust"),
            NOW,
        );
        assert!(matches!(outcome, Err(ValidateError::IssuerMismatch { .. })));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn an_unsupported_algorithm_does_not_use_the_network() {
        let root = scratch("alg");
        let header = b64::b64url_encode(br#"{"alg":"none"}"#);
        let payload = b64::b64url_encode(br#"{"iss":"https://issuer.example"}"#);
        let document = format!("{header}.{payload}.e30");
        let outcome = validate_with(
            "jwt_vc_json",
            ISSUER,
            &document,
            &Boom,
            &root.join("trust"),
            NOW,
        );
        assert!(matches!(outcome, Err(ValidateError::Unsupported(_))));
        let ldp = validate_with(
            "ldp_vc",
            ISSUER,
            r#"{"type":"VerifiableCredential"}"#,
            &Boom,
            &root.join("trust"),
            NOW,
        );
        assert!(matches!(ldp, Err(ValidateError::NotJws)));
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn a_non_json_payload_uses_the_stored_issuer() {
        let root = scratch("plain");
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let document = es256_jws(&signing, "", &[]);
        let body = jwks_body(&signing);
        let url = meta();
        let mut map = HashMap::new();
        map.insert(url.clone(), http(&url, 200, body.as_bytes(), Vec::new()));
        let outcome = check(
            Routes(map),
            "dc+sd-jwt",
            ISSUER,
            &document,
            &root.join("trust"),
        )
        .unwrap();
        assert!(matches!(outcome, Outcome::Accepted(_)));
        std::fs::remove_dir_all(&root).unwrap();
    }
}
