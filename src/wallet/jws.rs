//! Issuer signatures on a JWT or SD-JWT credential.
//!
//! The compact JWS is read here. The signature is checked with the curve,
//! RSA, EdDSA, ML-DSA and SLH-DSA primitives. Header parameters are ordinary
//! JSON. Each algorithm is one call into the matching primitive.
//!
//! A composite follows draft-ietf-jose-pq-composite-sigs the way iya-sts signs
//! it. Both halves sign M', which is the ASCII domain separator, the
//! composite label, a zero byte, and a prehash of the JWS signing input. The
//! ML-DSA half uses that label as its context string. The traditional half is
//! R||S for ECDSA and the raw signature for EdDSA. Pure ML-DSA and SLH-DSA
//! use an empty context.

use sha2::{Digest, Sha256};

use crate::protocol::Json;

use super::b64;

/// RFC 9278 prefix for an RFC 7638 SHA-256 JWK thumbprint.
pub(crate) const JWK_THUMBPRINT_PREFIX: &str = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:";

/// The issuer JWS, which is the part of an SD-JWT before the first `~`.
#[derive(Debug)]
pub(crate) struct IssuerJws {
    pub alg: String,
    pub kid: Option<String>,
    pub signing_input: Vec<u8>,
    pub signature: Vec<u8>,
    pub payload: Vec<u8>,
    pub x5c: Vec<Vec<u8>>,
}

/// Why the document did not yield a signature this wallet can check.
pub(crate) enum OpenError {
    NotJws,
    Unsupported(String),
}

/// A public key the signature can be checked against.
pub(crate) enum KeyMaterial {
    P256 {
        x: Vec<u8>,
        y: Vec<u8>,
    },
    P384 {
        x: Vec<u8>,
        y: Vec<u8>,
    },
    P521 {
        x: Vec<u8>,
        y: Vec<u8>,
    },
    K256 {
        x: Vec<u8>,
        y: Vec<u8>,
    },
    Rsa {
        n: Vec<u8>,
        e: Vec<u8>,
    },
    Ed25519 {
        x: Vec<u8>,
    },
    Ed448 {
        x: Vec<u8>,
    },
    /// `public` is the AKP `pub` value. For a composite it is `mldsaPK || tradPK`.
    Akp {
        alg: String,
        public: Vec<u8>,
    },
}

/// One key from a JWKS.
pub(crate) struct PublishedKey {
    pub kid: Option<String>,
    pub key: KeyMaterial,
}

/// Algorithms this wallet can check.
pub(crate) fn supported(alg: &str) -> bool {
    matches!(
        alg,
        "ES256"
            | "ES384"
            | "ES512"
            | "ES256K"
            | "RS256"
            | "RS384"
            | "RS512"
            | "PS256"
            | "PS384"
            | "PS512"
            | "EdDSA"
            | "ML-DSA-44"
            | "ML-DSA-65"
            | "ML-DSA-87"
            | "SLH-DSA-SHA2-128s"
            | "SLH-DSA-SHA2-128f"
            | "SLH-DSA-SHA2-192s"
            | "SLH-DSA-SHA2-192f"
            | "SLH-DSA-SHA2-256s"
            | "SLH-DSA-SHA2-256f"
            | "SLH-DSA-SHAKE-128s"
            | "SLH-DSA-SHAKE-128f"
            | "SLH-DSA-SHAKE-192s"
            | "SLH-DSA-SHAKE-192f"
            | "SLH-DSA-SHAKE-256s"
            | "SLH-DSA-SHAKE-256f"
            | "ML-DSA-44-ES256"
            | "ML-DSA-65-ES256"
            | "ML-DSA-87-ES384"
            | "ML-DSA-44-Ed25519"
            | "ML-DSA-65-Ed25519"
            | "ML-DSA-87-Ed448"
    )
}

/// The issuer's signature algorithm, as the credential names it.
///
/// A JWT or SD-JWT names it with the JWS `alg` header of the issuer part,
/// the segment before the first `~`. A Data Integrity document names it with
/// `proof.cryptosuite`, or with `proof.type` when the suite is absent.
/// Several proofs keep each distinct name, in order. `None` means the
/// document does not name an algorithm. The signature is not checked.
#[must_use]
pub fn signature_algorithm(format: &str, document: &str) -> Option<String> {
    let document = document.trim();
    if document.is_empty() {
        return None;
    }
    if document.starts_with('{') || is_data_integrity_format(format) {
        return linked_data_algorithm(document);
    }
    jws_algorithm(document)
}

fn is_data_integrity_format(format: &str) -> bool {
    let format = format.to_ascii_lowercase();
    format.contains("ldp") || format.contains("json-ld") || format.contains("bbs")
}

/// DER certificates from the issuer JWS `x5c` header, leaf first.
/// The signature is not checked. A document without `x5c` yields an empty list.
pub(crate) fn header_x5c(document: &str) -> Vec<Vec<u8>> {
    let Some(header) = jws_header(document) else {
        return Vec::new();
    };
    let Some(entries) = header.get("x5c").and_then(Json::as_array) else {
        return Vec::new();
    };
    let mut certificates = Vec::new();
    for entry in entries {
        let Some(text) = entry.as_str() else {
            continue;
        };
        if let Some(der) = super::b64::b64_decode(text) {
            certificates.push(der);
        }
    }
    certificates
}

fn jws_header(document: &str) -> Option<Json> {
    let document = document.trim();
    if document.is_empty() || document.starts_with('{') {
        return None;
    }
    let header = document.split('~').next()?.trim().split('.').next()?;
    if header.is_empty() {
        return None;
    }
    let header_bytes = super::b64::b64_decode(header)?;
    let header_text = std::str::from_utf8(&header_bytes).ok()?;
    Json::parse(header_text).ok()
}

fn jws_algorithm(document: &str) -> Option<String> {
    let compact = document.trim().split('~').next()?.trim();
    let mut parts = compact.split('.');
    let header = parts.next()?;
    let payload = parts.next()?;
    let signature = parts.next()?;
    if header.is_empty() || payload.is_empty() || signature.is_empty() || parts.next().is_some() {
        return None;
    }
    let header = jws_header(document)?;
    let alg = header.get("alg").and_then(Json::as_str)?;
    if alg.is_empty() {
        None
    } else {
        Some(alg.to_string())
    }
}

fn linked_data_algorithm(document: &str) -> Option<String> {
    let value = Json::parse(document).ok()?;
    let proof = value.get("proof")?;
    let mut names = Vec::new();
    match proof {
        Json::Array(proofs) => {
            for proof in proofs {
                push_algorithm(proof, &mut names);
            }
        }
        other => push_algorithm(other, &mut names),
    }
    if names.is_empty() {
        None
    } else {
        Some(names.join(", "))
    }
}

fn push_algorithm(proof: &Json, names: &mut Vec<String>) {
    let Some(name) = proof
        .get("cryptosuite")
        .and_then(Json::as_str)
        .filter(|name| !name.is_empty())
        .or_else(|| {
            proof
                .get("type")
                .and_then(Json::as_str)
                .filter(|name| !name.is_empty())
        })
    else {
        return;
    };
    if names.iter().any(|existing| existing == name) {
        return;
    }
    names.push(name.to_string());
}

/// The issuer compact JWS inside `document`.
pub(crate) fn open_issuer_jws(format: &str, document: &str) -> Result<IssuerJws, OpenError> {
    let format = format.to_ascii_lowercase();
    if format.contains("ldp") || format.contains("bbs") {
        return Err(OpenError::NotJws);
    }
    let trimmed = document.trim();
    if trimmed.starts_with('{') {
        return Err(OpenError::NotJws);
    }
    let compact = trimmed.split('~').next().unwrap_or("").trim();
    let parts: Vec<&str> = compact.split('.').collect();
    if parts.len() != 3 || parts.iter().any(|part| part.is_empty()) {
        return Err(OpenError::NotJws);
    }
    let header_bytes = b64::b64_decode(parts[0]).ok_or(OpenError::NotJws)?;
    let header_text = std::str::from_utf8(&header_bytes).map_err(|_| OpenError::NotJws)?;
    let header = Json::parse(header_text).map_err(|_| OpenError::NotJws)?;
    let alg = header
        .get("alg")
        .and_then(|value| value.as_str())
        .unwrap_or("")
        .to_string();
    if alg.is_empty() {
        return Err(OpenError::NotJws);
    }
    if !supported(&alg) {
        return Err(OpenError::Unsupported(alg));
    }
    let signature = b64::b64_decode(parts[2]).ok_or(OpenError::NotJws)?;
    let payload = b64::b64_decode(parts[1]).ok_or(OpenError::NotJws)?;
    let mut x5c = Vec::new();
    if let Some(entries) = header.get("x5c").and_then(|value| value.as_array()) {
        for entry in entries {
            let Some(text) = entry.as_str() else {
                continue;
            };
            if let Some(der) = b64::b64_decode(text) {
                x5c.push(der);
            }
        }
    }
    let kid = header
        .get("kid")
        .and_then(|value| value.as_str())
        .filter(|kid| !kid.is_empty())
        .map(str::to_string);
    Ok(IssuerJws {
        alg,
        kid,
        signing_input: format!("{}.{}", parts[0], parts[1]).into_bytes(),
        signature,
        payload,
        x5c,
    })
}

/// Read one public JWK. A private `d` is ignored. An AKP key without `alg`
/// is skipped, because that key type does not name an algorithm by itself.
pub(crate) fn key_from_jwk(jwk: &Json) -> Option<PublishedKey> {
    if jwk
        .get("use")
        .and_then(|value| value.as_str())
        .is_some_and(|use_| use_ != "sig")
    {
        return None;
    }
    let kid = jwk
        .get("kid")
        .and_then(|value| value.as_str())
        .filter(|kid| !kid.is_empty())
        .map(str::to_string);
    let kty = jwk
        .get("kty")
        .and_then(|value| value.as_str())
        .unwrap_or("");
    let key = match kty {
        "EC" => ec_jwk(jwk)?,
        "RSA" => {
            let n = b64::b64_decode(jwk.get("n").and_then(|value| value.as_str())?)?;
            let e = b64::b64_decode(jwk.get("e").and_then(|value| value.as_str())?)?;
            KeyMaterial::Rsa { n, e }
        }
        "OKP" => match jwk.get("crv").and_then(|value| value.as_str())? {
            "Ed25519" => KeyMaterial::Ed25519 {
                x: b64::b64_decode(jwk.get("x").and_then(|value| value.as_str())?)?,
            },
            "Ed448" => KeyMaterial::Ed448 {
                x: b64::b64_decode(jwk.get("x").and_then(|value| value.as_str())?)?,
            },
            _ => return None,
        },
        "AKP" => {
            let alg = jwk.get("alg").and_then(|value| value.as_str())?;
            if !supported(alg) {
                return None;
            }
            KeyMaterial::Akp {
                alg: alg.to_string(),
                public: b64::b64_decode(jwk.get("pub").and_then(|value| value.as_str())?)?,
            }
        }
        _ => return None,
    };
    Some(PublishedKey { kid, key })
}

/// RFC 7638 SHA-256 thumbprint URI of a public JWK.
///
/// Only the required members are hashed, in lexicographic order, with no
/// whitespace. A private `d` is left out. `x`, `y`, `n`, and `e` are written
/// as unpadded base64url, which is the form this wallet stores.
pub(crate) fn jwk_thumbprint_uri(jwk: &Json) -> Option<String> {
    let kty = jwk_token(jwk.get("kty")?.as_str()?)?;
    let canonical = match kty {
        "EC" => {
            let crv = jwk_token(jwk.get("crv")?.as_str()?)?;
            if !matches!(crv, "P-256" | "P-384" | "P-521" | "secp256k1") {
                return None;
            }
            let x = canonical_b64(jwk.get("x")?.as_str()?)?;
            let y = canonical_b64(jwk.get("y")?.as_str()?)?;
            format!(r#"{{"crv":"{crv}","kty":"EC","x":"{x}","y":"{y}"}}"#)
        }
        "RSA" => {
            let e = canonical_b64(jwk.get("e")?.as_str()?)?;
            let n = canonical_b64(jwk.get("n")?.as_str()?)?;
            format!(r#"{{"e":"{e}","kty":"RSA","n":"{n}"}}"#)
        }
        "OKP" => {
            let crv = jwk_token(jwk.get("crv")?.as_str()?)?;
            if !matches!(crv, "Ed25519" | "Ed448") {
                return None;
            }
            let x = canonical_b64(jwk.get("x")?.as_str()?)?;
            format!(r#"{{"crv":"{crv}","kty":"OKP","x":"{x}"}}"#)
        }
        _ => return None,
    };
    let digest = Sha256::digest(canonical.as_bytes());
    Some(format!(
        "{JWK_THUMBPRINT_PREFIX}{}",
        b64::b64url_encode(&digest)
    ))
}

/// A JWK member that is a short token, so it can sit inside the canonical
/// JSON without further escaping.
fn jwk_token(value: &str) -> Option<&str> {
    if value.is_empty()
        || !value
            .bytes()
            .all(|byte| matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_'))
    {
        return None;
    }
    Some(value)
}

fn canonical_b64(value: &str) -> Option<String> {
    let bytes = b64::b64_decode(value)?;
    if bytes.is_empty() {
        return None;
    }
    Some(b64::b64url_encode(&bytes))
}

fn ec_jwk(jwk: &Json) -> Option<KeyMaterial> {
    let x = b64::b64_decode(jwk.get("x").and_then(|value| value.as_str())?)?;
    let y = b64::b64_decode(jwk.get("y").and_then(|value| value.as_str())?)?;
    Some(match jwk.get("crv").and_then(|value| value.as_str())? {
        "P-256" => KeyMaterial::P256 { x, y },
        "P-384" => KeyMaterial::P384 { x, y },
        "P-521" => KeyMaterial::P521 { x, y },
        "secp256k1" => KeyMaterial::K256 { x, y },
        _ => return None,
    })
}

/// `true` when `signature` is valid for `signing_input` under `alg` and `key`.
pub(crate) fn verifies(
    alg: &str,
    key: &KeyMaterial,
    signing_input: &[u8],
    signature: &[u8],
) -> bool {
    match (alg, key) {
        ("ES256", KeyMaterial::P256 { x, y }) => verify_p256(x, y, signing_input, signature),
        ("ES384", KeyMaterial::P384 { x, y }) => verify_p384(x, y, signing_input, signature),
        ("ES512", KeyMaterial::P521 { x, y }) => verify_p521(x, y, signing_input, signature),
        ("ES256K", KeyMaterial::K256 { x, y }) => verify_k256(x, y, signing_input, signature),
        ("RS256", KeyMaterial::Rsa { n, e }) => verify_pkcs1_sha256(n, e, signing_input, signature),
        ("RS384", KeyMaterial::Rsa { n, e }) => verify_pkcs1_sha384(n, e, signing_input, signature),
        ("RS512", KeyMaterial::Rsa { n, e }) => verify_pkcs1_sha512(n, e, signing_input, signature),
        ("PS256", KeyMaterial::Rsa { n, e }) => verify_pss_sha256(n, e, signing_input, signature),
        ("PS384", KeyMaterial::Rsa { n, e }) => verify_pss_sha384(n, e, signing_input, signature),
        ("PS512", KeyMaterial::Rsa { n, e }) => verify_pss_sha512(n, e, signing_input, signature),
        ("EdDSA", KeyMaterial::Ed25519 { x }) => verify_ed25519(x, signing_input, signature),
        ("EdDSA", KeyMaterial::Ed448 { x }) => verify_ed448(x, signing_input, signature),
        (
            _,
            KeyMaterial::Akp {
                alg: key_alg,
                public,
            },
        ) if key_alg == alg => verify_pq(alg, public, signing_input, signature),
        _ => false,
    }
}

fn verify_p256(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    if x.len() != 32 || y.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let Ok(point) = p256::EncodedPoint::from_bytes(&sec1) else {
        return false;
    };
    let Ok(key) = p256::ecdsa::VerifyingKey::from_encoded_point(&point) else {
        return false;
    };
    let Ok(signature) = p256::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

fn verify_p384(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p384::ecdsa::signature::Verifier;
    if x.len() != 48 || y.len() != 48 || signature.len() != 96 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(97);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let Ok(key) = p384::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(signature) = p384::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

fn verify_p521(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p521::ecdsa::signature::Verifier;
    if x.len() != 66 || y.len() != 66 || signature.len() != 132 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(133);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let Ok(key) = p521::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(signature) = p521::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

fn verify_k256(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use k256::ecdsa::signature::Verifier;
    if x.len() != 32 || y.len() != 32 || signature.len() != 64 {
        return false;
    }
    let mut sec1 = Vec::with_capacity(65);
    sec1.push(0x04);
    sec1.extend_from_slice(x);
    sec1.extend_from_slice(y);
    let Ok(key) = k256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1) else {
        return false;
    };
    let Ok(signature) = k256::ecdsa::Signature::from_slice(signature) else {
        return false;
    };
    key.verify(message, &signature).is_ok()
}

fn rsa_public(n: &[u8], e: &[u8]) -> Option<rsa::RsaPublicKey> {
    let modulus = rsa::BigUint::from_bytes_be(n);
    let exponent = rsa::BigUint::from_bytes_be(e);
    rsa::RsaPublicKey::new(modulus, exponent).ok()
}

fn verify_pkcs1_sha256(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_pkcs1::<sha2::Sha256>(n, e, message, signature)
}

fn verify_pkcs1_sha384(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_pkcs1::<sha2::Sha384>(n, e, message, signature)
}

fn verify_pkcs1_sha512(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_pkcs1::<sha2::Sha512>(n, e, message, signature)
}

fn verify_pkcs1<D>(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool
where
    D: sha2::digest::Digest + rsa::pkcs8::AssociatedOid,
{
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let Some(key) = rsa_public(n, e) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature) else {
        return false;
    };
    VerifyingKey::<D>::new(key)
        .verify(message, &signature)
        .is_ok()
}

fn verify_pss_sha256(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_pss::<sha2::Sha256>(n, e, message, signature)
}

fn verify_pss_sha384(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_pss::<sha2::Sha384>(n, e, message, signature)
}

fn verify_pss_sha512(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool {
    verify_pss::<sha2::Sha512>(n, e, message, signature)
}

fn verify_pss<D>(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool
where
    D: sha2::digest::Digest + sha2::digest::FixedOutputReset,
{
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let Some(key) = rsa_public(n, e) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(signature) else {
        return false;
    };
    VerifyingKey::<D>::new(key)
        .verify(message, &signature)
        .is_ok()
}

fn verify_ed25519(x: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use ed25519_dalek::Verifier;
    let Ok(raw_key) = <[u8; 32]>::try_from(x) else {
        return false;
    };
    let Ok(raw_sig) = <[u8; 64]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&raw_key) else {
        return false;
    };
    let signature = ed25519_dalek::Signature::from_bytes(&raw_sig);
    key.verify(message, &signature).is_ok()
}

fn verify_ed448(x: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(raw_key) = <[u8; 57]>::try_from(x) else {
        return false;
    };
    let Ok(raw_sig) = <[u8; 114]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = ed448_goldilocks_plus::ed448::VerifyingKey::from_bytes(&raw_key) else {
        return false;
    };
    let Ok(signature) = ed448_goldilocks_plus::ed448::Signature::from_bytes(&raw_sig) else {
        return false;
    };
    key.verify_raw(&signature, message).is_ok()
}

fn verify_pq(alg: &str, public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    match alg {
        "ML-DSA-44" => verify_ml_dsa_44(public, signature, message, &[]),
        "ML-DSA-65" => verify_ml_dsa_65(public, signature, message, &[]),
        "ML-DSA-87" => verify_ml_dsa_87(public, signature, message, &[]),
        "SLH-DSA-SHA2-128s" => verify_slh_sha2_128s(public, signature, message),
        "SLH-DSA-SHA2-128f" => verify_slh_sha2_128f(public, signature, message),
        "SLH-DSA-SHA2-192s" => verify_slh_sha2_192s(public, signature, message),
        "SLH-DSA-SHA2-192f" => verify_slh_sha2_192f(public, signature, message),
        "SLH-DSA-SHA2-256s" => verify_slh_sha2_256s(public, signature, message),
        "SLH-DSA-SHA2-256f" => verify_slh_sha2_256f(public, signature, message),
        "SLH-DSA-SHAKE-128s" => verify_slh_shake_128s(public, signature, message),
        "SLH-DSA-SHAKE-128f" => verify_slh_shake_128f(public, signature, message),
        "SLH-DSA-SHAKE-192s" => verify_slh_shake_192s(public, signature, message),
        "SLH-DSA-SHAKE-192f" => verify_slh_shake_192f(public, signature, message),
        "SLH-DSA-SHAKE-256s" => verify_slh_shake_256s(public, signature, message),
        "SLH-DSA-SHAKE-256f" => verify_slh_shake_256f(public, signature, message),
        _ => verify_composite(alg, public, message, signature),
    }
}

fn verify_ml_dsa_44(public: &[u8], signature: &[u8], message: &[u8], ctx: &[u8]) -> bool {
    use fips204::traits::{SerDes, Verifier};
    let Ok(public) = <[u8; fips204::ml_dsa_44::PK_LEN]>::try_from(public) else {
        return false;
    };
    let Ok(signature) = <[u8; fips204::ml_dsa_44::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = fips204::ml_dsa_44::PublicKey::try_from_bytes(public) else {
        return false;
    };
    key.verify(message, &signature, ctx)
}

fn verify_ml_dsa_65(public: &[u8], signature: &[u8], message: &[u8], ctx: &[u8]) -> bool {
    use fips204::traits::{SerDes, Verifier};
    let Ok(public) = <[u8; fips204::ml_dsa_65::PK_LEN]>::try_from(public) else {
        return false;
    };
    let Ok(signature) = <[u8; fips204::ml_dsa_65::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = fips204::ml_dsa_65::PublicKey::try_from_bytes(public) else {
        return false;
    };
    key.verify(message, &signature, ctx)
}

fn verify_ml_dsa_87(public: &[u8], signature: &[u8], message: &[u8], ctx: &[u8]) -> bool {
    use fips204::traits::{SerDes, Verifier};
    let Ok(public) = <[u8; fips204::ml_dsa_87::PK_LEN]>::try_from(public) else {
        return false;
    };
    let Ok(signature) = <[u8; fips204::ml_dsa_87::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(key) = fips204::ml_dsa_87::PublicKey::try_from_bytes(public) else {
        return false;
    };
    key.verify(message, &signature, ctx)
}

macro_rules! slh_verify {
    ($module:ident, $public:expr, $signature:expr, $message:expr) => {{
        use fips205::traits::{SerDes, Verifier};
        let Ok(public) = <[u8; $module::PK_LEN]>::try_from($public) else {
            return false;
        };
        let Ok(signature) = <[u8; $module::SIG_LEN]>::try_from($signature) else {
            return false;
        };
        let Ok(key) = $module::PublicKey::try_from_bytes(&public) else {
            return false;
        };
        key.verify($message, &signature, &[])
    }};
}

fn verify_slh_sha2_128s(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_128s as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_sha2_128f(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_128f as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_sha2_192s(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_192s as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_sha2_192f(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_192f as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_sha2_256s(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_256s as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_sha2_256f(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_sha2_256f as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_shake_128s(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_shake_128s as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_shake_128f(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_shake_128f as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_shake_192s(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_shake_192s as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_shake_192f(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_shake_192f as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_shake_256s(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_shake_256s as alg;
    slh_verify!(alg, public, signature, message)
}
fn verify_slh_shake_256f(public: &[u8], signature: &[u8], message: &[u8]) -> bool {
    use fips205::slh_dsa_shake_256f as alg;
    slh_verify!(alg, public, signature, message)
}

enum Half {
    P256,
    P384,
    Ed25519,
    Ed448,
}

enum Lattice {
    D44,
    D65,
    D87,
}

#[derive(Clone, Copy)]
enum Prehash {
    Sha256,
    Sha512,
    Shake64,
}

struct Composite {
    lattice: Lattice,
    half: Half,
    prehash: Prehash,
    label: &'static str,
}

fn composite_of(alg: &str) -> Option<Composite> {
    Some(match alg {
        "ML-DSA-44-ES256" => Composite {
            lattice: Lattice::D44,
            half: Half::P256,
            prehash: Prehash::Sha256,
            label: "COMPSIG-MLDSA44-ECDSA-P256-SHA256",
        },
        "ML-DSA-65-ES256" => Composite {
            lattice: Lattice::D65,
            half: Half::P256,
            prehash: Prehash::Sha512,
            label: "COMPSIG-MLDSA65-ECDSA-P256-SHA512",
        },
        "ML-DSA-87-ES384" => Composite {
            lattice: Lattice::D87,
            half: Half::P384,
            prehash: Prehash::Sha512,
            label: "COMPSIG-MLDSA87-ECDSA-P384-SHA512",
        },
        "ML-DSA-44-Ed25519" => Composite {
            lattice: Lattice::D44,
            half: Half::Ed25519,
            prehash: Prehash::Sha512,
            label: "COMPSIG-MLDSA44-Ed25519-SHA512",
        },
        "ML-DSA-65-Ed25519" => Composite {
            lattice: Lattice::D65,
            half: Half::Ed25519,
            prehash: Prehash::Sha512,
            label: "COMPSIG-MLDSA65-Ed25519-SHA512",
        },
        "ML-DSA-87-Ed448" => Composite {
            lattice: Lattice::D87,
            half: Half::Ed448,
            prehash: Prehash::Shake64,
            label: "COMPSIG-MLDSA87-Ed448-SHAKE256",
        },
        _ => return None,
    })
}

fn verify_composite(alg: &str, public: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Some(composite) = composite_of(alg) else {
        return false;
    };
    let (ml_pub, ml_sig) = match composite.lattice {
        Lattice::D44 => (fips204::ml_dsa_44::PK_LEN, fips204::ml_dsa_44::SIG_LEN),
        Lattice::D65 => (fips204::ml_dsa_65::PK_LEN, fips204::ml_dsa_65::SIG_LEN),
        Lattice::D87 => (fips204::ml_dsa_87::PK_LEN, fips204::ml_dsa_87::SIG_LEN),
    };
    let (trad_pub, trad_sig) = match composite.half {
        Half::P256 => (64, 64),
        Half::P384 => (96, 96),
        Half::Ed25519 => (32, 64),
        Half::Ed448 => (57, 114),
    };
    if public.len() != ml_pub + trad_pub || signature.len() != ml_sig + trad_sig {
        return false;
    }
    let signed = composite_message(composite.label, composite.prehash, message);
    let ml_ok = match composite.lattice {
        Lattice::D44 => verify_ml_dsa_44(
            &public[..ml_pub],
            &signature[..ml_sig],
            &signed,
            composite.label.as_bytes(),
        ),
        Lattice::D65 => verify_ml_dsa_65(
            &public[..ml_pub],
            &signature[..ml_sig],
            &signed,
            composite.label.as_bytes(),
        ),
        Lattice::D87 => verify_ml_dsa_87(
            &public[..ml_pub],
            &signature[..ml_sig],
            &signed,
            composite.label.as_bytes(),
        ),
    };
    if !ml_ok {
        return false;
    }
    let trad_public = &public[ml_pub..];
    let trad_signature = &signature[ml_sig..];
    match composite.half {
        Half::P256 => verify_p256(
            &trad_public[..32],
            &trad_public[32..],
            &signed,
            trad_signature,
        ),
        Half::P384 => verify_p384(
            &trad_public[..48],
            &trad_public[48..],
            &signed,
            trad_signature,
        ),
        Half::Ed25519 => verify_ed25519(trad_public, &signed, trad_signature),
        Half::Ed448 => verify_ed448(trad_public, &signed, trad_signature),
    }
}

fn composite_message(label: &str, prehash: Prehash, message: &[u8]) -> Vec<u8> {
    let mut out = b"CompositeAlgorithmSignatures2025".to_vec();
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    out.extend(prehash_bytes(prehash, message));
    out
}

fn prehash_bytes(prehash: Prehash, message: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    match prehash {
        Prehash::Sha256 => sha2::Sha256::digest(message).to_vec(),
        Prehash::Sha512 => sha2::Sha512::digest(message).to_vec(),
        Prehash::Shake64 => {
            use sha3::digest::{ExtendableOutput, Update, XofReader};
            let mut hasher = sha3::Shake256::default();
            hasher.update(message);
            let mut reader = hasher.finalize_xof();
            let mut out = [0u8; 64];
            reader.read(&mut out);
            out.to_vec()
        }
    }
}

/// DER ECDSA (`SEQUENCE { INTEGER r, INTEGER s }`) as fixed-width R||S.
/// Certificate signatures use this form. A JWS already carries R||S.
pub(crate) fn der_ecdsa_to_rs(der: &[u8], coord: usize) -> Option<Vec<u8>> {
    let body = der_body(der, 0x30)?;
    let (r, rest) = der_integer(body)?;
    let (s, rest) = der_integer(rest)?;
    if !rest.is_empty() {
        return None;
    }
    let mut out = vec![0u8; coord * 2];
    copy_integer(&mut out[..coord], r)?;
    copy_integer(&mut out[coord..], s)?;
    Some(out)
}

fn der_body(der: &[u8], tag: u8) -> Option<&[u8]> {
    if der.first().copied() != Some(tag) {
        return None;
    }
    let (len, header) = der_length(&der[1..])?;
    let rest = der.get(1 + header..)?;
    if rest.len() != len {
        return None;
    }
    Some(rest)
}

fn der_integer(der: &[u8]) -> Option<(&[u8], &[u8])> {
    if der.first().copied() != Some(0x02) {
        return None;
    }
    let (len, header) = der_length(der.get(1..)?)?;
    let start = 1 + header;
    let end = start + len;
    if der.len() < end {
        return None;
    }
    Some((&der[start..end], &der[end..]))
}

fn der_length(bytes: &[u8]) -> Option<(usize, usize)> {
    let first = *bytes.first()?;
    if first < 0x80 {
        return Some((first as usize, 1));
    }
    let count = (first & 0x7f) as usize;
    if count == 0 || count > 2 || bytes.len() < 1 + count {
        return None;
    }
    let mut len = 0usize;
    for byte in &bytes[1..=count] {
        len = (len << 8) | *byte as usize;
    }
    Some((len, 1 + count))
}

fn copy_integer(dest: &mut [u8], integer: &[u8]) -> Option<()> {
    let bytes = match integer {
        [0x00, rest @ ..] => rest,
        other => other,
    };
    if bytes.len() > dest.len() || (bytes.is_empty() && !integer.is_empty()) {
        return None;
    }
    if bytes.is_empty() {
        return Some(());
    }
    let start = dest.len() - bytes.len();
    dest[start..].copy_from_slice(bytes);
    Some(())
}

#[cfg(test)]
mod tests {
    use super::{
        jwk_thumbprint_uri, open_issuer_jws, signature_algorithm, verifies, KeyMaterial, OpenError,
        JWK_THUMBPRINT_PREFIX,
    };

    fn compact(alg: &str, signature: &str) -> String {
        let header = crate::wallet::b64::b64url_encode(format!(r#"{{"alg":"{alg}"}}"#).as_bytes());
        let payload = crate::wallet::b64::b64url_encode(b"{}");
        format!("{header}.{payload}.{signature}")
    }

    #[test]
    fn the_issuer_algorithm_is_named_before_disclosures() {
        let document = format!(
            "{}~eyJhbGciOiJFUzM4NCJ9.e30.holder",
            compact("ES256", "sig")
        );
        assert_eq!(
            signature_algorithm("dc+sd-jwt", &document).as_deref(),
            Some("ES256")
        );
        assert_eq!(
            signature_algorithm("jwt_vc_json", &compact("HS256", "sig")).as_deref(),
            Some("HS256")
        );
        assert_eq!(signature_algorithm("dc+sd-jwt", "not-a-credential"), None);
        assert_eq!(signature_algorithm("dc+sd-jwt", ""), None);
    }

    #[test]
    fn a_data_integrity_proof_names_its_cryptosuite() {
        let one = r#"{"type":["VerifiableCredential"],"proof":{"type":"DataIntegrityProof","cryptosuite":"ecdsa-rdfc-2019"}}"#;
        assert_eq!(
            signature_algorithm("ldp_vc", one).as_deref(),
            Some("ecdsa-rdfc-2019")
        );
        let typed = r#"{"proof":{"type":"Ed25519Signature2020"}}"#;
        assert_eq!(
            signature_algorithm("ldp_vc", typed).as_deref(),
            Some("Ed25519Signature2020")
        );
        let several = r#"{"proof":[{"type":"DataIntegrityProof","cryptosuite":"ecdsa-rdfc-2019"},{"type":"DataIntegrityProof","cryptosuite":"eddsa-rdfc-2022"},{"cryptosuite":"ecdsa-rdfc-2019"}]}"#;
        assert_eq!(
            signature_algorithm("ldp_vc", several).as_deref(),
            Some("ecdsa-rdfc-2019, eddsa-rdfc-2022")
        );
        assert_eq!(
            signature_algorithm("ldp_vc", r#"{"type":"VerifiableCredential"}"#),
            None
        );
    }

    fn es256_material(signing: &p256::ecdsa::SigningKey) -> KeyMaterial {
        let point = signing.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        KeyMaterial::P256 {
            x: bytes[1..33].to_vec(),
            y: bytes[33..65].to_vec(),
        }
    }

    #[test]
    fn es256_round_trip() {
        use p256::ecdsa::signature::Signer;
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let message = b"header.payload";
        let signature: p256::ecdsa::Signature = signing.sign(message);
        let key = es256_material(&signing);
        assert!(verifies("ES256", &key, message, &signature.to_bytes()));
        let mut bad = signature.to_bytes().to_vec();
        bad[0] ^= 0xff;
        assert!(!verifies("ES256", &key, message, &bad));
    }

    #[test]
    fn rs256_round_trip() {
        use rsa::signature::{SignatureEncoding, Signer};
        use rsa::traits::PublicKeyParts;
        let private = rsa::RsaPrivateKey::new(&mut rand_core::OsRng, 2048).unwrap();
        let n = private.n().to_bytes_be();
        let e = private.e().to_bytes_be();
        let signing = rsa::pkcs1v15::SigningKey::<sha2::Sha256>::new(private);
        let message = b"header.payload";
        let signature = signing.sign(message);
        let key = KeyMaterial::Rsa { n, e };
        assert!(verifies("RS256", &key, message, &signature.to_vec()));
        let mut bad = signature.to_vec();
        bad[0] ^= 0xff;
        assert!(!verifies("RS256", &key, message, &bad));
    }

    #[test]
    fn ed25519_round_trip() {
        use ed25519_dalek::Signer;
        let signing = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let message = b"header.payload";
        let signature = signing.sign(message);
        let key = KeyMaterial::Ed25519 {
            x: signing.verifying_key().to_bytes().to_vec(),
        };
        assert!(verifies("EdDSA", &key, message, &signature.to_bytes()));
    }

    #[test]
    fn ed448_round_trip() {
        let secret = ed448_goldilocks_plus::ed448::SecretKey::from([9u8; 57]);
        let signing = ed448_goldilocks_plus::ed448::SigningKey::from_bytes(&secret);
        let message = b"header.payload";
        let signature = signing.sign_raw(message);
        let key = KeyMaterial::Ed448 {
            x: signing.verifying_key().to_bytes().to_vec(),
        };
        assert!(verifies("EdDSA", &key, message, &signature.to_bytes()));
    }

    #[test]
    fn ml_dsa_44_round_trip() {
        use fips204::traits::{KeyGen, SerDes, Signer};
        let (public, secret) = fips204::ml_dsa_44::KG::try_keygen().unwrap();
        let message = b"header.payload";
        let signature = secret.try_sign(message, &[]).unwrap();
        let key = KeyMaterial::Akp {
            alg: "ML-DSA-44".to_string(),
            public: public.into_bytes().to_vec(),
        };
        assert!(verifies("ML-DSA-44", &key, message, &signature));
    }

    #[test]
    fn slh_dsa_sha2_128s_round_trip() {
        use fips205::traits::{SerDes, Signer};
        let (public, secret) = fips205::slh_dsa_sha2_128s::try_keygen().unwrap();
        let message = b"header.payload";
        let signature = secret.try_sign(message, &[], false).unwrap();
        let key = KeyMaterial::Akp {
            alg: "SLH-DSA-SHA2-128s".to_string(),
            public: public.into_bytes().to_vec(),
        };
        assert!(verifies("SLH-DSA-SHA2-128s", &key, message, &signature));
    }

    #[test]
    fn composite_ml_dsa_44_es256_round_trip() {
        use fips204::traits::{KeyGen, SerDes, Signer as MlSigner};
        use p256::ecdsa::signature::Signer as P256Signer;
        use sha2::Digest;
        let (public, secret) = fips204::ml_dsa_44::KG::try_keygen().unwrap();
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let message = b"header.payload";
        let label = "COMPSIG-MLDSA44-ECDSA-P256-SHA256";
        let mut signed = b"CompositeAlgorithmSignatures2025".to_vec();
        signed.extend_from_slice(label.as_bytes());
        signed.push(0);
        signed.extend(sha2::Sha256::digest(message));
        let ml_signature = secret.try_sign(&signed, label.as_bytes()).unwrap();
        let trad: p256::ecdsa::Signature = signing.sign(&signed);
        let mut signature = ml_signature.to_vec();
        signature.extend_from_slice(&trad.to_bytes());
        let point = signing.verifying_key().to_encoded_point(false);
        let bytes = point.as_bytes();
        let mut material = public.into_bytes().to_vec();
        material.extend_from_slice(&bytes[1..65]);
        let key = KeyMaterial::Akp {
            alg: "ML-DSA-44-ES256".to_string(),
            public: material,
        };
        assert!(verifies("ML-DSA-44-ES256", &key, message, &signature));
        let last = signature.len() - 1;
        signature[last] ^= 0xff;
        assert!(!verifies("ML-DSA-44-ES256", &key, message, &signature));
    }

    #[test]
    fn a_jwk_thumbprint_uses_the_required_members() {
        // RFC 7638 section 3.1.
        let rsa = crate::protocol::Json::parse(
            r#"{"kty":"RSA","n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw","e":"AQAB"}"#,
        )
        .unwrap();
        assert_eq!(
            jwk_thumbprint_uri(&rsa).as_deref(),
            Some("urn:ietf:params:oauth:jwk-thumbprint:sha-256:NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs")
        );
        let ordered = crate::protocol::Json::parse(
            r#"{"y":"Ag","x":"AQ","use":"sig","kty":"EC","crv":"P-256","d":"Aw"}"#,
        )
        .unwrap();
        let plain = crate::protocol::Json::parse(r#"{"crv":"P-256","kty":"EC","x":"AQ","y":"Ag"}"#)
            .unwrap();
        let thumb = jwk_thumbprint_uri(&ordered).unwrap();
        assert_eq!(thumb, jwk_thumbprint_uri(&plain).unwrap());
        assert!(thumb.starts_with(JWK_THUMBPRINT_PREFIX));
        assert_eq!(thumb.len(), JWK_THUMBPRINT_PREFIX.len() + 43);
        assert!(jwk_thumbprint_uri(
            &crate::protocol::Json::parse(r#"{"kty":"oct","k":"YQ"}"#).unwrap()
        )
        .is_none());
    }

    #[test]
    fn a_json_ld_document_is_not_a_jws() {
        let err = open_issuer_jws("ldp_vc", r#"{"type":"VerifiableCredential"}"#).unwrap_err();
        assert!(matches!(err, OpenError::NotJws));
        let err = open_issuer_jws("bbs-2023", "header.payload.signature").unwrap_err();
        assert!(matches!(err, OpenError::NotJws));
    }
}
