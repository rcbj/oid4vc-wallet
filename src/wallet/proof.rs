//! An OpenID4VCI proof of possession, signed here.
//!
//! The proof is a compact JWS. `typ` is `openid4vci-proof+jwt`, `alg` is
//! ES256, and the header carries the P-256 public key as a JWK. The signature
//! is the raw R||S encoding from RFC 7518. No JOSE crate is used.

use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;

use crate::protocol::Json;

/// A key this wallet just created, and the proof an issuer asked for.
pub(crate) struct Proof {
    /// Compact JWS the credential request sends in `proofs.jwt`.
    pub jwt: String,
    /// Private JWK, sealed with the credential so a later presentation can
    /// use the same key. It is not shown in the window.
    pub private_jwk: String,
}

/// Sign a proof whose `aud` is the credential issuer and whose `nonce` is
/// the issuer's `c_nonce`. `iat` is seconds since the Unix epoch.
pub(crate) fn sign_proof(audience: &str, nonce: &str, iat: u64) -> Proof {
    let signing = SigningKey::random(&mut OsRng);
    let public = signing.verifying_key().to_encoded_point(false);
    let x = b64url(public.x().expect("an uncompressed point has x"));
    let y = b64url(public.y().expect("an uncompressed point has y"));
    let d = b64url(signing.to_bytes().as_slice());
    let public_jwk = Json::Object(vec![
        ("kty".to_string(), Json::String("EC".to_string())),
        ("crv".to_string(), Json::String("P-256".to_string())),
        ("x".to_string(), Json::String(x.clone())),
        ("y".to_string(), Json::String(y.clone())),
    ]);
    let header = Json::Object(vec![
        ("alg".to_string(), Json::String("ES256".to_string())),
        (
            "typ".to_string(),
            Json::String("openid4vci-proof+jwt".to_string()),
        ),
        ("jwk".to_string(), public_jwk),
    ]);
    let payload = Json::Object(vec![
        ("aud".to_string(), Json::String(audience.to_string())),
        ("iat".to_string(), Json::Number(iat.to_string())),
        ("nonce".to_string(), Json::String(nonce.to_string())),
    ]);
    let signing_input = format!(
        "{}.{}",
        b64url(header.to_string().as_bytes()),
        b64url(payload.to_string().as_bytes())
    );
    let signature: Signature = signing.sign(signing_input.as_bytes());
    let jwt = format!(
        "{signing_input}.{}",
        b64url(signature.to_bytes().as_slice())
    );
    let private_jwk = Json::Object(vec![
        ("kty".to_string(), Json::String("EC".to_string())),
        ("crv".to_string(), Json::String("P-256".to_string())),
        ("x".to_string(), Json::String(x)),
        ("y".to_string(), Json::String(y)),
        ("d".to_string(), Json::String(d)),
    ])
    .to_string();
    Proof { jwt, private_jwk }
}

fn b64url(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    let rest = bytes.len() - index;
    if rest == 1 {
        let n = u32::from(bytes[index]) << 16;
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
    } else if rest == 2 {
        let n = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Verifier;
    use p256::ecdsa::{Signature, VerifyingKey};

    #[test]
    fn the_proof_verifies_with_the_jwk_in_its_header() {
        let proof = sign_proof("https://localhost:8081", "nonce-1", 1_700_000_000);
        let mut parts = proof.jwt.split('.');
        let header = decode_json(parts.next().unwrap());
        let payload = decode_json(parts.next().unwrap());
        let signature = b64url_decode(parts.next().unwrap());
        assert!(parts.next().is_none());
        assert_eq!(
            header.get("typ").and_then(|value| value.as_str()),
            Some("openid4vci-proof+jwt")
        );
        assert_eq!(
            payload.get("aud").and_then(|value| value.as_str()),
            Some("https://localhost:8081")
        );
        assert_eq!(
            payload.get("nonce").and_then(|value| value.as_str()),
            Some("nonce-1")
        );
        let jwk = header.get("jwk").unwrap();
        assert!(jwk.get("d").is_none());
        let x = b64url_decode(jwk.get("x").unwrap().as_str().unwrap());
        let y = b64url_decode(jwk.get("y").unwrap().as_str().unwrap());
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&x);
        sec1.extend_from_slice(&y);
        let point = p256::EncodedPoint::from_bytes(&sec1).unwrap();
        let key = VerifyingKey::from_encoded_point(&point).unwrap();
        let signing_input = {
            let mut split = proof.jwt.rsplitn(2, '.');
            let _signature = split.next();
            split.next().unwrap().to_string()
        };
        let signature = Signature::from_slice(&signature).unwrap();
        assert!(key.verify(signing_input.as_bytes(), &signature).is_ok());
        let stored = Json::parse(&proof.private_jwk).unwrap();
        assert!(
            stored
                .get("d")
                .and_then(|value| value.as_str())
                .unwrap()
                .len()
                > 10
        );
    }

    fn decode_json(part: &str) -> Json {
        let bytes = b64url_decode(part);
        Json::parse(std::str::from_utf8(&bytes).unwrap()).unwrap()
    }

    fn b64url_decode(text: &str) -> Vec<u8> {
        fn value(byte: u8) -> u8 {
            match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => panic!("bad base64url"),
            }
        }
        let bytes = text.as_bytes();
        let mut out = Vec::new();
        let mut index = 0;
        while index + 4 <= bytes.len() {
            let n = (u32::from(value(bytes[index])) << 18)
                | (u32::from(value(bytes[index + 1])) << 12)
                | (u32::from(value(bytes[index + 2])) << 6)
                | u32::from(value(bytes[index + 3]));
            let [_, first, second, third] = n.to_be_bytes();
            out.extend_from_slice(&[first, second, third]);
            index += 4;
        }
        let rest = bytes.len() - index;
        if rest == 2 {
            let n =
                (u32::from(value(bytes[index])) << 18) | (u32::from(value(bytes[index + 1])) << 12);
            out.push(n.to_be_bytes()[1]);
        } else if rest == 3 {
            let n = (u32::from(value(bytes[index])) << 18)
                | (u32::from(value(bytes[index + 1])) << 12)
                | (u32::from(value(bytes[index + 2])) << 6);
            let [_, first, second, _] = n.to_be_bytes();
            out.extend_from_slice(&[first, second]);
        }
        out
    }
}
