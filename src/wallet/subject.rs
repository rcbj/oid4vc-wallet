//! The subject a self-issued ID Token names (SIOPv2 section 8).
//!
//! The JWK Thumbprint syntax is the default: `iss` and `sub` are the RFC 9278
//! thumbprint URI of the key, and the token carries the public key in
//! `sub_jwk`. The three DID choices name the same self-issued key with a DID
//! instead. `did:jwk` is the public JWK, base64url encoded, and its one
//! verification method is `#0`. `did:key` is the multicodec `p256-pub` code
//! (`0x1200`, the varint `0x80 0x24`) and the compressed point, base58btc
//! encoded with the multibase prefix `z`. Its one verification method is the
//! fragment that repeats that multibase value. A `did:web` is a document the
//! person publishes over https at the URL the DID names (DID Web Method
//! section 3.2). This wallet builds that document from the self-issued key.
//!
//! The choice is one line in `$XDG_CONFIG_HOME/oid4vc-wallet/self-issued-subject`.
//! The directory is mode `0700` and the file is mode `0600`. A missing file
//! is the JWK Thumbprint syntax.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::i18n::{t, t_args};
use crate::protocol::Json;

use super::b64;

/// The Subject Syntax Type value for the JWK Thumbprint syntax (SIOPv2 section 7.5).
pub const THUMBPRINT_TYPE: &str = "urn:ietf:params:oauth:jwk-thumbprint";

/// The multicodec `p256-pub` code 0x1200, as its unsigned varint.
const P256_PUB: [u8; 2] = [0x80, 0x24];

const BASE58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// How a self-issued ID Token names its subject.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum SubjectSyntax {
    /// `urn:ietf:params:oauth:jwk-thumbprint:sha-256:...` with `sub_jwk`.
    #[default]
    JwkThumbprint,
    /// `did:jwk:...`, resolved from the identifier.
    DidJwk,
    /// `did:key:zDn...`, resolved from the identifier.
    DidKey,
    /// A `did:web` the person publishes. The value is the DID.
    DidWeb(String),
}

impl SubjectSyntax {
    /// The Subject Syntax Type a verifier lists in `subject_syntax_types_supported`.
    pub fn type_value(&self) -> &'static str {
        match self {
            Self::JwkThumbprint => THUMBPRINT_TYPE,
            Self::DidJwk => "did:jwk",
            Self::DidKey => "did:key",
            Self::DidWeb(_) => "did:web",
        }
    }

    /// `true` for the three DID choices.
    pub fn is_did(&self) -> bool {
        !matches!(self, Self::JwkThumbprint)
    }

    /// The line kept in the settings file.
    fn line(&self) -> String {
        match self {
            Self::DidWeb(did) => did.clone(),
            other => other.type_value().to_string(),
        }
    }

    /// The setting a line names. A `did:web` must be well formed.
    fn from_line(line: &str) -> Option<Self> {
        match line {
            THUMBPRINT_TYPE => Some(Self::JwkThumbprint),
            "did:jwk" => Some(Self::DidJwk),
            "did:key" => Some(Self::DidKey),
            other => did_web_url(other).map(|_| Self::DidWeb(other.to_string())),
        }
    }
}

/// Does a verifier's `subject_syntax_types_supported` list allow `type_value`?
/// SIOPv2 section 7.5: a DID method is `did:` and the method name, and `did`
/// alone means every DID method.
pub(crate) fn accepts(supported: &[String], type_value: &str) -> bool {
    supported
        .iter()
        .any(|value| value == type_value || (value == "did" && type_value.starts_with("did:")))
}

/// The `did:jwk` of a P-256 public key whose coordinates are base64url.
/// The JWK is `{"kty","crv","x","y"}` in that order.
pub(crate) fn did_jwk(x: &str, y: &str) -> String {
    let jwk = format!(r#"{{"kty":"EC","crv":"P-256","x":"{x}","y":"{y}"}}"#);
    format!("did:jwk:{}", b64::b64url_encode(jwk.as_bytes()))
}

/// The verification method of a `did:jwk`: its one method is `#0`.
pub(crate) fn did_jwk_kid(did: &str) -> String {
    format!("{did}#0")
}

/// The `did:key` of a compressed P-256 point (33 bytes, `02` or `03` first).
pub(crate) fn did_key(compressed: &[u8]) -> Option<String> {
    if compressed.len() != 33 || !matches!(compressed[0], 2 | 3) {
        return None;
    }
    let mut bytes = P256_PUB.to_vec();
    bytes.extend_from_slice(compressed);
    Some(format!("did:key:z{}", base58btc_encode(&bytes)))
}

/// The verification method of a `did:key`: the fragment repeats the multibase value.
pub(crate) fn did_key_kid(did: &str) -> Option<String> {
    let multibase = did.strip_prefix("did:key:")?;
    Some(format!("{did}#{multibase}"))
}

/// The compressed P-256 point a `did:key` names, when it names one.
#[cfg(test)]
pub(crate) fn did_key_point(did: &str) -> Option<Vec<u8>> {
    let encoded = did.strip_prefix("did:key:z")?;
    let bytes = base58btc_decode(encoded)?;
    let point = bytes.strip_prefix(&P256_PUB[..])?;
    if point.len() == 33 && matches!(point[0], 2 | 3) {
        Some(point.to_vec())
    } else {
        None
    }
}

/// The https URL a `did:web` document is served at (DID Web Method section 3.2),
/// or `None` when `did` is not a well formed `did:web`.
///
/// `did:web:example.com` is `https://example.com/.well-known/did.json`.
/// `did:web:example.com:users:alice` is `https://example.com/users/alice/did.json`.
/// A port is written `%3A`: `did:web:example.com%3A8443`.
pub fn did_web_url(did: &str) -> Option<String> {
    let rest = did.strip_prefix("did:web:")?;
    let mut parts = rest.split(':');
    let authority = parts.next()?;
    let (host, port) = split_port(authority)?;
    if !dns_name(host) {
        return None;
    }
    let mut path = String::new();
    for segment in parts {
        if !path_segment(segment) {
            return None;
        }
        path.push('/');
        path.push_str(segment);
    }
    let port = port.map(|value| format!(":{value}")).unwrap_or_default();
    if path.is_empty() {
        Some(format!("https://{host}{port}/.well-known/did.json"))
    } else {
        Some(format!("https://{host}{port}{path}/did.json"))
    }
}

fn split_port(authority: &str) -> Option<(&str, Option<u16>)> {
    let lower = authority.to_ascii_lowercase();
    let Some(at) = lower.find("%3a") else {
        return Some((authority, None));
    };
    let host = &authority[..at];
    let digits = &authority[at + 3..];
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let port: u32 = digits.parse().ok()?;
    if port == 0 || port > 65535 {
        return None;
    }
    Some((host, Some(port as u16)))
}

/// A fully qualified domain name: two or more labels of letters, digits and
/// hyphens, none starting or ending with a hyphen.
fn dns_name(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.len() < 2 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    }) && !labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|byte| byte.is_ascii_digit()))
}

/// A path segment of a `did:web`: DID Core `idchar` without percent-encoding,
/// and never `.` or `..`.
fn path_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment != "."
        && segment != ".."
        && segment
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
}

/// The fragment of the one verification method in a generated `did:web` document:
/// the key's RFC 7638 thumbprint, so a different key is a different method id.
pub(crate) fn did_web_fragment(thumbprint_uri: &str) -> Option<&str> {
    thumbprint_uri.strip_prefix(super::jws::JWK_THUMBPRINT_PREFIX)
}

/// The DID document a `did:web` publishes for one P-256 public key.
///
/// The verification method is a Controlled Identifiers v1.0 `JsonWebKey`
/// (DID 1.1 context). It is listed in `authentication`, which SIOPv2
/// section 11.1 requires of the key a self-issued ID Token is signed with,
/// and in `assertionMethod`.
pub(crate) fn did_web_document(did: &str, kid: &str, x: &str, y: &str) -> Json {
    let method = Json::Object(vec![
        ("id".to_string(), Json::String(kid.to_string())),
        ("type".to_string(), Json::String("JsonWebKey".to_string())),
        ("controller".to_string(), Json::String(did.to_string())),
        (
            "publicKeyJwk".to_string(),
            Json::Object(vec![
                ("kty".to_string(), Json::String("EC".to_string())),
                ("crv".to_string(), Json::String("P-256".to_string())),
                ("x".to_string(), Json::String(x.to_string())),
                ("y".to_string(), Json::String(y.to_string())),
            ]),
        ),
    ]);
    let reference = Json::Array(vec![Json::String(kid.to_string())]);
    Json::Object(vec![
        (
            "@context".to_string(),
            Json::Array(vec![Json::String(
                "https://www.w3.org/ns/did/v1.1".to_string(),
            )]),
        ),
        ("id".to_string(), Json::String(did.to_string())),
        ("verificationMethod".to_string(), Json::Array(vec![method])),
        ("authentication".to_string(), reference.clone()),
        ("assertionMethod".to_string(), reference),
    ])
}

/// Base58btc (the Bitcoin alphabet). Leading zero bytes become `1`.
pub(crate) fn base58btc_encode(bytes: &[u8]) -> String {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    let mut digits: Vec<u8> = Vec::new();
    for byte in &bytes[zeros..] {
        let mut carry = u32::from(*byte);
        for digit in digits.iter_mut() {
            carry += u32::from(*digit) << 8;
            *digit = (carry % 58) as u8;
            carry /= 58;
        }
        while carry > 0 {
            digits.push((carry % 58) as u8);
            carry /= 58;
        }
    }
    let mut out = String::with_capacity(zeros + digits.len());
    out.extend(std::iter::repeat_n('1', zeros));
    out.extend(
        digits
            .iter()
            .rev()
            .map(|digit| BASE58[*digit as usize] as char),
    );
    out
}

/// Base58btc decoding. Any character outside the alphabet is `None`.
#[cfg(test)]
pub(crate) fn base58btc_decode(text: &str) -> Option<Vec<u8>> {
    let ones = text.bytes().take_while(|byte| *byte == b'1').count();
    let mut bytes: Vec<u8> = Vec::new();
    for symbol in text.bytes().skip(ones) {
        let mut carry = BASE58.iter().position(|one| *one == symbol)? as u32;
        for byte in bytes.iter_mut() {
            carry += u32::from(*byte) * 58;
            *byte = (carry & 0xff) as u8;
            carry >>= 8;
        }
        while carry > 0 {
            bytes.push((carry & 0xff) as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0u8; ones];
    out.extend(bytes.iter().rev());
    Some(out)
}

/// `$XDG_CONFIG_HOME/oid4vc-wallet/self-issued-subject`.
pub fn default_path() -> Result<PathBuf, String> {
    Ok(crate::xdg::config_home()?
        .join("oid4vc-wallet")
        .join("self-issued-subject"))
}

/// The saved choice. A missing file is the JWK Thumbprint syntax. A file
/// that cannot be read, or that names nothing this wallet knows, is an error:
/// the wallet does not fall back to another subject without saying so.
pub fn read(path: &Path) -> Result<SubjectSyntax, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            return Ok(SubjectSyntax::JwkThumbprint)
        }
        Err(err) => {
            return Err(t_args(
                "wallet.subject.read",
                &[("error", &err.to_string())],
            ))
        }
    };
    let line = text.lines().map(str::trim).find(|line| !line.is_empty());
    match line {
        None => Ok(SubjectSyntax::JwkThumbprint),
        Some(line) => SubjectSyntax::from_line(line).ok_or_else(|| t("wallet.subject.malformed")),
    }
}

/// Save `syntax` as the only line of `path`.
pub fn write(path: &Path, syntax: &SubjectSyntax) -> Result<(), String> {
    if let SubjectSyntax::DidWeb(did) = syntax {
        if did_web_url(did).is_none() {
            return Err(t_args("wallet.subject.did_web_invalid", &[("did", did)]));
        }
    }
    let fail = |err: io::Error| t_args("wallet.subject.write", &[("error", &err.to_string())]);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(0o700);
            builder.create(parent).map_err(fail)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(fail)?;
        }
    }
    let temporary = path.with_extension("new");
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&temporary)
            .map_err(fail)?;
        writeln!(file, "{}", syntax.line()).map_err(fail)?;
        file.sync_all().map_err(fail)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(fail)?;
        fs::rename(&temporary, path).map_err(fail)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(fail)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::elliptic_curve::sec1::ToEncodedPoint;

    /// The P-256 example in the W3C did:key method specification, and the
    /// P-256 Multikey of the W3C ECDSA Cryptosuites test vectors.
    const SPEC_DID_KEYS: &[&str] = &[
        "did:key:zDnaerx9CtbPJ1q36T5Ln5wYt3MQYeGRG5ehnPAmxcf5mDZpv",
        "did:key:zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
    ];

    #[test]
    fn base58btc_matches_known_values() {
        assert_eq!(base58btc_encode(b""), "");
        assert_eq!(base58btc_encode(&[0]), "1");
        assert_eq!(base58btc_encode(&[0, 0, 1]), "112");
        assert_eq!(base58btc_encode(b"hello world"), "StV1DL6CwTryKyV");
        assert_eq!(base58btc_encode(&[0xff; 4]), "7YXq9G");
        assert_eq!(base58btc_decode("StV1DL6CwTryKyV").unwrap(), b"hello world");
        assert_eq!(base58btc_decode("112").unwrap(), vec![0, 0, 1]);
        assert!(base58btc_decode("0OIl").is_none());
    }

    #[test]
    fn spec_did_keys_round_trip_through_a_p256_point() {
        for did in SPEC_DID_KEYS {
            let point = did_key_point(did).expect("a P-256 did:key");
            assert_eq!(point.len(), 33);
            let public = p256::PublicKey::from_sec1_bytes(&point).expect("on the curve");
            let again = public.to_encoded_point(true);
            assert_eq!(did_key(again.as_bytes()).as_deref(), Some(*did));
            let multibase = did.strip_prefix("did:key:").unwrap();
            assert!(multibase.starts_with("zDn"));
            assert_eq!(
                did_key_kid(did).unwrap(),
                format!("{did}#{multibase}"),
                "iya-sts resolves a did:key's one method as #<multibase>"
            );
        }
        let mut bad = [2u8; 33];
        assert!(did_key(&bad[..32]).is_none());
        bad[0] = 4;
        assert!(did_key(&bad).is_none());
        assert!(
            did_key_point("did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK").is_none()
        );
    }

    #[test]
    fn did_jwk_is_base64url_of_the_public_jwk() {
        let x = "acbIQiuMs3i8_uszEjJ2tpTtRM4EU3yz91PH6CdH2V0";
        let y = "_KcyLj9vWMptnmKtm46GqDz8wf74I5LKgrl2GzH3nSE";
        let did = did_jwk(x, y);
        let encoded = did.strip_prefix("did:jwk:").unwrap();
        assert!(!encoded.contains('='));
        let json = String::from_utf8(b64::b64_decode(encoded).unwrap()).unwrap();
        let jwk = Json::parse(&json).unwrap();
        assert_eq!(jwk.keys(), vec!["kty", "crv", "x", "y"]);
        assert_eq!(jwk.get("kty").and_then(Json::as_str), Some("EC"));
        assert_eq!(jwk.get("crv").and_then(Json::as_str), Some("P-256"));
        assert_eq!(jwk.get("x").and_then(Json::as_str), Some(x));
        assert_eq!(jwk.get("y").and_then(Json::as_str), Some(y));
        assert_eq!(did_jwk_kid(&did), format!("{did}#0"));
        // The did:jwk specification's own P-256 example, which encodes the
        // same key with its members in another order.
        let spec = "did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczN\
                    pOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOX\
                    ZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9";
        let spec_json =
            String::from_utf8(b64::b64_decode(spec.strip_prefix("did:jwk:").unwrap()).unwrap())
                .unwrap();
        let spec_jwk = Json::parse(&spec_json).unwrap();
        assert_eq!(spec_jwk.get("x").and_then(Json::as_str), Some(x));
        assert_eq!(spec_jwk.get("y").and_then(Json::as_str), Some(y));
    }

    #[test]
    fn did_web_maps_to_an_https_url() {
        let cases = [
            (
                "did:web:example.com",
                "https://example.com/.well-known/did.json",
            ),
            (
                "did:web:w3c-ccg.github.io:user:alice",
                "https://w3c-ccg.github.io/user/alice/did.json",
            ),
            (
                "did:web:example.com%3A3000",
                "https://example.com:3000/.well-known/did.json",
            ),
            (
                "did:web:example.com%3a8443:users:alice",
                "https://example.com:8443/users/alice/did.json",
            ),
            (
                "did:web:Sub-1.Example.co.uk:a_b.c",
                "https://Sub-1.Example.co.uk/a_b.c/did.json",
            ),
        ];
        for (did, url) in cases {
            assert_eq!(did_web_url(did).as_deref(), Some(url), "{did}");
        }
        let refused = [
            "did:web:",
            "did:web:localhost",
            "did:web:example",
            "did:web:-bad.example.com",
            "did:web:bad-.example.com",
            "did:web:exa mple.com",
            "did:web:example..com",
            "did:web:192.168.1.1",
            "did:web:example.com:",
            "did:web:example.com::alice",
            "did:web:example.com:..",
            "did:web:example.com:a%2Fb",
            "did:web:example.com%3A",
            "did:web:example.com%3A0",
            "did:web:example.com%3A70000",
            "did:web:example.com%3Aport",
            "did:web:example.com#key-1",
            "did:web:example.com/path",
            "did:web:example.com?x=1",
            "did:key:example.com",
            "web:example.com",
            "https://example.com",
        ];
        for did in refused {
            assert!(did_web_url(did).is_none(), "{did} was accepted");
        }
    }

    #[test]
    fn a_did_web_document_lists_the_key_for_authentication() {
        let did = "did:web:example.com:users:alice";
        let kid = format!("{did}#thumb");
        let doc = did_web_document(did, &kid, "xx", "yy");
        assert_eq!(
            doc.keys(),
            vec![
                "@context",
                "id",
                "verificationMethod",
                "authentication",
                "assertionMethod"
            ]
        );
        assert_eq!(doc.get("id").and_then(Json::as_str), Some(did));
        let methods = doc
            .get("verificationMethod")
            .and_then(Json::as_array)
            .unwrap();
        assert_eq!(methods.len(), 1);
        let method = &methods[0];
        assert_eq!(method.get("id").and_then(Json::as_str), Some(kid.as_str()));
        assert_eq!(
            method.get("type").and_then(Json::as_str),
            Some("JsonWebKey")
        );
        assert_eq!(method.get("controller").and_then(Json::as_str), Some(did));
        let jwk = method.get("publicKeyJwk").unwrap();
        assert_eq!(jwk.keys(), vec!["kty", "crv", "x", "y"]);
        for relation in ["authentication", "assertionMethod"] {
            let refs = doc.get(relation).and_then(Json::as_array).unwrap();
            assert_eq!(refs.len(), 1);
            assert_eq!(refs[0].as_str(), Some(kid.as_str()));
        }
        assert!(!doc.to_string().contains("\"d\""));
    }

    #[test]
    fn a_verifier_list_names_a_method_or_every_did() {
        let list = |items: &[&str]| items.iter().map(|one| one.to_string()).collect::<Vec<_>>();
        assert!(accepts(&list(&["did:key"]), "did:key"));
        assert!(!accepts(&list(&["did:key"]), "did:jwk"));
        assert!(accepts(&list(&["did"]), "did:web"));
        assert!(!accepts(&list(&["did"]), THUMBPRINT_TYPE));
        assert!(accepts(&list(&[THUMBPRINT_TYPE]), THUMBPRINT_TYPE));
        assert!(!accepts(&list(&[]), THUMBPRINT_TYPE));
        assert!(!accepts(&list(&["did:web:example.com"]), "did:web"));
    }

    #[test]
    fn the_choice_persists_privately_and_reloads() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-subject-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = root.join("self-issued-subject");
        assert_eq!(read(&path).unwrap(), SubjectSyntax::JwkThumbprint);
        for choice in [
            SubjectSyntax::DidJwk,
            SubjectSyntax::DidKey,
            SubjectSyntax::DidWeb("did:web:example.com%3A8443:users:alice".to_string()),
            SubjectSyntax::JwkThumbprint,
        ] {
            write(&path, &choice).unwrap();
            assert_eq!(read(&path).unwrap(), choice);
        }
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert!(write(
            &path,
            &SubjectSyntax::DidWeb("did:web:localhost".to_string())
        )
        .is_err());
        assert_eq!(read(&path).unwrap(), SubjectSyntax::JwkThumbprint);
        fs::write(&path, "did:example:123\n").unwrap();
        assert!(
            read(&path).is_err(),
            "an unknown choice is not read as the default"
        );
        fs::remove_dir_all(&root).unwrap();
    }
}
