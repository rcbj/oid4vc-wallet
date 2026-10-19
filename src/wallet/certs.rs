//! X.509 chains carried in a JWS `x5c` header.
//!
//! `x5c` is base64 DER and, for iya-sts, stops before the service root. The
//! missing parent is the certificate named by the Authority Information Access
//! `caIssuers` URL (RFC 5280). That URL is how a wallet retrieves the
//! published parent. A root that was only embedded in `x5c` was not retrieved.
//!
//! Certificate signatures are DER ECDSA or PKCS#1 RSA. A JWS signature is
//! R||S, so the two forms are converted before the same primitive checks them.

use x509_parser::oid_registry::{
    OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, OID_PKCS1_RSASSAPSS, OID_PKCS1_SHA256WITHRSA,
    OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA, OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS,
    OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384, OID_SIG_ECDSA_WITH_SHA512,
    OID_SIG_ED25519, OID_SIG_ED448,
};
use x509_parser::prelude::*;
use x509_parser::public_key::PublicKey;

use super::jws::{self, KeyMaterial};

const MAX_PARENTS: usize = 6;

/// One certificate, owned so it outlives the parser borrow.
pub(crate) struct OwnedCert {
    pub subject_der: Vec<u8>,
    pub issuer_der: Vec<u8>,
    pub spki_der: Vec<u8>,
    pub name: String,
    pub not_before: i64,
    pub not_after: i64,
    pub aia: Vec<String>,
    pub key: KeyMaterial,
    tbs: Vec<u8>,
    signature: Vec<u8>,
    sig_oid: String,
}

/// What a chain walk established.
pub(crate) enum Chain {
    /// The self-signed root was fetched from `url`.
    Published {
        name: String,
        url: String,
    },
    Broken(ChainFault),
    /// The certificates that did verify, leaf first. The parent was not retrieved.
    Incomplete(Vec<OwnedCert>),
}

pub(crate) enum ChainFault {
    Bad,
    Name,
    Date,
}

enum Link {
    Verified,
    Bad,
    Unknown,
}

impl OwnedCert {
    pub(crate) fn parse(der: &[u8]) -> Option<Self> {
        let (rest, cert) = X509Certificate::from_der(der).ok()?;
        if !rest.is_empty() {
            return None;
        }
        let key = key_from_cert(&cert)?;
        let name = cert
            .subject()
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .filter(|name| !name.is_empty())
            .map(str::to_string)
            .unwrap_or_else(|| cert.subject().to_string());
        Some(Self {
            subject_der: cert.subject().as_raw().to_vec(),
            issuer_der: cert.issuer().as_raw().to_vec(),
            spki_der: cert.public_key().raw.to_vec(),
            name,
            not_before: cert.validity().not_before.timestamp(),
            not_after: cert.validity().not_after.timestamp(),
            aia: ca_issuer_urls(&cert),
            key,
            tbs: cert.tbs_certificate.as_ref().to_vec(),
            signature: cert.signature_value.data.to_vec(),
            sig_oid: cert.signature_algorithm.algorithm.to_id_string(),
        })
    }

    fn current(&self, now: i64) -> bool {
        now >= self.not_before && now <= self.not_after
    }
}

/// Walk `ders` (leaf first). Fetch missing parents from `caIssuers`.
/// `fetch_der` returns the DER certificates at one URL, or `None` when the
/// URL could not be read. A self-signed root counts as published only when
/// this function fetched it.
pub(crate) fn walk<F>(ders: &[Vec<u8>], now: i64, mut fetch_der: F) -> Chain
where
    F: FnMut(&str) -> Option<Vec<Vec<u8>>>,
{
    let mut certs = Vec::new();
    for der in ders {
        let Some(cert) = OwnedCert::parse(der) else {
            return if certs.is_empty() {
                Chain::Broken(ChainFault::Bad)
            } else {
                Chain::Incomplete(certs)
            };
        };
        if !cert.current(now) {
            return Chain::Broken(ChainFault::Date);
        }
        if let Some(previous) = certs.last() {
            if previous.issuer_der != cert.subject_der {
                return Chain::Broken(ChainFault::Name);
            }
            match link(previous, &cert.key, &cert.sig_oid) {
                Link::Verified => {}
                Link::Bad => return Chain::Broken(ChainFault::Bad),
                Link::Unknown => {
                    certs.push(cert);
                    return Chain::Incomplete(certs);
                }
            }
        }
        certs.push(cert);
    }
    if certs.is_empty() {
        return Chain::Incomplete(certs);
    }
    for _ in 0..MAX_PARENTS {
        let top = certs.last().expect("the chain has a certificate");
        if top.subject_der == top.issuer_der {
            return match link(top, &top.key, &top.sig_oid) {
                // The root arrived inside the credential. It was not retrieved.
                Link::Verified => Chain::Incomplete(certs),
                Link::Bad => Chain::Broken(ChainFault::Bad),
                Link::Unknown => Chain::Incomplete(certs),
            };
        }
        let urls = top.aia.clone();
        if urls.is_empty() {
            return Chain::Incomplete(certs);
        }
        let mut matched_bad = false;
        let mut found = None;
        for url in &urls {
            let Some(bodies) = fetch_der(url) else {
                continue;
            };
            for der in bodies {
                let Some(parent) = OwnedCert::parse(&der) else {
                    continue;
                };
                if parent.subject_der != top.issuer_der {
                    continue;
                }
                if !parent.current(now) {
                    return Chain::Broken(ChainFault::Date);
                }
                match link(top, &parent.key, &parent.sig_oid) {
                    Link::Verified => {
                        found = Some((parent, url.clone()));
                        break;
                    }
                    Link::Bad => matched_bad = true,
                    Link::Unknown => {}
                }
            }
            if found.is_some() {
                break;
            }
        }
        let Some((parent, url)) = found else {
            return if matched_bad {
                Chain::Broken(ChainFault::Bad)
            } else {
                Chain::Incomplete(certs)
            };
        };
        let parent_is_root = parent.subject_der == parent.issuer_der;
        certs.push(parent);
        if parent_is_root {
            let root = certs.last().expect("the fetched root is on the chain");
            return match link(root, &root.key, &root.sig_oid) {
                Link::Verified => Chain::Published {
                    name: root.name.clone(),
                    url,
                },
                Link::Bad => Chain::Broken(ChainFault::Bad),
                Link::Unknown => Chain::Incomplete(certs),
            };
        }
    }
    Chain::Incomplete(certs)
}

/// The TLS certificates anchor the credential chain when one of them is a
/// parent of the top certificate, or when the two chains share a key.
pub(crate) fn tls_anchors(chain: &[OwnedCert], peers: &[OwnedCert]) -> bool {
    let Some(top) = chain.last() else {
        return false;
    };
    for peer in peers {
        if chain.iter().any(|cert| cert.spki_der == peer.spki_der) {
            return true;
        }
        if peer.subject_der == top.issuer_der
            && matches!(link(top, &peer.key, &top.sig_oid), Link::Verified)
        {
            return true;
        }
    }
    false
}

/// An uploaded certificate anchors `chain` when its key is already on the
/// chain, or when that key verifies the top certificate.
pub(crate) fn anchored_by(chain: &[OwnedCert], anchors: &[OwnedCert]) -> Option<String> {
    let top = chain.last()?;
    for anchor in anchors {
        let label = if anchor.name.is_empty() {
            super::b64::sha256_hex(&anchor.spki_der)
        } else {
            anchor.name.clone()
        };
        if chain.iter().any(|cert| cert.spki_der == anchor.spki_der) {
            return Some(label);
        }
        if matches!(link(top, &anchor.key, &top.sig_oid), Link::Verified) {
            return Some(label);
        }
    }
    None
}

fn link(child: &OwnedCert, parent_key: &KeyMaterial, child_sig_oid: &str) -> Link {
    let oid = child_sig_oid;
    if oid == OID_PKCS1_SHA256WITHRSA.to_id_string() {
        return rsa_link::<sha2::Sha256>(child, parent_key);
    }
    if oid == OID_PKCS1_SHA384WITHRSA.to_id_string() {
        return rsa_link::<sha2::Sha384>(child, parent_key);
    }
    if oid == OID_PKCS1_SHA512WITHRSA.to_id_string() {
        return rsa_link::<sha2::Sha512>(child, parent_key);
    }
    if oid == OID_PKCS1_RSASSAPSS.to_id_string() {
        return rsa_pss_any(child, parent_key);
    }
    if oid == OID_SIG_ECDSA_WITH_SHA256.to_id_string() {
        return ecdsa_link(child, parent_key, 32, EcdsaCurve::P256);
    }
    if oid == OID_SIG_ECDSA_WITH_SHA384.to_id_string() {
        return ecdsa_link(child, parent_key, 48, EcdsaCurve::P384);
    }
    if oid == OID_SIG_ECDSA_WITH_SHA512.to_id_string() {
        return ecdsa_link(child, parent_key, 66, EcdsaCurve::P521);
    }
    if oid == OID_SIG_ED25519.to_id_string() {
        return eddsa_link(child, parent_key, true);
    }
    if oid == OID_SIG_ED448.to_id_string() {
        return eddsa_link(child, parent_key, false);
    }
    Link::Unknown
}

enum EcdsaCurve {
    P256,
    P384,
    P521,
}

fn ecdsa_link(
    child: &OwnedCert,
    parent_key: &KeyMaterial,
    coord: usize,
    curve: EcdsaCurve,
) -> Link {
    let Some(rs) = jws::der_ecdsa_to_rs(&child.signature, coord) else {
        return Link::Bad;
    };
    let ok = match (curve, parent_key) {
        (EcdsaCurve::P256, KeyMaterial::P256 { x, y }) => jws_p256(x, y, &child.tbs, &rs),
        (EcdsaCurve::P384, KeyMaterial::P384 { x, y }) => jws_p384(x, y, &child.tbs, &rs),
        (EcdsaCurve::P521, KeyMaterial::P521 { x, y }) => jws_p521(x, y, &child.tbs, &rs),
        _ => return Link::Bad,
    };
    if ok {
        Link::Verified
    } else {
        Link::Bad
    }
}

fn jws_p256(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    jws::verifies(
        "ES256",
        &KeyMaterial::P256 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        message,
        signature,
    )
}

fn jws_p384(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    jws::verifies(
        "ES384",
        &KeyMaterial::P384 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        message,
        signature,
    )
}

fn jws_p521(x: &[u8], y: &[u8], message: &[u8], signature: &[u8]) -> bool {
    jws::verifies(
        "ES512",
        &KeyMaterial::P521 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        message,
        signature,
    )
}

fn rsa_link<D>(child: &OwnedCert, parent_key: &KeyMaterial) -> Link
where
    D: sha2::digest::Digest,
{
    let KeyMaterial::Rsa { n, e } = parent_key else {
        return Link::Bad;
    };
    if pkcs1_with::<D>(n, e, &child.tbs, &child.signature) {
        Link::Verified
    } else {
        Link::Bad
    }
}

fn pkcs1_with<D>(n: &[u8], e: &[u8], message: &[u8], signature: &[u8]) -> bool
where
    D: sha2::digest::Digest,
{
    // The hash-specific PKCS#1 verifier lives with the JWS code. Dispatch by
    // the digest's output size, which is unambiguous for SHA-256/384/512.
    let alg = match <D as sha2::digest::OutputSizeUser>::output_size() {
        32 => "RS256",
        48 => "RS384",
        64 => "RS512",
        _ => return false,
    };
    jws::verifies(
        alg,
        &KeyMaterial::Rsa {
            n: n.to_vec(),
            e: e.to_vec(),
        },
        message,
        signature,
    )
}

fn rsa_pss_any(child: &OwnedCert, parent_key: &KeyMaterial) -> Link {
    let KeyMaterial::Rsa { n, e } = parent_key else {
        return Link::Bad;
    };
    let key = KeyMaterial::Rsa {
        n: n.clone(),
        e: e.clone(),
    };
    let ok = ["PS256", "PS384", "PS512"]
        .iter()
        .any(|alg| jws::verifies(alg, &key, &child.tbs, &child.signature));
    if ok {
        Link::Verified
    } else {
        Link::Bad
    }
}

fn eddsa_link(child: &OwnedCert, parent_key: &KeyMaterial, ed25519: bool) -> Link {
    let ok = if ed25519 {
        let KeyMaterial::Ed25519 { x } = parent_key else {
            return Link::Bad;
        };
        jws::verifies(
            "EdDSA",
            &KeyMaterial::Ed25519 { x: x.clone() },
            &child.tbs,
            &child.signature,
        )
    } else {
        let KeyMaterial::Ed448 { x } = parent_key else {
            return Link::Bad;
        };
        jws::verifies(
            "EdDSA",
            &KeyMaterial::Ed448 { x: x.clone() },
            &child.tbs,
            &child.signature,
        )
    };
    if ok {
        Link::Verified
    } else {
        Link::Bad
    }
}

fn key_from_cert(cert: &X509Certificate<'_>) -> Option<KeyMaterial> {
    let spki = cert.public_key();
    let oid = spki.algorithm.algorithm.to_id_string();
    let bits = spki.subject_public_key.data.as_ref();
    if oid == x509_parser::oid_registry::OID_PKCS1_RSAENCRYPTION.to_id_string() {
        let key = spki.parsed().ok()?;
        let PublicKey::RSA(rsa) = key else {
            return None;
        };
        return Some(KeyMaterial::Rsa {
            n: strip_leading_zero(rsa.modulus).to_vec(),
            e: strip_leading_zero(rsa.exponent).to_vec(),
        });
    }
    if oid == x509_parser::oid_registry::OID_KEY_TYPE_EC_PUBLIC_KEY.to_id_string() {
        let curve = spki.algorithm.parameters()?.as_oid().ok()?.to_id_string();
        return ec_point(bits, &curve);
    }
    if oid == OID_SIG_ED25519.to_id_string() {
        return Some(KeyMaterial::Ed25519 { x: bits.to_vec() });
    }
    if oid == OID_SIG_ED448.to_id_string() {
        return Some(KeyMaterial::Ed448 { x: bits.to_vec() });
    }
    None
}

fn ec_point(bits: &[u8], curve: &str) -> Option<KeyMaterial> {
    if bits.first().copied() != Some(0x04) {
        return None;
    }
    let body = &bits[1..];
    if !body.len().is_multiple_of(2) {
        return None;
    }
    let (x, y) = body.split_at(body.len() / 2);
    let material = match curve {
        id if id == OID_EC_P256.to_id_string() && x.len() == 32 => KeyMaterial::P256 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        id if id == OID_NIST_EC_P384.to_id_string() && x.len() == 48 => KeyMaterial::P384 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        id if id == OID_NIST_EC_P521.to_id_string() && x.len() == 66 => KeyMaterial::P521 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        // secp256k1 is not in the OID registry this crate carries.
        "1.3.132.0.10" if x.len() == 32 => KeyMaterial::K256 {
            x: x.to_vec(),
            y: y.to_vec(),
        },
        _ => return None,
    };
    Some(material)
}

fn strip_leading_zero(bytes: &[u8]) -> &[u8] {
    match bytes {
        [0x00, rest @ ..] if !rest.is_empty() => rest,
        other => other,
    }
}

fn ca_issuer_urls(cert: &X509Certificate<'_>) -> Vec<String> {
    let mut urls = Vec::new();
    for ext in cert.extensions() {
        let ParsedExtension::AuthorityInfoAccess(aia) = ext.parsed_extension() else {
            continue;
        };
        for desc in &aia.accessdescs {
            if desc.access_method != OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS {
                continue;
            }
            if let GeneralName::URI(uri) = &desc.access_location {
                if uri.starts_with("https://") || uri.starts_with("http://") {
                    urls.push((*uri).to_string());
                }
            }
        }
    }
    urls
}

/// DER certificates in a PEM body or one DER certificate.
pub(crate) fn certificates_in(body: &[u8]) -> Vec<Vec<u8>> {
    if body.windows(10).any(|window| window == b"-----BEGIN") {
        let mut out = Vec::new();
        for pem in Pem::iter_from_buffer(body) {
            let Ok(pem) = pem else {
                continue;
            };
            if pem.label == "CERTIFICATE" {
                out.push(pem.contents);
            }
        }
        return out;
    }
    if body.first().copied() == Some(0x30) {
        vec![body.to_vec()]
    } else {
        Vec::new()
    }
}
