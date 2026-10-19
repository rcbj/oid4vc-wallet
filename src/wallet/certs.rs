//! X.509 chains carried in a JWS `x5c` header.
//!
//! `x5c` is base64 DER and, for iya-sts, stops before the service root. The
//! missing parent is the certificate named by the Authority Information Access
//! `caIssuers` URL (RFC 5280). That URL is how a wallet retrieves the
//! published parent. A root that was only embedded in `x5c` was not retrieved.
//!
//! Certificate signatures are DER ECDSA or PKCS#1 RSA. A JWS signature is
//! R||S, so the two forms are converted before the same primitive checks them.
//!
//! [`signer_certificates`] reads that same embedded `x5c` for display. It does
//! not check the signature and it does not fetch a parent.
//!
//! A credential this wallet creates for a sign-in has no external issuer
//! certificate. [`self_signed_p256`] builds one self-signed certificate for
//! that key, and the credential stores it as `x5c`. The chain is that
//! certificate.

use x509_parser::oid_registry::{
    Oid, OID_EC_P256, OID_NIST_EC_P384, OID_NIST_EC_P521, OID_PKCS1_RSASSAPSS,
    OID_PKCS1_SHA256WITHRSA, OID_PKCS1_SHA384WITHRSA, OID_PKCS1_SHA512WITHRSA,
    OID_PKIX_ACCESS_DESCRIPTOR_CA_ISSUERS, OID_SIG_ECDSA_WITH_SHA256, OID_SIG_ECDSA_WITH_SHA384,
    OID_SIG_ECDSA_WITH_SHA512, OID_SIG_ED25519, OID_SIG_ED448,
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

/// One signer certificate, ready to show. The signature is not checked.
#[derive(Clone)]
pub struct SignerCertificate {
    /// Subject distinguished name, used as the chain label.
    pub title: String,
    /// X.509 fields, one row per value. Names are the English field names.
    pub fields: Vec<(String, String)>,
    /// PEM of this certificate. This is the raw view and the copy payload.
    pub pem: String,
}

/// Signer certificates embedded in `document`, leaf first.
///
/// Reads the issuer JWS `x5c` header. A credential with no `x5c`, and an
/// entry that is not a certificate, are omitted. Nothing is fetched.
pub fn signer_certificates(document: &str) -> Vec<SignerCertificate> {
    jws::header_x5c(document)
        .into_iter()
        .filter_map(|der| describe_certificate(&der))
        .collect()
}

fn describe_certificate(der: &[u8]) -> Option<SignerCertificate> {
    let (rest, cert) = X509Certificate::from_der(der).ok()?;
    if !rest.is_empty() {
        return None;
    }
    let mut fields = Vec::new();
    push_tbs_fields(&mut fields, &cert);
    for extension in cert.extensions() {
        push_extension(&mut fields, extension);
    }
    push_signature(&mut fields, &cert);
    Some(SignerCertificate {
        title: cert.subject().to_string(),
        fields,
        pem: pem_certificate(der),
    })
}

fn push_tbs_fields(rows: &mut Vec<(String, String)>, cert: &X509Certificate<'_>) {
    let version = cert.version().0;
    rows.push((
        "Version".to_string(),
        format!("{} (0x{version:X})", version + 1),
    ));
    rows.push(("Serial number".to_string(), upper_hex(&cert.serial)));
    rows.push((
        "Signature algorithm".to_string(),
        algorithm_text(&cert.signature),
    ));
    push_name(rows, "Issuer", cert.issuer());
    rows.push((
        "Not before".to_string(),
        cert.validity().not_before.to_string(),
    ));
    rows.push((
        "Not after".to_string(),
        cert.validity().not_after.to_string(),
    ));
    push_name(rows, "Subject", cert.subject());
    let public_key = cert.public_key();
    rows.push((
        "Public key algorithm".to_string(),
        oid_label(&public_key.algorithm.algorithm),
    ));
    if let Some(parameters) = &public_key.algorithm.parameters {
        rows.push((
            "Public key parameters".to_string(),
            parameter_text(parameters),
        ));
    }
    rows.push((
        "Public key".to_string(),
        hex_bytes(public_key.subject_public_key.data.as_ref()),
    ));
    if let Some(uid) = &cert.issuer_uid {
        rows.push((
            "Issuer unique ID".to_string(),
            hex_bytes(uid.0.data.as_ref()),
        ));
    }
    if let Some(uid) = &cert.subject_uid {
        rows.push((
            "Subject unique ID".to_string(),
            hex_bytes(uid.0.data.as_ref()),
        ));
    }
}

fn push_name(rows: &mut Vec<(String, String)>, role: &str, name: &X509Name<'_>) {
    rows.push((role.to_string(), name.to_string()));
    for attribute in name.iter_attributes() {
        let value = attribute.as_str().map_or_else(
            |_| hex_bytes(attribute.attr_value().as_bytes()),
            str::to_string,
        );
        rows.push((
            format!("{role}.{}", oid_short(attribute.attr_type())),
            value,
        ));
    }
}

fn push_signature(rows: &mut Vec<(String, String)>, cert: &X509Certificate<'_>) {
    rows.push((
        "Signature algorithm".to_string(),
        algorithm_text(&cert.signature_algorithm),
    ));
    rows.push((
        "Signature value".to_string(),
        hex_bytes(cert.signature_value.data.as_ref()),
    ));
}

fn push_extension(rows: &mut Vec<(String, String)>, extension: &X509Extension<'_>) {
    let name = oid_label(&extension.oid);
    let values = extension_values(extension.parsed_extension());
    if values.is_empty() {
        rows.push((name.clone(), hex_bytes(extension.value)));
    } else {
        for value in values {
            rows.push((name.clone(), value));
        }
    }
    rows.push((format!("{name}.critical"), extension.critical.to_string()));
}

fn extension_values(parsed: &ParsedExtension<'_>) -> Vec<String> {
    let mut values = Vec::new();
    if !identity_extension(&mut values, parsed) {
        status_extension(&mut values, parsed);
    }
    values
}

fn identity_extension(values: &mut Vec<String>, parsed: &ParsedExtension<'_>) -> bool {
    match parsed {
        ParsedExtension::AuthorityKeyIdentifier(aki) => push_aki(values, aki),
        ParsedExtension::SubjectKeyIdentifier(id) => values.push(hex_bytes(id.0)),
        ParsedExtension::SubjectAlternativeName(names) => {
            push_general_names(values, &names.general_names)
        }
        ParsedExtension::IssuerAlternativeName(names) => {
            push_general_names(values, &names.general_names)
        }
        ParsedExtension::AuthorityInfoAccess(access) => push_access(values, &access.accessdescs),
        ParsedExtension::SubjectInfoAccess(access) => push_access(values, &access.accessdescs),
        ParsedExtension::CRLDistributionPoints(points) => push_crl_points(values, points),
        ParsedExtension::IssuingDistributionPoint(point) => push_issuing_point(values, point),
        ParsedExtension::NameConstraints(constraints) => push_name_constraints(values, constraints),
        ParsedExtension::CertificatePolicies(policies) => push_policies(values, policies),
        ParsedExtension::PolicyMappings(mappings) => push_mappings(values, mappings),
        _ => return false,
    }
    true
}

fn status_extension(values: &mut Vec<String>, parsed: &ParsedExtension<'_>) {
    match parsed {
        ParsedExtension::KeyUsage(usage) => values.push(usage.to_string()),
        ParsedExtension::ExtendedKeyUsage(usage) => push_extended_usage(values, usage),
        ParsedExtension::BasicConstraints(constraints) => {
            push_basic_constraints(values, constraints)
        }
        ParsedExtension::PolicyConstraints(constraints) => {
            push_policy_constraints(values, constraints)
        }
        ParsedExtension::InhibitAnyPolicy(policy) => values.push(policy.skip_certs.to_string()),
        ParsedExtension::NSCertType(kind) => values.push(kind.to_string()),
        ParsedExtension::NsCertComment(comment) => values.push((*comment).to_string()),
        ParsedExtension::CRLNumber(number) => values.push(upper_hex(number)),
        ParsedExtension::ReasonCode(code) => values.push(code.to_string()),
        ParsedExtension::InvalidityDate(when) => values.push(when.to_string()),
        ParsedExtension::SCT(timestamps) => push_timestamps(values, timestamps),
        ParsedExtension::UnsupportedExtension { .. }
        | ParsedExtension::ParseError { .. }
        | ParsedExtension::Unparsed => {}
        _ => {}
    }
}

fn push_aki(values: &mut Vec<String>, aki: &AuthorityKeyIdentifier<'_>) {
    if let Some(id) = &aki.key_identifier {
        values.push(hex_bytes(id.0));
    }
    if let Some(names) = &aki.authority_cert_issuer {
        push_general_names(values, names);
    }
    if let Some(serial) = aki.authority_cert_serial {
        values.push(hex_bytes(serial));
    }
}

fn push_general_names(values: &mut Vec<String>, names: &[GeneralName<'_>]) {
    for name in names {
        values.push(name.to_string());
    }
}

fn push_access(values: &mut Vec<String>, descriptions: &[AccessDescription<'_>]) {
    for description in descriptions {
        values.push(format!(
            "{} {}",
            oid_label(&description.access_method),
            description.access_location
        ));
    }
}

fn push_crl_points(values: &mut Vec<String>, points: &CRLDistributionPoints<'_>) {
    for point in &points.points {
        if let Some(name) = &point.distribution_point {
            push_distribution_point(values, name);
        }
        if let Some(reasons) = &point.reasons {
            values.push(reasons.to_string());
        }
        if let Some(issuers) = &point.crl_issuer {
            push_general_names(values, issuers);
        }
    }
}

fn push_distribution_point(values: &mut Vec<String>, name: &DistributionPointName<'_>) {
    match name {
        DistributionPointName::FullName(names) => push_general_names(values, names),
        DistributionPointName::NameRelativeToCRLIssuer(rdn) => values.push(rdn_text(rdn)),
    }
}

fn push_issuing_point(values: &mut Vec<String>, point: &IssuingDistributionPoint<'_>) {
    if let Some(name) = &point.distribution_point {
        push_distribution_point(values, name);
    }
    values.push(format!(
        "onlyContainsUserCerts: {}",
        point.only_contains_user_certs
    ));
    values.push(format!(
        "onlyContainsCACerts: {}",
        point.only_contains_ca_certs
    ));
    if let Some(reasons) = &point.only_some_reasons {
        values.push(reasons.to_string());
    }
    values.push(format!("indirectCRL: {}", point.indirect_crl));
    values.push(format!(
        "onlyContainsAttributeCerts: {}",
        point.only_contains_attribute_certs
    ));
}

fn push_name_constraints(values: &mut Vec<String>, constraints: &NameConstraints<'_>) {
    if let Some(permitted) = &constraints.permitted_subtrees {
        for subtree in permitted {
            values.push(format!("permitted {}", subtree.base));
        }
    }
    if let Some(excluded) = &constraints.excluded_subtrees {
        for subtree in excluded {
            values.push(format!("excluded {}", subtree.base));
        }
    }
}

fn push_policies(values: &mut Vec<String>, policies: &CertificatePolicies<'_>) {
    for policy in policies {
        values.push(oid_label(&policy.policy_id));
        let Some(qualifiers) = &policy.policy_qualifiers else {
            continue;
        };
        for qualifier in qualifiers {
            values.push(format!(
                "{} {}",
                oid_label(&qualifier.policy_qualifier_id),
                hex_bytes(qualifier.qualifier)
            ));
        }
    }
}

fn push_mappings(values: &mut Vec<String>, mappings: &PolicyMappings<'_>) {
    for mapping in &mappings.mappings {
        values.push(format!(
            "{} -> {}",
            oid_label(&mapping.issuer_domain_policy),
            oid_label(&mapping.subject_domain_policy)
        ));
    }
}

fn push_extended_usage(values: &mut Vec<String>, usage: &ExtendedKeyUsage<'_>) {
    let named = [
        (usage.any, "any"),
        (usage.server_auth, "serverAuth"),
        (usage.client_auth, "clientAuth"),
        (usage.code_signing, "codeSigning"),
        (usage.email_protection, "emailProtection"),
        (usage.time_stamping, "timeStamping"),
        (usage.ocsp_signing, "OCSPSigning"),
    ];
    for (present, label) in named {
        if present {
            values.push(label.to_string());
        }
    }
    for oid in &usage.other {
        values.push(oid_label(oid));
    }
}

fn push_basic_constraints(values: &mut Vec<String>, constraints: &BasicConstraints) {
    values.push(format!("CA: {}", constraints.ca));
    if let Some(length) = constraints.path_len_constraint {
        values.push(format!("pathLen: {length}"));
    }
}

fn push_policy_constraints(values: &mut Vec<String>, constraints: &PolicyConstraints) {
    if let Some(count) = constraints.require_explicit_policy {
        values.push(format!("requireExplicitPolicy: {count}"));
    }
    if let Some(count) = constraints.inhibit_policy_mapping {
        values.push(format!("inhibitPolicyMapping: {count}"));
    }
}

fn push_timestamps(values: &mut Vec<String>, timestamps: &[SignedCertificateTimestamp<'_>]) {
    for stamp in timestamps {
        values.push(format!(
            "version {} timestamp {} log {}",
            stamp.version.0,
            stamp.timestamp,
            hex_bytes(stamp.id.key_id)
        ));
    }
}

fn rdn_text(rdn: &RelativeDistinguishedName<'_>) -> String {
    rdn.iter()
        .map(|attribute| {
            let value = attribute.as_str().map_or_else(
                |_| hex_bytes(attribute.attr_value().as_bytes()),
                str::to_string,
            );
            format!("{}={value}", oid_short(attribute.attr_type()))
        })
        .collect::<Vec<_>>()
        .join("+")
}

fn algorithm_text(algorithm: &AlgorithmIdentifier<'_>) -> String {
    let name = oid_label(&algorithm.algorithm);
    match &algorithm.parameters {
        Some(parameters) => format!("{name} {}", parameter_text(parameters)),
        None => name,
    }
}

fn parameter_text(value: &asn1_rs::Any<'_>) -> String {
    if value.tag() == asn1_rs::Tag::Null {
        return "NULL".to_string();
    }
    if value.tag() == asn1_rs::Tag::Oid && value.as_bytes().len() < 128 {
        let content = value.as_bytes();
        let mut encoded = Vec::with_capacity(content.len() + 2);
        encoded.push(0x06);
        encoded.push(content.len() as u8);
        encoded.extend_from_slice(content);
        if let Ok((_, oid)) = Oid::from_der(&encoded) {
            return oid_label(&oid);
        }
    }
    format!("tag {} {}", value.tag().0, hex_bytes(value.as_bytes()))
}

fn oid_label(oid: &Oid<'_>) -> String {
    match oid_registry().get(oid) {
        Some(entry) => format!("{} ({})", entry.sn(), oid.to_id_string()),
        None => oid.to_id_string(),
    }
}

fn oid_short(oid: &Oid<'_>) -> String {
    oid_registry()
        .get(oid)
        .map(|entry| entry.sn().to_string())
        .unwrap_or_else(|| oid.to_id_string())
}

fn upper_hex(value: &impl std::fmt::UpperHex) -> String {
    format!("{value:X}")
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Common name of the self-signed certificate this wallet puts in a sign-in
/// credential. The thumbprint URI is a subject alternative name.
pub(crate) const SELF_ISSUED_COMMON_NAME: &str = "Self-issued";

/// Self-signed P-256 certificate for `signing`. `subject_uri` is the key's
/// JWK thumbprint URI. `not_before` is a Unix time. The certificate is valid
/// for ten years from that time.
pub(crate) fn self_signed_p256(
    signing: &p256::ecdsa::SigningKey,
    subject_uri: &str,
    not_before: i64,
) -> Option<Vec<u8>> {
    use p256::ecdsa::signature::Signer;
    if subject_uri.is_empty() || !subject_uri.is_ascii() {
        return None;
    }
    let not_before = not_before.max(0);
    let not_after = not_before.saturating_add(10 * 365 * 24 * 60 * 60);
    let point = signing.verifying_key().to_encoded_point(false);
    let public = point.as_bytes();
    if public.len() != 65 {
        return None;
    }
    let serial = random_serial();
    let name = distinguished_name(SELF_ISSUED_COMMON_NAME);
    let mut tbs_body = der_explicit(0, &der_unsigned(&[2]));
    tbs_body.extend(der_unsigned(&serial));
    tbs_body.extend(ecdsa_sha256_alg());
    tbs_body.extend(name.clone());
    tbs_body.extend(validity(not_before, not_after));
    tbs_body.extend(name);
    tbs_body.extend(subject_public_key(public));
    tbs_body.extend(der_explicit(3, &v3_extensions(subject_uri)));
    let tbs = der_seq(&tbs_body);
    let signature: p256::ecdsa::Signature = signing.sign(&tbs);
    let mut certificate = tbs;
    certificate.extend(ecdsa_sha256_alg());
    certificate.extend(der_bit_string(&ecdsa_signature_der(&signature.to_bytes())));
    Some(der_seq(&certificate))
}

fn random_serial() -> [u8; 16] {
    use rand_core::RngCore;
    let mut serial = [0u8; 16];
    rand_core::OsRng.fill_bytes(&mut serial);
    serial[0] &= 0x7f;
    if serial.iter().all(|byte| *byte == 0) {
        serial[15] = 1;
    }
    serial
}

fn distinguished_name(common_name: &str) -> Vec<u8> {
    let mut attribute = der_oid(&[0x55, 0x04, 0x03]);
    attribute.extend(der_tlv(0x0c, common_name.as_bytes()));
    let attribute = der_seq(&attribute);
    der_seq(&der_tlv(0x31, &attribute))
}

fn subject_public_key(point: &[u8]) -> Vec<u8> {
    let mut algorithm = der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    algorithm.extend(der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]));
    let mut body = der_seq(&algorithm);
    body.extend(der_bit_string(point));
    der_seq(&body)
}

fn ecdsa_sha256_alg() -> Vec<u8> {
    der_seq(&der_oid(&[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]))
}

fn validity(not_before: i64, not_after: i64) -> Vec<u8> {
    let mut body = der_time(not_before);
    body.extend(der_time(not_after));
    der_seq(&body)
}

fn v3_extensions(subject_uri: &str) -> Vec<u8> {
    // digitalSignature. One bit of the bit string is used.
    let key_usage = der_tlv(0x03, &[0x07, 0x80]);
    let mut body = extension(&[0x55, 0x1d, 0x0f], true, &key_usage);
    body.extend(extension(&[0x55, 0x1d, 0x13], true, &der_seq(&[])));
    let alt_name = der_tlv(0x86, subject_uri.as_bytes());
    body.extend(extension(&[0x55, 0x1d, 0x11], false, &der_seq(&alt_name)));
    der_seq(&body)
}

fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
    let mut body = der_oid(oid);
    if critical {
        body.extend(der_tlv(0x01, &[0xff]));
    }
    body.extend(der_tlv(0x04, value));
    der_seq(&body)
}

fn ecdsa_signature_der(raw: &[u8]) -> Vec<u8> {
    let mut body = der_unsigned(&raw[..32]);
    body.extend(der_unsigned(&raw[32..]));
    der_seq(&body)
}

fn der_time(unix: i64) -> Vec<u8> {
    let (year, month, day, hour, minute, second) = civil_utc(unix);
    if (1950..2050).contains(&year) {
        let text = format!(
            "{:02}{:02}{:02}{:02}{:02}{:02}Z",
            year % 100,
            month,
            day,
            hour,
            minute,
            second
        );
        der_tlv(0x17, text.as_bytes())
    } else {
        let text = format!("{year:04}{month:02}{day:02}{hour:02}{minute:02}{second:02}Z");
        der_tlv(0x18, text.as_bytes())
    }
}

/// Gregorian UTC date from a Unix time. Years before 1970 become 1970-01-01.
fn civil_utc(unix: i64) -> (i32, u32, u32, u32, u32, u32) {
    let secs = unix.max(0) as u64;
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let hour = (tod / 3_600) as u32;
    let minute = ((tod % 3_600) / 60) as u32;
    let second = (tod % 60) as u32;
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    if month <= 2 {
        year += 1;
    }
    (year as i32, month, day, hour, minute, second)
}

fn der_unsigned(bytes: &[u8]) -> Vec<u8> {
    let mut start = 0;
    while start + 1 < bytes.len() && bytes[start] == 0 && bytes[start + 1] & 0x80 == 0 {
        start += 1;
    }
    let mut body = Vec::new();
    if bytes.get(start).is_some_and(|byte| byte & 0x80 != 0) {
        body.push(0);
    }
    body.extend_from_slice(&bytes[start..]);
    der_tlv(0x02, &body)
}

fn der_oid(body: &[u8]) -> Vec<u8> {
    der_tlv(0x06, body)
}

fn der_bit_string(bytes: &[u8]) -> Vec<u8> {
    let mut body = Vec::with_capacity(bytes.len() + 1);
    body.push(0);
    body.extend_from_slice(bytes);
    der_tlv(0x03, &body)
}

fn der_seq(body: &[u8]) -> Vec<u8> {
    der_tlv(0x30, body)
}

fn der_explicit(number: u8, body: &[u8]) -> Vec<u8> {
    der_tlv(0xa0 | number, body)
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

fn pem_certificate(der: &[u8]) -> String {
    let encoded = super::b64::b64_encode(der);
    let mut pem = String::from("-----BEGIN CERTIFICATE-----\n");
    let mut rest = encoded.as_str();
    while !rest.is_empty() {
        let end = rest.len().min(64);
        pem.push_str(&rest[..end]);
        pem.push('\n');
        rest = &rest[end..];
    }
    pem.push_str("-----END CERTIFICATE-----\n");
    pem
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

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
    ) -> rcgen::Certificate {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::ExplicitNoCa;
        params.distinguished_name.push(DnType::CommonName, cn);
        let issuer = Issuer::from_params(issuer_params, issuer_key);
        params.signed_by(&key, &issuer).unwrap()
    }

    fn document_with(ders: &[Vec<u8>]) -> String {
        let entries = ders
            .iter()
            .map(|der| format!("\"{}\"", super::super::b64::b64_encode(der)))
            .collect::<Vec<_>>()
            .join(",");
        let header = super::super::b64::b64url_encode(
            format!(r#"{{"alg":"ES256","x5c":[{entries}]}}"#).as_bytes(),
        );
        let payload = super::super::b64::b64url_encode(b"{{}}");
        let signature = super::super::b64::b64url_encode(&[1, 2, 3]);
        format!("{header}.{payload}.{signature}~disclosure")
    }

    fn field<'a>(cert: &'a SignerCertificate, name: &str) -> &'a str {
        cert.fields
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .unwrap_or("")
    }

    #[test]
    fn the_signer_chain_is_leaf_first_and_pem_round_trips() {
        let (ca_key, ca_params, ca_cert) = ca("Wallet CA");
        let leaf_cert = leaf("Wallet Leaf", &ca_params, &ca_key);
        let leaf_der = leaf_cert.der().to_vec();
        let ca_der = ca_cert.der().to_vec();
        let chain = signer_certificates(&document_with(&[leaf_der.clone(), ca_der.clone()]));
        assert_eq!(chain.len(), 2);
        assert!(chain[0].title.contains("Wallet Leaf"));
        assert!(chain[1].title.contains("Wallet CA"));
        assert!(field(&chain[0], "Issuer").contains("Wallet CA"));
        assert!(field(&chain[0], "Subject").contains("Wallet Leaf"));
        assert!(chain[0]
            .fields
            .iter()
            .any(|(key, _)| key.starts_with("Subject.")));
        assert!(field(&chain[0], "Version").starts_with('3'));
        assert!(chain[0].pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
        assert!(chain[0].pem.ends_with("-----END CERTIFICATE-----\n"));
        assert_eq!(certificates_in(chain[0].pem.as_bytes()), vec![leaf_der]);
        assert_eq!(certificates_in(chain[1].pem.as_bytes()), vec![ca_der]);
        assert!(chain[1].fields.iter().any(|(key, value)| {
            key.contains("basicConstraints") && value.contains("CA: true")
        }));
    }

    #[test]
    fn a_document_without_x5c_has_no_signer_certificate() {
        let header = super::super::b64::b64url_encode(br#"{"alg":"ES256"}"#);
        assert!(signer_certificates(&format!("{header}.e30.AQ")).is_empty());
        assert!(signer_certificates(r#"{"proof":{"type":"DataIntegrityProof"}}"#).is_empty());
    }

    #[test]
    fn a_disclosure_does_not_change_the_signer_chain() {
        let (ca_key, ca_params, ca_cert) = ca("Wallet CA");
        let leaf_cert = leaf("Wallet Leaf", &ca_params, &ca_key);
        let document = document_with(&[leaf_cert.der().to_vec(), ca_cert.der().to_vec()]);
        let with_disclosure = signer_certificates(&document);
        let issuer_only = document.split('~').next().unwrap();
        let without = signer_certificates(issuer_only);
        assert_eq!(with_disclosure.len(), without.len());
        assert_eq!(with_disclosure[0].pem, without[0].pem);
        assert_eq!(with_disclosure[1].title, without[1].title);
    }

    #[test]
    fn a_self_signed_signer_certificate_verifies_and_names_the_key() {
        let signing = p256::ecdsa::SigningKey::random(&mut rand_core::OsRng);
        let not_before = 1_700_000_000;
        let uri = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        let der = self_signed_p256(&signing, uri, not_before).unwrap();
        let cert = OwnedCert::parse(&der).unwrap();
        assert_eq!(cert.name, SELF_ISSUED_COMMON_NAME);
        assert_eq!(cert.subject_der, cert.issuer_der);
        assert_eq!(cert.not_before, not_before);
        assert_eq!(cert.not_after, not_before + 10 * 365 * 24 * 60 * 60);
        assert!(matches!(
            link(&cert, &cert.key, &cert.sig_oid),
            Link::Verified
        ));
        let shown = signer_certificates(&document_with(&[der]));
        assert_eq!(shown.len(), 1);
        assert!(shown[0].title.contains(SELF_ISSUED_COMMON_NAME));
        assert!(shown[0].fields.iter().any(|(_, value)| value.contains(uri)));
        assert!(shown[0].pem.starts_with("-----BEGIN CERTIFICATE-----\n"));
    }
}
