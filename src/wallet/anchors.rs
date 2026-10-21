//! Certificates this person uploaded for credential validation.
//!
//! The directory is `$XDG_CONFIG_HOME/oid4vc-wallet/trust-anchors`, mode
//! `0700`. Each file is one DER certificate, mode `0600`, named by the hex
//! SHA-256 of that certificate. Validation can treat these as trust anchors
//! when the issuer did not publish a completable chain.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::b64;
use super::certs::{self, OwnedCert};

/// One uploaded certificate, for the Settings list.
pub struct StoredAnchor {
    pub name: String,
    pub fingerprint: String,
}

/// `$XDG_CONFIG_HOME/oid4vc-wallet/trust-anchors`.
///
/// # Errors
///
/// The configuration directory cannot be found.
pub fn default_dir() -> Result<PathBuf, String> {
    Ok(crate::xdg::config_home()?
        .join("oid4vc-wallet")
        .join("trust-anchors"))
}

/// DER certificates in `dir`. A missing directory is an empty list.
pub(crate) fn anchor_ders(dir: &Path) -> Vec<Vec<u8>> {
    let Ok(entries) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut ders = Vec::new();
    for entry in entries.flatten() {
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if Path::new(&name).extension().is_none_or(|ext| ext != "der") {
            continue;
        }
        let Ok(bytes) = fs::read(entry.path()) else {
            continue;
        };
        if OwnedCert::parse(&bytes).is_some() {
            ders.push(bytes);
        }
    }
    ders.sort();
    ders
}

/// Name and fingerprint of each certificate in `dir`.
#[must_use]
pub fn list(dir: &Path) -> Vec<StoredAnchor> {
    anchor_ders(dir)
        .into_iter()
        .filter_map(|der| {
            let cert = OwnedCert::parse(&der)?;
            Some(StoredAnchor {
                name: display_name(&cert),
                fingerprint: b64::sha256_hex(&cert.spki_der),
            })
        })
        .collect()
}

/// Store every certificate in a PEM document or a DER body.
///
/// A blank document and a document with no certificate are different errors.
///
/// # Errors
///
/// `text` is blank, holds no certificate this wallet can parse, or a
/// certificate cannot be written to `dir`.
pub fn install_pem(dir: &Path, text: &str) -> Result<usize, String> {
    if text.trim().is_empty() {
        return Err(crate::i18n::t("wallet.anchor.empty"));
    }
    let mut stored = 0usize;
    for der in certs::certificates_in(text.as_bytes()) {
        if OwnedCert::parse(&der).is_none() {
            continue;
        }
        write_der(dir, &der)?;
        stored += 1;
    }
    if stored == 0 {
        return Err(crate::i18n::t("wallet.anchor.invalid"));
    }
    Ok(stored)
}

/// Remove the certificate whose subject-key fingerprint is `fingerprint`.
///
/// # Errors
///
/// `fingerprint` is not a hex SHA-256, no certificate with it is stored, or the
/// file cannot be removed.
pub fn remove(dir: &Path, fingerprint: &str) -> Result<(), String> {
    if !is_fingerprint(fingerprint) {
        return Err(crate::i18n::t("wallet.anchor.invalid"));
    }
    let path = dir.join(format!("{fingerprint}.der"));
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            Err(crate::i18n::t("wallet.anchor.missing"))
        }
        Err(err) => Err(io_err(&err)),
    }
}

fn io_err(err: &impl std::fmt::Display) -> String {
    crate::i18n::t_args("wallet.anchor.io", &[("error", &err.to_string())])
}

fn display_name(cert: &OwnedCert) -> String {
    if cert.name.is_empty() {
        b64::sha256_hex(&cert.spki_der)
    } else {
        cert.name.clone()
    }
}

fn is_fingerprint(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn write_der(dir: &Path, der: &[u8]) -> Result<(), String> {
    let cert = OwnedCert::parse(der).ok_or_else(|| crate::i18n::t("wallet.anchor.invalid"))?;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    builder.mode(0o700);
    builder.create(dir).map_err(|err| io_err(&err))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|err| io_err(&err))?;
    let path = dir.join(format!("{}.der", b64::sha256_hex(&cert.spki_der)));
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&path)
        .map_err(|err| io_err(&err))?;
    file.write_all(der).map_err(|err| io_err(&err))?;
    file.sync_all().map_err(|err| io_err(&err))?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(|err| io_err(&err))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;

    use rcgen::{
        BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, PKCS_ECDSA_P256_SHA256,
    };

    use super::*;

    fn scratch() -> PathBuf {
        std::env::temp_dir().join(format!(
            "oid4vc-wallet-anchors-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ))
    }

    fn pem_cert(cn: &str) -> String {
        let key = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::default();
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.distinguished_name.push(DnType::CommonName, cn);
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn a_pem_root_is_stored_listed_and_removed() {
        let dir = scratch();
        let pem = pem_cert("Uploaded Root");
        let count = install_pem(&dir, &pem).unwrap();
        assert_eq!(count, 1);
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let listed = list(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].name, "Uploaded Root");
        assert_eq!(listed[0].fingerprint.len(), 64);
        let file = dir.join(format!("{}.der", listed[0].fingerprint));
        let file_mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(file_mode, 0o600);
        let ders = anchor_ders(&dir);
        assert_eq!(ders.len(), 1);
        assert!(OwnedCert::parse(&ders[0]).is_some());
        let fingerprint = listed[0].fingerprint.clone();
        remove(&dir, &fingerprint).unwrap();
        assert!(list(&dir).is_empty());
        assert_eq!(
            remove(&dir, &fingerprint).unwrap_err(),
            "no stored certificate has that fingerprint"
        );
        assert_eq!(
            install_pem(&dir, "   ").unwrap_err(),
            "no certificate was provided"
        );
        assert_eq!(
            install_pem(&dir, "this is not a certificate").unwrap_err(),
            "the text is not a PEM certificate"
        );
        assert_eq!(
            remove(&dir, "../etc/passwd").unwrap_err(),
            "the text is not a PEM certificate"
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
