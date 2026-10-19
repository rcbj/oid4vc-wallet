//! Issuers this person has agreed to trust.
//!
//! The file is `$XDG_CONFIG_HOME/oid4vc-wallet/trusted-issuers`. The directory
//! is mode `0700` and the file is mode `0600`. Each line is the issuer URL, a
//! tab, and the hex SHA-256 of the leaf certificate's public key. A different
//! key for the same issuer is a different line, so it is asked again.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

/// `$XDG_CONFIG_HOME/oid4vc-wallet/trusted-issuers`.
pub(crate) fn default_path() -> Result<PathBuf, String> {
    Ok(crate::xdg::config_home()?
        .join("oid4vc-wallet")
        .join("trusted-issuers"))
}

/// `true` when this issuer and this key were accepted before.
pub(crate) fn is_trusted(path: &Path, issuer: &str, fingerprint: &str) -> bool {
    let Ok(text) = fs::read_to_string(path) else {
        return false;
    };
    text.lines().any(|line| match line.split_once('\t') {
        Some((saved_issuer, saved_fingerprint)) => {
            !saved_fingerprint.contains('\t')
                && saved_issuer == issuer
                && saved_fingerprint == fingerprint
        }
        None => false,
    })
}

/// Record that `issuer`'s key `fingerprint` is trusted.
pub(crate) fn remember(path: &Path, issuer: &str, fingerprint: &str) -> Result<(), String> {
    let issuer = one_field(issuer)?;
    let fingerprint = one_field(fingerprint)?;
    if is_trusted(path, issuer, fingerprint) {
        return Ok(());
    }
    let mut lines = match fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .filter(|line| line.split_once('\t').is_some())
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => return Err(err.to_string()),
    };
    lines.push(format!("{issuer}\t{fingerprint}"));
    write_lines(path, &lines)
}

fn one_field(value: &str) -> Result<&str, String> {
    if value.contains(['\t', '\n', '\r']) {
        return Err("invalid trust record".to_string());
    }
    let value = value.trim();
    if value.is_empty() {
        Err("invalid trust record".to_string())
    } else {
        Ok(value)
    }
}

fn write_lines(path: &Path, lines: &[String]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(0o700);
            builder.create(parent).map_err(|err| err.to_string())?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| err.to_string())?;
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
            .map_err(|err| err.to_string())?;
        for line in lines {
            writeln!(file, "{line}").map_err(|err| err.to_string())?;
        }
        file.sync_all().map_err(|err| err.to_string())?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|err| err.to_string())?;
        fs::rename(&temporary, path).map_err(|err| err.to_string())?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| err.to_string())?;
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
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn remembers_one_key_and_asks_again_for_another() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-trust-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let path = root.join("trusted-issuers");
        assert!(!is_trusted(&path, "https://issuer.example", "aa"));
        remember(&path, "https://issuer.example", "aa").unwrap();
        assert!(is_trusted(&path, "https://issuer.example", "aa"));
        assert!(!is_trusted(&path, "https://issuer.example", "bb"));
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert!(remember(&path, "https://issuer.example\n", "aa").is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
