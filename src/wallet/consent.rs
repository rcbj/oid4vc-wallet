//! Credentials this person has agreed to present without being asked again.
//!
//! The file is `$XDG_CONFIG_HOME/oid4vc-wallet/presentation-approvals`. The
//! directory is mode `0700` and the file is mode `0600`. Each line is one
//! credential id. A credential that is not listed is asked the next time its
//! key would be used.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use crate::i18n::{t, t_args};

/// `$XDG_CONFIG_HOME/oid4vc-wallet/presentation-approvals`.
///
/// # Errors
///
/// The configuration directory cannot be found.
pub fn default_path() -> Result<PathBuf, String> {
    Ok(crate::xdg::config_home()?
        .join("oid4vc-wallet")
        .join("presentation-approvals"))
}

/// Credential ids that skip the presentation prompt. A missing file is empty.
pub fn approved_ids(path: &Path) -> Vec<String> {
    let Ok(text) = fs::read_to_string(path) else {
        return Vec::new();
    };
    text.lines()
        .filter(|line| valid_id(line))
        .map(str::to_string)
        .collect()
}

/// Remember that `id` may be presented again without a prompt.
///
/// # Errors
///
/// `id` is not a credential id, or the approvals file cannot be read or
/// written.
pub fn remember(path: &Path, id: &str) -> Result<(), String> {
    if !valid_id(id) {
        return Err(t("wallet.consent.bad_id"));
    }
    let mut lines = match fs::read_to_string(path) {
        Ok(text) => text
            .lines()
            .filter(|line| valid_id(line))
            .map(str::to_string)
            .collect::<Vec<_>>(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(err) => {
            return Err(t_args(
                "wallet.consent.write",
                &[("error", &err.to_string())],
            ))
        }
    };
    if lines.iter().any(|saved| saved == id) {
        return Ok(());
    }
    lines.push(id.to_string());
    write_lines(path, &lines)
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

fn write_lines(path: &Path, lines: &[String]) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(0o700);
            builder
                .create(parent)
                .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
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
            .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
        for line in lines {
            writeln!(file, "{line}")
                .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
        }
        file.sync_all()
            .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600))
            .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
        fs::rename(&temporary, path)
            .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .map_err(|err| t_args("wallet.consent.write", &[("error", &err.to_string())]))?;
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
    fn remembers_one_credential_and_asks_again_for_another() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-consent-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let path = root.join("presentation-approvals");
        let kept = "0123456789abcdef0123456789abcdef";
        let other = "fedcba9876543210fedcba9876543210";
        assert_eq!(approved_ids(&path), Vec::<String>::new());
        remember(&path, kept).unwrap();
        assert_eq!(approved_ids(&path), vec![kept.to_string()]);
        assert!(!approved_ids(&path).iter().any(|id| id == other));
        remember(&path, kept).unwrap();
        assert_eq!(approved_ids(&path).len(), 1);
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        assert!(remember(&path, "cred-same").is_err());
        assert!(remember(&path, "not-hex-and-not-32-chars!!!!").is_err());
        fs::remove_dir_all(&root).unwrap();
    }
}
