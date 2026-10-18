//! The saved language, one tag in `$XDG_CONFIG_HOME/oid4vc-wallet/language`.
//!
//! The directory is mode `0700` and the file is mode `0600`. Tests pass a
//! path so they do not read the process environment.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use super::matching::canonical;

/// `$XDG_CONFIG_HOME/oid4vc-wallet/language`.
pub fn language_path() -> Result<PathBuf, String> {
    Ok(crate::xdg::config_home()?
        .join("oid4vc-wallet")
        .join("language"))
}

/// The tag in `path`, canonicalised. An empty or malformed file is absent.
pub fn read_tag(path: &Path) -> Option<String> {
    let text = fs::read_to_string(path).ok()?;
    let line = text.lines().find(|line| !line.trim().is_empty())?;
    let tag = canonical(line.trim());
    if tag.is_empty() {
        None
    } else {
        Some(tag)
    }
}

/// Write `tag` as the only line of `path`.
pub fn write_tag(path: &Path, tag: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            builder.mode(0o700);
            builder.create(parent).map_err(write_error)?;
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).map_err(write_error)?;
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
            .map_err(write_error)?;
        writeln!(file, "{tag}").map_err(write_error)?;
        file.sync_all().map_err(write_error)?;
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).map_err(write_error)?;
        fs::rename(&temporary, path).map_err(write_error)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).map_err(write_error)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

/// Remove `path` when it is there.
pub fn remove_tag(path: &Path) -> Result<(), String> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(write_error(err)),
    }
}

fn write_error(err: std::io::Error) -> String {
    super::t_args("wallet.cli.language_write", &[("error", &err.to_string())])
}
