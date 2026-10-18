//! XDG Base Directory paths this wallet reads and writes.
//!
//! `XDG_DATA_HOME` defaults to `~/.local/share` and `XDG_CONFIG_HOME` to
//! `~/.config`. An empty variable is treated as unset, which is what the
//! base-directory spec says.

use std::path::PathBuf;

/// The user's home directory, from `HOME`.
pub fn home() -> Result<PathBuf, String> {
    let value = std::env::var("HOME").map_err(|_| crate::i18n::t("wallet.xdg.home_unset"))?;
    if value.is_empty() {
        return Err(crate::i18n::t("wallet.xdg.home_empty"));
    }
    Ok(PathBuf::from(value))
}

/// `$XDG_DATA_HOME` or `~/.local/share`.
pub fn data_home() -> Result<PathBuf, String> {
    override_or("XDG_DATA_HOME", || Ok(home()?.join(".local/share")))
}

/// `$XDG_CONFIG_HOME` or `~/.config`.
pub fn config_home() -> Result<PathBuf, String> {
    override_or("XDG_CONFIG_HOME", || Ok(home()?.join(".config")))
}

fn override_or(
    var: &str,
    fallback: impl FnOnce() -> Result<PathBuf, String>,
) -> Result<PathBuf, String> {
    match std::env::var(var) {
        Ok(value) if !value.is_empty() => Ok(PathBuf::from(value)),
        _ => fallback(),
    }
}
