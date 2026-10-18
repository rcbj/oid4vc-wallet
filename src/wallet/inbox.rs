//! Files under the wallet's data directory, one per invocation.
//!
//! A pre-authorized code is a bearer credential, so the directory is `0700`
//! and each file is `0600`.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Where invocations are stored.
pub struct Inbox {
    root: PathBuf,
}

/// One stored invocation.
pub struct InboxEntry {
    pub path: PathBuf,
}

impl Inbox {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// `$XDG_DATA_HOME/oid4vc-wallet/inbox`.
    pub fn default_location() -> Result<Self, String> {
        Ok(Self::new(
            crate::xdg::data_home()?.join("oid4vc-wallet").join("inbox"),
        ))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Write one invocation. The file name sorts by the time it was received.
    pub fn save(&self, uri: &str, summary: &str) -> io::Result<PathBuf> {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true);
        builder.mode(0o700);
        builder.create(&self.root)?;
        // A directory that already existed may be looser. Tighten it.
        fs::set_permissions(&self.root, fs::Permissions::from_mode(0o700))?;
        let name = format!("{}-{}.txt", utc_stamp(now_millis()), scheme_of(uri));
        let path = unique_path(&self.root, &name)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)?;
        writeln!(file, "uri {uri}")?;
        writeln!(file)?;
        writeln!(file, "{summary}")?;
        file.flush()?;
        Ok(path)
    }

    /// Stored invocations, oldest first.
    pub fn list(&self) -> io::Result<Vec<InboxEntry>> {
        if !self.root.exists() {
            return Ok(Vec::new());
        }
        let mut names = Vec::new();
        for entry in fs::read_dir(&self.root)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(text) = name.to_str() else {
                continue;
            };
            if text.ends_with(".txt") {
                names.push(text.to_string());
            }
        }
        names.sort();
        Ok(names
            .into_iter()
            .map(|name| InboxEntry {
                path: self.root.join(name),
            })
            .collect())
    }
}

fn scheme_of(uri: &str) -> String {
    let scheme = uri.split(':').next().unwrap_or("invocation");
    let mut cleaned = String::new();
    for ch in scheme.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            cleaned.push(ch);
        }
    }
    if cleaned.is_empty() {
        "invocation".to_string()
    } else {
        cleaned
    }
}

fn unique_path(root: &Path, name: &str) -> io::Result<PathBuf> {
    let candidate = root.join(name);
    if !candidate.exists() {
        return Ok(candidate);
    }
    let stem = name.trim_end_matches(".txt");
    for index in 2..10_000 {
        let path = root.join(format!("{stem}-{index}.txt"));
        if !path.exists() {
            return Ok(path);
        }
    }
    Err(io::Error::new(
        io::ErrorKind::AlreadyExists,
        "could not choose an inbox file name",
    ))
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// `YYYYMMDDTHHMMSS.mmmZ` for a Unix timestamp in milliseconds.
pub fn utc_stamp(unix_ms: u64) -> String {
    let secs = unix_ms / 1000;
    let millis = unix_ms % 1000;
    let days = (secs / 86_400) as i64;
    let tod = secs % 86_400;
    let hour = tod / 3600;
    let minute = (tod % 3600) / 60;
    let second = tod % 60;
    let (year, month, day) = civil_from_days(days);
    format!("{year:04}{month:02}{day:02}T{hour:02}{minute:02}{second:02}.{millis:03}Z")
}

/// Howard Hinnant's `civil_from_days`. `days` is the number of days since
/// 1970-01-01. Returns `(year, month, day)`.
fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let shifted = if z >= 0 { z } else { z - 146_096 };
    let era = shifted / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = (if mp < 10 { mp + 3 } else { mp - 9 }) as u32;
    let year = (if month <= 2 { y + 1 } else { y }) as i32;
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    #[test]
    fn stamps_the_unix_epoch_and_a_leap_day() {
        assert_eq!(utc_stamp(0), "19700101T000000.000Z");
        // 2000-02-29 00:00:00 UTC.
        assert_eq!(utc_stamp(951_782_400_000), "20000229T000000.000Z");
    }

    #[test]
    fn stores_an_offer_where_only_the_owner_can_read_it() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-inbox-{}-{}",
            std::process::id(),
            now_millis()
        ));
        let inbox = Inbox::new(&root);
        let path = inbox
            .save(
                "openid-credential-offer://?credential_offer=%7B%7D",
                "summary line",
            )
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        let text = fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("uri openid-credential-offer://"));
        assert!(text.contains("summary line"));
        assert_eq!(inbox.list().unwrap().len(), 1);
        fs::remove_dir_all(&root).unwrap();
    }
}
