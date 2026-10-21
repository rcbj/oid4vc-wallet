//! Embed `locales/` so a language is a catalog file plus a row in
//! `locales/catalogs.json`, which is the same layout iya-sts uses.
//!
//! Also stamp the version, M.N.O, the scheme iya-sts and id-proto-debugger
//! use: M.N from the repo-root `VERSION` file, O the UTC build instant as
//! `YYYYMMDDHHMMSS` unless `BUILD_NUMBER` names one. It is stamped here so a
//! restarted window reports the build that was made, not a new number.

use std::fs;
use std::path::Path;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn main() {
    let manifest = std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR");
    stamp_version(&manifest);
    let locales = Path::new(&manifest).join("locales");
    println!("cargo:rerun-if-changed={}", locales.display());
    let mut out = String::new();
    out.push_str(&format!(
        "pub const INDEX_JSON: &str = include_str!(r\"{}/locales/catalogs.json\");\n",
        manifest
    ));
    out.push_str("pub fn catalog_json(namespace: &str, tag: &str) -> Option<&'static str> {\n");
    out.push_str("    match (namespace, tag) {\n");
    let entries = fs::read_dir(&locales).expect("locales directory");
    for entry in entries {
        let entry = entry.expect("locales entry");
        if !entry.file_type().expect("file type").is_dir() {
            continue;
        }
        let ns = entry.file_name().into_string().expect("namespace name");
        println!("cargo:rerun-if-changed={}", entry.path().display());
        for file in fs::read_dir(entry.path()).expect("namespace directory") {
            let file = file.expect("catalog file");
            let name = file.file_name().into_string().expect("catalog file name");
            let Some(tag) = name.strip_suffix(".json") else {
                continue;
            };
            println!("cargo:rerun-if-changed={}", file.path().display());
            out.push_str(&format!(
                "        (\"{ns}\", \"{tag}\") => Some(include_str!(r\"{path}\")),\n",
                path = file.path().display()
            ));
        }
    }
    out.push_str("        _ => None,\n    }\n}\n");
    let dest = Path::new(&std::env::var("OUT_DIR").expect("OUT_DIR")).join("locales_gen.rs");
    fs::write(dest, out).expect("write locales_gen.rs");
}

fn stamp_version(manifest: &str) {
    // Any explicit rerun-if-changed turns off cargo's "rerun on any package
    // change". Without the sources here the build number would keep the
    // instant of the last locale edit and name two different binaries.
    for input in ["VERSION", "Cargo.toml", "build.rs", "src"] {
        println!("cargo:rerun-if-changed={manifest}/{input}");
    }
    println!("cargo:rerun-if-env-changed=BUILD_NUMBER");
    println!("cargo:rerun-if-env-changed=GIT_COMMIT");
    let major_minor = major_minor(manifest);
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let stamp = utc_stamp(secs);
    let build = match std::env::var("BUILD_NUMBER") {
        Ok(value) if printable(value.trim()) => value.trim().to_string(),
        Ok(value) if !value.trim().is_empty() => {
            println!("cargo:warning=ignoring BUILD_NUMBER {value:?}; using {stamp}");
            stamp.clone()
        }
        _ => stamp.clone(),
    };
    let built_at = format!(
        "{}-{}-{}T{}:{}:{}Z",
        &stamp[0..4],
        &stamp[4..6],
        &stamp[6..8],
        &stamp[8..10],
        &stamp[10..12],
        &stamp[12..14]
    );
    println!("cargo:rustc-env=OID4VC_WALLET_MAJOR_MINOR={major_minor}");
    println!("cargo:rustc-env=OID4VC_WALLET_BUILD={build}");
    println!("cargo:rustc-env=OID4VC_WALLET_VERSION={major_minor}.{build}");
    println!("cargo:rustc-env=OID4VC_WALLET_BUILT_AT={built_at}");
    println!("cargo:rustc-env=OID4VC_WALLET_COMMIT={}", commit(manifest));
}

// A malformed or missing file warns and builds as 0.0, as iya-sts does: a
// version misinforms a reader, and must never be what stops a build. The
// test in src/version.rs then fails because Cargo.toml no longer matches.
fn major_minor(manifest: &str) -> String {
    let path = Path::new(manifest).join("VERSION");
    let raw = match fs::read_to_string(&path) {
        Ok(raw) => raw,
        Err(err) => {
            println!(
                "cargo:warning=no readable {}: {err}; using 0.0",
                path.display()
            );
            return "0.0".to_string();
        }
    };
    let text = raw.trim();
    let valid = text.split_once('.').is_some_and(|(major, minor)| {
        [major, minor]
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
    });
    if valid {
        return text.to_string();
    }
    println!(
        "cargo:warning=ignoring malformed {}: {text:?} (want M.N); using 0.0",
        path.display()
    );
    "0.0".to_string()
}

// A cargo directive ends at the newline, so a control character would cut
// the value or inject another directive.
fn printable(value: &str) -> bool {
    !value.is_empty() && !value.chars().any(char::is_control)
}

fn utc_stamp(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Days since 1970-01-01 to a civil date (Howard Hinnant's algorithm),
    // because the build script has no date crate and should not gain one.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}{month:02}{day:02}{:02}{:02}{:02}",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

// Provenance for the hover text only. A tarball or an AppImage build without
// history has no commit, and that is an empty string rather than a failure.
fn commit(manifest: &str) -> String {
    if let Ok(value) = std::env::var("GIT_COMMIT") {
        let value: String = value.trim().chars().take(12).collect();
        if printable(&value) {
            return value;
        }
    }
    Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .current_dir(manifest)
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| String::from_utf8(out.stdout).ok())
        .map(|text| text.trim().to_string())
        .filter(|text| printable(text))
        .unwrap_or_default()
}
