//! The build's version, M.N.O, stamped by `build.rs`.
//!
//! This is the scheme iya-sts and id-proto-debugger use, so one version
//! string reads the same way in all three. M.N is the repo-root `VERSION`
//! file. O is the UTC build instant as `YYYYMMDDHHMMSS`, or `BUILD_NUMBER`
//! when the build set it. `Cargo.toml` carries M.N.0 because semver needs
//! three parts.

/// The full version, for example `0.1.20261020143205`.
pub const VERSION: &str = env!("OID4VC_WALLET_VERSION");
/// M.N from the `VERSION` file.
pub const MAJOR_MINOR: &str = env!("OID4VC_WALLET_MAJOR_MINOR");
/// O, the build number.
pub const BUILD: &str = env!("OID4VC_WALLET_BUILD");
/// When `build.rs` ran, as RFC 3339 UTC.
pub const BUILT_AT: &str = env!("OID4VC_WALLET_BUILT_AT");
/// Short commit id, empty when the build had no git history.
pub const COMMIT: &str = env!("OID4VC_WALLET_COMMIT");

#[cfg(test)]
mod tests {
    use super::*;

    // Bumping a release means editing VERSION and Cargo.toml together. This
    // is the check that catches the half-done bump, since build.rs only warns.
    #[test]
    fn cargo_version_is_the_version_file_plus_zero() {
        assert_eq!(env!("CARGO_PKG_VERSION"), format!("{MAJOR_MINOR}.0"));
        assert_ne!(MAJOR_MINOR, "0.0");
    }

    #[test]
    fn version_is_major_minor_then_build() {
        assert_eq!(VERSION, format!("{MAJOR_MINOR}.{BUILD}"));
        assert!(!BUILD.is_empty());
        assert_eq!(BUILT_AT.len(), "2026-10-20T14:32:05Z".len());
        assert!(BUILT_AT.ends_with('Z'));
    }

    // Without BUILD_NUMBER the build number is the build instant, so the two
    // must name the same second.
    #[test]
    fn default_build_number_is_the_build_instant() {
        if option_env!("BUILD_NUMBER").is_some() {
            return;
        }
        let digits: String = BUILT_AT.chars().filter(char::is_ascii_digit).collect();
        assert_eq!(BUILD, digits);
    }
}
