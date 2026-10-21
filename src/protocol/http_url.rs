//! The absolute `http` and `https` URLs a credential issuer, an offer fetched
//! by reference, and a verifier's request URI are required to be.

/// An absolute `http` or `https` URL with a host and no spaces or controls.
///
/// This is the check the wallet applies before it is willing to remember an
/// address. It does not resolve the name and it does not fetch it.
#[must_use]
pub fn is_http_url(value: &str) -> bool {
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"));
    let Some(rest) = rest else {
        return false;
    };
    if rest.is_empty() || rest.starts_with('/') {
        return false;
    }
    let host = rest.split(['/', '?', '#']).next().unwrap_or("");
    if host.is_empty() {
        return false;
    }
    !value
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_issuer_and_localhost() {
        assert!(is_http_url("https://sts.example/oid4vci"));
        assert!(is_http_url("http://localhost:8080/oid4vp/request/abc"));
        assert!(is_http_url("https://sts.example"));
    }

    #[test]
    fn rejects_schemes_a_wallet_must_not_fetch() {
        assert!(!is_http_url(""));
        assert!(!is_http_url("sts.example"));
        assert!(!is_http_url("javascript:alert(1)"));
        assert!(!is_http_url("file:///tmp/offer.json"));
        assert!(!is_http_url("https://"));
        assert!(!is_http_url("https:///missing-host"));
        assert!(!is_http_url("https://sts.example/a b"));
        assert!(!is_http_url("openid-credential-offer://?x=1"));
    }
}
