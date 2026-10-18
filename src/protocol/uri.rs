//! Custom-scheme URIs of the form a wallet is launched with.
//!
//! `openid-credential-offer://?credential_offer=…` and `siopv2://?client_id=…`
//! have an empty authority. The `url` pattern most libraries use still
//! expects a host, so this parser is the one that accepts the strings the
//! desktop actually delivers.

use super::query::{parse_query, QueryError, QueryParam};

/// The longest invocation this process will parse. A credential offer by
/// value is a few kilobytes; anything larger is refused before it is stored.
pub const MAX_URI_LEN: usize = 2 * 1024 * 1024;

/// A custom-scheme URI split into its scheme, query and fragment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CustomUri {
    /// Lowercased scheme, without `:`.
    pub scheme: String,
    /// Characters between the scheme's `:` and the query, such as `//`.
    pub hier: String,
    pub query: Vec<QueryParam>,
    pub fragment: Option<String>,
}

/// Why an invocation URI was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UriError {
    Empty,
    TooLong,
    Whitespace,
    MissingScheme,
    BadScheme,
    Query(QueryError),
}

impl std::fmt::Display for UriError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => write!(f, "the invocation URI is empty"),
            Self::TooLong => write!(f, "the invocation URI is longer than {MAX_URI_LEN} bytes"),
            Self::Whitespace => {
                write!(
                    f,
                    "the invocation URI contains whitespace or a control character"
                )
            }
            Self::MissingScheme => write!(f, "the invocation URI has no scheme"),
            Self::BadScheme => write!(f, "the invocation URI's scheme is not a valid scheme"),
            Self::Query(err) => write!(f, "{err}"),
        }
    }
}

impl std::error::Error for UriError {}

/// Split a wallet invocation into its scheme and query.
pub fn parse_uri(input: &str) -> Result<CustomUri, UriError> {
    if input.is_empty() {
        return Err(UriError::Empty);
    }
    if input.len() > MAX_URI_LEN {
        return Err(UriError::TooLong);
    }
    if input
        .chars()
        .any(|c| c.is_ascii_whitespace() || c.is_control())
    {
        return Err(UriError::Whitespace);
    }
    let (scheme, rest) = input.split_once(':').ok_or(UriError::MissingScheme)?;
    if !is_scheme(scheme) {
        return Err(UriError::BadScheme);
    }
    let (before_fragment, fragment) = match rest.split_once('#') {
        Some((head, fragment)) => (head, Some(fragment.to_string())),
        None => (rest, None),
    };
    let (hier, raw_query) = match before_fragment.split_once('?') {
        Some((hier, query)) => (hier, query),
        None => (before_fragment, ""),
    };
    let query = parse_query(raw_query).map_err(UriError::Query)?;
    Ok(CustomUri {
        scheme: scheme.to_ascii_lowercase(),
        hier: hier.to_string(),
        query,
        fragment,
    })
}

fn is_scheme(scheme: &str) -> bool {
    let mut chars = scheme.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
}

/// Build `scheme://?name=value&…` with `encodeURIComponent` encoding.
///
/// Test code uses this to build the same URIs iya-sts builds. The wallet
/// itself only parses invocations.
#[cfg(test)]
pub(crate) fn build_uri(scheme: &str, pairs: &[(&str, &str)]) -> String {
    use super::percent::encode_uri_component;

    let mut out = String::new();
    out.push_str(scheme);
    out.push_str("://?");
    for (index, (name, value)) in pairs.iter().enumerate() {
        if index > 0 {
            out.push('&');
        }
        out.push_str(&encode_uri_component(name));
        out.push('=');
        out.push_str(&encode_uri_component(value));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_empty_authority_offer_uri() {
        let uri = parse_uri("openid-credential-offer://?credential_offer=%7B%7D").unwrap();
        assert_eq!(uri.scheme, "openid-credential-offer");
        assert_eq!(uri.hier, "//");
        assert_eq!(uri.query.len(), 1);
        assert_eq!(uri.query[0].name, "credential_offer");
        assert_eq!(uri.query[0].value, "{}");
    }

    #[test]
    fn lowercases_the_scheme_and_keeps_a_fragment() {
        let uri = parse_uri("SIOPV2://?client_id=abc#ignored").unwrap();
        assert_eq!(uri.scheme, "siopv2");
        assert_eq!(uri.fragment.as_deref(), Some("ignored"));
    }

    #[test]
    fn rejects_whitespace_and_a_missing_scheme() {
        assert!(matches!(
            parse_uri("siopv2://?client_id=a b"),
            Err(UriError::Whitespace)
        ));
        assert!(matches!(
            parse_uri("not-a-uri"),
            Err(UriError::MissingScheme)
        ));
        assert!(matches!(parse_uri("1bad://?a=1"), Err(UriError::BadScheme)));
    }

    #[test]
    fn builds_the_query_the_way_an_issuer_does() {
        let uri = build_uri("siopv2", &[("client_id", "a b")]);
        assert_eq!(uri, "siopv2://?client_id=a%20b");
        let parsed = parse_uri(&uri).unwrap();
        assert_eq!(parsed.query[0].value, "a b");
    }
}
