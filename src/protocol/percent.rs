//! Percent-encoding for the query strings issuers and verifiers hand a wallet.
//!
//! iya-sts builds those queries with `encodeURIComponent`, which leaves
//! `A-Z a-z 0-9 - _ . ! ~ * ' ( )` alone and encodes every other UTF-8 byte.
//! Decoding also accepts `+` as a space, because a query string is
//! `application/x-www-form-urlencoded`.

/// Why a percent-encoded value could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PercentError {
    /// A `%` was not followed by two hex digits.
    BadEscape { at: usize },
    /// The decoded bytes were not UTF-8.
    Utf8 { at: usize },
}

impl std::fmt::Display for PercentError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadEscape { at } => {
                write!(f, "invalid percent-escape at byte {at}")
            }
            Self::Utf8 { at } => {
                write!(f, "percent-decoded bytes are not UTF-8 at byte {at}")
            }
        }
    }
}

impl std::error::Error for PercentError {}

/// Decode a query component. `+` becomes a space.
pub fn form_decode(input: &str) -> Result<String, PercentError> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b'%' => {
                if i + 2 >= bytes.len() {
                    return Err(PercentError::BadEscape { at: i });
                }
                let hi = hex_digit(bytes[i + 1]).ok_or(PercentError::BadEscape { at: i })?;
                let lo = hex_digit(bytes[i + 2]).ok_or(PercentError::BadEscape { at: i })?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            byte => {
                out.push(byte);
                i += 1;
            }
        }
    }
    match String::from_utf8(out) {
        Ok(text) => Ok(text),
        Err(err) => Err(PercentError::Utf8 {
            at: err.utf8_error().valid_up_to(),
        }),
    }
}

/// Encode the way JavaScript `encodeURIComponent` does, so tests can build
/// the same URIs iya-sts builds.
pub fn encode_uri_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if is_uri_component_unreserved(byte) {
            out.push(byte as char);
        } else {
            out.push('%');
            out.push(hex_char(byte >> 4));
            out.push(hex_char(byte & 0x0f));
        }
    }
    out
}

fn is_uri_component_unreserved(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'_' | b'.' | b'!' | b'~' | b'*' | b'\'' | b'(' | b')'
        )
}

fn hex_digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_char(nibble: u8) -> char {
    char::from(b"0123456789ABCDEF"[nibble as usize])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_encode_uri_component_round_trip() {
        let raw = "héllo ✓ +/=";
        let encoded = encode_uri_component(raw);
        assert!(!encoded.contains('é'));
        assert!(encoded.contains("%2B") || encoded.contains("%2b"));
        assert_eq!(form_decode(&encoded).unwrap(), raw);
    }

    #[test]
    fn plus_is_a_space_and_percent_2b_is_a_plus() {
        assert_eq!(form_decode("a+b%2Bc").unwrap(), "a b+c");
    }

    #[test]
    fn rejects_a_truncated_escape() {
        assert!(matches!(
            form_decode("abc%2"),
            Err(PercentError::BadEscape { .. })
        ));
        assert!(matches!(
            form_decode("%zz"),
            Err(PercentError::BadEscape { .. })
        ));
    }

    #[test]
    fn rejects_invalid_utf8() {
        assert!(matches!(form_decode("%FF"), Err(PercentError::Utf8 { .. })));
    }
}
