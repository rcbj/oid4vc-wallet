//! Base64 and base64url, for JWS segments and `x5c` certificates.
//!
//! JWS segments are unpadded base64url. An `x5c` certificate is standard
//! base64. Both decoders accept the other's alphabet so a credential that
//! mixes them still parses.

/// Encode `bytes` as unpadded base64url.
pub(crate) fn b64url_encode(bytes: &[u8]) -> String {
    encode(bytes, true, false)
}

/// Encode `bytes` as standard base64 with padding.
pub(crate) fn b64_encode(bytes: &[u8]) -> String {
    encode(bytes, false, true)
}

/// Decode standard base64 or base64url. Whitespace is ignored. Padding is
/// optional.
pub(crate) fn b64_decode(text: &str) -> Option<Vec<u8>> {
    let mut filtered = String::new();
    for ch in text.chars() {
        if ch.is_ascii_whitespace() {
            continue;
        }
        filtered.push(match ch {
            '-' => '+',
            '_' => '/',
            other => other,
        });
    }
    match filtered.len() % 4 {
        1 => return None,
        2 => filtered.push_str("=="),
        3 => filtered.push('='),
        _ => {}
    }
    let bytes = filtered.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut index = 0;
    while index + 4 <= bytes.len() {
        let chunk = &bytes[index..index + 4];
        let pad = chunk.iter().rev().take_while(|byte| **byte == b'=').count();
        if pad > 2 || chunk[..4 - pad].contains(&b'=') {
            return None;
        }
        let mut n = 0u32;
        for (shift, byte) in chunk.iter().enumerate() {
            let value = if *byte == b'=' { 0 } else { value(*byte)? };
            n |= u32::from(value) << (18 - 6 * shift);
        }
        let [_, first, second, third] = n.to_be_bytes();
        out.push(first);
        if pad < 2 {
            out.push(second);
        }
        if pad < 1 {
            out.push(third);
        }
        index += 4;
    }
    Some(out)
}

fn encode(bytes: &[u8], url: bool, pad: bool) -> String {
    let table = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = (u32::from(bytes[index]) << 16)
            | (u32::from(bytes[index + 1]) << 8)
            | u32::from(bytes[index + 2]);
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        out.push(table[((n >> 6) & 63) as usize] as char);
        out.push(table[(n & 63) as usize] as char);
        index += 3;
    }
    let rest = bytes.len() - index;
    if rest == 1 {
        let n = u32::from(bytes[index]) << 16;
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        if pad {
            out.push_str("==");
        }
    } else if rest == 2 {
        let n = (u32::from(bytes[index]) << 16) | (u32::from(bytes[index + 1]) << 8);
        out.push(table[((n >> 18) & 63) as usize] as char);
        out.push(table[((n >> 12) & 63) as usize] as char);
        out.push(table[((n >> 6) & 63) as usize] as char);
        if pad {
            out.push('=');
        }
    }
    out
}

fn value(byte: u8) -> Option<u8> {
    match byte {
        b'A'..=b'Z' => Some(byte - b'A'),
        b'a'..=b'z' => Some(byte - b'a' + 26),
        b'0'..=b'9' => Some(byte - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Lower-case hex SHA-256 of `bytes`.
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    use std::fmt::Write as _;
    let digest = sha2::Sha256::digest(bytes);
    let mut out = String::with_capacity(digest.len() * 2);
    for byte in digest {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
