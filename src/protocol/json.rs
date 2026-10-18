//! A JSON reader and writer for the documents OpenID4VCI and OpenID4VP carry
//! inside a query parameter.
//!
//! Numbers are kept as their literal text. A credential offer's `length` is
//! an integer, and turning it into a float first would be a second parser.

/// One JSON value.
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    /// The exact number literal, for example `5` or `1.5e-2`.
    Number(String),
    String(String),
    Array(Vec<Json>),
    /// Object members in the order they were written.
    Object(Vec<(String, Json)>),
}

/// Why JSON text was refused, with a byte offset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonError {
    pub at: usize,
    pub message: String,
}

impl std::fmt::Display for JsonError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "JSON at byte {}: {}", self.at, self.message)
    }
}

impl std::error::Error for JsonError {}

impl Json {
    /// Parse one JSON value and refuse trailing text.
    pub fn parse(input: &str) -> Result<Self, JsonError> {
        let mut parser = Parser {
            bytes: input.as_bytes(),
            index: 0,
        };
        parser.skip();
        let value = parser.value()?;
        parser.skip();
        if parser.index != parser.bytes.len() {
            return Err(parser.error("trailing text after the JSON value"));
        }
        Ok(value)
    }

    /// The member named `key`, or the last one when the name is repeated.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Self::Object(members) => members
                .iter()
                .rev()
                .find(|(name, _)| name == key)
                .map(|(_, value)| value),
            _ => None,
        }
    }

    /// Names of the members, in order, including duplicates.
    pub fn keys(&self) -> Vec<&str> {
        match self {
            Self::Object(members) => members.iter().map(|(name, _)| name.as_str()).collect(),
            _ => Vec::new(),
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::String(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Self::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Self::Object(members) => Some(members),
            _ => None,
        }
    }

    /// The number when it is a base-10 integer with no exponent and no
    /// fraction, and it fits in `u64`.
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Self::Number(literal) => parse_u64_literal(literal),
            _ => None,
        }
    }
}

fn parse_u64_literal(literal: &str) -> Option<u64> {
    if literal.is_empty() || literal.bytes().any(|byte| !byte.is_ascii_digit()) {
        return None;
    }
    if literal.len() > 1 && literal.starts_with('0') {
        return None;
    }
    literal.parse().ok()
}

impl std::fmt::Display for Json {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Null => write!(f, "null"),
            Self::Bool(true) => write!(f, "true"),
            Self::Bool(false) => write!(f, "false"),
            Self::Number(literal) => write!(f, "{literal}"),
            Self::String(text) => write_string(f, text),
            Self::Array(items) => {
                write!(f, "[")?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        write!(f, ",")?;
                    }
                    write!(f, "{item}")?;
                }
                write!(f, "]")
            }
            Self::Object(members) => {
                write!(f, "{{")?;
                for (index, (name, value)) in members.iter().enumerate() {
                    if index > 0 {
                        write!(f, ",")?;
                    }
                    write_string(f, name)?;
                    write!(f, ":{value}")?;
                }
                write!(f, "}}")
            }
        }
    }
}

fn write_string(f: &mut std::fmt::Formatter<'_>, text: &str) -> std::fmt::Result {
    write!(f, "\"")?;
    for ch in text.chars() {
        match ch {
            '"' => write!(f, "\\\"")?,
            '\\' => write!(f, "\\\\")?,
            '\u{0008}' => write!(f, "\\b")?,
            '\u{000c}' => write!(f, "\\f")?,
            '\n' => write!(f, "\\n")?,
            '\r' => write!(f, "\\r")?,
            '\t' => write!(f, "\\t")?,
            ch if (ch as u32) < 0x20 => write!(f, "\\u{value:04x}", value = ch as u32)?,
            ch => write!(f, "{ch}")?,
        }
    }
    write!(f, "\"")
}

struct Parser<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Parser<'a> {
    fn error(&self, message: impl Into<String>) -> JsonError {
        JsonError {
            at: self.index,
            message: message.into(),
        }
    }

    fn skip(&mut self) {
        while let Some(byte) = self.peek() {
            if byte == b' ' || byte == b'\t' || byte == b'\n' || byte == b'\r' {
                self.index += 1;
            } else {
                break;
            }
        }
    }

    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.index).copied()
    }

    fn bump(&mut self) -> Result<u8, JsonError> {
        let byte = self.peek().ok_or_else(|| self.error("unexpected end"))?;
        self.index += 1;
        Ok(byte)
    }

    fn value(&mut self) -> Result<Json, JsonError> {
        match self.peek() {
            Some(b'n') => self.literal(b"null", Json::Null),
            Some(b't') => self.literal(b"true", Json::Bool(true)),
            Some(b'f') => self.literal(b"false", Json::Bool(false)),
            Some(b'"') => Ok(Json::String(self.string()?)),
            Some(b'[') => self.array(),
            Some(b'{') => self.object(),
            Some(b'-') | Some(b'0'..=b'9') => self.number(),
            Some(_) => Err(self.error("expected a JSON value")),
            None => Err(self.error("unexpected end")),
        }
    }

    fn literal(&mut self, expected: &[u8], value: Json) -> Result<Json, JsonError> {
        for expected_byte in expected {
            let at = self.index;
            let byte = self.bump()?;
            if byte != *expected_byte {
                self.index = at;
                return Err(self.error(format!(
                    "expected {}",
                    std::str::from_utf8(expected).unwrap_or("literal")
                )));
            }
        }
        Ok(value)
    }

    fn array(&mut self) -> Result<Json, JsonError> {
        self.bump()?;
        let mut items = Vec::new();
        loop {
            self.skip();
            if self.peek() == Some(b']') {
                self.index += 1;
                return Ok(Json::Array(items));
            }
            if !items.is_empty() {
                if self.peek() != Some(b',') {
                    return Err(self.error("expected ',' or ']' in an array"));
                }
                self.index += 1;
                self.skip();
                if self.peek() == Some(b']') {
                    return Err(self.error("trailing comma in an array"));
                }
            }
            items.push(self.value()?);
        }
    }

    fn object(&mut self) -> Result<Json, JsonError> {
        self.bump()?;
        let mut members = Vec::new();
        loop {
            self.skip();
            if self.peek() == Some(b'}') {
                self.index += 1;
                return Ok(Json::Object(members));
            }
            if !members.is_empty() {
                if self.peek() != Some(b',') {
                    return Err(self.error("expected ',' or '}' in an object"));
                }
                self.index += 1;
                self.skip();
                if self.peek() == Some(b'}') {
                    return Err(self.error("trailing comma in an object"));
                }
            }
            if self.peek() != Some(b'"') {
                return Err(self.error("expected an object key"));
            }
            let name = self.string()?;
            self.skip();
            if self.bump()? != b':' {
                return Err(self.error("expected ':' after an object key"));
            }
            self.skip();
            let value = self.value()?;
            members.push((name, value));
        }
    }

    fn number(&mut self) -> Result<Json, JsonError> {
        let start = self.index;
        if self.peek() == Some(b'-') {
            self.index += 1;
        }
        match self.peek() {
            Some(b'0') => self.index += 1,
            Some(b'1'..=b'9') => {
                self.index += 1;
                while matches!(self.peek(), Some(b'0'..=b'9')) {
                    self.index += 1;
                }
            }
            _ => return Err(self.error("expected a digit in a number")),
        }
        if self.peek() == Some(b'.') {
            self.index += 1;
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("expected a digit after the decimal point"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.index += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.index += 1;
            }
            if !matches!(self.peek(), Some(b'0'..=b'9')) {
                return Err(self.error("expected a digit in an exponent"));
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.index += 1;
            }
        }
        let literal = std::str::from_utf8(&self.bytes[start..self.index])
            .expect("a JSON number is ASCII")
            .to_string();
        Ok(Json::Number(literal))
    }

    fn string(&mut self) -> Result<String, JsonError> {
        self.bump()?;
        let mut out = String::new();
        loop {
            let byte = self.bump()?;
            match byte {
                b'"' => return Ok(out),
                b'\\' => out.push(self.escape()?),
                byte if byte < 0x20 => {
                    return Err(self.error("unescaped control character in a string"));
                }
                byte => {
                    // The source is a `&str`, so a non-ASCII lead byte is the
                    // start of a UTF-8 sequence that is already valid.
                    let width = utf8_width(byte).ok_or_else(|| self.error("invalid UTF-8"))?;
                    let start = self.index - 1;
                    if self.index + width - 1 > self.bytes.len() {
                        return Err(self.error("truncated UTF-8 in a string"));
                    }
                    self.index += width - 1;
                    let text = std::str::from_utf8(&self.bytes[start..self.index])
                        .map_err(|_| self.error("invalid UTF-8 in a string"))?;
                    out.push_str(text);
                }
            }
        }
    }

    fn escape(&mut self) -> Result<char, JsonError> {
        let byte = self.bump()?;
        match byte {
            b'"' => Ok('"'),
            b'\\' => Ok('\\'),
            b'/' => Ok('/'),
            b'b' => Ok('\u{0008}'),
            b'f' => Ok('\u{000c}'),
            b'n' => Ok('\n'),
            b'r' => Ok('\r'),
            b't' => Ok('\t'),
            b'u' => self.unicode_escape(),
            _ => Err(self.error("unknown string escape")),
        }
    }

    fn unicode_escape(&mut self) -> Result<char, JsonError> {
        let unit = self.hex4()?;
        let ch = match char::from_u32(unit) {
            Some(ch) => ch,
            None => {
                if !(0xD800..=0xDBFF).contains(&unit) {
                    return Err(self.error("invalid unicode escape"));
                }
                if self.peek() != Some(b'\\') {
                    return Err(self.error("lone surrogate in a string"));
                }
                self.index += 1;
                if self.bump()? != b'u' {
                    return Err(self.error("lone surrogate in a string"));
                }
                let low = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&low) {
                    return Err(self.error("invalid surrogate pair"));
                }
                let point = 0x10000 + (((unit - 0xD800) << 10) | (low - 0xDC00));
                char::from_u32(point).ok_or_else(|| self.error("invalid surrogate pair"))?
            }
        };
        Ok(ch)
    }

    fn hex4(&mut self) -> Result<u32, JsonError> {
        let mut value = 0u32;
        for _ in 0..4 {
            let byte = self.bump()?;
            let digit = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte - b'a' + 10,
                b'A'..=b'F' => byte - b'A' + 10,
                _ => return Err(self.error("expected a hex digit in a unicode escape")),
            };
            value = (value << 4) | u32::from(digit);
        }
        Ok(value)
    }
}

fn utf8_width(lead: u8) -> Option<usize> {
    if lead < 0x80 {
        Some(1)
    } else if (0xC2..=0xDF).contains(&lead) {
        Some(2)
    } else if (0xE0..=0xEF).contains(&lead) {
        Some(3)
    } else if (0xF0..=0xF4).contains(&lead) {
        Some(4)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_offer_object() {
        let value = Json::parse(
            r#"{"credential_issuer":"https://sts.example","credential_configuration_ids":["id"],"n":5,"ok":true,"x":null}"#,
        )
        .unwrap();
        assert_eq!(
            value.get("credential_issuer").and_then(Json::as_str),
            Some("https://sts.example")
        );
        assert_eq!(value.get("n").and_then(Json::as_u64), Some(5));
        assert!(matches!(value.get("ok"), Some(Json::Bool(true))));
        assert!(matches!(value.get("x"), Some(Json::Null)));
        let rendered = value.to_string();
        assert_eq!(Json::parse(&rendered).unwrap(), value);
    }

    #[test]
    fn unescapes_and_rejects_the_loose_cases() {
        assert_eq!(
            Json::parse(r#""h\u00e9llo\n""#).unwrap().as_str(),
            Some("héllo\n")
        );
        assert_eq!(
            Json::parse(r#""\uD83D\uDE00""#).unwrap().as_str(),
            Some("😀")
        );
        assert!(Json::parse(r#"{"a":1,}"#).is_err());
        assert!(Json::parse(r#"[1,]"#).is_err());
        assert!(Json::parse("01").is_err());
        assert!(Json::parse(r#""\uD800""#).is_err());
        assert!(Json::parse("{\"a\":1} true").is_err());
    }

    #[test]
    fn last_duplicate_key_wins_the_lookup() {
        let value = Json::parse(r#"{"a":1,"a":2}"#).unwrap();
        assert_eq!(value.get("a").and_then(Json::as_u64), Some(2));
        assert_eq!(value.keys(), vec!["a", "a"]);
    }
}
