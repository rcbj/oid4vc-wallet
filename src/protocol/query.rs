//! `application/x-www-form-urlencoded` query strings.
//!
//! Order is kept. A key that appears twice is kept twice; the caller decides
//! whether that is an error. An empty segment (`&&`) is skipped. A key with
//! no `=` has an empty value.

use super::percent::{form_decode, PercentError};

/// One decoded query parameter, in the order it appeared.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryParam {
    pub name: String,
    pub value: String,
}

/// Why a query string could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryError {
    pub name_or_value: &'static str,
    pub source: PercentError,
}

impl std::fmt::Display for QueryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "could not decode query {}: {}",
            self.name_or_value, self.source
        )
    }
}

impl std::error::Error for QueryError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

/// Decode `a=1&b=2` into parameters.
pub fn parse_query(query: &str) -> Result<Vec<QueryParam>, QueryError> {
    if query.is_empty() {
        return Ok(Vec::new());
    }
    let mut params = Vec::new();
    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let (raw_name, raw_value) = segment.split_once('=').unwrap_or((segment, ""));
        let name = form_decode(raw_name).map_err(|source| QueryError {
            name_or_value: "name",
            source,
        })?;
        let value = form_decode(raw_value).map_err(|source| QueryError {
            name_or_value: "value",
            source,
        })?;
        params.push(QueryParam { name, value });
    }
    Ok(params)
}

/// Every value of `name`, in order.
pub fn values<'a>(params: &'a [QueryParam], name: &str) -> Vec<&'a str> {
    params
        .iter()
        .filter(|param| param.name == name)
        .map(|param| param.value.as_str())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_order_duplicates_and_plus() {
        let params = parse_query("b=2&a=h%C3%A9llo+x&a=second&&bare").unwrap();
        assert_eq!(params.len(), 4);
        assert_eq!(params[0].name, "b");
        assert_eq!(params[1].value, "héllo x");
        assert_eq!(values(&params, "a"), vec!["héllo x", "second"]);
        assert_eq!(params[3].value, "");
    }
}
