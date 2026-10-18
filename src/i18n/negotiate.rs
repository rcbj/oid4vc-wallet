//! BCP 47 tags and RFC 4647 lookup, with the script made explicit.
//!
//! This is the negotiation in iya-sts `common/web_locale.ts`. A tag is
//! canonicalised (`tl` becomes `fil`), then maximised with the likely
//! subtags (`zh-HK` is Traditional Chinese, `zh-CN` is Simplified). A
//! catalog matches when its language and script match, and, when the
//! catalog itself names a region, that region matches too. `zh-HK` therefore
//! reads `zh-Hant-HK` and then `zh-Hant`, and never the Simplified catalog.

/// Text direction of a negotiated locale.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    Ltr,
    Rtl,
}

/// A tag taken apart the way the catalog matcher compares them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagParts {
    pub tag: String,
    pub language: String,
    pub script: String,
    /// Region after likely-subtag maximisation.
    pub region: String,
    /// Region the tag itself names. Empty when it names none.
    pub explicit_region: String,
    pub direction: Direction,
}

/// The catalogs that answer one tag, most specific first, English last.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chain {
    pub chain: Vec<String>,
    pub matched: bool,
    pub direction: Direction,
}

/// Canonicalise a language tag, or `""` when it is not well-formed.
pub fn canonical(tag: &str) -> String {
    let text = tag.trim();
    if text.is_empty() || text.len() > 64 || text == "*" {
        return String::new();
    }
    let text = text.replace('_', "-");
    let parts: Vec<&str> = text.split('-').filter(|part| !part.is_empty()).collect();
    if parts.is_empty() {
        return String::new();
    }
    let mut language = parts[0].to_ascii_lowercase();
    if !is_language(&language) {
        return String::new();
    }
    language = match language.as_str() {
        "tl" => "fil".to_string(),
        "iw" => "he".to_string(),
        "in" => "id".to_string(),
        "ji" => "yi".to_string(),
        "sh" => "sr".to_string(),
        other => other.to_string(),
    };
    let mut index = 1;
    let mut script = None;
    let mut region = None;
    let mut rest = Vec::new();
    if index < parts.len() && is_script(parts[index]) {
        script = Some(title_script(parts[index]));
        index += 1;
    }
    if index < parts.len() && is_region(parts[index]) {
        region = Some(if parts[index].chars().all(|ch| ch.is_ascii_digit()) {
            parts[index].to_string()
        } else {
            parts[index].to_ascii_uppercase()
        });
        index += 1;
    }
    while index < parts.len() {
        if !is_variant(parts[index]) {
            return String::new();
        }
        rest.push(parts[index].to_ascii_lowercase());
        index += 1;
    }
    let mut out = language;
    if let Some(script) = script {
        out.push('-');
        out.push_str(&script);
    }
    if let Some(region) = region {
        out.push('-');
        out.push_str(&region);
    }
    for variant in rest {
        out.push('-');
        out.push_str(&variant);
    }
    out
}

/// Language, script, region, and direction. `None` when the tag is not
/// well-formed.
pub fn parts_of(tag: &str) -> Option<TagParts> {
    let tag = canonical(tag);
    if tag.is_empty() {
        return None;
    }
    let parts: Vec<&str> = tag.split('-').collect();
    let language = parts[0].to_string();
    let mut index = 1;
    let mut named_script = None;
    let mut named_region = None;
    if index < parts.len() && is_script(parts[index]) {
        named_script = Some(parts[index].to_string());
        index += 1;
    }
    if index < parts.len() && is_region(parts[index]) {
        named_region = Some(parts[index].to_string());
    }
    let script = named_script.unwrap_or_else(|| likely_script(&language, named_region.as_deref()));
    let region = named_region
        .clone()
        .unwrap_or_else(|| likely_region(&language, &script));
    let direction = direction_of(&language);
    Some(TagParts {
        tag,
        language,
        script,
        region,
        explicit_region: named_region.unwrap_or_default(),
        direction,
    })
}

/// Catalogs that answer `tag`, most specific first, with English at the end.
pub fn chain_for(tag: &str, catalogs: &[TagParts]) -> Chain {
    let Some(want) = parts_of(tag) else {
        return Chain {
            chain: vec!["en".to_string()],
            matched: false,
            direction: Direction::Ltr,
        };
    };
    let same: Vec<&TagParts> = catalogs
        .iter()
        .filter(|has| has.language == want.language && has.script == want.script)
        .collect();
    let mut chain = Vec::new();
    for has in same
        .iter()
        .filter(|has| !has.explicit_region.is_empty() && has.explicit_region == want.region)
    {
        push_unique(&mut chain, &has.tag);
    }
    for has in same.iter().filter(|has| has.explicit_region.is_empty()) {
        push_unique(&mut chain, &has.tag);
    }
    let matched = !chain.is_empty();
    push_unique(&mut chain, "en");
    Chain {
        chain,
        matched,
        direction: want.direction,
    }
}

/// The first preference a catalog answers. `last_resort` is used when none
/// of the preferences answer; English when that answers nothing either.
pub fn negotiate(preferences: &[String], last_resort: &str, catalogs: &[TagParts]) -> Negotiated {
    for raw in preferences {
        if let Some(found) = answered(raw, catalogs) {
            return found;
        }
    }
    // The last resort is the language we fall back to. It is not a preference
    // the reader asked for, so `matched` stays false.
    if let Some(mut found) = answered(last_resort, catalogs) {
        found.matched = false;
        return found;
    }
    Negotiated {
        locale: "en".to_string(),
        chain: vec!["en".to_string()],
        catalog: "en".to_string(),
        direction: Direction::Ltr,
        matched: false,
    }
}

fn answered(raw: &str, catalogs: &[TagParts]) -> Option<Negotiated> {
    let tag = canonical(raw);
    if tag.is_empty() {
        return None;
    }
    let found = chain_for(&tag, catalogs);
    if !found.matched {
        return None;
    }
    let catalog = found.chain[0].clone();
    Some(Negotiated {
        locale: tag,
        chain: found.chain,
        catalog,
        direction: found.direction,
        matched: true,
    })
}

/// What [`negotiate`] chose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Negotiated {
    pub locale: String,
    pub chain: Vec<String>,
    pub catalog: String,
    pub direction: Direction,
    pub matched: bool,
}

/// `Accept-Language`, best first. A `q=0` tag and a tag that is not
/// well-formed are left out.
pub fn accept_language(value: &str) -> Vec<String> {
    let mut rows = Vec::new();
    for (at, part) in value.split(',').take(32).enumerate() {
        let mut bits = part.trim().split(';');
        let Some(head) = bits.next() else {
            continue;
        };
        let tag = canonical(head);
        if tag.is_empty() {
            continue;
        }
        let mut quality = 1.0;
        for param in bits {
            let param = param.trim();
            let Some(raw) = param
                .strip_prefix("q=")
                .or_else(|| param.strip_prefix("Q="))
            else {
                continue;
            };
            if let Ok(parsed) = raw.trim().parse::<f64>() {
                quality = parsed;
            }
        }
        if quality > 0.0 {
            rows.push((tag, quality.min(1.0), at));
        }
    }
    rows.sort_by(|left, right| {
        right
            .1
            .partial_cmp(&left.1)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(left.2.cmp(&right.2))
    });
    let mut out = Vec::new();
    for (tag, _, _) in rows {
        push_unique(&mut out, &tag);
    }
    out
}

/// OpenID Connect `ui_locales`: space-separated tags, best first.
pub fn ui_locales(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    for part in value.split_whitespace().take(32) {
        let tag = canonical(part);
        if !tag.is_empty() {
            push_unique(&mut out, &tag);
        }
    }
    out
}

/// The language subtag (`zh` for `zh-Hant-HK`).
pub fn language_of(tag: &str) -> &str {
    tag.split('-').next().unwrap_or(tag)
}

fn push_unique(out: &mut Vec<String>, tag: &str) {
    if !out.iter().any(|have| have == tag) {
        out.push(tag.to_string());
    }
}

fn is_language(text: &str) -> bool {
    let len = text.len();
    (len == 2 || len == 3 || (5..=8).contains(&len))
        && text.chars().all(|ch| ch.is_ascii_alphabetic())
}

fn is_script(text: &str) -> bool {
    text.len() == 4 && text.chars().all(|ch| ch.is_ascii_alphabetic())
}

fn is_region(text: &str) -> bool {
    (text.len() == 2 && text.chars().all(|ch| ch.is_ascii_alphabetic()))
        || (text.len() == 3 && text.chars().all(|ch| ch.is_ascii_digit()))
}

fn is_variant(text: &str) -> bool {
    let chars: Vec<char> = text.chars().collect();
    if chars.len() == 4 {
        return chars[0].is_ascii_digit() && chars[1..].iter().all(|ch| ch.is_ascii_alphanumeric());
    }
    (5..=8).contains(&chars.len()) && chars.iter().all(|ch| ch.is_ascii_alphanumeric())
}

fn title_script(text: &str) -> String {
    let mut chars = text.chars();
    let Some(first) = chars.next() else {
        return String::new();
    };
    let mut out = first.to_ascii_uppercase().to_string();
    out.extend(chars.map(|ch| ch.to_ascii_lowercase()));
    out
}

fn likely_script(language: &str, region: Option<&str>) -> String {
    match language {
        "zh" => match region {
            Some("TW" | "HK" | "MO") => "Hant",
            _ => "Hans",
        },
        "ja" => "Jpan",
        "ko" => "Kore",
        "ar" | "fa" | "ur" | "ps" | "sd" | "ug" => "Arab",
        "he" | "yi" => "Hebr",
        "th" => "Thai",
        "el" => "Grek",
        "ru" | "uk" | "bg" | "be" | "kk" | "mk" | "sr" => "Cyrl",
        _ => "Latn",
    }
    .to_string()
}

fn likely_region(language: &str, script: &str) -> String {
    match (language, script) {
        ("zh", "Hant") => "TW",
        ("zh", _) => "CN",
        ("en", _) => "US",
        ("fr", _) => "FR",
        ("es", _) => "ES",
        ("fil", _) => "PH",
        ("sv", _) => "SE",
        ("de", _) => "DE",
        ("pt", _) => "BR",
        ("ja", _) => "JP",
        ("ko", _) => "KR",
        ("ar", _) => "EG",
        _ => "",
    }
    .to_string()
}

fn direction_of(language: &str) -> Direction {
    match language {
        "ar" | "he" | "fa" | "ur" | "ps" | "sd" | "yi" | "dv" | "ckb" | "ug" => Direction::Rtl,
        _ => Direction::Ltr,
    }
}
