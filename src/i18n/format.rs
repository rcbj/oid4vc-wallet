//! The plain-text half of the message format iya-sts implements in
//! `common/web_messages.ts`.
//!
//! `{name}` inserts a parameter. `{count, plural, one {# item} other {# items}}`
//! follows the language's plural categories, and `{kind, select, a {…} other {…}}`
//! chooses by value. `#` inside a plural is the number. Inline elements such
//! as `<code>` are stripped. A parameter is put back after that, so a value
//! is never edited. A message that cannot be parsed is returned unchanged.

#[derive(Clone)]
enum Node {
    Text(String),
    Hash,
    Argument { name: String, kind: Kind },
}

#[derive(Clone)]
enum Kind {
    Simple,
    Plural(Vec<(String, Vec<Node>)>),
    Select(Vec<(String, Vec<Node>)>),
}

/// Format `template` for `locale`. `locale` chooses the plural category.
pub fn format_message(template: &str, params: &[(&str, &str)], locale: &str) -> String {
    let Ok(nodes) = parse(template) else {
        return template.to_string();
    };
    let mut slots = Vec::new();
    let rendered = render(&nodes, params, locale, None, &mut slots);
    let stripped = strip_tags(&rendered);
    restore_slots(&stripped, &slots)
}

/// The parameter names a message uses, in order of first appearance.
pub fn placeholder_names(template: &str) -> Result<Vec<String>, ()> {
    let nodes = parse(template)?;
    let mut names = Vec::new();
    collect_names(&nodes, &mut names);
    Ok(names)
}

/// Plural category for the languages this wallet ships, and `other` for the rest.
pub fn plural_category(locale: &str, number: f64) -> &'static str {
    if !number.is_finite() {
        return "other";
    }
    let whole = number.fract() == 0.0;
    match language(locale) {
        "zh" => "other",
        "fr" | "fil" => {
            if whole && (0.0..=1.0).contains(&number) {
                "one"
            } else {
                "other"
            }
        }
        _ => {
            // `whole`, so the only number in this range is 1.
            if whole && (0.5..1.5).contains(&number) {
                "one"
            } else {
                "other"
            }
        }
    }
}

fn language(locale: &str) -> &str {
    locale.split(['-', '_']).next().unwrap_or(locale)
}

fn parse(template: &str) -> Result<Vec<Node>, ()> {
    let mut at = 0;
    let nodes = parse_nodes(template, &mut at, false, false)?;
    if at < template.len() {
        return Err(());
    }
    Ok(nodes)
}

fn parse_nodes(
    template: &str,
    at: &mut usize,
    nested: bool,
    in_plural: bool,
) -> Result<Vec<Node>, ()> {
    let mut nodes = Vec::new();
    let mut text = String::new();
    while *at < template.len() {
        let ch = template[*at..].chars().next().ok_or(())?;
        let width = ch.len_utf8();
        if ch == '}' {
            if !nested {
                return Err(());
            }
            break;
        }
        if ch == '#' && in_plural {
            if !text.is_empty() {
                nodes.push(Node::Text(std::mem::take(&mut text)));
            }
            nodes.push(Node::Hash);
            *at += width;
            continue;
        }
        if ch == '{' {
            if !text.is_empty() {
                nodes.push(Node::Text(std::mem::take(&mut text)));
            }
            nodes.push(parse_argument(template, at)?);
            continue;
        }
        text.push(ch);
        *at += width;
    }
    if !text.is_empty() {
        nodes.push(Node::Text(text));
    }
    Ok(nodes)
}

fn parse_argument(template: &str, at: &mut usize) -> Result<Node, ()> {
    let bytes = template.as_bytes();
    let close = template[*at..].find('}').map(|offset| *at + offset);
    let comma = template[*at..].find(',').map(|offset| *at + offset);
    let Some(close) = close else {
        return Err(());
    };
    if comma.is_none_or(|comma| comma > close) {
        let name = template[*at + 1..close].trim();
        if !is_name(name) {
            return Err(());
        }
        *at = close + 1;
        return Ok(Node::Argument {
            name: name.to_string(),
            kind: Kind::Simple,
        });
    }
    let comma = comma.ok_or(())?;
    let name = template[*at + 1..comma].trim();
    if !is_name(name) {
        return Err(());
    }
    let Some(after_kind) = template[comma + 1..]
        .find(',')
        .map(|offset| comma + 1 + offset)
    else {
        return Err(());
    };
    let kind = template[comma + 1..after_kind].trim();
    if kind != "plural" && kind != "select" {
        return Err(());
    }
    *at = after_kind + 1;
    let mut options = Vec::new();
    loop {
        skip_space(bytes, at);
        if *at >= bytes.len() {
            return Err(());
        }
        if bytes[*at] == b'}' {
            *at += 1;
            break;
        }
        let (label, label_end) = option_label(template, *at)?;
        *at = label_end;
        let body = parse_nodes(template, at, true, kind == "plural")?;
        if *at >= bytes.len() || bytes[*at] != b'}' {
            return Err(());
        }
        *at += 1;
        options.push((label, body));
    }
    if !options.iter().any(|(label, _)| label == "other") {
        return Err(());
    }
    let kind = if kind == "plural" {
        Kind::Plural(options)
    } else {
        Kind::Select(options)
    };
    Ok(Node::Argument {
        name: name.to_string(),
        kind,
    })
}

fn option_label(template: &str, start: usize) -> Result<(String, usize), ()> {
    let bytes = template.as_bytes();
    let mut index = start;
    if index < bytes.len() && bytes[index] == b'=' {
        index += 1;
    }
    let label_start = start;
    if index >= bytes.len() || !is_label_byte(bytes[index]) {
        return Err(());
    }
    while index < bytes.len() && is_label_byte(bytes[index]) {
        index += 1;
    }
    skip_space(bytes, &mut index);
    if index >= bytes.len() || bytes[index] != b'{' {
        return Err(());
    }
    let label = template[label_start..index].trim().to_string();
    Ok((label, index + 1))
}

fn is_label_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

fn skip_space(bytes: &[u8], at: &mut usize) {
    while *at < bytes.len() && bytes[*at].is_ascii_whitespace() {
        *at += 1;
    }
}

fn is_name(text: &str) -> bool {
    let mut chars = text.chars();
    match chars.next() {
        Some(first) if first.is_ascii_alphabetic() || first == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn render(
    nodes: &[Node],
    params: &[(&str, &str)],
    locale: &str,
    count: Option<f64>,
    slots: &mut Vec<String>,
) -> String {
    let mut out = String::new();
    for node in nodes {
        match node {
            Node::Text(text) => out.push_str(text),
            Node::Hash => out.push_str(&number_text(count.unwrap_or(0.0))),
            Node::Argument { name, kind } => {
                let value = param(params, name);
                match kind {
                    Kind::Simple => {
                        out.push('\u{E000}');
                        out.push_str(&slots.len().to_string());
                        out.push('\u{E001}');
                        slots.push(value.to_string());
                    }
                    Kind::Select(options) => {
                        let chosen = options
                            .iter()
                            .find(|(label, _)| label == value)
                            .or_else(|| options.iter().find(|(label, _)| label == "other"));
                        if let Some((_, body)) = chosen {
                            out.push_str(&render(body, params, locale, count, slots));
                        }
                    }
                    Kind::Plural(options) => {
                        let number = value.parse::<f64>().unwrap_or(f64::NAN);
                        let exact = format!("={}", number_text_exact(number));
                        let chosen = options
                            .iter()
                            .find(|(label, _)| *label == exact)
                            .or_else(|| {
                                let category = plural_category(locale, number);
                                options.iter().find(|(label, _)| label == category)
                            })
                            .or_else(|| options.iter().find(|(label, _)| label == "other"));
                        if let Some((_, body)) = chosen {
                            out.push_str(&render(body, params, locale, Some(number), slots));
                        }
                    }
                }
            }
        }
    }
    out
}

fn param<'a>(params: &'a [(&str, &str)], name: &str) -> &'a str {
    params
        .iter()
        .find(|(key, _)| *key == name)
        .map_or("", |(_, value)| *value)
}

fn number_text(number: f64) -> String {
    if number.is_finite() && number.fract() == 0.0 && number.abs() < 1e15 {
        whole_text(number)
    } else if number.is_finite() {
        format!("{number}")
    } else {
        String::new()
    }
}

fn number_text_exact(number: f64) -> String {
    if number.is_finite() && number.fract() == 0.0 && number.abs() < 1e15 {
        whole_text(number)
    } else {
        String::new()
    }
}

// Below 1e15 every whole f64 is exact, so `{:.0}` prints the integer.
// Adding 0.0 turns -0 into 0, which is what the reader expects.
fn whole_text(number: f64) -> String {
    format!("{:.0}", number + 0.0)
}

fn strip_tags(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '<'
            && (chars.peek() == Some(&'/') || chars.peek().is_some_and(char::is_ascii_alphabetic))
        {
            for next in chars.by_ref() {
                if next == '>' {
                    break;
                }
            }
            continue;
        }
        out.push(ch);
    }
    out
}

fn restore_slots(text: &str, slots: &[String]) -> String {
    let mut out = String::with_capacity(text.len());
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if text[index..].starts_with('\u{E000}') {
            let start = index + '\u{E000}'.len_utf8();
            if let Some(end) = text[start..].find('\u{E001}') {
                let slot = &text[start..start + end];
                if let Ok(slot) = slot.parse::<usize>() {
                    if let Some(value) = slots.get(slot) {
                        out.push_str(value);
                    }
                }
                index = start + end + '\u{E001}'.len_utf8();
                continue;
            }
        }
        let ch = text[index..].chars().next().unwrap_or('\u{FFFD}');
        out.push(ch);
        index += ch.len_utf8();
    }
    out
}

fn collect_names(nodes: &[Node], names: &mut Vec<String>) {
    for node in nodes {
        if let Node::Argument { name, kind } = node {
            if !names.iter().any(|have| have == name) {
                names.push(name.clone());
            }
            let options = match kind {
                Kind::Plural(options) | Kind::Select(options) => options.as_slice(),
                Kind::Simple => &[],
            };
            for (_, body) in options {
                collect_names(body, names);
            }
        }
    }
}
