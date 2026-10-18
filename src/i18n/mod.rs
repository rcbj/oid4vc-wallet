//! Languages, in the shape iya-sts uses.
//!
//! English is the source catalog. A regional catalog holds only the keys it
//! words differently, and lookup walks to the base catalog and then to
//! English. The active language is thread-local and starts as English, so a
//! library test does not follow the machine's locale. The program calls
//! [`set_active`] after it has read `--lang`, the saved tag, and the
//! environment.

mod catalog;
mod format;
#[path = "negotiate.rs"]
mod matching;
mod preference;

use std::cell::{Cell, RefCell};

pub use matching::{accept_language, canonical, chain_for, language_of, ui_locales, Direction};

use catalog::CatalogSet;
use matching::{negotiate as match_tags, Negotiated};

/// The language a call to [`t`] formats with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Translator {
    /// The preference that was answered, for example `es-PA`.
    pub locale: String,
    /// Catalogs to read, most specific first, English last.
    pub chain: Vec<String>,
    /// The most specific catalog that answered.
    pub catalog: String,
    pub direction: Direction,
    /// False when only the last-resort English catalog answered.
    pub matched: bool,
}

impl Translator {
    fn from_negotiated(found: Negotiated) -> Self {
        Self {
            locale: found.locale,
            chain: found.chain,
            catalog: found.catalog,
            direction: found.direction,
            matched: found.matched,
        }
    }

    /// `namespace.key`, with the parameters the message names.
    pub fn text(&self, key: &str) -> String {
        self.text_args(key, &[])
    }

    /// `namespace.key`. A value is inserted as itself.
    pub fn text_args(&self, key: &str, args: &[(&str, &str)]) -> String {
        if is_loading() {
            return key.to_string();
        }
        let Some((message_catalog, message)) = catalog::find(catalogs(), &self.chain, key) else {
            return key.to_string();
        };
        let locale = plural_locale(&message_catalog, &self.catalog, &self.locale);
        format::format_message(&message, args, &locale)
    }
}

/// Plural rules follow the catalog whose words are used.
fn plural_locale(
    message_catalog: &str,
    negotiated_catalog: &str,
    negotiated_locale: &str,
) -> String {
    if language_of(message_catalog) == language_of(negotiated_catalog) {
        negotiated_locale.to_string()
    } else {
        message_catalog.to_string()
    }
}

/// A localized desktop name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopString {
    /// `fr_FR`, the form a Desktop Entry key uses.
    pub locale: String,
    pub name: String,
    pub generic_name: String,
    pub comment: String,
}

#[derive(Debug, Clone)]
struct Active {
    explicit: Option<String>,
    preferences: Vec<String>,
    translator: Translator,
}

thread_local! {
    static ACTIVE: RefCell<Active> = RefCell::new(Active {
        explicit: None,
        preferences: Vec::new(),
        translator: english(),
    });
    static LOADING: Cell<bool> = const { Cell::new(false) };
}

fn english() -> Translator {
    Translator {
        locale: "en".to_string(),
        chain: vec!["en".to_string()],
        catalog: "en".to_string(),
        direction: Direction::Ltr,
        matched: true,
    }
}

/// True while the catalogs are being read. [`t`] returns the key then, so
/// the JSON parser can load a catalog without formatting a message.
pub fn is_loading() -> bool {
    LOADING.with(Cell::get)
}

fn catalogs() -> &'static CatalogSet {
    use std::sync::OnceLock;
    static CATALOGS: OnceLock<CatalogSet> = OnceLock::new();
    CATALOGS.get_or_init(|| {
        struct ClearLoading;
        impl Drop for ClearLoading {
            fn drop(&mut self) {
                LOADING.with(|flag| flag.set(false));
            }
        }
        LOADING.with(|flag| flag.set(true));
        let _clear = ClearLoading;
        CatalogSet::load()
    })
}

/// The message for `namespace.key` in the active language.
pub fn t(key: &str) -> String {
    if is_loading() {
        return key.to_string();
    }
    ACTIVE.with(|active| active.borrow().translator.text(key))
}

/// The message for `namespace.key`, with parameters.
pub fn t_args(key: &str, args: &[(&str, &str)]) -> String {
    if is_loading() {
        return key.to_string();
    }
    ACTIVE.with(|active| active.borrow().translator.text_args(key, args))
}

/// The active translator.
pub fn current() -> Translator {
    ACTIVE.with(|active| active.borrow().translator.clone())
}

/// Choose a language. `explicit` is `--lang`. `preferences` are the saved
/// tag and then the environment, best first.
pub fn set_active(explicit: Option<String>, preferences: Vec<String>) {
    let translator = match &explicit {
        Some(tag) => negotiate_tag(tag),
        None => negotiate(&preferences, "en"),
    };
    ACTIVE.with(|active| {
        *active.borrow_mut() = Active {
            explicit,
            preferences,
            translator,
        };
    });
}

/// Run `body` with `locales` ahead of the saved language and the environment.
/// `--lang` stays in front of `locales`.
pub fn with_ui_locales<R>(locales: &[String], body: impl FnOnce() -> R) -> R {
    let (explicit, preferences, previous) = ACTIVE.with(|active| {
        let active = active.borrow();
        (
            active.explicit.clone(),
            active.preferences.clone(),
            active.translator.clone(),
        )
    });
    if explicit.is_none() {
        let mut ordered = locales.to_vec();
        ordered.extend(preferences.iter().cloned());
        let translator = negotiate(&ordered, "en");
        ACTIVE.with(|active| active.borrow_mut().translator = translator);
    }
    let result = body();
    ACTIVE.with(|active| active.borrow_mut().translator = previous);
    result
}

/// The first preference a shipped catalog answers.
pub fn negotiate(preferences: &[String], last_resort: &str) -> Translator {
    Translator::from_negotiated(match_tags(preferences, last_resort, &catalogs().parts))
}

/// The catalog chain for one tag.
pub fn negotiate_tag(tag: &str) -> Translator {
    negotiate(&[tag.to_string()], "en")
}

/// `tag` when it is one the chooser offers, after canonicalisation.
pub fn canonical_offered(tag: &str) -> Option<String> {
    let tag = canonical(tag);
    if tag.is_empty() {
        return None;
    }
    catalogs()
        .offered
        .iter()
        .find(|offered| offered.tag == tag)
        .map(|offered| offered.tag.clone())
}

/// The locales a person can switch to, in chooser order.
pub fn offered() -> Vec<catalog::Offered> {
    catalogs().offered.clone()
}

/// The locale's own name. An offered tag uses the chooser name.
pub fn endonym(tag: &str) -> String {
    let tag = canonical(tag);
    if let Some(offered) = catalogs().offered.iter().find(|offered| offered.tag == tag) {
        return offered.name.clone();
    }
    let catalog = negotiate_tag(&tag).catalog;
    catalogs()
        .catalogs
        .iter()
        .find(|meta| meta.tag == catalog)
        .map(|meta| meta.name.clone())
        .unwrap_or(tag)
}

/// The offered tag the chooser would mark: the exact tag, or else the first
/// offered locale that reads the same catalog.
pub fn selected_offered() -> Option<String> {
    let translator = current();
    let offered = catalogs().offered.clone();
    if let Some(exact) = offered
        .iter()
        .find(|one| one.tag.eq_ignore_ascii_case(&translator.locale))
    {
        return Some(exact.tag.clone());
    }
    if let Some(same) = offered
        .iter()
        .find(|one| negotiate_tag(&one.tag).catalog == translator.catalog)
    {
        return Some(same.tag.clone());
    }
    offered.first().map(|one| one.tag.clone())
}

/// `LANGUAGE`, then `LC_ALL`, `LC_MESSAGES`, and `LANG`.
pub fn system_tags() -> Vec<String> {
    tags_from_environment(
        nonempty("LANGUAGE").as_deref(),
        nonempty("LC_ALL").as_deref(),
        nonempty("LC_MESSAGES").as_deref(),
        nonempty("LANG").as_deref(),
    )
}

fn nonempty(var: &str) -> Option<String> {
    std::env::var(var).ok().filter(|value| !value.is_empty())
}

/// The same order as [`system_tags`], from values the caller supplies.
pub fn tags_from_environment(
    language: Option<&str>,
    lc_all: Option<&str>,
    lc_messages: Option<&str>,
    lang: Option<&str>,
) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(language) = language {
        for part in language.split(':') {
            push_environment_tag(&mut out, part);
        }
    }
    for value in [lc_all, lc_messages, lang].into_iter().flatten() {
        push_environment_tag(&mut out, value);
    }
    out
}

fn push_environment_tag(out: &mut Vec<String>, raw: &str) {
    let Some(tag) = environment_tag(raw) else {
        return;
    };
    if !out.iter().any(|have| have == &tag) {
        out.push(tag);
    }
}

fn environment_tag(raw: &str) -> Option<String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    let base = raw.split(['.', '@']).next().unwrap_or(raw);
    if base.is_empty() || base == "C" || base == "POSIX" {
        return None;
    }
    let tag = canonical(&base.replace('_', "-"));
    if tag.is_empty() {
        None
    } else {
        Some(tag)
    }
}

/// The saved tag, when the file holds one.
pub fn saved_tag() -> Option<String> {
    let path = preference::language_path().ok()?;
    preference::read_tag(&path)
}

/// Remember `tag`. It has to be a locale the chooser offers.
pub fn store_tag(tag: &str) -> Result<(), String> {
    let Some(tag) = canonical_offered(tag) else {
        return Err(t_args("wallet.cli.language_unknown", &[("tag", tag)]));
    };
    let path = preference::language_path()?;
    preference::write_tag(&path, &tag)
}

/// Forget the saved tag. The session language is used afterwards.
pub fn clear_tag() -> Result<(), String> {
    let path = preference::language_path()?;
    preference::remove_tag(&path)
}

/// `Name`, `GenericName`, and `Comment` for every offered locale.
pub fn desktop_translations() -> Vec<DesktopString> {
    catalogs()
        .offered
        .iter()
        .map(|offered| {
            let translator = negotiate_tag(&offered.tag);
            DesktopString {
                locale: offered.tag.replace('-', "_"),
                name: translator.text("wallet.desktop.name"),
                generic_name: translator.text("wallet.desktop.generic_name"),
                comment: translator.text("wallet.desktop.comment"),
            }
        })
        .collect()
}

#[cfg(test)]
struct ActiveGuard {
    previous: Active,
}

#[cfg(test)]
impl ActiveGuard {
    fn acquire() -> Self {
        Self {
            previous: ACTIVE.with(|active| active.borrow().clone()),
        }
    }
}

#[cfg(test)]
impl Drop for ActiveGuard {
    fn drop(&mut self) {
        ACTIVE.with(|active| *active.borrow_mut() = self.previous.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn negotiation_follows_the_iya_sts_chain() {
        let cases = [
            ("fr-CA", vec!["fr-CA", "fr", "en"], "fr-CA"),
            ("fr", vec!["fr", "en"], "fr"),
            ("fr-FR", vec!["fr", "en"], "fr-FR"),
            ("zh-HK", vec!["zh-Hant-HK", "zh-Hant", "en"], "zh-HK"),
            ("zh-TW", vec!["zh-Hant", "en"], "zh-TW"),
            ("zh-CN", vec!["zh-Hans", "en"], "zh-CN"),
            ("es-MX", vec!["es", "en"], "es-MX"),
            ("es-PA", vec!["es", "en"], "es-PA"),
            ("es-ES", vec!["es-ES", "es", "en"], "es-ES"),
            ("en-GB", vec!["en"], "en-GB"),
            ("fil-PH", vec!["fil", "en"], "fil-PH"),
            ("sv-SE", vec!["sv", "en"], "sv-SE"),
        ];
        for (tag, chain, locale) in cases {
            let found = negotiate(&[tag.to_string()], "en");
            assert_eq!(found.chain, chain, "{tag}");
            assert_eq!(found.locale, locale, "{tag}");
            assert!(found.matched, "{tag}");
        }
        let german_then_french = negotiate(&["de".to_string(), "fr".to_string()], "en");
        assert_eq!(german_then_french.catalog, "fr");
        assert_eq!(german_then_french.locale, "fr");
        let german = negotiate(&["de".to_string()], "en");
        assert_eq!(german.locale, "en");
        assert!(!german.matched);
        let tagalog = negotiate(&["tl".to_string()], "en");
        assert_eq!(tagalog.locale, "fil");
        assert_eq!(tagalog.chain, vec!["fil".to_string(), "en".to_string()]);
    }

    #[test]
    fn direction_is_recorded_for_scripts_this_wallet_knows() {
        assert_eq!(matching::parts_of("en").unwrap().direction, Direction::Ltr);
        assert_eq!(matching::parts_of("ar").unwrap().direction, Direction::Rtl);
        assert_eq!(
            matching::chain_for("ar", &catalogs().parts).direction,
            Direction::Rtl
        );
    }

    #[test]
    fn catalogs_have_the_english_keys_and_placeholders() {
        let set = catalogs();
        assert_eq!(set.source, "en");
        let english = set.file_keys("wallet", "en").expect("english catalog");
        let mut english_names = std::collections::BTreeMap::new();
        for (key, message) in english {
            english_names.insert(key.clone(), format::placeholder_names(message).unwrap());
        }
        let offered = [
            "en", "fr-FR", "fr-CA", "es-MX", "es-PA", "es-ES", "zh-CN", "zh-HK", "zh-TW", "fil-PH",
            "sv-SE",
        ];
        assert_eq!(
            set.offered
                .iter()
                .map(|one| one.tag.as_str())
                .collect::<Vec<_>>(),
            offered
        );
        for meta in &set.catalogs {
            let file = set.file_keys("wallet", &meta.tag).expect(&meta.tag);
            if meta.tag == "en" {
                assert_eq!(meta.status, "source");
                assert!(meta.base.is_none());
            } else {
                assert_eq!(meta.status, "machine-unreviewed");
            }
            if meta.base.is_none() {
                assert_eq!(file.len(), english.len(), "{}", meta.tag);
                for key in english.keys() {
                    assert!(file.contains_key(key), "{} missing {key}", meta.tag);
                }
            } else {
                assert!(file.len() < english.len(), "{}", meta.tag);
                for key in file.keys() {
                    assert!(english.contains_key(key), "{} extra {key}", meta.tag);
                }
            }
            for (key, message) in file {
                let names = format::placeholder_names(message).unwrap();
                assert_eq!(&names, &english_names[key], "{} {key}", meta.tag);
            }
        }
        assert_eq!(t("wallet.summary.by_value"), "by value");
        assert!(english["invocation.unknown_scheme"].contains("scheme"));
        assert!(english["cred.no_key"].contains("no AES-256 key"));
        assert!(english["seal.auth_failed"].contains("could not be opened"));
        assert!(english["offer.old_credentials"].contains("credential_configuration_ids"));
        assert_eq!(english["json.at"].as_str(), "JSON at byte {at}: {message}");
    }

    #[test]
    fn plural_zero_is_one_in_french_and_filipino() {
        assert_eq!(format::plural_category("en", 0.0), "other");
        assert_eq!(format::plural_category("en", 1.0), "one");
        assert_eq!(format::plural_category("es", 0.0), "other");
        assert_eq!(format::plural_category("sv-SE", 1.0), "one");
        assert_eq!(format::plural_category("fr", 0.0), "one");
        assert_eq!(format::plural_category("fr-CA", 0.0), "one");
        assert_eq!(format::plural_category("fil", 0.0), "one");
        assert_eq!(format::plural_category("fil", 2.0), "other");
        assert_eq!(format::plural_category("zh-Hans", 0.0), "other");
        assert_eq!(format::plural_category("zh-Hant", 1.0), "other");
        let message = "{count, plural, one {# handler} other {# handlers}}";
        assert_eq!(
            format::format_message(message, &[("count", "0")], "en"),
            "0 handlers"
        );
        assert_eq!(
            format::format_message(message, &[("count", "0")], "fr"),
            "0 handler"
        );
    }

    #[test]
    fn markup_is_stripped_and_a_value_is_left_intact() {
        let out = format::format_message("see <code>{path}</code>", &[("path", "a <b>")], "en");
        assert_eq!(out, "see a <b>");
        assert_eq!(
            format::format_message("钱包 {id}", &[("id", "abc")], "zh-Hans"),
            "钱包 abc"
        );
        assert_eq!(format::format_message("no {close", &[], "en"), "no {close");
    }

    #[test]
    fn an_english_message_keeps_english_plural_rules() {
        assert_eq!(plural_locale("en", "fr-CA", "fr-CA"), "en");
        assert_eq!(plural_locale("fr", "fr-CA", "fr-CA"), "fr-CA");
    }

    #[test]
    fn environment_tags_follow_gettext_order() {
        let tags = tags_from_environment(
            Some("fr_CA:de:en_US.UTF-8"),
            Some("C"),
            Some("POSIX"),
            Some("sv_SE.utf8@euro"),
        );
        assert_eq!(
            tags,
            vec![
                "fr-CA".to_string(),
                "de".to_string(),
                "en-US".to_string(),
                "sv-SE".to_string()
            ]
        );
        assert!(tags_from_environment(Some(""), Some(""), None, Some("C.UTF-8")).is_empty());
    }

    #[test]
    fn switching_language_restores_the_previous_one() {
        let _guard = ActiveGuard::acquire();
        assert_eq!(t("wallet.summary.by_value"), "by value");
        set_active(Some("fr-FR".to_string()), Vec::new());
        assert_eq!(t("wallet.summary.by_value"), "par valeur");
        assert_eq!(selected_offered().as_deref(), Some("fr-FR"));
        set_active(None, vec!["fr".to_string()]);
        assert_eq!(selected_offered().as_deref(), Some("fr-FR"));
        assert_eq!(t("wallet.summary.by_value"), "par valeur");
        set_active(Some("es-PA".to_string()), Vec::new());
        assert_eq!(selected_offered().as_deref(), Some("es-PA"));
        let kept = with_ui_locales(&["sv-SE".to_string()], || t("wallet.summary.by_value"));
        assert_eq!(kept, "por valor");
        set_active(None, vec!["sv-SE".to_string()]);
        let switched = with_ui_locales(&["fr-CA".to_string()], || t("wallet.desktop.generic_name"));
        assert!(switched.contains("titres de compétences"));
        assert_eq!(t("wallet.summary.by_value"), "som värde");
    }

    #[test]
    fn regional_desktop_names_differ() {
        let lines = desktop_translations();
        let line = |locale: &str| {
            lines
                .iter()
                .find(|line| line.locale == locale)
                .unwrap_or_else(|| panic!("{locale}"))
        };
        assert!(line("fr_FR").generic_name.contains("justificatifs"));
        assert!(line("fr_CA").generic_name.contains("titres de compétences"));
        assert!(line("es_MX").generic_name.contains("Billetera"));
        assert!(line("es_PA").generic_name.contains("Billetera"));
        assert!(line("es_ES").generic_name.contains("Cartera"));
        assert!(line("zh_HK").generic_name.contains('銀'));
        assert!(line("zh_TW").generic_name.contains('錢'));
        assert!(line("zh_CN").generic_name.contains('钱'));
        assert_eq!(line("en").name, "OID4VC Wallet");
    }

    #[test]
    fn the_language_file_is_private() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-lang-{}-{}",
            std::process::id(),
            unique_suffix()
        ));
        let path = root.join("language");
        use std::os::unix::fs::PermissionsExt;
        preference::write_tag(&path, "fr-FR").unwrap();
        assert_eq!(preference::read_tag(&path).as_deref(), Some("fr-FR"));
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let dir_mode = std::fs::metadata(&root).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700);
        preference::remove_tag(&path).unwrap();
        assert!(preference::read_tag(&path).is_none());
        let _ = std::fs::remove_dir_all(&root);
    }

    fn unique_suffix() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos()
    }
}
