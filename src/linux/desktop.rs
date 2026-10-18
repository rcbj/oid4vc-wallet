//! Desktop Entry and `mimeapps.list` for the wallet's custom URL schemes.
//!
//! The schemes the installer registers by default are the ones iya-sts hands
//! a wallet on this machine:
//!
//! * `openid-credential-offer` — OpenID4VCI 1.0 section 4.1
//! * `siopv2` — SIOPv2, which iya-sts uses for an ID Token alone
//! * `openid4vp` — OpenID4VP 1.0, which iya-sts uses for a presentation
//!
//! `haip-vci` and `haip-vp` are registered only when the install is asked for
//! HAIP. The parser accepts them either way.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Desktop file id. The file name is what `mimeapps.list` points at.
pub const DESKTOP_FILE_NAME: &str = "org.rcbj.oid4vc-wallet.desktop";

/// PNG copied into the icon theme and named from the desktop file.
const ICON_PNG: &[u8] = include_bytes!("../../install/org.rcbj.oid4vc-wallet.png");

/// `Icon=` value. GNOME Shell looks this up in the hicolor theme. An absolute
/// path is drawn as the generic application icon.
const ICON_NAME: &str = "org.rcbj.oid4vc-wallet";

/// Sizes the shell and the dock ask for. 256 is the source image.
const ICON_SIZES: &[u32] = &[48, 64, 72, 96, 128, 256];

/// Schemes a normal install registers. `openid4vp` is included because that
/// is the scheme iya-sts uses for a presentation request; `siopv2` is the
/// scheme it uses for an ID Token alone.
pub const DEFAULT_SCHEMES: &[&str] = &["openid-credential-offer", "siopv2", "openid4vp"];

/// Every scheme this wallet knows how to remove, including HAIP.
pub const ALL_SCHEMES: &[&str] = &[
    "openid-credential-offer",
    "siopv2",
    "openid4vp",
    "haip-vci",
    "haip-vp",
];

/// Where the installer writes.
pub struct Layout {
    pub applications_dir: PathBuf,
    pub binary_path: PathBuf,
    pub mimeapps_path: PathBuf,
    /// `icons/hicolor`. The desktop file names [`ICON_NAME`]; the PNG is
    /// written under each size in [`ICON_SIZES`].
    pub icon_theme: PathBuf,
}

impl Layout {
    /// Per-user install: `~/.local/bin`, `~/.local/share/applications`,
    /// `~/.config/mimeapps.list`.
    pub fn user() -> Result<Self, String> {
        let home = crate::xdg::home()?;
        Ok(Self {
            applications_dir: crate::xdg::data_home()?.join("applications"),
            binary_path: home.join(".local/bin/oid4vc-wallet"),
            mimeapps_path: crate::xdg::config_home()?.join("mimeapps.list"),
            icon_theme: crate::xdg::data_home()?.join("icons/hicolor"),
        })
    }

    /// System install. The desktop file is discovered from
    /// `/usr/share/applications`. The default handlers are written to
    /// `/etc/xdg/mimeapps.list`, which is the spec's system `mimeapps.list`.
    pub fn system() -> Self {
        Self {
            applications_dir: PathBuf::from("/usr/share/applications"),
            binary_path: PathBuf::from("/usr/local/bin/oid4vc-wallet"),
            mimeapps_path: PathBuf::from("/etc/xdg/mimeapps.list"),
            icon_theme: PathBuf::from("/usr/share/icons/hicolor"),
        }
    }
}

fn icon_file(theme: &Path, size: u32) -> PathBuf {
    theme
        .join(format!("{size}x{size}"))
        .join("apps")
        .join(format!("{ICON_NAME}.png"))
}

/// What an install changed.
pub struct InstallReport {
    pub desktop_file: PathBuf,
    pub binary: PathBuf,
    pub icon: PathBuf,
    pub schemes: Vec<String>,
    /// `update-desktop-database` or `xdg-mime` could not be run. The files
    /// were still written, and those files are the registration.
    pub warnings: Vec<String>,
}

/// A failure while writing the registration.
#[derive(Debug)]
pub enum InstallError {
    Io { path: PathBuf, source: io::Error },
}

impl std::fmt::Display for InstallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io { path, source } => f.write_str(&crate::i18n::t_args(
                "wallet.cli.path_error",
                &[
                    ("path", &path.display().to_string()),
                    ("error", &source.to_string()),
                ],
            )),
        }
    }
}

impl std::error::Error for InstallError {}

/// Runs a program. Tests pass a recorder; the real installer runs the command.
pub trait CommandRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), String>;
}

/// `std::process::Command`.
pub struct SystemRunner;

impl CommandRunner for SystemRunner {
    fn run(&mut self, program: &str, args: &[String]) -> Result<(), String> {
        let status = Command::new(program).args(args).status().map_err(|err| {
            crate::i18n::t_args(
                "wallet.linux.could_not_run",
                &[("program", program), ("error", &err.to_string())],
            )
        })?;
        if status.success() {
            Ok(())
        } else {
            Err(crate::i18n::t_args(
                "wallet.linux.exited",
                &[("program", program), ("status", &status.to_string())],
            ))
        }
    }
}

/// Write the desktop file and the default-handler entries, then ask the
/// desktop cache to reload.
pub fn install_handlers(
    layout: &Layout,
    schemes: &[&str],
    runner: &mut dyn CommandRunner,
) -> Result<InstallReport, InstallError> {
    fs::create_dir_all(&layout.applications_dir).map_err(|source| InstallError::Io {
        path: layout.applications_dir.clone(),
        source,
    })?;
    if let Some(parent) = layout.mimeapps_path.parent() {
        fs::create_dir_all(parent).map_err(|source| InstallError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let desktop_path = layout.applications_dir.join(DESKTOP_FILE_NAME);
    write_theme_icons(&layout.icon_theme)?;
    write_new(&desktop_path, &desktop_entry(&layout.binary_path, schemes))?;
    let existing = read_optional(&layout.mimeapps_path)?;
    write_new(
        &layout.mimeapps_path,
        &set_scheme_handlers(&existing, DESKTOP_FILE_NAME, schemes),
    )?;
    let warnings = refresh_desktop(
        runner,
        &layout.applications_dir,
        &layout.icon_theme,
        schemes,
    );
    Ok(InstallReport {
        desktop_file: desktop_path,
        binary: layout.binary_path.clone(),
        icon: icon_file(&layout.icon_theme, 256),
        schemes: schemes.iter().map(|scheme| (*scheme).to_string()).collect(),
        warnings,
    })
}

/// Remove this wallet's desktop file and its handler lines.
pub fn uninstall_handlers(
    layout: &Layout,
    runner: &mut dyn CommandRunner,
) -> Result<Vec<String>, InstallError> {
    let desktop_path = layout.applications_dir.join(DESKTOP_FILE_NAME);
    remove_if_present(&desktop_path)?;
    if layout.mimeapps_path.exists() {
        let existing = read_optional(&layout.mimeapps_path)?;
        write_new(
            &layout.mimeapps_path,
            &clear_scheme_handlers(&existing, DESKTOP_FILE_NAME, ALL_SCHEMES),
        )?;
    }
    if layout.binary_path.exists() {
        remove_if_present(&layout.binary_path)?;
    }
    for size in ICON_SIZES {
        remove_if_present(&icon_file(&layout.icon_theme, *size))?;
    }
    Ok(refresh_desktop(
        runner,
        &layout.applications_dir,
        &layout.icon_theme,
        &[],
    ))
}

/// The Desktop Entry text. `Exec` runs this binary in window mode. `%u` is
/// the field code the session replaces with the invocation URI.
pub fn desktop_entry(binary: &Path, schemes: &[&str]) -> String {
    let mut mime = String::new();
    for scheme in schemes {
        mime.push_str("x-scheme-handler/");
        mime.push_str(scheme);
        mime.push(';');
    }
    let mut localized = String::new();
    for line in crate::i18n::desktop_translations() {
        localized.push_str(&format!(
            "Name[{locale}]={name}\nGenericName[{locale}]={generic}\nComment[{locale}]={comment}\n",
            locale = line.locale,
            name = line.name,
            generic = line.generic_name,
            comment = line.comment,
        ));
    }
    format!(
        "[Desktop Entry]\n\
         Version=1.0\n\
         Type=Application\n\
         Name=OID4VC Wallet\n\
         GenericName=Verifiable Credential Wallet\n\
         Comment=Accept OpenID4VCI credential offers and OpenID4VP and SIOPv2 requests\n\
         {localized}\
         Icon={ICON_NAME}\n\
         Exec={exec} --ui %u\n\
         Terminal=false\n\
         StartupWMClass=oid4vc-wallet\n\
         Categories=Network;Security;\n\
         MimeType={mime}\n\
         StartupNotify=true\n\
         NoDisplay=false\n",
        exec = desktop_quote(binary),
    )
}

/// Write the launcher icon at each size the shell asks for.
fn write_theme_icons(theme: &Path) -> Result<(), InstallError> {
    let source = image::load_from_memory(ICON_PNG).map_err(|err| InstallError::Io {
        path: icon_file(theme, 256),
        source: io::Error::new(io::ErrorKind::InvalidData, err.to_string()),
    })?;
    for size in ICON_SIZES {
        let path = icon_file(theme, *size);
        let bytes = if *size == 256 {
            ICON_PNG.to_vec()
        } else {
            let scaled = source.resize_exact(*size, *size, image::imageops::FilterType::CatmullRom);
            let mut encoded = Vec::new();
            scaled
                .write_to(
                    &mut std::io::Cursor::new(&mut encoded),
                    image::ImageFormat::Png,
                )
                .map_err(|err| InstallError::Io {
                    path: path.clone(),
                    source: io::Error::new(io::ErrorKind::InvalidData, err.to_string()),
                })?;
            encoded
        };
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|source| InstallError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        }
        fs::write(&path, bytes).map_err(|source| InstallError::Io {
            path: path.clone(),
            source,
        })?;
    }
    Ok(())
}

/// Quote a path the way the Desktop Entry spec quotes an `Exec` argument.
pub fn desktop_quote(path: &Path) -> String {
    let text = path.to_string_lossy();
    let needs_quotes = text
        .chars()
        .any(|ch| ch.is_whitespace() || matches!(ch, '"' | '\\' | '$' | '`'));
    if !needs_quotes {
        return text.into_owned();
    }
    let mut out = String::from("\"");
    for ch in text.chars() {
        if matches!(ch, '"' | '\\' | '$' | '`') {
            out.push('\\');
        }
        out.push(ch);
    }
    out.push('"');
    out
}

/// Set this desktop file as the default handler for each scheme, and add it
/// to the associations, without dropping handlers for other types.
pub fn set_scheme_handlers(existing: &str, desktop_name: &str, schemes: &[&str]) -> String {
    let mut doc = Doc::parse(existing);
    let defaults: Vec<(String, String)> = schemes
        .iter()
        .map(|scheme| {
            (
                format!("x-scheme-handler/{scheme}"),
                desktop_name.to_string(),
            )
        })
        .collect();
    doc.upsert("Default Applications", &defaults, Upsert::Replace);
    let associations: Vec<(String, String)> = schemes
        .iter()
        .map(|scheme| {
            (
                format!("x-scheme-handler/{scheme}"),
                format!("{desktop_name};"),
            )
        })
        .collect();
    doc.upsert("Added Associations", &associations, Upsert::AppendDesktop);
    doc.render()
}

/// Remove this desktop file from the default and the association lists.
pub fn clear_scheme_handlers(existing: &str, desktop_name: &str, schemes: &[&str]) -> String {
    let mut doc = Doc::parse(existing);
    let keys: Vec<String> = schemes
        .iter()
        .map(|scheme| format!("x-scheme-handler/{scheme}"))
        .collect();
    doc.remove_defaults("Default Applications", &keys, desktop_name);
    doc.remove_association("Added Associations", &keys, desktop_name);
    doc.render()
}

fn refresh_desktop(
    runner: &mut dyn CommandRunner,
    applications_dir: &Path,
    icon_theme: &Path,
    schemes: &[&str],
) -> Vec<String> {
    let mut warnings = Vec::new();
    let dir = applications_dir.to_string_lossy().into_owned();
    if let Err(err) = runner.run("update-desktop-database", &[dir]) {
        warnings.push(crate::i18n::t_args(
            "wallet.linux.desktop_database",
            &[("error", &err)],
        ));
    }
    for scheme in schemes {
        let mime = format!("x-scheme-handler/{scheme}");
        if let Err(err) = runner.run(
            "xdg-mime",
            &["default".to_string(), DESKTOP_FILE_NAME.to_string(), mime],
        ) {
            warnings.push(crate::i18n::t_args(
                "wallet.linux.xdg_mime",
                &[("scheme", scheme), ("error", &err)],
            ));
        }
    }
    // `-t` lets a per-user hicolor directory work when it has no index.theme.
    // `-i` is a different switch: it omits the image data.
    let mut cache_args = vec!["-f".to_string()];
    if !icon_theme.join("index.theme").exists() {
        cache_args.push("-t".to_string());
    }
    cache_args.push(icon_theme.to_string_lossy().into_owned());
    if let Err(err) = runner.run("gtk-update-icon-cache", &cache_args) {
        warnings.push(crate::i18n::t_args(
            "wallet.linux.desktop_database",
            &[("error", &err)],
        ));
    }
    warnings
}

/// Replace `path` by renaming a temporary file onto it, so a directory
/// monitor sees a new file rather than a rewrite of the old one.
fn write_new(path: &Path, contents: &str) -> Result<(), InstallError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|source| InstallError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut temporary_name = path.as_os_str().to_owned();
    temporary_name.push(".tmp");
    let temporary = PathBuf::from(temporary_name);
    let write_result = (|| {
        let mut file = fs::File::create(&temporary).map_err(|source| InstallError::Io {
            path: temporary.clone(),
            source,
        })?;
        file.write_all(contents.as_bytes())
            .map_err(|source| InstallError::Io {
                path: temporary.clone(),
                source,
            })?;
        file.sync_all().map_err(|source| InstallError::Io {
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, path).map_err(|source| InstallError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    write_result
}

fn read_optional(path: &Path) -> Result<String, InstallError> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(text),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(source) => Err(InstallError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn remove_if_present(path: &Path) -> Result<(), InstallError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(source) => Err(InstallError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}

enum Upsert {
    /// The default handler is one desktop file.
    Replace,
    /// An association is a list. Keep the other entries and add ours.
    AppendDesktop,
}

struct Doc {
    preamble: Vec<String>,
    sections: Vec<Section>,
}

struct Section {
    name: String,
    body: Vec<String>,
}

impl Doc {
    fn parse(text: &str) -> Self {
        let mut preamble = Vec::new();
        let mut sections = Vec::new();
        let mut current: Option<Section> = None;
        for line in text.lines() {
            if let Some(name) = section_name(line) {
                if let Some(section) = current.take() {
                    sections.push(section);
                }
                current = Some(Section {
                    name,
                    body: Vec::new(),
                });
            } else if let Some(section) = current.as_mut() {
                section.body.push(line.to_string());
            } else {
                preamble.push(line.to_string());
            }
        }
        if let Some(section) = current {
            sections.push(section);
        }
        Self { preamble, sections }
    }

    fn section_mut(&mut self, name: &str) -> &mut Section {
        if let Some(index) = self
            .sections
            .iter()
            .position(|section| section.name == name)
        {
            return &mut self.sections[index];
        }
        self.sections.push(Section {
            name: name.to_string(),
            body: Vec::new(),
        });
        self.sections
            .last_mut()
            .expect("the section was just pushed")
    }

    fn upsert(&mut self, section_name: &str, pairs: &[(String, String)], mode: Upsert) {
        let section = self.section_mut(section_name);
        for (key, value) in pairs {
            let mut found = false;
            for line in &mut section.body {
                let Some(existing) = line_key(line) else {
                    continue;
                };
                if existing != key {
                    continue;
                }
                *line = match mode {
                    Upsert::Replace => format!("{key}={value}"),
                    Upsert::AppendDesktop => {
                        let current = line.split_once('=').map(|(_, value)| value).unwrap_or("");
                        format!(
                            "{key}={}",
                            append_desktop(current, value.trim_end_matches(';'))
                        )
                    }
                };
                found = true;
            }
            if !found {
                section.body.push(format!("{key}={value}"));
            }
        }
    }

    fn remove_defaults(&mut self, section_name: &str, keys: &[String], desktop_name: &str) {
        let Some(section) = self
            .sections
            .iter_mut()
            .find(|section| section.name == section_name)
        else {
            return;
        };
        section.body.retain(|line| match line_key(line) {
            Some(key) if keys.iter().any(|wanted| wanted == key) => {
                let value = line
                    .split_once('=')
                    .map(|(_, value)| value.trim())
                    .unwrap_or("");
                value != desktop_name
            }
            _ => true,
        });
    }

    fn remove_association(&mut self, section_name: &str, keys: &[String], desktop_name: &str) {
        let Some(section) = self
            .sections
            .iter_mut()
            .find(|section| section.name == section_name)
        else {
            return;
        };
        let mut kept = Vec::new();
        for line in section.body.drain(..) {
            let Some(key) = line_key(&line) else {
                kept.push(line);
                continue;
            };
            if !keys.iter().any(|wanted| wanted == key) {
                kept.push(line);
                continue;
            }
            let value = line.split_once('=').map(|(_, value)| value).unwrap_or("");
            let next = remove_desktop(value, desktop_name);
            if !next.is_empty() && next != ";" {
                kept.push(format!("{key}={next}"));
            }
        }
        section.body = kept;
    }

    fn render(&self) -> String {
        let mut out = String::new();
        for line in &self.preamble {
            out.push_str(line);
            out.push('\n');
        }
        if !self.preamble.is_empty() && !self.sections.is_empty() && !out.ends_with("\n\n") {
            out.push('\n');
        }
        for (index, section) in self.sections.iter().enumerate() {
            if index > 0 && !out.ends_with("\n\n") {
                out.push('\n');
            }
            out.push('[');
            out.push_str(&section.name);
            out.push_str("]\n");
            for line in &section.body {
                out.push_str(line);
                out.push('\n');
            }
        }
        if out.is_empty() {
            out.push('\n');
        }
        out
    }
}

fn section_name(line: &str) -> Option<String> {
    let trimmed = line.trim();
    if trimmed.starts_with('[') && trimmed.ends_with(']') && trimmed.len() > 2 {
        Some(trimmed[1..trimmed.len() - 1].trim().to_string())
    } else {
        None
    }
}

fn line_key(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    trimmed.split_once('=').map(|(key, _)| key.trim())
}

fn append_desktop(current: &str, desktop_name: &str) -> String {
    let mut parts: Vec<&str> = current
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .collect();
    if !parts.contains(&desktop_name) {
        parts.push(desktop_name);
    }
    let mut out = parts.join(";");
    out.push(';');
    out
}

fn remove_desktop(current: &str, desktop_name: &str) -> String {
    let parts: Vec<&str> = current
        .split(';')
        .map(str::trim)
        .filter(|part| !part.is_empty() && *part != desktop_name)
        .collect();
    if parts.is_empty() {
        String::new()
    } else {
        let mut out = parts.join(";");
        out.push(';');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Recorded {
        calls: Vec<(String, Vec<String>)>,
    }

    impl CommandRunner for Recorded {
        fn run(&mut self, program: &str, args: &[String]) -> Result<(), String> {
            self.calls.push((program.to_string(), args.to_vec()));
            Ok(())
        }
    }

    #[test]
    fn desktop_entry_registers_the_three_default_schemes() {
        let text = desktop_entry(
            Path::new("/home/rcbj/.local/bin/oid4vc-wallet"),
            DEFAULT_SCHEMES,
        );
        assert!(text.contains("Icon=org.rcbj.oid4vc-wallet\n"));
        assert!(text.contains("StartupWMClass=oid4vc-wallet\n"));
        assert!(text.contains("StartupNotify=true\n"));
        assert!(text.contains("Exec=/home/rcbj/.local/bin/oid4vc-wallet --ui %u\n"));
        assert!(text.contains(
            "MimeType=x-scheme-handler/openid-credential-offer;x-scheme-handler/siopv2;x-scheme-handler/openid4vp;\n"
        ));
        assert!(text.contains("Terminal=false\n"));
        assert!(text.contains("Name=OID4VC Wallet\n"));
        assert!(
            text.contains("GenericName[fr_CA]=Portefeuille de titres de compétences vérifiables\n")
        );
        assert!(text.contains("GenericName[es_ES]=Cartera de credenciales verificables\n"));
        assert!(text.contains("GenericName[zh_HK]=可驗證憑證銀包\n"));
    }

    #[test]
    fn quotes_an_exec_path_that_has_a_space() {
        let quoted = desktop_quote(Path::new("/home/rcbj/my wallet/oid4vc-wallet"));
        assert_eq!(quoted, "\"/home/rcbj/my wallet/oid4vc-wallet\"");
    }

    #[test]
    fn mimeapps_keeps_handlers_it_did_not_set() {
        let existing = "\
[Default Applications]
text/plain=gedit.desktop
x-scheme-handler/siopv2=other.desktop

[Added Associations]
text/html=firefox.desktop;
x-scheme-handler/siopv2=other.desktop;
";
        let updated = set_scheme_handlers(
            existing,
            DESKTOP_FILE_NAME,
            &["siopv2", "openid-credential-offer"],
        );
        assert!(updated.contains("text/plain=gedit.desktop\n"));
        assert!(updated.contains("x-scheme-handler/siopv2=org.rcbj.oid4vc-wallet.desktop\n"));
        assert!(updated
            .contains("x-scheme-handler/openid-credential-offer=org.rcbj.oid4vc-wallet.desktop\n"));
        assert!(updated.contains("text/html=firefox.desktop;\n"));
        assert!(updated
            .contains("x-scheme-handler/siopv2=other.desktop;org.rcbj.oid4vc-wallet.desktop;\n"));
        let cleared = clear_scheme_handlers(&updated, DESKTOP_FILE_NAME, ALL_SCHEMES);
        assert!(cleared.contains("text/plain=gedit.desktop\n"));
        assert!(!cleared.contains("org.rcbj.oid4vc-wallet.desktop"));
        assert!(cleared.contains("x-scheme-handler/siopv2=other.desktop;\n"));
    }

    #[test]
    fn install_writes_the_files_and_asks_the_desktop_to_reload() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-install-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis()
        ));
        let layout = Layout {
            applications_dir: root.join("applications"),
            binary_path: PathBuf::from("/tmp/oid4vc-wallet"),
            mimeapps_path: root.join("config/mimeapps.list"),
            icon_theme: root.join("icons/hicolor"),
        };
        let mut runner = Recorded { calls: Vec::new() };
        let report = install_handlers(&layout, DEFAULT_SCHEMES, &mut runner).unwrap();
        let desktop = fs::read_to_string(&report.desktop_file).unwrap();
        assert!(desktop.contains("Icon=org.rcbj.oid4vc-wallet\n"));
        let source_icon = icon_file(&layout.icon_theme, 256);
        assert_eq!(fs::read(&source_icon).unwrap(), ICON_PNG);
        let dock_icon = fs::read(icon_file(&layout.icon_theme, 72)).unwrap();
        assert!(dock_icon.starts_with(b"\x89PNG"));
        assert_ne!(dock_icon, ICON_PNG);
        assert!(desktop.contains("x-scheme-handler/openid-credential-offer;"));
        assert!(desktop.contains("x-scheme-handler/siopv2;"));
        let mimeapps = fs::read_to_string(&layout.mimeapps_path).unwrap();
        assert!(mimeapps
            .contains("x-scheme-handler/openid-credential-offer=org.rcbj.oid4vc-wallet.desktop"));
        assert!(mimeapps.contains("x-scheme-handler/siopv2=org.rcbj.oid4vc-wallet.desktop"));
        assert!(mimeapps.contains("x-scheme-handler/openid4vp=org.rcbj.oid4vc-wallet.desktop"));
        assert!(runner
            .calls
            .iter()
            .any(|(program, _)| program == "update-desktop-database"));
        assert!(runner.calls.iter().any(|(program, args)| {
            program == "gtk-update-icon-cache"
                && args.iter().any(|arg| arg == "-t")
                && args.iter().all(|arg| arg != "-i")
        }));
        assert!(runner.calls.iter().any(|(program, args)| {
            program == "xdg-mime"
                && args.get(2).map(String::as_str) == Some("x-scheme-handler/siopv2")
        }));
        assert!(runner.calls.iter().any(|(program, args)| {
            program == "xdg-mime"
                && args.get(2).map(String::as_str)
                    == Some("x-scheme-handler/openid-credential-offer")
        }));
        fs::remove_dir_all(&root).unwrap();
    }
}
