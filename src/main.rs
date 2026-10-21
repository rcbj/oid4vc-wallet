//! `oid4vc-wallet` — a Linux wallet for OpenID4VCI and OpenID4VP.
//!
//! The desktop launches this program with `--ui` and the invocation URI.
//! That window lists credentials and runs the same operations as the
//! command line. `install` registers that launch with the session.
//! Credentials are sealed with AES-256-GCM. The key lives in GNOME Keyring,
//! or in KWallet when the Secret Service is not running. Settings can wrap
//! it to two FIDO2 security keys instead. Display text
//! follows the languages iya-sts ships. `--lang` and `language` choose one.

use std::env;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, IsTerminal, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use zeroize::Zeroize;

use oid4vc_wallet::i18n::{self, t, t_args};
use oid4vc_wallet::linux::{
    install_handlers, uninstall_handlers, InstallReport, Layout, SystemRunner, ALL_SCHEMES,
    DEFAULT_SCHEMES,
};
use oid4vc_wallet::protocol::{ui_locales_of_uri, Json};
use oid4vc_wallet::version;
use oid4vc_wallet::wallet::{
    accept, fido_locked, signature_algorithm, unlock_fido, Credential, CredentialVault, Inbox,
    NewCredential,
};

mod browser;
mod single;
mod ui;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(io::stderr(), "oid4vc-wallet: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

#[derive(Debug)]
struct Failure {
    message: String,
    code: u8,
}

fn fail(message: impl Into<String>, code: u8) -> Failure {
    Failure {
        message: message.into(),
        code,
    }
}

struct Options {
    json: bool,
    no_save: bool,
    system: bool,
    haip: bool,
    help: bool,
    version: bool,
    /// Open the window. Extra positionals are invocation URIs.
    ui: bool,
    format: Option<String>,
    issuer: Option<String>,
    document: Option<String>,
    document_file: Option<String>,
    /// Applied by [`activate_language`] before the rest of the command is read.
    lang: Option<String>,
    /// `--user` or `--system` was present.
    saw_scope: bool,
    positionals: Vec<String>,
}

fn run() -> Result<(), Failure> {
    activate_language()?;
    let options = options()?;
    let _applied_lang = options.lang.as_deref();
    if options.help {
        println!("{}", usage());
        return Ok(());
    }
    if options.version {
        println!("{}", version_text(options.json));
        return Ok(());
    }
    if options.ui {
        reject_ui_flags(&options)?;
        require_ui_arguments(&options)?;
        return ui::run(&options.positionals, options.no_save);
    }
    match options.positionals.first().map(String::as_str) {
        None => {
            println!("{}", usage());
            pause_if_interactive();
            Ok(())
        }
        Some("install") => {
            reject_extra(&options, 1)?;
            reject_credential_fields(&options)?;
            let text = install(&options)?;
            println!("{text}");
            Ok(())
        }
        Some("uninstall") => {
            reject_extra(&options, 1)?;
            reject_credential_fields(&options)?;
            let text = uninstall(&options)?;
            println!("{text}");
            Ok(())
        }
        Some("inbox") => {
            reject_extra(&options, 1)?;
            reject_credential_fields(&options)?;
            list_inbox()
        }
        Some("credentials") => {
            reject_extra(&options, 1)?;
            reject_credential_fields(&options)?;
            reject_install_flags(&options)?;
            list_credentials(options.json)
        }
        Some("credential") => credential_command(&options),
        Some("language") => {
            reject_credential_fields(&options)?;
            reject_install_flags(&options)?;
            language_command(&options)
        }
        Some("handle") => {
            reject_credential_fields(&options)?;
            handle(&options.positionals[1..], &options)?;
            pause_if_interactive();
            Ok(())
        }
        Some(command) if command.contains("://") => {
            reject_credential_fields(&options)?;
            handle(&options.positionals, &options)?;
            pause_if_interactive();
            Ok(())
        }
        Some(command) => Err(fail(
            t_args("wallet.cli.unknown_command", &[("command", command)]),
            1,
        )),
    }
}

enum LangPeek {
    Absent,
    Missing,
    Value(String),
}

fn activate_language() -> Result<(), Failure> {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut preferences = Vec::new();
    if let Some(saved) = i18n::saved_tag() {
        preferences.push(saved);
    }
    preferences.extend(i18n::system_tags());
    match peek_lang(&args) {
        LangPeek::Absent => i18n::set_active(None, preferences),
        LangPeek::Missing => {
            i18n::set_active(None, preferences);
            return Err(fail(
                t_args("wallet.cli.flag_needs_value", &[("name", "--lang")]),
                1,
            ));
        }
        LangPeek::Value(raw) => {
            if let Some(tag) = i18n::canonical_offered(&raw) {
                i18n::set_active(Some(tag), preferences);
            } else {
                i18n::set_active(None, preferences);
                return Err(fail(
                    t_args("wallet.cli.language_unknown", &[("tag", &raw)]),
                    1,
                ));
            }
        }
    }
    Ok(())
}

fn peek_lang(args: &[String]) -> LangPeek {
    let mut found = LangPeek::Absent;
    let mut index = 0;
    while index < args.len() {
        let arg = &args[index];
        if let Some(value) = arg.strip_prefix("--lang=") {
            found = if value.is_empty() {
                LangPeek::Missing
            } else {
                LangPeek::Value(value.to_string())
            };
        } else if arg == "--lang" {
            match args.get(index + 1) {
                Some(value) if !value.starts_with('-') || value == "-" => {
                    found = LangPeek::Value(value.clone());
                    index += 1;
                }
                _ => found = LangPeek::Missing,
            }
        }
        index += 1;
    }
    found
}

fn options() -> Result<Options, Failure> {
    options_from(env::args().skip(1))
}

fn options_from(args: impl IntoIterator<Item = String>) -> Result<Options, Failure> {
    let mut options = Options {
        json: false,
        no_save: false,
        system: false,
        haip: false,
        help: false,
        version: false,
        ui: false,
        format: None,
        issuer: None,
        document: None,
        document_file: None,
        lang: None,
        saw_scope: false,
        positionals: Vec::new(),
    };
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        let (name, inline) = split_valued(&arg);
        match name {
            "--json" => {
                reject_inline(inline, "--json")?;
                options.json = true;
            }
            "--no-save" => {
                reject_inline(inline, "--no-save")?;
                options.no_save = true;
            }
            "--haip" => {
                reject_inline(inline, "--haip")?;
                options.haip = true;
            }
            "--help" | "-h" | "help" => {
                reject_inline(inline, name)?;
                options.help = true;
            }
            "--version" | "-V" => {
                reject_inline(inline, name)?;
                options.version = true;
            }
            "--ui" => {
                reject_inline(inline, "--ui")?;
                options.ui = true;
            }
            "--system" => {
                reject_inline(inline, "--system")?;
                if options.saw_scope && !options.system {
                    return Err(fail(t("wallet.cli.both_scopes"), 1));
                }
                options.system = true;
                options.saw_scope = true;
            }
            "--user" => {
                reject_inline(inline, "--user")?;
                if options.saw_scope && options.system {
                    return Err(fail(t("wallet.cli.both_scopes"), 1));
                }
                options.system = false;
                options.saw_scope = true;
            }
            "--format" => set_once(
                &mut options.format,
                "--format",
                take_value(inline, &mut args, "--format")?,
            )?,
            "--issuer" => set_once(
                &mut options.issuer,
                "--issuer",
                take_value(inline, &mut args, "--issuer")?,
            )?,
            "--document" => set_once(
                &mut options.document,
                "--document",
                take_value(inline, &mut args, "--document")?,
            )?,
            "--document-file" => set_once(
                &mut options.document_file,
                "--document-file",
                take_value(inline, &mut args, "--document-file")?,
            )?,
            "--lang" => set_once(
                &mut options.lang,
                "--lang",
                take_value(inline, &mut args, "--lang")?,
            )?,
            other if other.starts_with('-') => {
                return Err(fail(
                    t_args("wallet.cli.unknown_option", &[("option", other)]),
                    1,
                ));
            }
            other => options.positionals.push(other.to_string()),
        }
    }
    Ok(options)
}

/// `--name=value` is accepted. A bare `--name` takes the next argument.
fn split_valued(arg: &str) -> (&str, Option<&str>) {
    match arg.split_once('=') {
        Some((name, value)) if name.starts_with("--") && name != "--" => (name, Some(value)),
        _ => (arg, None),
    }
}

fn reject_inline(inline: Option<&str>, name: &str) -> Result<(), Failure> {
    if inline.is_some() {
        Err(fail(
            t_args("wallet.cli.flag_no_value", &[("name", name)]),
            1,
        ))
    } else {
        Ok(())
    }
}

fn take_value(
    inline: Option<&str>,
    args: &mut impl Iterator<Item = String>,
    name: &str,
) -> Result<String, Failure> {
    if let Some(value) = inline {
        return Ok(value.to_string());
    }
    match args.next() {
        Some(value) if !value.starts_with('-') || value == "-" => Ok(value),
        Some(_) | None => Err(fail(
            t_args("wallet.cli.flag_needs_value", &[("name", name)]),
            1,
        )),
    }
}

fn set_once(slot: &mut Option<String>, name: &str, value: String) -> Result<(), Failure> {
    if slot.is_some() {
        return Err(fail(t_args("wallet.cli.flag_twice", &[("name", name)]), 1));
    }
    *slot = Some(value);
    Ok(())
}

fn reject_extra(options: &Options, keep: usize) -> Result<(), Failure> {
    if options.positionals.len() > keep {
        Err(fail(
            t_args(
                "wallet.cli.unexpected_argument",
                &[("argument", &options.positionals[keep])],
            ),
            1,
        ))
    } else {
        Ok(())
    }
}

fn reject_credential_fields(options: &Options) -> Result<(), Failure> {
    if options.format.is_some()
        || options.issuer.is_some()
        || options.document.is_some()
        || options.document_file.is_some()
    {
        Err(fail(t("wallet.cli.no_credential_fields"), 1))
    } else {
        Ok(())
    }
}

fn reject_install_flags(options: &Options) -> Result<(), Failure> {
    if options.saw_scope || options.haip || options.no_save {
        Err(fail(t("wallet.cli.no_install_flags"), 1))
    } else {
        Ok(())
    }
}

/// `--ui` is the window. Registration and credential fields are chosen there.
/// `--no-save` still applies to URIs passed on this launch.
fn reject_ui_flags(options: &Options) -> Result<(), Failure> {
    if options.json
        || options.saw_scope
        || options.haip
        || options.format.is_some()
        || options.issuer.is_some()
        || options.document.is_some()
        || options.document_file.is_some()
    {
        Err(fail(t("wallet.cli.ui_flags"), 1))
    } else {
        Ok(())
    }
}

/// A desktop with no URI omits `%u`. An empty argument is that same launch.
fn require_ui_arguments(options: &Options) -> Result<(), Failure> {
    for argument in &options.positionals {
        if argument.is_empty() {
            continue;
        }
        if !argument.contains("://") {
            return Err(fail(
                t_args("wallet.cli.ui_argument", &[("argument", argument)]),
                1,
            ));
        }
    }
    Ok(())
}

fn credential_command(options: &Options) -> Result<(), Failure> {
    reject_install_flags(options)?;
    match options.positionals.get(1).map(String::as_str) {
        Some("add") => {
            reject_extra(options, 2)?;
            add_credential(options)
        }
        Some("show") => {
            reject_credential_fields(options)?;
            one_id(options, show_credential)
        }
        Some("delete") => {
            reject_credential_fields(options)?;
            one_id(options, delete_credential)
        }
        Some("list") => {
            reject_extra(options, 2)?;
            reject_credential_fields(options)?;
            list_credentials(options.json)
        }
        Some(other) => Err(fail(
            t_args(
                "wallet.cli.unknown_credential_command",
                &[("command", other)],
            ),
            1,
        )),
        None => Err(fail(t("wallet.cli.credential_command_usage"), 1)),
    }
}

fn language_command(options: &Options) -> Result<(), Failure> {
    match options.positionals.get(1).map(String::as_str) {
        None => {
            reject_extra(options, 1)?;
            list_languages();
            Ok(())
        }
        Some("set") => {
            reject_extra(options, 3)?;
            let tag = options
                .positionals
                .get(2)
                .map(String::as_str)
                .ok_or_else(|| fail(t("wallet.cli.need_language_tag"), 1))?;
            language_set(tag)
        }
        Some("clear") => {
            reject_extra(options, 2)?;
            language_clear()
        }
        Some(other) => Err(fail(
            t_args("wallet.cli.unknown_language_command", &[("command", other)]),
            1,
        )),
    }
}

fn list_languages() {
    let translator = i18n::current();
    let name = i18n::endonym(&translator.locale);
    println!(
        "{}",
        t_args(
            "wallet.cli.language_current",
            &[("tag", &translator.locale), ("name", &name)],
        )
    );
    let selected = i18n::selected_offered();
    for offered in i18n::offered() {
        let mark = if selected.as_deref() == Some(offered.tag.as_str()) {
            "*"
        } else {
            " "
        };
        println!("{mark} {}  {}", offered.tag, offered.name);
    }
}

fn language_set(tag: &str) -> Result<(), Failure> {
    let canonical = i18n::canonical_offered(tag)
        .ok_or_else(|| fail(t_args("wallet.cli.language_unknown", &[("tag", tag)]), 1))?;
    i18n::store_tag(&canonical).map_err(|err| fail(err, 1))?;
    let translator = i18n::negotiate_tag(&canonical);
    let name = i18n::endonym(&canonical);
    println!(
        "{}",
        translator.text_args(
            "wallet.cli.language_set",
            &[("tag", &canonical), ("name", &name)],
        )
    );
    Ok(())
}

fn language_clear() -> Result<(), Failure> {
    i18n::clear_tag().map_err(|err| fail(err, 1))?;
    println!("{}", t("wallet.cli.language_cleared"));
    Ok(())
}

fn one_id(
    options: &Options,
    command: impl FnOnce(&str, bool) -> Result<(), Failure>,
) -> Result<(), Failure> {
    reject_extra(options, 3)?;
    let id = options
        .positionals
        .get(2)
        .map(String::as_str)
        .ok_or_else(|| fail(t("wallet.cli.need_id"), 1))?;
    command(id, options.json)
}

fn install(options: &Options) -> Result<String, Failure> {
    let layout = layout(options)?;
    place_binary(&layout.binary_path)?;
    let schemes = schemes(options);
    let mut runner = SystemRunner;
    let report =
        install_handlers(&layout, schemes, &mut runner).map_err(|err| fail(err.to_string(), 1))?;
    Ok(format_install(&report))
}

fn uninstall(options: &Options) -> Result<String, Failure> {
    let layout = layout(options)?;
    let mut runner = SystemRunner;
    let warnings =
        uninstall_handlers(&layout, &mut runner).map_err(|err| fail(err.to_string(), 1))?;
    let mut lines = vec![
        t_args(
            "wallet.cli.removed",
            &[(
                "path",
                &layout
                    .applications_dir
                    .join(oid4vc_wallet::linux::DESKTOP_FILE_NAME)
                    .display()
                    .to_string(),
            )],
        ),
        t_args(
            "wallet.cli.removed",
            &[("path", &layout.binary_path.display().to_string())],
        ),
    ];
    for warning in &warnings {
        lines.push(t_args("wallet.cli.warning", &[("warning", warning)]));
    }
    Ok(lines.join("\n"))
}

fn layout(options: &Options) -> Result<Layout, Failure> {
    if options.system {
        Ok(Layout::system())
    } else {
        Layout::user().map_err(|err| fail(err, 1))
    }
}

fn schemes(options: &Options) -> &'static [&'static str] {
    if options.haip {
        ALL_SCHEMES
    } else {
        DEFAULT_SCHEMES
    }
}

fn format_install(report: &InstallReport) -> String {
    let mut lines = vec![
        t_args(
            "wallet.cli.installed",
            &[("path", &report.binary.display().to_string())],
        ),
        t_args(
            "wallet.cli.desktop_file",
            &[("path", &report.desktop_file.display().to_string())],
        ),
        t_args(
            "wallet.cli.icon",
            &[("path", &report.icon.display().to_string())],
        ),
        t_args(
            "wallet.cli.registered",
            &[("count", &report.schemes.len().to_string())],
        ),
    ];
    for scheme in &report.schemes {
        lines.push(format!("  {scheme}://"));
    }
    for warning in &report.warnings {
        lines.push(t_args("wallet.cli.warning", &[("warning", warning)]));
    }
    lines.join("\n")
}

/// A desktop click opens a terminal for this process. The terminal closes
/// when the process exits, so leave the help or the parsed request on screen
/// until the user dismisses it. A shell that is already open is not a
/// problem: one extra Enter returns to the prompt. A pipe is not asked.
fn pause_if_interactive() {
    if !io::stdin().is_terminal() {
        return;
    }
    println!("\n{}", t("wallet.cli.press_enter"));
    let mut line = String::new();
    let _ = io::stdin().read_line(&mut line);
}

fn place_binary(dest: &Path) -> Result<(), Failure> {
    let current = env::current_exe().map_err(|err| {
        fail(
            t_args("wallet.cli.binary_missing", &[("error", &err.to_string())]),
            1,
        )
    })?;
    let appimage = env::var_os("APPIMAGE").map(PathBuf::from);
    let source = installed_binary(appimage.as_deref(), &current);
    if same_file(&source, dest) {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            fail(
                t_args(
                    "wallet.cli.path_error",
                    &[
                        ("path", &parent.display().to_string()),
                        ("error", &err.to_string()),
                    ],
                ),
                1,
            )
        })?;
    }
    let temporary = dest.with_extension("new");
    fs::copy(&source, &temporary).map_err(|err| {
        fail(
            t_args(
                "wallet.cli.copy_failed",
                &[
                    ("path", &dest.display().to_string()),
                    ("error", &err.to_string()),
                ],
            ),
            1,
        )
    })?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755)).map_err(|err| {
        fail(
            t_args(
                "wallet.cli.chmod_failed",
                &[
                    ("path", &dest.display().to_string()),
                    ("error", &err.to_string()),
                ],
            ),
            1,
        )
    })?;
    fs::rename(&temporary, dest).map_err(|err| {
        fail(
            t_args(
                "wallet.cli.install_failed",
                &[
                    ("path", &dest.display().to_string()),
                    ("error", &err.to_string()),
                ],
            ),
            1,
        )
    })?;
    Ok(())
}

/// The file `install` copies into place.
///
/// An AppImage sets `APPIMAGE` to its own path. That file is the
/// self-contained program, so it is what gets registered. The mounted
/// payload inside the image is only the inner binary.
fn installed_binary(appimage: Option<&Path>, current_exe: &Path) -> PathBuf {
    if let Some(path) = appimage {
        if path.is_file() {
            return path.to_path_buf();
        }
    }
    current_exe.to_path_buf()
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn list_inbox() -> Result<(), Failure> {
    let inbox = Inbox::default_location().map_err(|err| fail(err, 1))?;
    let entries = inbox.list().map_err(|err| {
        fail(
            t_args("wallet.cli.inbox_read", &[("error", &err.to_string())]),
            1,
        )
    })?;
    if entries.is_empty() {
        println!(
            "{}",
            t_args(
                "wallet.cli.inbox_empty",
                &[("path", &inbox.root().display().to_string())],
            )
        );
        return Ok(());
    }
    for entry in entries {
        println!("{}", entry.path.display());
    }
    Ok(())
}

fn handle(uris: &[String], options: &Options) -> Result<(), Failure> {
    if uris.is_empty() {
        return Err(fail(t("wallet.cli.need_uri"), 1));
    }
    let inbox = if options.no_save {
        None
    } else {
        Some(Inbox::default_location().map_err(|err| fail(err, 1))?)
    };
    let mut errors = Vec::new();
    for uri in uris {
        let locales = ui_locales_of_uri(uri);
        let outcome = i18n::with_ui_locales(&locales, || match accept(uri, inbox.as_ref()) {
            Ok(accepted) => {
                if options.json {
                    println!("{}", accepted.json);
                    if let Some(path) = &accepted.saved {
                        let _ = writeln!(
                            io::stderr(),
                            "{}",
                            t_args(
                                "wallet.cli.saved_note",
                                &[("path", &path.display().to_string())],
                            )
                        );
                    }
                } else {
                    println!("{}", accepted.summary);
                    if let Some(path) = &accepted.saved {
                        println!(
                            "\n{}",
                            t_args("wallet.cli.saved", &[("path", &path.display().to_string())])
                        );
                    }
                }
                Ok(())
            }
            Err(err) => Err(t_args(
                "wallet.cli.handled",
                &[("uri", uri), ("error", &err.to_string())],
            )),
        });
        if let Err(err) = outcome {
            errors.push(err);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(fail(errors.join("\n"), 2))
    }
}

fn open_vault() -> Result<CredentialVault<oid4vc_wallet::wallet::DesktopKeyStore>, Failure> {
    if fido_locked().map_err(|err| fail(err.to_string(), 1))? {
        let mut pin = prompt_fido_pin()?;
        let unlocked = unlock_fido(&pin);
        pin.zeroize();
        unlocked.map_err(|err| fail(err.to_string(), 1))?;
    }
    CredentialVault::open_default().map_err(|err| fail(err.to_string(), 1))
}

/// The PIN is read from the terminal, not stdin. Stdin may be the credential
/// document. Echo is turned off so the PIN is not shown.
fn prompt_fido_pin() -> Result<String, Failure> {
    let mut guard = EchoGuard::silence()?;
    let pin = read_hidden_line(&guard.tty)?;
    let _ = writeln!(guard.tty);
    Ok(pin)
}

struct EchoGuard {
    tty: std::fs::File,
}

impl EchoGuard {
    fn silence() -> Result<Self, Failure> {
        let tty = OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/tty")
            .map_err(|_| fail(t("wallet.fido.tty"), 1))?;
        let guard = Self { tty };
        if !guard.stty("-echo") {
            return Err(fail(t("wallet.fido.tty"), 1));
        }
        Ok(guard)
    }

    fn stty(&self, arg: &str) -> bool {
        let Ok(cloned) = self.tty.try_clone() else {
            return false;
        };
        Command::new("stty")
            .arg(arg)
            .stdin(Stdio::from(cloned))
            .status()
            .is_ok_and(|status| status.success())
    }
}

impl Drop for EchoGuard {
    fn drop(&mut self) {
        let _ = self.stty("echo");
    }
}

fn read_hidden_line(tty: &std::fs::File) -> Result<String, Failure> {
    let mut out = tty.try_clone().map_err(|_| fail(t("wallet.fido.tty"), 1))?;
    writeln!(out, "{}", t("wallet.fido.prompt")).map_err(|_| fail(t("wallet.fido.tty"), 1))?;
    out.flush().map_err(|_| fail(t("wallet.fido.tty"), 1))?;
    let mut line = String::new();
    let read = BufReader::new(tty.try_clone().map_err(|_| fail(t("wallet.fido.tty"), 1))?)
        .read_line(&mut line);
    if read.is_err() {
        line.zeroize();
        return Err(fail(t("wallet.fido.tty"), 1));
    }
    if line.ends_with('\n') {
        line.pop();
    }
    if line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

fn add_credential(options: &Options) -> Result<(), Failure> {
    let format = options
        .format
        .clone()
        .ok_or_else(|| fail(t("wallet.cli.pass_format"), 1))?;
    let issuer = options
        .issuer
        .clone()
        .ok_or_else(|| fail(t("wallet.cli.pass_issuer"), 1))?;
    let document = document_text(options)?;
    let stored = open_vault()?
        .put(NewCredential {
            format,
            issuer,
            document,
            holder_key: None,
        })
        .map_err(|err| fail(err.to_string(), 1))?;
    if options.json {
        println!("{}", stored.to_json());
    } else {
        println!("{}", t_args("wallet.cli.stored", &[("id", &stored.id)]));
        println!(
            "{}",
            t_args("wallet.cli.format", &[("format", &stored.format)])
        );
        println!(
            "{}",
            t_args("wallet.cli.issuer", &[("issuer", &stored.issuer)])
        );
        println!(
            "{}",
            t_args("wallet.cli.received", &[("time", &stored.received_at)])
        );
    }
    Ok(())
}

fn document_text(options: &Options) -> Result<String, Failure> {
    match (&options.document, &options.document_file) {
        (Some(_), Some(_)) => Err(fail(t("wallet.cli.either_document"), 1)),
        (None, None) => Err(fail(t("wallet.cli.pass_document"), 1)),
        (Some(text), None) => Ok(text.clone()),
        (None, Some(path)) => read_document_file(path),
    }
}

fn read_document_file(path: &str) -> Result<String, Failure> {
    if path == "-" {
        let mut text = String::new();
        io::stdin().read_to_string(&mut text).map_err(|err| {
            fail(
                t_args("wallet.cli.stdin", &[("error", &err.to_string())]),
                1,
            )
        })?;
        return Ok(text);
    }
    fs::read_to_string(path).map_err(|err| {
        fail(
            t_args(
                "wallet.cli.read_file",
                &[("path", path), ("error", &err.to_string())],
            ),
            1,
        )
    })
}

fn list_credentials(json: bool) -> Result<(), Failure> {
    let vault = open_vault()?;
    let credentials = vault.list().map_err(|err| fail(err.to_string(), 1))?;
    if json {
        let value = Json::Array(credentials.iter().map(Credential::to_json).collect());
        println!("{value}");
        return Ok(());
    }
    if credentials.is_empty() {
        println!(
            "{}",
            t_args(
                "wallet.cli.no_credentials",
                &[("path", &vault.root().display().to_string())],
            )
        );
        return Ok(());
    }
    for credential in &credentials {
        println!(
            "{}  {}  {}  {}",
            credential.id, credential.received_at, credential.format, credential.issuer
        );
    }
    Ok(())
}

fn show_credential(id: &str, json: bool) -> Result<(), Failure> {
    let credential = open_vault()?
        .get(id)
        .map_err(|err| fail(err.to_string(), 1))?;
    if json {
        println!("{}", credential.to_json());
    } else {
        println!("{}", t_args("wallet.cli.id", &[("id", &credential.id)]));
        println!(
            "{}",
            t_args("wallet.cli.format", &[("format", &credential.format)])
        );
        println!(
            "{}",
            t_args("wallet.cli.issuer", &[("issuer", &credential.issuer)])
        );
        let algorithm = signature_algorithm(&credential.format, &credential.document)
            .unwrap_or_else(|| t("wallet.cli.algorithm_unknown"));
        println!(
            "{}",
            t_args("wallet.cli.algorithm", &[("algorithm", &algorithm)])
        );
        println!(
            "{}",
            t_args("wallet.cli.received", &[("time", &credential.received_at)])
        );
        println!();
        println!("{}", credential.document);
    }
    Ok(())
}

fn delete_credential(id: &str, json: bool) -> Result<(), Failure> {
    open_vault()?
        .delete(id)
        .map_err(|err| fail(err.to_string(), 1))?;
    if json {
        println!(
            "{}",
            Json::Object(vec![("deleted".to_string(), Json::String(id.to_string()))])
        );
    } else {
        println!("{}", t_args("wallet.cli.deleted", &[("id", id)]));
    }
    Ok(())
}

fn version_text(json: bool) -> String {
    if !json {
        return format!("oid4vc-wallet {}", version::VERSION);
    }
    let text = |value: &str| Json::String(value.to_string());
    let commit = if version::COMMIT.is_empty() {
        Json::Null
    } else {
        text(version::COMMIT)
    };
    Json::Object(vec![
        ("version".to_string(), text(version::VERSION)),
        ("major_minor".to_string(), text(version::MAJOR_MINOR)),
        ("build".to_string(), text(version::BUILD)),
        ("built_at".to_string(), text(version::BUILT_AT)),
        ("commit".to_string(), commit),
    ])
    .to_string()
}

fn usage() -> String {
    [
        t("wallet.usage.title"),
        String::new(),
        t("wallet.usage.intro"),
        String::new(),
        t("wallet.usage.crypto"),
        String::new(),
        t("wallet.usage.desktop"),
        String::new(),
        t("wallet.usage.install"),
        String::new(),
        t("wallet.usage.uninstall"),
        String::new(),
        t("wallet.usage.handle"),
        String::new(),
        t("wallet.usage.inbox"),
        String::new(),
        t("wallet.usage.add"),
        String::new(),
        t("wallet.usage.list"),
        String::new(),
        t("wallet.usage.language"),
        String::new(),
        t("wallet.usage.ui"),
        String::new(),
        t("wallet.usage.version"),
        String::new(),
        t("wallet.usage.footer"),
    ]
    .join("\n")
}

#[cfg(test)]
mod tests {
    use super::installed_binary;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn install_copies_the_appimage_when_that_is_what_was_run() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-appimage-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        let appimage = root.join("OID4VC_Wallet.AppImage");
        let current = root.join("oid4vc-wallet");
        fs::write(&appimage, b"appimage").unwrap();
        fs::write(&current, b"inner").unwrap();
        assert_eq!(installed_binary(Some(&appimage), &current), appimage);
        let missing = root.join("missing.AppImage");
        assert_eq!(installed_binary(Some(&missing), &current), current);
        assert_eq!(installed_binary(None, &current), current);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn ui_flag_keeps_invocation_uris_and_no_save() {
        let options = super::options_from([
            "--ui".to_string(),
            "--no-save".to_string(),
            "siopv2://?client_id=abc".to_string(),
        ])
        .unwrap();
        assert!(options.ui);
        assert!(options.no_save);
        assert_eq!(options.positionals, vec!["siopv2://?client_id=abc"]);
    }

    #[test]
    fn version_flag_prints_the_stamped_version() {
        let options = super::options_from(["--version".to_string(), "--json".to_string()]).unwrap();
        assert!(options.version);
        assert!(super::options_from(["-V".to_string()]).unwrap().version);
        assert!(super::options_from(["--version=1".to_string()]).is_err());
        let plain = super::version_text(false);
        assert_eq!(plain, format!("oid4vc-wallet {}", super::version::VERSION));
        let json = oid4vc_wallet::protocol::Json::parse(&super::version_text(true)).unwrap();
        assert_eq!(
            json.get("version").and_then(|v| v.as_str()),
            Some(super::version::VERSION)
        );
        assert_eq!(
            json.get("build").and_then(|v| v.as_str()),
            Some(super::version::BUILD)
        );
    }

    #[test]
    fn ui_mode_rejects_a_command_name() {
        let options = super::options_from(["--ui".to_string(), "install".to_string()]).unwrap();
        let err = super::require_ui_arguments(&options).unwrap_err();
        assert!(err.message.contains("install"));
    }
}
