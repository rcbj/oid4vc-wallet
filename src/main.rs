//! `oid4vc-wallet` — a Linux wallet for OpenID4VCI and OpenID4VP.
//!
//! The desktop launches this program with the invocation URI as its argument.
//! `install` registers that launch with the session.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::ExitCode;

use oid4vc_wallet::linux::{
    install_handlers, uninstall_handlers, InstallReport, Layout, SystemRunner, ALL_SCHEMES,
    DEFAULT_SCHEMES,
};
use oid4vc_wallet::wallet::{accept, Inbox};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            let _ = writeln!(io::stderr(), "oid4vc-wallet: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

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
    positionals: Vec<String>,
}

fn run() -> Result<(), Failure> {
    let options = options()?;
    if options.help {
        println!("{USAGE}");
        return Ok(());
    }
    match options.positionals.first().map(String::as_str) {
        None => {
            println!("{USAGE}");
            Ok(())
        }
        Some("install") => {
            reject_extra(&options, 1)?;
            install(&options)
        }
        Some("uninstall") => {
            reject_extra(&options, 1)?;
            uninstall(&options)
        }
        Some("inbox") => {
            reject_extra(&options, 1)?;
            list_inbox()
        }
        Some("handle") => handle(&options.positionals[1..], &options),
        Some(command) if command.contains("://") => handle(&options.positionals, &options),
        Some(command) => Err(fail(
            format!("unknown command {command}. Run `oid4vc-wallet help`."),
            1,
        )),
    }
}

fn options() -> Result<Options, Failure> {
    let mut options = Options {
        json: false,
        no_save: false,
        system: false,
        haip: false,
        help: false,
        positionals: Vec::new(),
    };
    let mut saw_scope = false;
    for arg in env::args().skip(1) {
        match arg.as_str() {
            "--json" => options.json = true,
            "--no-save" => options.no_save = true,
            "--haip" => options.haip = true,
            "--help" | "-h" | "help" => options.help = true,
            "--system" => {
                if saw_scope && !options.system {
                    return Err(fail("pass either --user or --system, not both", 1));
                }
                options.system = true;
                saw_scope = true;
            }
            "--user" => {
                if saw_scope && options.system {
                    return Err(fail("pass either --user or --system, not both", 1));
                }
                options.system = false;
                saw_scope = true;
            }
            other if other.starts_with('-') => {
                return Err(fail(format!("unknown option {other}"), 1));
            }
            other => options.positionals.push(other.to_string()),
        }
    }
    Ok(options)
}

fn reject_extra(options: &Options, keep: usize) -> Result<(), Failure> {
    if options.positionals.len() > keep {
        Err(fail(
            format!("unexpected argument {}", options.positionals[keep]),
            1,
        ))
    } else {
        Ok(())
    }
}

fn install(options: &Options) -> Result<(), Failure> {
    let layout = layout(options)?;
    place_binary(&layout.binary_path)?;
    let schemes = schemes(options);
    let mut runner = SystemRunner;
    let report =
        install_handlers(&layout, schemes, &mut runner).map_err(|err| fail(err.to_string(), 1))?;
    report_install(&report);
    Ok(())
}

fn uninstall(options: &Options) -> Result<(), Failure> {
    let layout = layout(options)?;
    let mut runner = SystemRunner;
    let warnings =
        uninstall_handlers(&layout, &mut runner).map_err(|err| fail(err.to_string(), 1))?;
    println!(
        "Removed {}",
        layout
            .applications_dir
            .join(oid4vc_wallet::linux::DESKTOP_FILE_NAME)
            .display()
    );
    println!("Removed {}", layout.binary_path.display());
    print_warnings(&warnings);
    Ok(())
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

fn report_install(report: &InstallReport) {
    println!("Installed {}", report.binary.display());
    println!("Desktop file {}", report.desktop_file.display());
    println!("Registered these protocol handlers:");
    for scheme in &report.schemes {
        println!("  {scheme}://");
    }
    print_warnings(&report.warnings);
}

fn print_warnings(warnings: &[String]) {
    for warning in warnings {
        let _ = writeln!(io::stderr(), "warning: {warning}");
    }
}

fn place_binary(dest: &Path) -> Result<(), Failure> {
    let source =
        env::current_exe().map_err(|err| fail(format!("could not find this binary: {err}"), 1))?;
    if same_file(&source, dest) {
        return Ok(());
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent)
            .map_err(|err| fail(format!("{}: {err}", parent.display()), 1))?;
    }
    let temporary = dest.with_extension("new");
    fs::copy(&source, &temporary).map_err(|err| {
        fail(
            format!("could not copy the wallet to {}: {err}", dest.display()),
            1,
        )
    })?;
    fs::set_permissions(&temporary, fs::Permissions::from_mode(0o755)).map_err(|err| {
        fail(
            format!("could not mark {} executable: {err}", dest.display()),
            1,
        )
    })?;
    fs::rename(&temporary, dest).map_err(|err| {
        fail(
            format!("could not install the wallet at {}: {err}", dest.display()),
            1,
        )
    })?;
    Ok(())
}

fn same_file(left: &Path, right: &Path) -> bool {
    match (fs::canonicalize(left), fs::canonicalize(right)) {
        (Ok(left), Ok(right)) => left == right,
        _ => false,
    }
}

fn list_inbox() -> Result<(), Failure> {
    let inbox = Inbox::default_location().map_err(|err| fail(err, 1))?;
    let entries = inbox
        .list()
        .map_err(|err| fail(format!("could not read the inbox: {err}"), 1))?;
    if entries.is_empty() {
        println!("Inbox is empty ({})", inbox.root().display());
        return Ok(());
    }
    for entry in entries {
        println!("{}", entry.path.display());
    }
    Ok(())
}

fn handle(uris: &[String], options: &Options) -> Result<(), Failure> {
    if uris.is_empty() {
        return Err(fail("pass the invocation URI", 1));
    }
    let inbox = if options.no_save {
        None
    } else {
        Some(Inbox::default_location().map_err(|err| fail(err, 1))?)
    };
    let mut errors = Vec::new();
    for uri in uris {
        match accept(uri, inbox.as_ref()) {
            Ok(accepted) => {
                if options.json {
                    println!("{}", accepted.json);
                    if let Some(path) = &accepted.saved {
                        let _ = writeln!(io::stderr(), "saved {}", path.display());
                    }
                } else {
                    println!("{}", accepted.summary);
                    if let Some(path) = &accepted.saved {
                        println!("\nSaved: {}", path.display());
                    }
                }
            }
            Err(err) => errors.push(format!("{uri}: {err}")),
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(fail(errors.join("\n"), 2))
    }
}

const USAGE: &str = "\
OID4VC Wallet

A Linux wallet for OpenID4VCI credential offers and OpenID4VP / SIOPv2
presentation requests. Protocol messages are implemented in this program.
It does not use an OpenID library.

The desktop starts the wallet with the URI as its argument. Until then:

  oid4vc-wallet install [--user | --system] [--haip]
      Copy this binary and register it for
      openid-credential-offer://, siopv2:// and openid4vp://.
      --user is the default and writes under your home directory.
      --system writes /usr/share/applications and /etc/xdg/mimeapps.list.
      --haip also registers haip-vci:// and haip-vp://.

  oid4vc-wallet uninstall [--user | --system]
      Remove that registration and the copied binary.

  oid4vc-wallet <uri>
  oid4vc-wallet handle <uri>
      Parse an invocation, print it, and store it in the inbox.
      --json prints one JSON object. --no-save does not write the inbox.

  oid4vc-wallet inbox
      List stored invocations.

iya-sts hands an offer to openid-credential-offer://, a presentation request
to openid4vp://, and an ID Token request to siopv2://. This build parses and
stores those invocations. It does not redeem an offer or send a presentation yet.
";
