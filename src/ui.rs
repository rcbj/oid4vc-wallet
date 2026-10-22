//! The `--ui` window.
//!
//! The same binary serves the command line and this window. The window lists
//! stored credentials and runs the operations the command line runs: add,
//! show, delete, and validate a credential, read and delete an inbox entry,
//! accept an invocation URI, redeem a pre-authorized offer, present a
//! same-device request from the credential list, answer a self-issued ID
//! Token request, show the signer certificate chain carried in a credential,
//! and open Settings for the language, the protocol handlers, trust anchors,
//! the self-issued subject, the storage key, and security-key protection, import
//! and export, and About.

use std::collections::{HashMap, HashSet};
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use eframe::egui;
use oid4vc_wallet::i18n::{self, t, t_args};
use oid4vc_wallet::protocol::offer::{CredentialOffer, OfferPassing};
use oid4vc_wallet::protocol::{ui_locales_of_uri, Invocation, Json};
use oid4vc_wallet::version;
use oid4vc_wallet::wallet::{
    accept, activate_fido, approve_presentation, begin_replace, cancel_replace,
    create_self_issued_credential, delete_anchor, did_web_publication, did_web_url,
    discard_pending, enroll_fido, ensure_self_issued_certificate, export_credentials,
    finish_replace, import_anchors, import_credentials, list_anchors, prepare_presentation,
    presentation_approval_path, presentation_approvals, protection_status, read_subject_setting,
    redeem_pre_authorized, refuse_presentation, remember_presentation, remember_trust,
    self_issued_identifier, signature_algorithm, signer_certificates, subject_setting_path,
    switch_to_keyring, trust_anchors_dir, unlock_fido, unlock_other_fido, validate_stored,
    write_subject_setting, AnchorInfo, Applet, AuthenticatorRef, Credential, CredentialVault,
    Inbox, KeyStoreError, Mechanism, NewCredential, Outcome, PendingPresentation, PortableError,
    Presentation, Presented, ProtectionStatus, Redeemed, SignerCertificate, SubjectSyntax,
};
use zeroize::Zeroize;

use super::single::Incoming;
use super::{install, uninstall, Failure, Options};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Section {
    Credentials,
    Inbox,
    Accept,
    Settings,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SettingsTab {
    Language,
    Registration,
    Trust,
    Security,
    ImportExport,
    About,
}

const ABOUT_PAGES: &[(&str, &str)] = &[
    (
        "wallet.ui.about_docs",
        "https://rcbj.github.io/oid4vc-wallet/",
    ),
    (
        "wallet.ui.about_help",
        "https://github.com/rcbj/oid4vc-wallet/issues",
    ),
    (
        "wallet.ui.about_license",
        "https://github.com/rcbj/oid4vc-wallet/blob/main/LICENSE",
    ),
];

fn about_built() -> String {
    if version::COMMIT.is_empty() {
        t_args("wallet.ui.about_built", &[("time", version::BUILT_AT)])
    } else {
        t_args(
            "wallet.ui.about_built_commit",
            &[("time", version::BUILT_AT), ("commit", version::COMMIT)],
        )
    }
}

/// The radio buttons of Settings → Security → Self-issued ID subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum SubjectChoice {
    Thumbprint,
    DidJwk,
    DidKey,
    DidWeb,
}

impl SubjectChoice {
    fn of(syntax: &SubjectSyntax) -> Self {
        match syntax {
            SubjectSyntax::JwkThumbprint => Self::Thumbprint,
            SubjectSyntax::DidJwk => Self::DidJwk,
            SubjectSyntax::DidKey => Self::DidKey,
            SubjectSyntax::DidWeb(_) => Self::DidWeb,
        }
    }
}

const SUBJECT_CHOICES: &[(SubjectChoice, &str, &str)] = &[
    (
        SubjectChoice::Thumbprint,
        "wallet.ui.subject_thumbprint",
        "wallet.ui.subject_thumbprint_help",
    ),
    (
        SubjectChoice::DidJwk,
        "wallet.ui.subject_did_jwk",
        "wallet.ui.subject_did_jwk_help",
    ),
    (
        SubjectChoice::DidKey,
        "wallet.ui.subject_did_key",
        "wallet.ui.subject_did_key_help",
    ),
    (
        SubjectChoice::DidWeb,
        "wallet.ui.subject_did_web",
        "wallet.ui.subject_did_web_help",
    ),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum AcceptTab {
    Json,
    Fields,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum CertTab {
    Fields,
    Raw,
}

const NAV: &[(Section, &str)] = &[
    (Section::Credentials, "wallet.ui.credentials"),
    (Section::Inbox, "wallet.ui.inbox"),
    (Section::Accept, "wallet.ui.accept"),
    (Section::Settings, "wallet.ui.settings"),
];

enum Tone {
    Ok,
    Warn,
    Err,
}

struct Banner {
    tone: Tone,
    text: String,
}

#[derive(Clone)]
struct InboxRow {
    name: String,
    path: PathBuf,
}

struct AcceptReport {
    text: String,
    error: bool,
}

struct RedeemPrompt {
    offer: CredentialOffer,
    code: String,
}

#[derive(Clone)]
struct TrustPrompt {
    message: String,
    issuer: String,
    fingerprint: String,
}

pub(super) fn run(uris: &[String], no_save: bool) -> Result<(), Failure> {
    let uris: Vec<String> = uris.iter().filter(|uri| !uri.is_empty()).cloned().collect();
    // A socket error must not stop the window. The command line never claims.
    let handoff = match single_claim(&uris) {
        SingleClaim::HandedOff => return Ok(()),
        SingleClaim::Primary(incoming) => Some(incoming),
        SingleClaim::Alone => None,
    };
    let viewport = egui::ViewportBuilder::default()
        .with_title(t("wallet.desktop.name"))
        .with_inner_size([1080.0, 720.0])
        .with_min_inner_size([760.0, 520.0])
        .with_app_id("org.rcbj.oid4vc-wallet")
        .with_icon(window_icon());
    let native = eframe::NativeOptions {
        viewport,
        renderer: eframe::Renderer::Glow,
        persist_window: false,
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "org.rcbj.oid4vc-wallet",
        native,
        Box::new(move |cc| {
            apply_style(&cc.egui_ctx);
            if let Some(incoming) = &handoff {
                let ctx = cc.egui_ctx.clone();
                incoming.set_wake(move || ctx.request_repaint());
            }
            Ok(Box::new(WalletApp::new(&uris, no_save, handoff)))
        }),
    )
    .map_err(|err| {
        super::fail(
            t_args("wallet.ui.open_failed", &[("error", &err.to_string())]),
            1,
        )
    })
}

enum SingleClaim {
    HandedOff,
    Primary(Incoming),
    Alone,
}

/// Claim the UI socket. A failure still opens a window, with no handoff.
fn single_claim(uris: &[String]) -> SingleClaim {
    let Ok(dir) = super::single::runtime_dir() else {
        return SingleClaim::Alone;
    };
    match super::single::claim_ui(&dir, uris) {
        Ok(super::single::Claim::HandedOff) => SingleClaim::HandedOff,
        Ok(super::single::Claim::Primary(incoming)) => SingleClaim::Primary(incoming),
        Err(_) => SingleClaim::Alone,
    }
}

fn apply_style(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::dark();
    visuals.selection.bg_fill = egui::Color32::from_rgb(20, 122, 116);
    visuals.hyperlink_color = egui::Color32::from_rgb(143, 224, 214);
    visuals.widgets.active.bg_fill = egui::Color32::from_rgb(20, 122, 116);
    visuals.widgets.hovered.bg_fill = egui::Color32::from_rgb(28, 78, 76);
    ctx.set_visuals(visuals);
}

fn window_icon() -> egui::IconData {
    let bytes = include_bytes!("../install/org.rcbj.oid4vc-wallet.png");
    match image::load_from_memory(bytes) {
        Ok(image) => {
            let rgba = image.to_rgba8();
            let (width, height) = rgba.dimensions();
            egui::IconData {
                rgba: rgba.into_raw(),
                width,
                height,
            }
        }
        Err(_) => egui::IconData::default(),
    }
}

struct WalletApp {
    section: Section,
    banner: Option<Banner>,
    credentials: Vec<Credential>,
    selected: Option<String>,
    show_json: bool,
    adding: bool,
    confirm: bool,
    inbox_confirm: bool,
    trust: Option<TrustPrompt>,
    add_format: String,
    add_issuer: String,
    add_path: String,
    add_document: String,
    inbox: Vec<InboxRow>,
    inbox_index: Option<usize>,
    inbox_body: String,
    accept_uri: String,
    accept_output: String,
    /// Compact invocation JSON when one URI parsed. Absent when parsing failed.
    accept_parsed: Option<String>,
    accept_tab: AcceptTab,
    redeem: Option<RedeemPrompt>,
    no_save: bool,
    accept_json: bool,
    chosen_tag: String,
    settings_tab: SettingsTab,
    system_scope: bool,
    haip: bool,
    registration_log: String,
    export_path: String,
    /// Credential ids checked on Import and export. This is not the row
    /// selected on the Credentials page.
    export_checked: HashSet<String>,
    /// Shown only after the export file is on disk. This is not the storage key.
    export_key: Option<String>,
    export_count: usize,
    import_path: String,
    import_key: String,
    trust_pem: String,
    trust_path: String,
    trust_anchors: Vec<AnchorInfo>,
    trust_selected: Option<String>,
    /// Bound `ui.sock`, when this process owns the window.
    handoff: Option<Incoming>,
    /// Requests the verifier already answered, keyed by the launch URI.
    answered: HashMap<String, Recall>,
    /// A presentation whose holder key is waiting for approval.
    present_prompt: Option<PresentPrompt>,
    /// Signer certificates of one credential, when that window is open.
    cert_view: Option<CertView>,
    /// The saved self-issued subject.
    subject: SubjectSyntax,
    /// The radio button selected on the Security tab, saved or not.
    subject_choice: SubjectChoice,
    /// The `did:web` typed on the Security tab.
    did_web_input: String,
    /// Desktop key ring or security keys, as the person selected it. This is
    /// not reset on every frame, or enrolling would snap back to the key ring.
    protection_choice: ProtectionChoice,
    /// FIDO2 or PIV for the next enrollment. A pending or enrolled pair
    /// fixes the application, and the file's value wins then.
    applet_choice: Applet,
    fido_pin: String,
    /// Credential reads are waiting for a FIDO2 PIN.
    fido_locked: bool,
    /// Credential id of the authenticator a replacement will remove.
    replacing: Option<String>,
    /// The key being kept has unwrapped the storage key.
    replace_verified: bool,
    protection: Option<ProtectionStatus>,
    /// False until Settings → Security has loaded the protection file.
    protection_loaded: bool,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ProtectionChoice {
    Keyring,
    Fido,
}

#[derive(Clone)]
struct CertView {
    credential_id: String,
    certs: Vec<SignerCertificate>,
    index: usize,
    tab: CertTab,
}

struct PresentPrompt {
    uri: String,
    pending: PendingPresentation,
    remember: bool,
}

#[derive(Clone)]
struct Recall {
    ok: bool,
    message: String,
    redirect: Option<String>,
}

impl WalletApp {
    fn new(uris: &[String], no_save: bool, handoff: Option<Incoming>) -> Self {
        let mut app = Self {
            section: Section::Credentials,
            banner: None,
            credentials: Vec::new(),
            selected: None,
            show_json: false,
            adding: false,
            confirm: false,
            inbox_confirm: false,
            trust: None,
            add_format: String::new(),
            add_issuer: String::new(),
            add_path: String::new(),
            add_document: String::new(),
            inbox: Vec::new(),
            inbox_index: None,
            inbox_body: String::new(),
            accept_uri: String::new(),
            accept_output: String::new(),
            accept_parsed: None,
            accept_tab: AcceptTab::Json,
            redeem: None,
            no_save,
            accept_json: false,
            chosen_tag: i18n::selected_offered().unwrap_or_else(|| "en".to_string()),
            settings_tab: SettingsTab::Language,
            system_scope: false,
            haip: false,
            registration_log: String::new(),
            export_path: String::new(),
            export_checked: HashSet::new(),
            export_key: None,
            export_count: 0,
            import_path: String::new(),
            import_key: String::new(),
            trust_pem: String::new(),
            trust_path: String::new(),
            trust_anchors: Vec::new(),
            trust_selected: None,
            handoff,
            answered: HashMap::new(),
            present_prompt: None,
            cert_view: None,
            subject: SubjectSyntax::JwkThumbprint,
            subject_choice: SubjectChoice::Thumbprint,
            did_web_input: String::new(),
            protection_choice: ProtectionChoice::Keyring,
            applet_choice: Applet::Fido2,
            fido_pin: String::new(),
            fido_locked: false,
            replacing: None,
            replace_verified: false,
            protection: None,
            protection_loaded: false,
        };
        app.reload_subject();
        app.reload_credentials();
        app.reload_inbox();
        app.apply_launch(uris);
        app
    }

    /// Same routing as a fresh launch. A later `--ui` process uses this too.
    fn apply_launch(&mut self, uris: &[String]) {
        self.section = launch_section(uris);
        self.accept_uri = match uris {
            [uri] => uri.clone(),
            _ => String::new(),
        };
        self.accept_parsed = None;
        self.redeem = None;
        if !uris.is_empty() {
            let report = accept_all(uris, self.no_save, false);
            self.accept_output.clone_from(&report.text);
            if report.error {
                self.fail(report.text);
            } else if let [uri] = uris {
                self.accept_parsed = invocation_json(uri);
            }
            self.reload_inbox();
        }
        if let [uri] = uris {
            if let Some(offer) = preauthorized_offer(uri) {
                self.redeem = Some(RedeemPrompt {
                    offer,
                    code: String::new(),
                });
            } else if presentation_launch(uri) {
                self.present_launched(uri);
            }
        }
    }

    fn poll_handoff(&mut self, ctx: &egui::Context) {
        let Some(handoff) = &self.handoff else {
            return;
        };
        let mut batches = Vec::new();
        while let Ok(uris) = handoff.try_recv() {
            batches.push(uris);
        }
        if batches.is_empty() {
            return;
        }
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
            egui::UserAttentionType::Informational,
        ));
        for uris in batches {
            self.reload_credentials();
            self.apply_launch(&uris);
        }
    }

    fn present_launched(&mut self, uri: &str) {
        if let Some(prior) = self.answered.get(uri).cloned() {
            self.show_present(prior.ok, prior.message, prior.redirect.as_deref());
            return;
        }
        if self
            .present_prompt
            .as_ref()
            .is_some_and(|prompt| prompt.uri == uri)
        {
            return;
        }
        if self.present_prompt.is_some() {
            let old = self.present_prompt.take().expect("prompt");
            self.finish_present(old, false);
        }
        // Read the file again: the subject is what Settings saved, and a file
        // that cannot be read is said, not replaced by the default.
        let subject = match subject_setting_path().and_then(|path| read_subject_setting(&path)) {
            Ok(subject) => subject,
            Err(err) => {
                self.fail(err);
                return;
            }
        };
        self.subject = subject.clone();
        match prepare_presentation(uri, &self.credentials, &approved_presentations(), &subject) {
            Presentation::Finished(outcome) => {
                self.settle_present(uri, outcome);
            }
            Presentation::NeedsApproval(pending) => {
                self.present_prompt = Some(PresentPrompt {
                    uri: uri.to_string(),
                    pending: *pending,
                    remember: false,
                });
            }
        }
    }

    fn finish_present(&mut self, prompt: PresentPrompt, allow: bool) {
        let remember = allow && prompt.remember;
        let known = prompt.pending.summary.credential_id.clone();
        let outcome = if allow {
            approve_presentation(prompt.pending, &self.credentials)
        } else {
            refuse_presentation(&prompt.pending)
        };
        let stored = self.settle_present(&prompt.uri, outcome);
        if remember {
            if let Some(id) = known.or(stored) {
                self.remember_presentation_id(&id);
            }
        }
    }

    fn remember_presentation_id(&mut self, id: &str) {
        let path = match presentation_approval_path() {
            Ok(path) => path,
            Err(err) => {
                self.warn(err);
                return;
            }
        };
        if let Err(err) = remember_presentation(&path, id) {
            self.warn(err);
        }
    }

    /// Stores a new self-issued credential when the answer created one.
    /// The id of that credential is returned so a "do not ask again" choice
    /// can be recorded after the id exists.
    fn settle_present(&mut self, uri: &str, outcome: Presented) -> Option<String> {
        let mut stored_id = None;
        if let Some(new) = outcome.store {
            match CredentialVault::open_default().and_then(|vault| vault.put(new)) {
                Ok(stored) => {
                    let id = stored.id.clone();
                    stored_id = Some(id.clone());
                    self.reload_credentials();
                    self.selected = Some(id);
                }
                Err(err) => {
                    self.fail(err.to_string());
                    if let Some(redirect) = outcome.redirect_uri.as_deref() {
                        let _ = open_return(redirect);
                    }
                    return None;
                }
            }
        } else if let Some(id) = outcome.credential_id.clone() {
            self.selected = Some(id);
        }
        if outcome.answered {
            self.answered.insert(
                uri.to_string(),
                Recall {
                    ok: outcome.ok,
                    message: outcome.message.clone(),
                    redirect: outcome.redirect_uri.clone(),
                },
            );
        }
        self.show_present(outcome.ok, outcome.message, outcome.redirect_uri.as_deref());
        stored_id
    }

    fn show_present(&mut self, ok: bool, mut text: String, redirect: Option<&str>) {
        if let Some(redirect) = redirect {
            if let Err(error) = open_return(redirect) {
                text.push(' ');
                text.push_str(&t_args("wallet.present.open_failed", &[("error", &error)]));
                if ok {
                    self.warn(text);
                } else {
                    self.fail(text);
                }
                return;
            }
        }
        if ok {
            self.note(text);
        } else {
            self.fail(text);
        }
    }

    fn note(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            tone: Tone::Ok,
            text: text.into(),
        });
    }

    fn warn(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            tone: Tone::Warn,
            text: text.into(),
        });
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            tone: Tone::Err,
            text: text.into(),
        });
    }

    fn reload_credentials(&mut self) {
        match load_credentials() {
            Ok(credentials) => {
                self.fido_locked = false;
                let credentials = credentials
                    .into_iter()
                    .map(|credential| self.with_signer_certificate(credential))
                    .collect::<Vec<_>>();
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|id| !credentials.iter().any(|credential| &credential.id == id))
                {
                    self.selected = None;
                }
                retain_export_checks(&mut self.export_checked, &credentials);
                self.credentials = credentials;
            }
            Err(err) => {
                self.credentials.clear();
                self.selected = None;
                self.export_checked.clear();
                if err == KeyStoreError::Locked.to_string() {
                    self.fido_locked = true;
                    return;
                }
                self.fido_locked = false;
                self.fail(err);
            }
        }
    }

    fn reload_inbox(&mut self) {
        match load_inbox() {
            Ok(rows) => {
                if self.inbox_index.is_some_and(|index| index >= rows.len()) {
                    self.inbox_index = None;
                    self.inbox_body.clear();
                }
                self.inbox = rows;
                if let Some(index) = self.inbox_index {
                    self.read_inbox(index);
                }
            }
            Err(err) => {
                self.inbox.clear();
                self.inbox_index = None;
                self.inbox_body.clear();
                self.fail(err);
            }
        }
    }

    fn read_inbox(&mut self, index: usize) {
        self.inbox_index = Some(index);
        self.inbox_body = match self.inbox.get(index) {
            Some(row) => fs::read_to_string(&row.path).unwrap_or_else(|err| {
                t_args(
                    "wallet.cli.read_file",
                    &[
                        ("path", &row.path.display().to_string()),
                        ("error", &err.to_string()),
                    ],
                )
            }),
            None => String::new(),
        };
    }

    fn store_credential(&mut self) {
        let outcome = CredentialVault::open_default().and_then(|vault| {
            vault.put(NewCredential {
                format: self.add_format.trim().to_string(),
                issuer: self.add_issuer.trim().to_string(),
                document: self.add_document.clone(),
                holder_key: None,
            })
        });
        match outcome {
            Ok(credential) => {
                let id = credential.id.clone();
                self.note(t_args("wallet.cli.stored", &[("id", &id)]));
                self.adding = false;
                self.add_document.clear();
                self.reload_credentials();
                self.selected = Some(id);
                self.section = Section::Credentials;
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn load_document_file(&mut self) {
        let path = self.add_path.trim().to_string();
        if path.is_empty() || path == "-" {
            self.fail(t("wallet.ui.need_path"));
            return;
        }
        match fs::read_to_string(&path) {
            Ok(text) => {
                self.add_document = text;
                self.note(t_args("wallet.ui.loaded", &[("path", &path)]));
            }
            Err(err) => self.fail(t_args(
                "wallet.cli.read_file",
                &[("path", &path), ("error", &err.to_string())],
            )),
        }
    }

    fn delete_selected(&mut self) {
        let Some(id) = self.selected.clone() else {
            self.confirm = false;
            return;
        };
        let outcome = CredentialVault::open_default().and_then(|vault| vault.delete(&id));
        self.confirm = false;
        match outcome {
            Ok(()) => {
                self.note(t_args("wallet.cli.deleted", &[("id", &id)]));
                self.selected = None;
                self.reload_credentials();
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn accept_pasted(&mut self) {
        let uri = self.accept_uri.trim().to_string();
        if uri.is_empty() {
            self.fail(t("wallet.cli.need_uri"));
            return;
        }
        let report = accept_all(std::slice::from_ref(&uri), self.no_save, self.accept_json);
        self.accept_output.clone_from(&report.text);
        if report.error {
            self.accept_parsed = None;
            self.fail(report.text);
            return;
        }
        self.accept_parsed = invocation_json(&uri);
        self.banner = None;
        self.reload_inbox();
        if let Some(offer) = preauthorized_offer(&uri) {
            self.redeem = Some(RedeemPrompt {
                offer,
                code: String::new(),
            });
        }
    }

    fn redeem_current(&mut self) {
        let Some(prompt) = self.redeem.as_ref() else {
            return;
        };
        let offer = prompt.offer.clone();
        let typed = prompt.code.trim().to_string();
        let tx_code = offer
            .grants
            .pre_authorized_code
            .as_ref()
            .and_then(|grant| grant.tx_code.as_ref())
            .map(|_| typed);
        match redeem_pre_authorized(&offer, tx_code.as_deref()) {
            Ok(redeemed) => self.store_redeemed(redeemed),
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn store_redeemed(&mut self, redeemed: Vec<Redeemed>) {
        let vault = match CredentialVault::open_default() {
            Ok(vault) => vault,
            Err(err) => {
                self.fail(err.to_string());
                return;
            }
        };
        let mut ids = Vec::new();
        for one in redeemed {
            match vault.put(NewCredential {
                format: one.format,
                issuer: one.issuer,
                document: one.document,
                holder_key: Some(one.holder_key),
            }) {
                Ok(stored) => ids.push(stored.id),
                Err(err) => {
                    if !ids.is_empty() {
                        self.reload_credentials();
                        self.selected = ids.first().cloned();
                        self.section = Section::Credentials;
                    }
                    self.fail(err.to_string());
                    return;
                }
            }
        }
        let count = ids.len();
        let first = ids.first().cloned();
        self.redeem = None;
        self.accept_uri.clear();
        self.accept_output.clear();
        self.accept_parsed = None;
        if count == 1 {
            self.note(t_args(
                "wallet.cli.stored",
                &[("id", first.as_deref().unwrap_or(""))],
            ));
        } else {
            self.note(t_args(
                "wallet.redeem.stored",
                &[("count", &count.to_string())],
            ));
        }
        self.reload_credentials();
        self.selected = first;
        self.show_json = false;
        self.section = Section::Credentials;
    }

    fn save_language(&mut self) {
        match i18n::store_tag(&self.chosen_tag) {
            Ok(()) => {
                i18n::set_active(Some(self.chosen_tag.clone()), Vec::new());
                let name = i18n::endonym(&self.chosen_tag);
                self.note(t_args(
                    "wallet.cli.language_set",
                    &[("tag", &self.chosen_tag), ("name", &name)],
                ));
            }
            Err(err) => self.fail(err),
        }
    }

    fn clear_language(&mut self) {
        match i18n::clear_tag() {
            Ok(()) => {
                i18n::set_active(None, i18n::system_tags());
                self.chosen_tag = i18n::selected_offered().unwrap_or_else(|| "en".to_string());
                self.note(t("wallet.cli.language_cleared"));
            }
            Err(err) => self.fail(err),
        }
    }

    fn register(&mut self, install_handlers: bool) {
        let options = registration_options(self.system_scope, self.haip);
        let result = if install_handlers {
            install(&options)
        } else {
            uninstall(&options)
        };
        match result {
            Ok(text) => {
                self.registration_log.clone_from(&text);
                self.note(text);
            }
            Err(err) => {
                self.registration_log.clone_from(&err.message);
                self.fail(err.message);
            }
        }
    }

    fn nav(&mut self, ui: &mut egui::Ui) {
        ui.add_space(8.0);
        ui.heading(t("wallet.desktop.name"));
        ui.add_space(12.0);
        for (section, key) in NAV {
            let selected = self.section == *section;
            if ui.selectable_label(selected, t(key)).clicked() {
                self.section = *section;
                self.banner = None;
            }
        }
    }

    fn main_panel(&mut self, ui: &mut egui::Ui) {
        if let Some(banner) = &self.banner {
            let color = match banner.tone {
                Tone::Ok => egui::Color32::from_rgb(150, 220, 196),
                Tone::Warn => egui::Color32::from_rgb(230, 180, 80),
                Tone::Err => egui::Color32::from_rgb(255, 150, 140),
            };
            ui.colored_label(color, &banner.text);
            ui.separator();
        }
        match self.section {
            Section::Credentials => self.credentials_page(ui),
            Section::Inbox => self.inbox_page(ui),
            Section::Accept => self.accept_page(ui),
            Section::Settings => self.settings_page(ui),
        }
    }

    fn credentials_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(t("wallet.ui.credentials"));
        if self.fido_locked {
            ui.add_space(12.0);
            wrapped(ui, t("wallet.keystore.locked"));
            self.unlock_row(ui);
            return;
        }
        ui.horizontal(|ui| {
            if ui.button(t("wallet.ui.refresh")).clicked() {
                self.reload_credentials();
            }
            if ui.button(t("wallet.ui.add")).clicked() {
                self.adding = true;
            }
            if ui
                .add_enabled(
                    self.selected.is_some(),
                    egui::Button::new(t("wallet.ui.validate")),
                )
                .clicked()
            {
                self.validate_selected();
            }
            if ui
                .add_enabled(
                    self.selected.is_some(),
                    egui::Button::new(t("wallet.ui.delete")),
                )
                .clicked()
            {
                self.confirm = true;
            }
        });
        if self.credentials.is_empty() {
            ui.add_space(12.0);
            ui.label(t("wallet.ui.credentials_empty"));
            return;
        }
        ui.columns(2, |columns| {
            self.credential_list(&mut columns[0]);
            self.credential_detail(&mut columns[1]);
        });
    }

    fn credential_list(&mut self, ui: &mut egui::Ui) {
        let rows: Vec<(String, String, String, String)> = self
            .credentials
            .iter()
            .map(|credential| {
                (
                    credential.id.clone(),
                    credential.issuer.clone(),
                    credential.format.clone(),
                    credential.received_at.clone(),
                )
            })
            .collect();
        egui::ScrollArea::vertical()
            .id_salt("credential-list")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                for (id, issuer, format, received) in rows {
                    let selected = self.selected.as_deref() == Some(id.as_str());
                    let label = format!("{issuer}\n{received}    {format}\n{id}");
                    if ui.selectable_label(selected, label).clicked() {
                        self.selected = Some(id);
                    }
                }
            });
    }

    fn credential_detail(&mut self, ui: &mut egui::Ui) {
        let Some(credential) = self
            .credentials
            .iter()
            .find(|credential| self.selected.as_deref() == Some(credential.id.as_str()))
            .cloned()
        else {
            ui.label(t("wallet.ui.detail_empty"));
            return;
        };
        detail_lines(
            ui,
            &[
                t_args("wallet.cli.id", &[("id", &credential.id)]),
                t_args("wallet.cli.format", &[("format", &credential.format)]),
                t_args("wallet.cli.issuer", &[("issuer", &credential.issuer)]),
                t_args(
                    "wallet.cli.algorithm",
                    &[("algorithm", &algorithm_name(&credential))],
                ),
                t_args("wallet.cli.received", &[("time", &credential.received_at)]),
                t("wallet.ui.document"),
            ],
        );
        let id = credential.id.clone();
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_json, t("wallet.ui.json"));
            if ui.button(t("wallet.ui.copy")).clicked() {
                ui.ctx().copy_text(id.clone());
                self.note(t_args("wallet.ui.copied", &[("id", &id)]));
            }
        });
        if ui.button(t("wallet.ui.cert_chain")).clicked() {
            self.open_cert_chain(&credential);
        }
        let mut body = if self.show_json {
            credential.to_json().to_string()
        } else {
            credential.document
        };
        egui::ScrollArea::vertical()
            .id_salt("credential-document")
            .auto_shrink([false, false])
            .show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut body)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(16)
                        .interactive(false),
                );
            });
    }

    fn inbox_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(t("wallet.ui.inbox"));
        ui.horizontal(|ui| {
            if ui.button(t("wallet.ui.refresh")).clicked() {
                self.reload_inbox();
            }
            if ui
                .add_enabled(
                    self.inbox_index.is_some(),
                    egui::Button::new(t("wallet.ui.delete")),
                )
                .clicked()
            {
                self.inbox_confirm = true;
            }
        });
        if self.inbox.is_empty() {
            ui.add_space(12.0);
            ui.label(t("wallet.ui.inbox_empty"));
            return;
        }
        let names: Vec<(usize, String)> = self
            .inbox
            .iter()
            .enumerate()
            .map(|(index, row)| (index, row.name.clone()))
            .collect();
        ui.columns(2, |columns| {
            egui::ScrollArea::vertical()
                .id_salt("inbox-list")
                .auto_shrink([false, false])
                .show(&mut columns[0], |ui| {
                    for (index, name) in names {
                        let selected = self.inbox_index == Some(index);
                        if ui.selectable_label(selected, name).clicked() {
                            self.read_inbox(index);
                        }
                    }
                });
            if self.inbox_body.is_empty() {
                columns[1].label(t("wallet.ui.select_inbox"));
            } else {
                let mut body = self.inbox_body.clone();
                egui::ScrollArea::vertical()
                    .id_salt("inbox-body")
                    .auto_shrink([false, false])
                    .show(&mut columns[1], |ui| {
                        ui.add(
                            egui::TextEdit::multiline(&mut body)
                                .font(egui::TextStyle::Monospace)
                                .desired_width(f32::INFINITY)
                                .desired_rows(18)
                                .interactive(false),
                        );
                    });
            }
        });
    }

    fn accept_page(&mut self, ui: &mut egui::Ui) {
        if self.redeem.is_some() {
            self.redeem_page(ui);
            return;
        }
        ui.heading(t("wallet.ui.accept"));
        ui.label(t("wallet.ui.uri_help"));
        ui.add_space(6.0);
        ui.label(t("wallet.ui.uri"));
        ui.add(
            egui::TextEdit::multiline(&mut self.accept_uri)
                .hint_text("openid-credential-offer://")
                .desired_width(f32::INFINITY)
                .desired_rows(4)
                .font(egui::TextStyle::Monospace),
        );
        ui.checkbox(&mut self.no_save, t("wallet.ui.no_save"));
        ui.checkbox(&mut self.accept_json, t("wallet.ui.json"));
        if ui
            .add_enabled(
                !self.accept_uri.trim().is_empty(),
                egui::Button::new(t("wallet.ui.accept")),
            )
            .clicked()
        {
            self.accept_pasted();
        }
        if self.accept_output.is_empty() {
            return;
        }
        ui.add_space(8.0);
        let tabs = self.accept_parsed.is_some();
        let mut output = self.accept_output.clone();
        let mut summary = egui::ScrollArea::vertical()
            .id_salt("accept-output")
            .auto_shrink([false, !tabs]);
        if tabs {
            summary = summary.max_height(180.0);
        }
        summary.show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut output)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(if tabs { 6 } else { 12 })
                    .interactive(false),
            );
        });
        if tabs {
            self.accept_invocation_tabs(ui);
        }
    }

    fn accept_invocation_tabs(&mut self, ui: &mut egui::Ui) {
        let Some(raw) = self.accept_parsed.clone() else {
            return;
        };
        let Ok(value) = Json::parse(&raw) else {
            return;
        };
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.accept_tab,
                AcceptTab::Json,
                t("wallet.ui.accept_json"),
            );
            ui.selectable_value(
                &mut self.accept_tab,
                AcceptTab::Fields,
                t("wallet.ui.accept_fields"),
            );
        });
        ui.separator();
        match self.accept_tab {
            AcceptTab::Json => accept_json_tab(ui, &value),
            AcceptTab::Fields => accept_fields_tab(ui, &value),
        }
    }

    fn redeem_page(&mut self, ui: &mut egui::Ui) {
        let (issuer, configurations, description, needs_code) = match &self.redeem {
            Some(prompt) => {
                let tx = prompt
                    .offer
                    .grants
                    .pre_authorized_code
                    .as_ref()
                    .and_then(|grant| grant.tx_code.as_ref());
                (
                    prompt.offer.credential_issuer.clone(),
                    prompt.offer.credential_configuration_ids.join(", "),
                    tx.and_then(|tx| tx.description.clone())
                        .filter(|text| !text.is_empty()),
                    tx.is_some(),
                )
            }
            None => return,
        };
        ui.heading(t("wallet.ui.redeem"));
        ui.label(t("wallet.ui.tx_help"));
        ui.add_space(8.0);
        ui.label(t_args("wallet.summary.issuer", &[("issuer", &issuer)]));
        ui.label(t_args(
            "wallet.summary.configurations",
            &[("list", &configurations)],
        ));
        if let Some(description) = &description {
            ui.label(t_args(
                "wallet.summary.tx_prompt",
                &[("description", description)],
            ));
        }
        if needs_code {
            ui.add_space(8.0);
            ui.label(t("wallet.ui.tx_code"));
            if let Some(prompt) = &mut self.redeem {
                ui.add(egui::TextEdit::singleline(&mut prompt.code).desired_width(220.0));
            }
        }
        let ready = !needs_code
            || self
                .redeem
                .as_ref()
                .is_some_and(|prompt| !prompt.code.trim().is_empty());
        ui.add_space(8.0);
        let mut redeem = false;
        let mut other = false;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(ready, egui::Button::new(t("wallet.ui.redeem")))
                .clicked()
            {
                redeem = true;
            }
            if ui.button(t("wallet.ui.other_invocation")).clicked() {
                other = true;
            }
        });
        if other {
            self.redeem = None;
        } else if redeem {
            self.redeem_current();
        }
    }

    fn settings_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(t("wallet.ui.settings"));
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.selectable_value(
                &mut self.settings_tab,
                SettingsTab::Language,
                t("wallet.ui.language"),
            );
            ui.selectable_value(
                &mut self.settings_tab,
                SettingsTab::Registration,
                t("wallet.ui.registration"),
            );
            if ui
                .selectable_value(
                    &mut self.settings_tab,
                    SettingsTab::Trust,
                    t("wallet.ui.trust_anchors"),
                )
                .clicked()
            {
                self.reload_anchors();
            }
            if ui
                .selectable_value(
                    &mut self.settings_tab,
                    SettingsTab::Security,
                    t("wallet.ui.security"),
                )
                .clicked()
            {
                self.reload_protection(true);
            }
            if ui
                .selectable_value(
                    &mut self.settings_tab,
                    SettingsTab::ImportExport,
                    t("wallet.ui.import_export"),
                )
                .clicked()
            {
                self.reload_credentials();
            }
            ui.selectable_value(
                &mut self.settings_tab,
                SettingsTab::About,
                t("wallet.ui.about"),
            );
        });
        ui.separator();
        match self.settings_tab {
            SettingsTab::Language => self.language_tab(ui),
            SettingsTab::Registration => self.registration_tab(ui),
            SettingsTab::Trust => self.trust_tab(ui),
            SettingsTab::Security => self.security_tab(ui),
            SettingsTab::ImportExport => self.import_export_tab(ui),
            SettingsTab::About => self.about_tab(ui),
        }
    }

    fn about_tab(&mut self, ui: &mut egui::Ui) {
        ui.label(t_args(
            "wallet.ui.about_version",
            &[("version", version::VERSION)],
        ))
        .on_hover_text(about_built());
        ui.add_space(8.0);
        ui.label(t("wallet.ui.about_copyright"));
        ui.add_space(8.0);
        ui.label(t("wallet.ui.about_license_note"));
        ui.add_space(8.0);
        for (key, url) in ABOUT_PAGES {
            self.about_link(ui, key, url);
        }
    }

    fn about_link(&mut self, ui: &mut egui::Ui, key: &str, url: &str) {
        ui.add_space(6.0);
        if ui.link(t(key)).clicked() {
            self.open_about(url);
        }
        if ui
            .link(egui::RichText::new(url).small().monospace())
            .clicked()
        {
            self.open_about(url);
        }
    }

    fn open_about(&mut self, url: &str) {
        if !crate::browser::https_page(url) {
            self.fail(t("wallet.ui.about_refused"));
            return;
        }
        if let Err(err) = crate::browser::open_https(url) {
            self.fail(t_args("wallet.ui.about_open_failed", &[("error", &err)]));
        }
    }

    fn language_tab(&mut self, ui: &mut egui::Ui) {
        ui.label(t("wallet.ui.language_help"));
        ui.add_space(8.0);
        let offered = i18n::offered();
        egui::ScrollArea::vertical()
            .id_salt("language-list")
            .show(ui, |ui| {
                for offered in &offered {
                    let label = format!("{}    {}", offered.tag, offered.name);
                    ui.radio_value(&mut self.chosen_tag, offered.tag.clone(), label);
                }
            });
        ui.horizontal(|ui| {
            if ui.button(t("wallet.ui.save_language")).clicked() {
                self.save_language();
            }
            if ui.button(t("wallet.ui.clear_language")).clicked() {
                self.clear_language();
            }
        });
    }

    fn registration_tab(&mut self, ui: &mut egui::Ui) {
        ui.label(t("wallet.ui.registration_help"));
        ui.add_space(8.0);
        ui.radio_value(&mut self.system_scope, false, t("wallet.ui.scope_user"));
        ui.radio_value(&mut self.system_scope, true, t("wallet.ui.scope_system"));
        ui.checkbox(&mut self.haip, t("wallet.ui.haip"));
        ui.horizontal(|ui| {
            if ui.button(t("wallet.ui.install")).clicked() {
                self.register(true);
            }
            if ui.button(t("wallet.ui.uninstall")).clicked() {
                self.register(false);
            }
        });
        if !self.registration_log.is_empty() {
            ui.add_space(8.0);
            let mut log = self.registration_log.clone();
            ui.add(
                egui::TextEdit::multiline(&mut log)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(10)
                    .interactive(false),
            );
        }
    }

    fn security_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("security-tab")
            .show(ui, |ui| {
                self.subject_section(ui);
                ui.separator();
                self.storage_key_section(ui);
                self.fido_section(ui);
            });
    }

    fn reload_subject(&mut self) {
        match subject_setting_path().and_then(|path| read_subject_setting(&path)) {
            Ok(subject) => {
                self.subject_choice = SubjectChoice::of(&subject);
                if let SubjectSyntax::DidWeb(did) = &subject {
                    self.did_web_input = did.clone();
                }
                self.subject = subject;
            }
            Err(err) => self.warn(err),
        }
    }

    fn subject_section(&mut self, ui: &mut egui::Ui) {
        ui.strong(t("wallet.ui.subject_title"));
        wrapped(ui, t("wallet.ui.subject_help"));
        ui.add_space(6.0);
        for (choice, label, help) in SUBJECT_CHOICES {
            ui.radio_value(&mut self.subject_choice, *choice, t(label));
            ui.indent(label, |ui| {
                ui.add(egui::Label::new(egui::RichText::new(t(help)).small()).wrap());
            });
            if *choice == SubjectChoice::DidWeb && self.subject_choice == SubjectChoice::DidWeb {
                ui.indent("did-web-input", |ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.did_web_input)
                            .font(egui::TextStyle::Monospace)
                            .hint_text("did:web:example.com")
                            .desired_width(f32::INFINITY),
                    );
                });
            }
        }
        ui.add_space(6.0);
        if ui.button(t("wallet.ui.subject_save")).clicked() {
            self.save_subject();
        }
        ui.add_space(6.0);
        match self_issued_identifier(&self.credentials, &self.subject) {
            Some(identifier) => {
                ui.label(t("wallet.ui.subject_current"));
                let mut shown = identifier;
                ui.add(
                    egui::TextEdit::multiline(&mut shown)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(2)
                        .interactive(false),
                );
            }
            None => wrapped(ui, t("wallet.ui.subject_no_key")),
        }
        if let SubjectSyntax::DidWeb(did) = self.subject.clone() {
            self.did_web_section(ui, &did);
        }
    }

    fn did_web_section(&mut self, ui: &mut egui::Ui, did: &str) {
        let Some(publication) = did_web_publication(&self.credentials, did) else {
            return;
        };
        ui.add_space(6.0);
        wrapped(
            ui,
            t_args("wallet.ui.did_web_publish", &[("url", &publication.url)]),
        );
        let mut document = pretty_json(&publication.document);
        let copy = ui.button(t("wallet.ui.did_web_copy")).clicked();
        ui.add(
            egui::TextEdit::multiline(&mut document)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(12)
                .interactive(false),
        );
        if copy {
            ui.ctx().copy_text(document);
            self.note(t("wallet.ui.did_web_copied"));
        }
    }

    /// The choice on the tab, as a setting. A malformed `did:web` is refused.
    fn chosen_subject(&self) -> Result<SubjectSyntax, String> {
        Ok(match self.subject_choice {
            SubjectChoice::Thumbprint => SubjectSyntax::JwkThumbprint,
            SubjectChoice::DidJwk => SubjectSyntax::DidJwk,
            SubjectChoice::DidKey => SubjectSyntax::DidKey,
            SubjectChoice::DidWeb => {
                let did = self.did_web_input.trim();
                if did_web_url(did).is_none() {
                    return Err(t_args("wallet.subject.did_web_invalid", &[("did", did)]));
                }
                SubjectSyntax::DidWeb(did.to_string())
            }
        })
    }

    fn save_subject(&mut self) {
        let chosen = match self.chosen_subject() {
            Ok(chosen) => chosen,
            Err(err) => {
                self.fail(err);
                return;
            }
        };
        // A did:web document names a key, so the key has to exist before the
        // document can be published. Create it now rather than at the first
        // sign-in, which would sign with a key the document does not name.
        let mut created = None;
        if matches!(chosen, SubjectSyntax::DidWeb(_))
            && self_issued_identifier(&self.credentials, &chosen).is_none()
        {
            let Some(new) = create_self_issued_credential() else {
                self.fail(t("wallet.present.unsupported"));
                return;
            };
            match CredentialVault::open_default().and_then(|vault| vault.put(new)) {
                Ok(stored) => {
                    created = Some(stored.id);
                    self.reload_credentials();
                }
                Err(err) => {
                    self.fail(err.to_string());
                    return;
                }
            }
        }
        let saved = subject_setting_path().and_then(|path| write_subject_setting(&path, &chosen));
        if let Err(err) = saved {
            self.fail(err);
            return;
        }
        let changed = chosen != self.subject;
        self.subject = chosen;
        let mut text = t("wallet.ui.subject_saved");
        if let Some(id) = created {
            text.push(' ');
            text.push_str(&t_args("wallet.ui.subject_key_created", &[("id", &id)]));
        }
        if changed {
            text.push(' ');
            text.push_str(&t("wallet.ui.subject_enrol_again"));
        }
        self.note(text);
    }

    fn storage_key_section(&mut self, ui: &mut egui::Ui) {
        ui.strong(t("wallet.ui.storage_key_title"));
        ui.label(t("wallet.ui.rotate_help"));
        ui.add_space(8.0);
        if ui.button(t("wallet.ui.rotate_key")).clicked() {
            self.rotate_storage_key();
        }
    }

    fn reload_protection(&mut self, reset_choice: bool) {
        match protection_status() {
            Ok(status) => {
                if reset_choice || !self.protection_loaded {
                    self.protection_choice = match status.mechanism {
                        Mechanism::Fido => ProtectionChoice::Fido,
                        Mechanism::Keyring => ProtectionChoice::Keyring,
                    };
                    self.applet_choice = status.applet;
                }
                self.fido_locked = status.mechanism == Mechanism::Fido && !status.unlocked;
                self.protection = Some(status);
                self.protection_loaded = true;
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn fido_section(&mut self, ui: &mut egui::Ui) {
        ui.add_space(16.0);
        ui.separator();
        ui.strong(t("wallet.ui.fido_title"));
        wrapped(ui, t("wallet.ui.fido_help"));
        wrapped(ui, t("wallet.ui.fido_touch"));
        ui.add_space(6.0);
        ui.label(t("wallet.ui.fido_choice"));
        ui.radio_value(
            &mut self.protection_choice,
            ProtectionChoice::Keyring,
            t("wallet.ui.fido_keyring"),
        );
        ui.radio_value(
            &mut self.protection_choice,
            ProtectionChoice::Fido,
            t("wallet.ui.fido_title"),
        );
        let Some(status) = self.protection.clone() else {
            return;
        };
        ui.add_space(8.0);
        match (status.mechanism, self.protection_choice) {
            (Mechanism::Keyring, ProtectionChoice::Keyring) => self.keyring_home(ui, &status),
            (Mechanism::Keyring, ProtectionChoice::Fido) => self.enroll_panel(ui, &status),
            (Mechanism::Fido, ProtectionChoice::Fido) => self.fido_active_panel(ui, &status),
            (Mechanism::Fido, ProtectionChoice::Keyring) => self.move_back_panel(ui),
        }
    }

    fn keyring_home(&mut self, ui: &mut egui::Ui, status: &ProtectionStatus) {
        ui.label(t("wallet.ui.fido_status_keyring"));
        wrapped(ui, t("wallet.ui.fido_keyring_help"));
        if !status.pending.is_empty() {
            self.pending_actions(ui, status, false);
        }
    }

    fn enroll_panel(&mut self, ui: &mut egui::Ui, status: &ProtectionStatus) {
        ui.label(t("wallet.ui.fido_applet"));
        wrapped(ui, t("wallet.ui.fido_applet_help"));
        if status.pending.is_empty() {
            ui.radio_value(
                &mut self.applet_choice,
                Applet::Fido2,
                t("wallet.ui.fido_applet_fido2"),
            );
            ui.radio_value(
                &mut self.applet_choice,
                Applet::Piv,
                t("wallet.ui.fido_applet_piv"),
            );
        } else {
            applet_line(ui, status.applet);
        }
        ui.add_space(6.0);
        if self.active_applet() == Applet::Piv {
            wrapped(ui, t("wallet.ui.fido_piv_steps"));
        } else {
            wrapped(ui, t("wallet.ui.fido_step1"));
            wrapped(ui, t("wallet.ui.fido_step2"));
        }
        self.pending_actions(ui, status, true);
    }

    /// The application the PIN field and enroll speak to. Once a key is
    /// pending or enrolled, that is the file's; before, the radio's.
    fn active_applet(&self) -> Applet {
        match &self.protection {
            Some(status) if status.mechanism == Mechanism::Fido || !status.pending.is_empty() => {
                status.applet
            }
            _ => self.applet_choice,
        }
    }

    fn pending_actions(&mut self, ui: &mut egui::Ui, status: &ProtectionStatus, enroll: bool) {
        if !status.pending.is_empty() {
            ui.label(t_args(
                "wallet.ui.fido_status_pending",
                &[("labels", &label_list(&status.pending))],
            ));
        }
        if enroll {
            self.pin_field(ui);
        }
        let mut do_enroll = false;
        let mut do_discard = false;
        let mut do_activate = false;
        ui.horizontal(|ui| {
            if enroll && ui.button(t("wallet.ui.fido_enroll")).clicked() {
                do_enroll = true;
            }
            if !status.pending.is_empty() && ui.button(t("wallet.ui.fido_discard")).clicked() {
                do_discard = true;
            }
            if status.pending.len() == 2 && ui.button(t("wallet.ui.fido_activate")).clicked() {
                do_activate = true;
            }
        });
        if do_enroll {
            self.enroll_clicked();
        } else if do_discard {
            self.discard_clicked();
        } else if do_activate {
            self.activate_clicked();
        }
    }

    fn fido_active_panel(&mut self, ui: &mut egui::Ui, status: &ProtectionStatus) {
        ui.label(t("wallet.ui.fido_status_fido"));
        applet_line(ui, status.applet);
        for item in &status.enrolled {
            ui.label(t_args("wallet.ui.fido_label", &[("label", &item.label)]));
        }
        if status.keyring_pending_removal {
            wrapped(ui, t("wallet.ui.fido_keyring_copy"));
        }
        if !status.unlocked {
            ui.add_space(8.0);
            self.unlock_row(ui);
        } else if status.other_needed && self.replacing.is_none() {
            ui.add_space(8.0);
            wrapped(ui, t("wallet.ui.fido_other_help"));
            self.pin_field(ui);
            if ui.button(t("wallet.ui.fido_other")).clicked() {
                self.unlock_other_clicked();
            }
        }
        ui.add_space(8.0);
        self.replace_block(ui, status);
    }

    fn replace_block(&mut self, ui: &mut egui::Ui, status: &ProtectionStatus) {
        let Some(remove) = self.replacing.clone() else {
            let mut picked = None;
            for item in &status.enrolled {
                ui.horizontal(|ui| {
                    if ui.button(t("wallet.ui.fido_replace")).clicked() {
                        picked = Some(item.id.clone());
                    }
                    ui.label(t_args("wallet.ui.fido_label", &[("label", &item.label)]));
                });
            }
            if let Some(id) = picked {
                self.replacing = Some(id);
                self.replace_verified = false;
                self.wipe_pin_field();
            }
            return;
        };
        let keep = status
            .enrolled
            .iter()
            .find(|item| item.id != remove)
            .map_or_else(|| remove.clone(), |item| item.label.clone());
        wrapped(
            ui,
            t_args("wallet.ui.fido_replace_help", &[("keep", &keep)]),
        );
        if self.replace_verified {
            wrapped(ui, t("wallet.fido.insert_new"));
        }
        self.pin_field(ui);
        let mut verify = false;
        let mut finish = false;
        let mut cancel = false;
        ui.horizontal(|ui| {
            if !self.replace_verified && ui.button(t("wallet.ui.fido_verify_keep")).clicked() {
                verify = true;
            }
            if self.replace_verified && ui.button(t("wallet.ui.fido_finish_replace")).clicked() {
                finish = true;
            }
            if ui.button(t("wallet.ui.fido_cancel_replace")).clicked() {
                cancel = true;
            }
        });
        if verify {
            self.verify_keep_clicked();
        } else if finish {
            self.finish_replace_clicked();
        } else if cancel {
            self.cancel_replace_clicked();
        }
    }

    fn move_back_panel(&mut self, ui: &mut egui::Ui) {
        wrapped(ui, t("wallet.ui.fido_to_keyring_help"));
        self.pin_field(ui);
        if ui.button(t("wallet.ui.fido_to_keyring")).clicked() {
            self.switch_clicked();
        }
    }

    fn unlock_row(&mut self, ui: &mut egui::Ui) {
        self.pin_field(ui);
        if ui.button(t("wallet.ui.fido_unlock")).clicked() {
            self.unlock_clicked();
        }
    }

    fn pin_field(&mut self, ui: &mut egui::Ui) {
        ui.label(match self.active_applet() {
            Applet::Fido2 => t("wallet.ui.fido_pin"),
            Applet::Piv => t("wallet.ui.fido_pin_piv"),
        });
        ui.add(
            egui::TextEdit::singleline(&mut self.fido_pin)
                .password(true)
                .desired_width(220.0),
        );
    }

    fn wipe_pin_field(&mut self) {
        self.fido_pin.zeroize();
        self.fido_pin.clear();
    }

    fn take_pin(&mut self) -> String {
        std::mem::take(&mut self.fido_pin)
    }

    fn enroll_clicked(&mut self) {
        let mut pin = self.take_pin();
        let result = enroll_fido(&pin, self.active_applet());
        pin.zeroize();
        match result {
            Ok(label) => {
                self.reload_protection(false);
                self.note(t_args("wallet.fido.enrolled", &[("label", &label)]));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn discard_clicked(&mut self) {
        match discard_pending() {
            Ok(()) => {
                self.wipe_pin_field();
                self.reload_protection(false);
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn activate_clicked(&mut self) {
        match activate_fido() {
            Ok(()) => {
                self.replacing = None;
                self.replace_verified = false;
                self.wipe_pin_field();
                self.reload_protection(true);
                self.reload_credentials();
                self.note(t("wallet.fido.activated"));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn unlock_clicked(&mut self) {
        let mut pin = self.take_pin();
        let result = unlock_fido(&pin);
        pin.zeroize();
        match result {
            Ok(()) => {
                self.reload_protection(false);
                self.reload_credentials();
                self.note(t("wallet.fido.unlocked"));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn unlock_other_clicked(&mut self) {
        let mut pin = self.take_pin();
        let result = unlock_other_fido(&pin);
        pin.zeroize();
        match result {
            Ok(()) => {
                self.reload_protection(false);
                self.note(t("wallet.fido.unlocked"));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn verify_keep_clicked(&mut self) {
        let Some(remove) = self.replacing.clone() else {
            return;
        };
        let mut pin = self.take_pin();
        let result = begin_replace(&remove, &pin);
        pin.zeroize();
        match result {
            Ok(()) => {
                self.replace_verified = true;
                self.wipe_pin_field();
                self.reload_protection(false);
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn finish_replace_clicked(&mut self) {
        let Some(remove) = self.replacing.clone() else {
            return;
        };
        let old = self
            .protection
            .as_ref()
            .and_then(|status| status.enrolled.iter().find(|item| item.id == remove))
            .map_or_else(|| remove.clone(), |item| item.label.clone());
        let mut pin = self.take_pin();
        let result = finish_replace(&remove, &pin);
        pin.zeroize();
        match result {
            Ok(new_label) => {
                self.replacing = None;
                self.replace_verified = false;
                self.reload_protection(false);
                self.note(t_args(
                    "wallet.fido.replaced",
                    &[("old", &old), ("new", &new_label)],
                ));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn cancel_replace_clicked(&mut self) {
        match cancel_replace() {
            Ok(()) => {
                self.replacing = None;
                self.replace_verified = false;
                self.wipe_pin_field();
                self.reload_protection(false);
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn switch_clicked(&mut self) {
        let mut pin = self.take_pin();
        let result = switch_to_keyring(&pin);
        pin.zeroize();
        match result {
            Ok(()) => {
                self.replacing = None;
                self.replace_verified = false;
                self.reload_protection(true);
                self.reload_credentials();
                self.note(t("wallet.fido.now_keyring"));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn rotate_storage_key(&mut self) {
        let outcome = CredentialVault::open_default().and_then(|vault| vault.rotate());
        match outcome {
            Ok(report) => {
                self.reload_credentials();
                self.note(t_args(
                    "wallet.rotate.done",
                    &[("count", &report.count.to_string())],
                ));
            }
            Err(err) => self.fail(t_args(
                "wallet.rotate.failed",
                &[("error", &err.to_string())],
            )),
        }
    }

    fn trust_tab(&mut self, ui: &mut egui::Ui) {
        ui.label(t("wallet.ui.trust_help"));
        ui.add_space(8.0);
        ui.label(t("wallet.ui.trust_pem"));
        ui.add(
            egui::TextEdit::multiline(&mut self.trust_pem)
                .font(egui::TextStyle::Monospace)
                .desired_width(f32::INFINITY)
                .desired_rows(8),
        );
        ui.label(t("wallet.ui.trust_path"));
        ui.horizontal(|ui| {
            ui.add(egui::TextEdit::singleline(&mut self.trust_path).desired_width(360.0));
            if ui.button(t("wallet.ui.trust_load")).clicked() {
                self.load_anchor_file();
            }
        });
        if ui.button(t("wallet.ui.trust_save")).clicked() {
            self.save_anchors();
        }
        ui.add_space(8.0);
        let rows: Vec<(String, String)> = self
            .trust_anchors
            .iter()
            .map(|anchor| (anchor.name.clone(), anchor.fingerprint.clone()))
            .collect();
        egui::ScrollArea::vertical()
            .id_salt("trust-anchors")
            .max_height(220.0)
            .show(ui, |ui| {
                for (name, fingerprint) in rows {
                    let selected = self.trust_selected.as_deref() == Some(fingerprint.as_str());
                    let label = format!("{name}\n{fingerprint}");
                    if ui.selectable_label(selected, label).clicked() {
                        self.trust_selected = Some(fingerprint);
                    }
                }
            });
        if ui
            .add_enabled(
                self.trust_selected.is_some(),
                egui::Button::new(t("wallet.ui.trust_remove")),
            )
            .clicked()
        {
            self.remove_anchor();
        }
    }

    fn reload_anchors(&mut self) {
        let Ok(dir) = trust_anchors_dir() else {
            self.trust_anchors.clear();
            return;
        };
        self.trust_anchors = list_anchors(&dir);
        if self.trust_selected.as_ref().is_some_and(|id| {
            !self
                .trust_anchors
                .iter()
                .any(|anchor| &anchor.fingerprint == id)
        }) {
            self.trust_selected = None;
        }
    }

    fn load_anchor_file(&mut self) {
        let path = self.trust_path.trim().to_string();
        if path.is_empty() {
            self.save_anchors();
            return;
        }
        match fs::read_to_string(&path) {
            Ok(text) => {
                self.trust_pem = text;
                self.save_anchors();
            }
            Err(err) => self.fail(t_args(
                "wallet.cli.read_file",
                &[("path", &path), ("error", &err.to_string())],
            )),
        }
    }

    fn save_anchors(&mut self) {
        let dir = match trust_anchors_dir() {
            Ok(dir) => dir,
            Err(err) => {
                self.fail(err);
                return;
            }
        };
        match import_anchors(&dir, &self.trust_pem) {
            Ok(count) => {
                self.reload_anchors();
                self.note(t_args(
                    "wallet.anchor.saved",
                    &[("count", &count.to_string())],
                ));
            }
            Err(err) => self.fail(err),
        }
    }

    fn remove_anchor(&mut self) {
        let Some(fingerprint) = self.trust_selected.clone() else {
            return;
        };
        let dir = match trust_anchors_dir() {
            Ok(dir) => dir,
            Err(err) => {
                self.fail(err);
                return;
            }
        };
        match delete_anchor(&dir, &fingerprint) {
            Ok(()) => self.reload_anchors(),
            Err(err) => self.fail(err),
        }
    }

    fn import_export_tab(&mut self, ui: &mut egui::Ui) {
        egui::ScrollArea::vertical()
            .id_salt("import-export")
            .auto_shrink([false, false])
            .show(ui, |ui| self.import_export_body(ui));
    }

    fn import_export_body(&mut self, ui: &mut egui::Ui) {
        ui.label(t("wallet.ui.import_export_help"));
        ui.add_space(8.0);
        ui.colored_label(
            egui::Color32::from_rgb(230, 180, 80),
            t("wallet.export.warning"),
        );
        ui.add_space(8.0);
        self.export_key_field(ui);
        ui.add_space(8.0);
        self.export_credential_list(ui);
        ui.label(t("wallet.ui.import_path"));
        if ui.button(t("wallet.ui.choose_file")).clicked() {
            self.choose_export_file();
        }
        ui.label(chosen_file_label(&self.export_path));
        let path_ready = !self.export_path.trim().is_empty();
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    path_ready && !self.export_checked.is_empty(),
                    egui::Button::new(t("wallet.ui.export")),
                )
                .clicked()
            {
                self.confirm_export(false);
            }
            if ui
                .add_enabled(
                    path_ready && !self.credentials.is_empty(),
                    egui::Button::new(t("wallet.ui.export_all")),
                )
                .clicked()
            {
                self.confirm_export(true);
            }
        });
        ui.add_space(12.0);
        ui.separator();
        ui.label(t("wallet.ui.import_file"));
        if ui.button(t("wallet.ui.choose_file")).clicked() {
            self.choose_import_file();
        }
        ui.label(chosen_file_label(&self.import_path));
        ui.label(t("wallet.ui.import_key"));
        ui.add(
            egui::TextEdit::singleline(&mut self.import_key)
                .desired_width(f32::INFINITY)
                .font(egui::TextStyle::Monospace),
        );
        ui.add_space(8.0);
        let ready = !self.import_path.trim().is_empty() && !self.import_key.trim().is_empty();
        if ui
            .add_enabled(ready, egui::Button::new(t("wallet.ui.import")))
            .clicked()
        {
            self.confirm_import();
        }
    }

    /// Stored credentials in a fixed window, with a checkbox on each row.
    ///
    /// The window keeps [`EXPORT_LIST_HEIGHT`] so a long list scrolls here
    /// instead of lengthening the tab. Checking a row does not change the
    /// credential selected on the Credentials page.
    fn export_credential_list(&mut self, ui: &mut egui::Ui) {
        let rows: Vec<(String, String, String)> = self
            .credentials
            .iter()
            .map(|credential| {
                (
                    credential.id.clone(),
                    credential.issuer.clone(),
                    credential.format.clone(),
                )
            })
            .collect();
        let mut changes = Vec::new();
        egui::Frame::group(ui.style()).show(ui, |ui| {
            let width = ui.available_width();
            ui.allocate_ui_with_layout(
                egui::vec2(width, EXPORT_LIST_HEIGHT),
                egui::Layout::top_down(egui::Align::Min),
                |ui| {
                    egui::ScrollArea::vertical()
                        .id_salt("export-credentials")
                        .auto_shrink([false, false])
                        .max_height(EXPORT_LIST_HEIGHT)
                        .show(ui, |ui| {
                            if rows.is_empty() {
                                ui.label(t("wallet.ui.credentials_empty"));
                                return;
                            }
                            for (id, issuer, format) in &rows {
                                let mut on = self.export_checked.contains(id);
                                let label = format!("{issuer}    {format}\n{id}");
                                if ui.checkbox(&mut on, label).changed() {
                                    changes.push((id.clone(), on));
                                }
                            }
                        });
                },
            );
        });
        for (id, on) in changes {
            if on {
                self.export_checked.insert(id);
            } else {
                self.export_checked.remove(&id);
            }
        }
    }

    /// The key from the latest export, with a button that copies it.
    ///
    /// The field stays visible so the key is not left below the window.
    /// Editing the field does not change the key that Copy uses.
    fn export_key_field(&mut self, ui: &mut egui::Ui) {
        let Some(key) = self.export_key.clone() else {
            return;
        };
        ui.label(t_args(
            "wallet.export.ready",
            &[("count", &self.export_count.to_string())],
        ));
        ui.label(t("wallet.ui.export_key"));
        let mut shown = key.clone();
        let mut copy = false;
        ui.horizontal(|ui| {
            ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                if ui.button(t("wallet.ui.copy")).clicked() {
                    copy = true;
                }
                ui.add(
                    egui::TextEdit::singleline(&mut shown)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(ui.available_width())
                        .interactive(false),
                );
            });
        });
        if copy {
            ui.ctx().copy_text(key);
            self.note(t("wallet.ui.export_key_copied"));
        }
    }

    /// Opens the desktop save selector. The name starts as
    /// [`EXPORT_FILE_NAME`] until a file has been chosen.
    fn choose_export_file(&mut self) {
        let name = export_dialog_name(&self.export_path);
        let dialog =
            portable_dialog(&t("wallet.ui.import_path"), &self.export_path).set_file_name(name);
        if let Some(path) = dialog.save_file() {
            self.export_path = path.display().to_string();
        }
    }

    /// Opens the desktop open selector for a file written by an export.
    fn choose_import_file(&mut self) {
        let dialog = portable_dialog(&t("wallet.ui.import_file"), &self.import_path);
        if let Some(path) = dialog.pick_file() {
            self.import_path = path.display().to_string();
        }
    }

    fn confirm_export(&mut self, all: bool) {
        let path = self.export_path.trim().to_string();
        if path.is_empty() {
            return;
        }
        let chosen = credentials_for_export(&self.credentials, &self.export_checked, all);
        let exported = match export_credentials(&chosen) {
            Ok(exported) => exported,
            Err(PortableError::Empty) => {
                self.fail(t("wallet.export.empty"));
                return;
            }
            Err(PortableError::BadKey) => {
                self.fail(t("wallet.export.bad_key"));
                return;
            }
        };
        if let Err(err) = write_private(&path, &exported.bytes) {
            self.fail(err);
            return;
        }
        self.export_count = chosen.len();
        self.export_key = Some(exported.key);
    }

    fn confirm_import(&mut self) {
        let path = self.import_path.trim().to_string();
        let key = self.import_key.clone();
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) => {
                self.fail(t_args(
                    "wallet.cli.read_file",
                    &[("path", &path), ("error", &err.to_string())],
                ));
                return;
            }
        };
        let imported = match import_credentials(&bytes, &key) {
            Ok(imported) => imported,
            Err(PortableError::BadKey | PortableError::Empty) => {
                self.fail(t("wallet.export.bad_key"));
                return;
            }
        };
        let count = imported.len();
        let outcome = CredentialVault::open_default().and_then(|vault| {
            for credential in imported {
                vault.put(credential)?;
            }
            Ok(count)
        });
        self.reload_credentials();
        match outcome {
            Ok(stored) => {
                self.import_key.clear();
                self.note(t_args(
                    "wallet.export.imported",
                    &[("count", &stored.to_string())],
                ));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn open_cert_chain(&mut self, credential: &Credential) {
        if self
            .cert_view
            .as_ref()
            .is_some_and(|view| view.credential_id == credential.id)
        {
            return;
        }
        let credential = self.with_signer_certificate(credential.clone());
        self.cert_view = Some(CertView {
            credential_id: credential.id.clone(),
            certs: signer_certificates(&credential.document),
            index: 0,
            tab: CertTab::Fields,
        });
    }

    /// A sign-in credential minted before it carried `x5c` gains a self-signed
    /// certificate here. The payload stays the same. The sealed file is
    /// rewritten with that certificate.
    fn with_signer_certificate(&mut self, credential: Credential) -> Credential {
        let Some(holder) = credential.holder_key.as_deref() else {
            return credential;
        };
        if !signer_certificates(&credential.document).is_empty() {
            return credential;
        }
        let Some(updated) = ensure_self_issued_certificate(&credential.document, holder) else {
            return credential;
        };
        match CredentialVault::open_default()
            .and_then(|vault| vault.replace_document(&credential.id, &updated))
        {
            Ok(stored) => {
                if let Some(slot) = self
                    .credentials
                    .iter_mut()
                    .find(|item| item.id == stored.id)
                {
                    *slot = stored.clone();
                }
                stored
            }
            Err(err) => {
                self.fail(err.to_string());
                credential
            }
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        self.add_dialog(ctx);
        self.delete_dialog(ctx);
        self.inbox_dialog(ctx);
        self.trust_dialog(ctx);
        self.present_dialog(ctx);
        self.cert_dialog(ctx);
    }

    fn cert_dialog(&mut self, ctx: &egui::Context) {
        let Some(view) = self.cert_view.clone() else {
            return;
        };
        let mut open = true;
        let mut index = view.index;
        let mut tab = view.tab;
        let mut copied = None;
        let certs = view.certs;
        egui::Window::new(t("wallet.ui.cert_chain"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_size(egui::vec2(780.0, 520.0))
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                if certs.is_empty() {
                    ui.label(t("wallet.ui.cert_none"));
                    return;
                }
                index = index.min(certs.len() - 1);
                ui.horizontal_top(|ui| {
                    cert_chain_column(ui, &certs, &mut index);
                    cert_detail_column(ui, &certs[index], &mut tab);
                });
                if ui.button(t("wallet.ui.copy")).clicked() {
                    copied = Some(certs[index].pem.clone());
                }
            });
        if let Some(view) = self.cert_view.as_mut() {
            view.index = index;
            view.tab = tab;
        }
        if let Some(pem) = copied {
            ctx.copy_text(pem);
            self.note(t("wallet.ui.cert_copied"));
        }
        if !open {
            self.cert_view = None;
        }
    }

    fn add_dialog(&mut self, ctx: &egui::Context) {
        if !self.adding {
            return;
        }
        let mut open = true;
        egui::Window::new(t("wallet.ui.add"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(560.0)
            .show(ctx, |ui| {
                ui.label(t("wallet.ui.add_format"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.add_format)
                        .hint_text(t("wallet.ui.hint_format"))
                        .desired_width(f32::INFINITY),
                );
                ui.label(t("wallet.ui.add_issuer"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.add_issuer)
                        .hint_text(t("wallet.ui.hint_issuer"))
                        .desired_width(f32::INFINITY),
                );
                ui.label(t("wallet.ui.add_path"));
                ui.horizontal(|ui| {
                    ui.add(egui::TextEdit::singleline(&mut self.add_path).desired_width(320.0));
                    if ui.button(t("wallet.ui.load_file")).clicked() {
                        self.load_document_file();
                    }
                });
                ui.label(t("wallet.ui.add_document"));
                ui.add(
                    egui::TextEdit::multiline(&mut self.add_document)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(8),
                );
                ui.horizontal(|ui| {
                    if ui.button(t("wallet.ui.store")).clicked() {
                        self.store_credential();
                    }
                    if ui.button(t("wallet.ui.cancel")).clicked() {
                        self.adding = false;
                    }
                });
            });
        if !open {
            self.adding = false;
        }
    }

    fn delete_dialog(&mut self, ctx: &egui::Context) {
        if !self.confirm {
            return;
        }
        let Some(id) = self.selected.clone() else {
            self.confirm = false;
            return;
        };
        let mut open = true;
        egui::Window::new(t("wallet.ui.delete"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(t_args("wallet.ui.confirm_delete", &[("id", &id)]));
                ui.horizontal(|ui| {
                    if ui.button(t("wallet.ui.delete")).clicked() {
                        self.delete_selected();
                    }
                    if ui.button(t("wallet.ui.cancel")).clicked() {
                        self.confirm = false;
                    }
                });
            });
        if !open {
            self.confirm = false;
        }
    }

    fn inbox_dialog(&mut self, ctx: &egui::Context) {
        if !self.inbox_confirm {
            return;
        }
        let Some(name) = self
            .inbox_index
            .and_then(|index| self.inbox.get(index))
            .map(|row| row.name.clone())
        else {
            self.inbox_confirm = false;
            return;
        };
        let mut open = true;
        egui::Window::new(t("wallet.ui.delete"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(t_args("wallet.ui.confirm_inbox", &[("name", &name)]));
                ui.horizontal(|ui| {
                    if ui.button(t("wallet.ui.delete")).clicked() {
                        self.delete_inbox();
                    }
                    if ui.button(t("wallet.ui.cancel")).clicked() {
                        self.inbox_confirm = false;
                    }
                });
            });
        if !open {
            self.inbox_confirm = false;
        }
    }

    fn present_dialog(&mut self, ctx: &egui::Context) {
        let Some(summary) = self
            .present_prompt
            .as_ref()
            .map(|prompt| prompt.pending.summary.clone())
        else {
            return;
        };
        let mut remember = self
            .present_prompt
            .as_ref()
            .is_some_and(|prompt| prompt.remember);
        let mut open = true;
        let mut allow = false;
        let mut cancel = false;
        egui::Window::new(t("wallet.ui.present_title"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .default_width(480.0)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                wrapped(
                    ui,
                    t_args(
                        "wallet.ui.present_verifier",
                        &[("verifier", &summary.verifier)],
                    ),
                );
                ui.add_space(6.0);
                if summary.creates_key {
                    wrapped(ui, t("wallet.ui.present_new"));
                } else {
                    wrapped(ui, t("wallet.ui.present_help"));
                    if let Some(id) = &summary.credential_id {
                        wrapped(ui, t_args("wallet.cli.id", &[("id", id)]));
                    }
                    wrapped(
                        ui,
                        t_args("wallet.cli.format", &[("format", &summary.format)]),
                    );
                    wrapped(
                        ui,
                        t_args("wallet.cli.issuer", &[("issuer", &summary.issuer)]),
                    );
                    if !summary.received_at.is_empty() {
                        wrapped(
                            ui,
                            t_args("wallet.cli.received", &[("time", &summary.received_at)]),
                        );
                    }
                }
                ui.add_space(8.0);
                ui.checkbox(&mut remember, t("wallet.ui.present_remember"));
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button(t("wallet.ui.present_allow")).clicked() {
                        allow = true;
                    }
                    if ui.button(t("wallet.ui.cancel")).clicked() {
                        cancel = true;
                    }
                });
            });
        if let Some(prompt) = self.present_prompt.as_mut() {
            prompt.remember = remember;
        }
        if allow || cancel || !open {
            let Some(prompt) = self.present_prompt.take() else {
                return;
            };
            self.finish_present(prompt, allow && open);
        }
    }

    fn trust_dialog(&mut self, ctx: &egui::Context) {
        let Some(prompt) = self.trust.clone() else {
            return;
        };
        let mut open = true;
        egui::Window::new(t("wallet.ui.trust_title"))
            .open(&mut open)
            .collapsible(false)
            .resizable(false)
            .anchor(egui::Align2::CENTER_CENTER, egui::Vec2::ZERO)
            .show(ctx, |ui| {
                ui.label(&prompt.message);
                ui.horizontal(|ui| {
                    if ui.button(t("wallet.ui.trust")).clicked() {
                        match remember_trust(&prompt.issuer, &prompt.fingerprint) {
                            Ok(()) => {
                                self.note(t_args(
                                    "wallet.validate.prompt_saved",
                                    &[("issuer", &prompt.issuer)],
                                ));
                                self.trust = None;
                            }
                            Err(err) => self.fail(err.to_string()),
                        }
                    }
                    if ui.button(t("wallet.ui.cancel")).clicked() {
                        self.trust = None;
                    }
                });
            });
        if !open {
            self.trust = None;
        }
    }

    fn validate_selected(&mut self) {
        let Some(credential) = self
            .credentials
            .iter()
            .find(|credential| self.selected.as_deref() == Some(credential.id.as_str()))
            .cloned()
        else {
            return;
        };
        match validate_stored(&credential.format, &credential.issuer, &credential.document) {
            Ok(Outcome::Accepted(text)) => self.note(text),
            Ok(Outcome::Fallback(text)) => self.warn(text),
            Ok(Outcome::Ask {
                message,
                issuer,
                fingerprint,
            }) => {
                self.trust = Some(TrustPrompt {
                    message,
                    issuer,
                    fingerprint,
                });
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn delete_inbox(&mut self) {
        let Some(row) = self
            .inbox_index
            .and_then(|index| self.inbox.get(index))
            .cloned()
        else {
            self.inbox_confirm = false;
            return;
        };
        let outcome = Inbox::default_location()
            .and_then(|inbox| inbox.delete(&row.path).map_err(|err| err.to_string()));
        self.inbox_confirm = false;
        match outcome {
            Ok(()) => {
                self.note(t_args("wallet.ui.inbox_deleted", &[("name", &row.name)]));
                self.inbox_index = None;
                self.inbox_body.clear();
                self.reload_inbox();
            }
            Err(err) => self.fail(err.clone()),
        }
    }
}

impl eframe::App for WalletApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        self.poll_handoff(ui.ctx());
        ui.ctx()
            .send_viewport_cmd(egui::ViewportCommand::Title(t("wallet.desktop.name")));
        egui::Panel::left("nav")
            .exact_size(220.0)
            .resizable(false)
            .show(ui, |ui| self.nav(ui));
        egui::CentralPanel::default().show(ui, |ui| self.main_panel(ui));
        let ctx = ui.ctx().clone();
        self.dialogs(&ctx);
    }
}

fn load_credentials() -> Result<Vec<Credential>, String> {
    let vault = CredentialVault::open_default().map_err(|err| err.to_string())?;
    let mut credentials = vault.list().map_err(|err| err.to_string())?;
    credentials.reverse();
    Ok(credentials)
}

fn load_inbox() -> Result<Vec<InboxRow>, String> {
    let inbox = Inbox::default_location()?;
    let mut entries = inbox
        .list()
        .map_err(|err| t_args("wallet.cli.inbox_read", &[("error", &err.to_string())]))?;
    entries.reverse();
    Ok(entries
        .into_iter()
        .map(|entry| {
            let name = entry
                .path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("")
                .to_string();
            InboxRow {
                name,
                path: entry.path,
            }
        })
        .collect())
}

fn registration_options(system: bool, haip: bool) -> Options {
    Options {
        json: false,
        no_save: false,
        system,
        haip,
        help: false,
        version: false,
        ui: false,
        format: None,
        issuer: None,
        document: None,
        document_file: None,
        lang: None,
        saw_scope: true,
        positionals: Vec::new(),
    }
}

fn launch_section(uris: &[String]) -> Section {
    if uris.is_empty() || (uris.len() == 1 && presentation_launch(&uris[0])) {
        Section::Credentials
    } else {
        Section::Accept
    }
}

fn presentation_launch(uri: &str) -> bool {
    matches!(
        oid4vc_wallet::protocol::parse(uri),
        Ok(Invocation::Presentation(request))
            if request.request_uri.is_some() || request.request.is_some()
    )
}

fn open_return(url: &str) -> Result<(), String> {
    super::browser::open_return(url)
}

fn approved_presentations() -> Vec<String> {
    presentation_approval_path()
        .map(|path| presentation_approvals(&path))
        .unwrap_or_default()
}

fn algorithm_name(credential: &Credential) -> String {
    signature_algorithm(&credential.format, &credential.document)
        .unwrap_or_else(|| t("wallet.cli.algorithm_unknown"))
}

fn wrapped(ui: &mut egui::Ui, text: String) {
    ui.add(egui::Label::new(text).wrap());
}

fn label_list(items: &[AuthenticatorRef]) -> String {
    items
        .iter()
        .map(|item| item.label.clone())
        .collect::<Vec<_>>()
        .join(", ")
}

fn applet_line(ui: &mut egui::Ui, applet: Applet) {
    let name = match applet {
        Applet::Fido2 => t("wallet.ui.fido_applet_fido2"),
        Applet::Piv => t("wallet.ui.fido_applet_piv"),
    };
    ui.label(t_args("wallet.ui.fido_applet_in_use", &[("applet", &name)]));
}

/// Metadata rows on the Credentials detail pane.
///
/// `Ui::columns` lays its children out justified. egui then spreads each
/// wrapped row of a label across the column, so a long issuer value is
/// drawn with a gap between every letter. A plain vertical layout keeps
/// the rows left aligned.
fn detail_lines(ui: &mut egui::Ui, lines: &[String]) {
    ui.vertical(|ui| {
        for line in lines {
            ui.label(line);
        }
    });
}

fn preauthorized_offer(uri: &str) -> Option<CredentialOffer> {
    let Invocation::CredentialOffer { offer, .. } = oid4vc_wallet::protocol::parse(uri).ok()?
    else {
        return None;
    };
    match offer {
        OfferPassing::ByValue(offer) if offer.grants.pre_authorized_code.is_some() => Some(*offer),
        _ => None,
    }
}

fn invocation_json(uri: &str) -> Option<String> {
    let invocation = oid4vc_wallet::protocol::parse(uri).ok()?;
    Some(oid4vc_wallet::protocol::invocation::to_json(&invocation))
}

fn write_private(path: &str, bytes: &[u8]) -> Result<(), String> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| {
            t_args(
                "wallet.cli.path_error",
                &[("path", path), ("error", &err.to_string())],
            )
        })?;
    file.write_all(bytes).map_err(|err| {
        t_args(
            "wallet.cli.path_error",
            &[("path", path), ("error", &err.to_string())],
        )
    })?;
    Ok(())
}

fn accept_json_tab(ui: &mut egui::Ui, value: &Json) {
    let mut pretty = pretty_json(value);
    egui::ScrollArea::vertical()
        .id_salt("accept-json")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut pretty)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(12)
                    .interactive(false),
            );
        });
}

fn cert_chain_column(ui: &mut egui::Ui, certs: &[SignerCertificate], index: &mut usize) {
    ui.allocate_ui_with_layout(
        egui::vec2(240.0, 360.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            egui::ScrollArea::vertical()
                .id_salt("cert-chain")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for (number, cert) in certs.iter().enumerate() {
                        let label = format!("{}. {}", number + 1, cert.title);
                        if ui
                            .add(egui::Button::selectable(number == *index, label).wrap())
                            .clicked()
                        {
                            *index = number;
                        }
                    }
                });
        },
    );
}

fn cert_detail_column(ui: &mut egui::Ui, cert: &SignerCertificate, tab: &mut CertTab) {
    let width = ui.available_width();
    ui.allocate_ui_with_layout(
        egui::vec2(width, 360.0),
        egui::Layout::top_down(egui::Align::Min),
        |ui| {
            ui.horizontal(|ui| {
                ui.selectable_value(tab, CertTab::Fields, t("wallet.ui.cert_fields"));
                ui.selectable_value(tab, CertTab::Raw, t("wallet.ui.cert_raw"));
            });
            match tab {
                CertTab::Fields => cert_fields_tab(ui, &cert.fields),
                CertTab::Raw => cert_raw_tab(ui, &cert.pem),
            }
        },
    );
}

fn cert_fields_tab(ui: &mut egui::Ui, rows: &[(String, String)]) {
    egui::ScrollArea::both()
        .id_salt("cert-fields")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("cert-field-rows")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    ui.strong(t("wallet.ui.cert_field"));
                    ui.strong(t("wallet.ui.cert_value"));
                    ui.end_row();
                    for (name, value) in rows {
                        ui.monospace(name);
                        ui.monospace(value);
                        ui.end_row();
                    }
                });
        });
}

fn cert_raw_tab(ui: &mut egui::Ui, pem: &str) {
    let mut text = pem.to_string();
    let rows = pem.lines().count().max(8);
    egui::ScrollArea::both()
        .id_salt("cert-raw")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut text)
                    .font(egui::TextStyle::Monospace)
                    .desired_width(f32::INFINITY)
                    .desired_rows(rows)
                    .interactive(false),
            );
        });
}

fn accept_fields_tab(ui: &mut egui::Ui, value: &Json) {
    let rows = flatten_json(value);
    egui::ScrollArea::both()
        .id_salt("accept-fields")
        .auto_shrink([false, false])
        .show(ui, |ui| {
            egui::Grid::new("accept-field-rows")
                .num_columns(2)
                .striped(true)
                .show(ui, |ui| {
                    for (name, value) in rows {
                        ui.monospace(name);
                        ui.monospace(value);
                        ui.end_row();
                    }
                });
        });
}

fn flatten_json(value: &Json) -> Vec<(String, String)> {
    let mut rows = Vec::new();
    flatten_json_at(value, "", &mut rows);
    rows
}

fn flatten_json_at(value: &Json, prefix: &str, rows: &mut Vec<(String, String)>) {
    match value {
        Json::Object(members) if !members.is_empty() => {
            for (name, child) in members {
                let path = if prefix.is_empty() {
                    name.clone()
                } else {
                    format!("{prefix}.{name}")
                };
                flatten_json_at(child, &path, rows);
            }
        }
        Json::Array(items) if !items.is_empty() => {
            for (index, child) in items.iter().enumerate() {
                flatten_json_at(child, &format!("{prefix}[{index}]"), rows);
            }
        }
        other => rows.push((prefix.to_string(), json_leaf(other))),
    }
}

fn json_leaf(value: &Json) -> String {
    match value {
        Json::String(text) => text.clone(),
        other => other.to_string(),
    }
}

fn pretty_json(value: &Json) -> String {
    let mut out = String::new();
    write_pretty(value, 0, &mut out);
    out
}

fn write_pretty(value: &Json, depth: usize, out: &mut String) {
    match value {
        Json::Object(members) if !members.is_empty() => {
            out.push_str("{\n");
            for (index, (name, child)) in members.iter().enumerate() {
                push_indent(out, depth + 1);
                push_json_string(out, name);
                out.push_str(": ");
                write_pretty(child, depth + 1, out);
                if index + 1 != members.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            push_indent(out, depth);
            out.push('}');
        }
        Json::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                push_indent(out, depth + 1);
                write_pretty(item, depth + 1, out);
                if index + 1 != items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            push_indent(out, depth);
            out.push(']');
        }
        other => out.push_str(&other.to_string()),
    }
}

fn push_indent(out: &mut String, depth: usize) {
    for _ in 0..depth {
        out.push_str("  ");
    }
}

fn push_json_string(out: &mut String, text: &str) {
    out.push_str(&Json::String(text.to_string()).to_string());
}

fn accept_all(uris: &[String], no_save: bool, json: bool) -> AcceptReport {
    if uris.is_empty() {
        return AcceptReport {
            text: String::new(),
            error: false,
        };
    }
    let inbox = if no_save {
        Ok(None)
    } else {
        Inbox::default_location().map(Some)
    };
    let inbox = match inbox {
        Ok(inbox) => inbox,
        Err(err) => {
            return AcceptReport {
                text: err,
                error: true,
            };
        }
    };
    let mut blocks = Vec::new();
    let mut error = false;
    for uri in uris {
        let locales = ui_locales_of_uri(uri);
        let outcome =
            i18n::with_ui_locales(&locales, || describe_accept(uri, inbox.as_ref(), json));
        match outcome {
            Ok(text) => blocks.push(text),
            Err(err) => {
                error = true;
                blocks.push(t_args(
                    "wallet.cli.handled",
                    &[("uri", uri), ("error", &err)],
                ));
            }
        }
    }
    AcceptReport {
        text: blocks.join("\n\n"),
        error,
    }
}

fn describe_accept(uri: &str, inbox: Option<&Inbox>, json: bool) -> Result<String, String> {
    let accepted = accept(uri, inbox).map_err(|err| err.to_string())?;
    let mut text = if json {
        accepted.json
    } else {
        accepted.summary
    };
    if let Some(path) = &accepted.saved {
        text.push_str("\n\n");
        text.push_str(&t_args(
            "wallet.cli.saved",
            &[("path", &path.display().to_string())],
        ));
    }
    Ok(text)
}

/// The name the export selector offers until a file has been chosen.
const EXPORT_FILE_NAME: &str = "oid4vc-credentials.oid4vc";

/// Height of the credential list on Import and export. The list scrolls
/// inside this window.
const EXPORT_LIST_HEIGHT: f32 = 220.0;

/// Credentials to write, in stored order.
///
/// `all` keeps every credential. Otherwise only ids in `checked` are kept.
fn credentials_for_export(
    credentials: &[Credential],
    checked: &HashSet<String>,
    all: bool,
) -> Vec<Credential> {
    if all {
        return credentials.to_vec();
    }
    credentials
        .iter()
        .filter(|credential| checked.contains(&credential.id))
        .cloned()
        .collect()
}

/// Drops checks for credentials that are no longer stored.
fn retain_export_checks(checked: &mut HashSet<String>, credentials: &[Credential]) {
    checked.retain(|id| credentials.iter().any(|credential| &credential.id == id));
}

/// The file name the export selector starts with.
fn export_dialog_name(current: &str) -> String {
    let trimmed = current.trim();
    if trimmed.is_empty() {
        return EXPORT_FILE_NAME.to_string();
    }
    let path = Path::new(trimmed);
    // A chosen directory is where the selector opens, not the file name.
    if path.is_dir() {
        return EXPORT_FILE_NAME.to_string();
    }
    path.file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .unwrap_or(EXPORT_FILE_NAME)
        .to_string()
}

/// The folder the selector opens in, when a path was already chosen.
fn dialog_directory(current: &str) -> Option<PathBuf> {
    let trimmed = current.trim();
    if trimmed.is_empty() {
        return None;
    }
    let path = Path::new(trimmed);
    let dir = if path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent()?.to_path_buf()
    };
    if dir.as_os_str().is_empty() {
        None
    } else {
        Some(dir)
    }
}

/// The path already chosen, or the sentence that none has been.
fn chosen_file_label(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        t("wallet.ui.no_file")
    } else {
        trimmed.to_string()
    }
}

/// A desktop file selector limited to this wallet's export files, with every
/// file still available. `current` is the path already chosen, if any.
fn portable_dialog(title: &str, current: &str) -> rfd::FileDialog {
    let mut dialog = rfd::FileDialog::new()
        .set_title(title)
        .add_filter(t("wallet.ui.export_kind"), &["oid4vc"])
        .add_filter(t("wallet.ui.all_files"), &["*"]);
    if let Some(dir) = dialog_directory(current) {
        dialog = dialog.set_directory(dir);
    }
    dialog
}

#[cfg(test)]
mod tests {
    use super::describe_accept;
    use eframe::egui;
    use oid4vc_wallet::wallet::Inbox;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn about_pages_are_public_https_links() {
        let mut keys = Vec::new();
        for (key, url) in super::ABOUT_PAGES {
            assert!(crate::browser::https_page(url), "{url}");
            keys.push(*key);
        }
        assert_eq!(
            keys,
            [
                "wallet.ui.about_docs",
                "wallet.ui.about_help",
                "wallet.ui.about_license",
            ]
        );
        assert!(crate::browser::https_page(
            "https://rcbj.github.io/oid4vc-wallet/"
        ));
    }

    #[test]
    fn a_wrapped_issuer_line_is_not_letter_spaced() {
        let ctx = egui::Context::default();
        let text = "Issuer: urn:ietf:params:oauth:jwk-thumbprint:sha-256:UfPa-A8nmxIO2EdelUYI5Bw0FH5fibJu-8LpKbfXQ-A";
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(520.0, 360.0),
            )),
            ..Default::default()
        };
        let output = ctx.run_ui(input, |ui| {
            ui.columns(2, |columns| {
                columns[0].label(text);
                super::detail_lines(&mut columns[1], &[text.to_string()]);
            });
        });
        let mut gaps = Vec::new();
        for clipped in &output.shapes {
            collect_issuer_gaps(&clipped.shape, &mut gaps);
        }
        output.drop_without_applying_deltas();
        assert!(
            gaps.iter().any(|gap| *gap > 8.0),
            "the column label should still justify a wrapped issuer, gaps {gaps:?}"
        );
        assert!(
            gaps.iter().any(|gap| *gap < 1.5),
            "the detail issuer line is still letter-spaced, gaps {gaps:?}"
        );
    }

    fn widest_extra_gap(galley: &egui::Galley) -> f32 {
        let mut widest = 0.0_f32;
        for row in &galley.rows {
            for pair in row.glyphs.windows(2) {
                let extra = pair[1].pos.x - pair[0].pos.x - pair[0].advance_width;
                widest = widest.max(extra);
            }
        }
        widest
    }

    fn collect_issuer_gaps(shape: &egui::epaint::Shape, gaps: &mut Vec<f32>) {
        match shape {
            egui::epaint::Shape::Text(text) if text.galley.job.text.contains("urn:ietf") => {
                gaps.push(widest_extra_gap(&text.galley));
            }
            egui::epaint::Shape::Vec(shapes) => {
                for shape in shapes {
                    collect_issuer_gaps(shape, gaps);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn the_export_selector_offers_a_default_file_name() {
        assert_eq!(super::export_dialog_name(""), super::EXPORT_FILE_NAME);
        assert_eq!(super::export_dialog_name("   "), super::EXPORT_FILE_NAME);
        assert_eq!(super::export_dialog_name("/tmp/kept.oid4vc"), "kept.oid4vc");
        assert_eq!(
            super::dialog_directory("/tmp/kept.oid4vc").as_deref(),
            Some(std::path::Path::new("/tmp"))
        );
        assert!(super::dialog_directory("").is_none());
        assert!(super::dialog_directory("kept.oid4vc").is_none());
    }

    #[test]
    fn export_checks_keep_list_order_and_drop_unknown_ids() {
        use std::collections::HashSet;

        let credentials = vec![stored("a"), stored("b"), stored("c")];
        let mut checked = HashSet::new();
        checked.insert("c".to_string());
        checked.insert("a".to_string());
        checked.insert("missing".to_string());
        let chosen = super::credentials_for_export(&credentials, &checked, false);
        let ids: Vec<&str> = chosen
            .iter()
            .map(|credential| credential.id.as_str())
            .collect();
        assert_eq!(ids, ["a", "c"]);
        let all = super::credentials_for_export(&credentials, &checked, true);
        assert_eq!(all.len(), 3);
        assert_eq!(
            super::credentials_for_export(&credentials, &HashSet::new(), false),
            [] as [oid4vc_wallet::wallet::Credential; 0]
        );
        super::retain_export_checks(&mut checked, &credentials);
        assert!(checked.contains("a") && checked.contains("c"));
        assert!(!checked.contains("missing"));
    }

    fn stored(id: &str) -> oid4vc_wallet::wallet::Credential {
        oid4vc_wallet::wallet::Credential {
            id: id.to_string(),
            format: "dc+sd-jwt".to_string(),
            issuer: "https://issuer.example".to_string(),
            received_at: "20260101T000000.000Z".to_string(),
            document: "doc".to_string(),
            holder_key: None,
        }
    }

    #[test]
    fn accepting_a_uri_writes_the_inbox_and_returns_the_summary() {
        let root = std::env::temp_dir().join(format!(
            "oid4vc-wallet-ui-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        let inbox = Inbox::new(&root);
        let uri = "siopv2://?client_id=https%3A%2F%2Fsts.example&request_uri=https%3A%2F%2Fsts.example%2Frequest&request_uri_method=get";
        let text = describe_accept(uri, Some(&inbox), false).unwrap();
        assert!(text.contains("siopv2"), "{text}");
        assert!(text.contains(&root.display().to_string()), "{text}");
        let entries = inbox.list().unwrap();
        assert_eq!(entries.len(), 1);
        let body = fs::read_to_string(&entries[0].path).unwrap();
        assert!(body.contains(uri), "{body}");
        let json = describe_accept(uri, None, true).unwrap();
        assert!(json.contains("https://sts.example/request"), "{json}");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_preauthorized_offer_opens_the_redeem_prompt() {
        let offer = r#"{"credential_issuer":"https://issuer.example","credential_configuration_ids":["IdentityCredential"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"test-code","tx_code":{"length":5,"input_mode":"numeric","description":"Type the 5-digit code."}}}}"#;
        let uri = format!(
            "openid-credential-offer://?credential_offer={}",
            oid4vc_wallet::protocol::encode_uri_component(offer)
        );
        let parsed = super::preauthorized_offer(&uri).unwrap();
        assert_eq!(parsed.credential_issuer, "https://issuer.example");
        let request = "siopv2://?client_id=https%3A%2F%2Fsts.example&request_uri=https%3A%2F%2Fsts.example%2Frequest&request_uri_method=get";
        assert!(super::preauthorized_offer(request).is_none());
    }

    #[test]
    fn a_presentation_request_opens_the_credential_list() {
        let request = "openid4vp://?client_id=https%3A%2F%2Fverifier.example&request_uri=https%3A%2F%2Fverifier.example%2Foid4vp%2Frequest%2F1&request_uri_method=get";
        assert!(super::presentation_launch(request));
        assert_eq!(
            super::launch_section(&[request.to_string()]),
            super::Section::Credentials
        );
        assert_eq!(super::launch_section(&[]), super::Section::Credentials);
        let by_value =
            "openid4vp://?client_id=https%3A%2F%2Fverifier.example&response_type=vp_token";
        assert!(!super::presentation_launch(by_value));
        assert_eq!(
            super::launch_section(&[by_value.to_string()]),
            super::Section::Accept
        );
        let offer =
            "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer";
        assert_eq!(
            super::launch_section(&[offer.to_string()]),
            super::Section::Accept
        );
        assert_eq!(
            super::launch_section(&[request.to_string(), request.to_string()]),
            super::Section::Accept
        );
    }

    #[test]
    fn accept_fields_are_dotted_leaves_and_pretty_json_keeps_keys() {
        let value = oid4vc_wallet::protocol::Json::parse(
            r#"{"z":1,"msg":"say \"hi\"","grants":{"pre_authorized_code":"secret"},"ids":[{"k":"one"},true]}"#,
        )
        .unwrap();
        let rows = super::flatten_json(&value);
        assert_eq!(
            rows,
            vec![
                ("z".to_string(), "1".to_string()),
                ("msg".to_string(), "say \"hi\"".to_string()),
                (
                    "grants.pre_authorized_code".to_string(),
                    "secret".to_string()
                ),
                ("ids[0].k".to_string(), "one".to_string()),
                ("ids[1]".to_string(), "true".to_string()),
            ]
        );
        let pretty = super::pretty_json(&value);
        assert!(pretty.contains('\n'), "{pretty}");
        assert!(pretty.contains("\n  \"z\": "), "{pretty}");
        assert!(
            pretty.contains("\n    \"pre_authorized_code\": "),
            "{pretty}"
        );
        for key in ["z", "msg", "grants", "pre_authorized_code", "ids", "k"] {
            assert!(pretty.contains(&format!("\"{key}\"")), "{pretty}");
        }
        let again = oid4vc_wallet::protocol::Json::parse(&pretty).unwrap();
        assert_eq!(again, value);
    }
}
