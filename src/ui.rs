//! The `--ui` window.
//!
//! The same binary serves the command line and this window. The window lists
//! stored credentials and runs the operations the command line runs: add,
//! show, delete, and validate a credential, read and delete an inbox entry,
//! accept an invocation URI, redeem a pre-authorized offer, present a
//! same-device request from the credential list, answer a self-issued ID
//! Token request, import and export credentials, and open Settings for the
//! language, the protocol handlers, trust anchors, and the storage key.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::PathBuf;

use eframe::egui;
use oid4vc_wallet::i18n::{self, t, t_args};
use oid4vc_wallet::protocol::offer::{CredentialOffer, OfferPassing};
use oid4vc_wallet::protocol::{ui_locales_of_uri, Invocation, Json};
use oid4vc_wallet::wallet::{
    accept, delete_anchor, export_credentials, import_anchors, import_credentials, list_anchors,
    present_same_device, redeem_pre_authorized, remember_trust, trust_anchors_dir, validate_stored,
    AnchorInfo, Credential, CredentialVault, Inbox, NewCredential, Outcome, PortableError,
    Redeemed,
};

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
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AcceptTab {
    Json,
    Fields,
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
            Ok(Box::new(WalletApp::new(uris, no_save, handoff)))
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
    let dir = match super::single::runtime_dir() {
        Ok(dir) => dir,
        Err(_) => return SingleClaim::Alone,
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
    exporting: bool,
    export_all: bool,
    export_path: String,
    /// Shown only after the export file is on disk. This is not the storage key.
    export_key: Option<String>,
    export_count: usize,
    importing: bool,
    import_path: String,
    import_key: String,
    trust_pem: String,
    trust_path: String,
    trust_anchors: Vec<AnchorInfo>,
    trust_selected: Option<String>,
    /// Bound `ui.sock`, when this process owns the window.
    handoff: Option<Incoming>,
}

impl WalletApp {
    fn new(uris: Vec<String>, no_save: bool, handoff: Option<Incoming>) -> Self {
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
            exporting: false,
            export_all: false,
            export_path: String::new(),
            export_key: None,
            export_count: 0,
            importing: false,
            import_path: String::new(),
            import_key: String::new(),
            trust_pem: String::new(),
            trust_path: String::new(),
            trust_anchors: Vec::new(),
            trust_selected: None,
            handoff,
        };
        app.reload_credentials();
        app.reload_inbox();
        app.apply_launch(&uris);
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
            self.accept_output = report.text.clone();
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
        let outcome = present_same_device(uri, &self.credentials);
        if let Some(new) = outcome.store {
            match CredentialVault::open_default().and_then(|vault| vault.put(new)) {
                Ok(stored) => {
                    let id = stored.id.clone();
                    self.reload_credentials();
                    self.selected = Some(id);
                }
                Err(err) => {
                    self.fail(err.to_string());
                    if let Some(redirect) = outcome.redirect_uri.as_deref() {
                        let _ = open_browser(redirect);
                    }
                    return;
                }
            }
        } else if let Some(id) = outcome.credential_id.clone() {
            self.selected = Some(id);
        }
        let mut text = outcome.message;
        if let Some(redirect) = outcome.redirect_uri.as_deref() {
            if let Err(error) = open_browser(redirect) {
                text.push(' ');
                text.push_str(&t_args("wallet.present.open_failed", &[("error", &error)]));
                if outcome.ok {
                    self.warn(text);
                } else {
                    self.fail(text);
                }
                return;
            }
        }
        if outcome.ok {
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
                if self
                    .selected
                    .as_ref()
                    .is_some_and(|id| !credentials.iter().any(|credential| &credential.id == id))
                {
                    self.selected = None;
                }
                self.credentials = credentials;
            }
            Err(err) => {
                self.credentials.clear();
                self.selected = None;
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
        self.accept_output = report.text.clone();
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

    fn store_redeemed(&mut self, redeemed: Redeemed) {
        let outcome = CredentialVault::open_default().and_then(|vault| {
            vault.put(NewCredential {
                format: redeemed.format,
                issuer: redeemed.issuer,
                document: redeemed.document,
                holder_key: Some(redeemed.holder_key),
            })
        });
        match outcome {
            Ok(credential) => {
                let id = credential.id.clone();
                self.redeem = None;
                self.accept_uri.clear();
                self.accept_output.clear();
                self.accept_parsed = None;
                self.note(t_args("wallet.cli.stored", &[("id", &id)]));
                self.reload_credentials();
                self.selected = Some(id);
                self.show_json = false;
                self.section = Section::Credentials;
            }
            Err(err) => self.fail(err.to_string()),
        }
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
                self.registration_log = text.clone();
                self.note(text);
            }
            Err(err) => {
                self.registration_log = err.message.clone();
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
                    egui::Button::new(t("wallet.ui.export")),
                )
                .clicked()
            {
                self.begin_export(false);
            }
            if ui
                .add_enabled(
                    !self.credentials.is_empty(),
                    egui::Button::new(t("wallet.ui.export_all")),
                )
                .clicked()
            {
                self.begin_export(true);
            }
            if ui.button(t("wallet.ui.import")).clicked() {
                self.importing = true;
                self.import_path.clear();
                self.import_key.clear();
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
        ui.label(t_args("wallet.cli.id", &[("id", &credential.id)]));
        ui.label(t_args(
            "wallet.cli.format",
            &[("format", &credential.format)],
        ));
        ui.label(t_args(
            "wallet.cli.issuer",
            &[("issuer", &credential.issuer)],
        ));
        ui.label(t_args(
            "wallet.cli.received",
            &[("time", &credential.received_at)],
        ));
        ui.label(t("wallet.ui.document"));
        let id = credential.id.clone();
        ui.horizontal(|ui| {
            ui.checkbox(&mut self.show_json, t("wallet.ui.json"));
            if ui.button(t("wallet.ui.copy")).clicked() {
                ui.ctx().copy_text(id.clone());
                self.note(t_args("wallet.ui.copied", &[("id", &id)]));
            }
        });
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
        ui.horizontal(|ui| {
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
            ui.selectable_value(
                &mut self.settings_tab,
                SettingsTab::Security,
                t("wallet.ui.security"),
            );
        });
        ui.separator();
        match self.settings_tab {
            SettingsTab::Language => self.language_tab(ui),
            SettingsTab::Registration => self.registration_tab(ui),
            SettingsTab::Trust => self.trust_tab(ui),
            SettingsTab::Security => self.security_tab(ui),
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
        ui.label(t("wallet.ui.rotate_help"));
        ui.add_space(8.0);
        if ui.button(t("wallet.ui.rotate_key")).clicked() {
            self.rotate_storage_key();
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
        if self
            .trust_selected
            .as_ref()
            .is_some_and(|id| !self.trust_anchors.iter().any(|anchor| &anchor.fingerprint == id))
        {
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

    fn begin_export(&mut self, all: bool) {
        self.exporting = true;
        self.export_all = all;
        self.export_path.clear();
        self.export_key = None;
        self.export_count = 0;
    }

    fn confirm_export(&mut self) {
        let path = self.export_path.trim().to_string();
        if path.is_empty() {
            return;
        }
        let chosen: Vec<Credential> = if self.export_all {
            self.credentials.clone()
        } else {
            self.credentials
                .iter()
                .find(|credential| self.selected.as_deref() == Some(credential.id.as_str()))
                .cloned()
                .into_iter()
                .collect()
        };
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
                self.importing = false;
                self.import_key.clear();
                self.note(t_args(
                    "wallet.export.imported",
                    &[("count", &stored.to_string())],
                ));
            }
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn dialogs(&mut self, ctx: &egui::Context) {
        self.add_dialog(ctx);
        self.delete_dialog(ctx);
        self.inbox_dialog(ctx);
        self.trust_dialog(ctx);
        self.export_dialog(ctx);
        self.import_dialog(ctx);
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
            Err(err) => self.fail(err.to_string()),
        }
    }

    fn export_dialog(&mut self, ctx: &egui::Context) {
        if !self.exporting {
            return;
        }
        let mut open = true;
        egui::Window::new(t("wallet.ui.export"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.colored_label(
                    egui::Color32::from_rgb(230, 180, 80),
                    t("wallet.export.warning"),
                );
                ui.add_space(8.0);
                ui.label(t("wallet.ui.import_path"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.export_path)
                        .desired_width(f32::INFINITY),
                );
                if let Some(key) = self.export_key.clone() {
                    ui.add_space(8.0);
                    ui.label(t_args(
                        "wallet.export.ready",
                        &[("count", &self.export_count.to_string())],
                    ));
                    ui.label(t("wallet.ui.export_key"));
                    let mut shown = key;
                    ui.add(
                        egui::TextEdit::multiline(&mut shown)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(2)
                            .interactive(false),
                    );
                } else {
                    ui.add_space(8.0);
                    let ready = !self.export_path.trim().is_empty();
                    if ui
                        .add_enabled(ready, egui::Button::new(t("wallet.ui.export")))
                        .clicked()
                    {
                        self.confirm_export();
                    }
                }
            });
        if !open {
            self.exporting = false;
            self.export_key = None;
        }
    }

    fn import_dialog(&mut self, ctx: &egui::Context) {
        if !self.importing {
            return;
        }
        let mut open = true;
        egui::Window::new(t("wallet.ui.import"))
            .open(&mut open)
            .collapsible(false)
            .resizable(true)
            .default_width(520.0)
            .show(ctx, |ui| {
                ui.label(t("wallet.ui.import_path"));
                ui.add(
                    egui::TextEdit::singleline(&mut self.import_path)
                        .desired_width(f32::INFINITY),
                );
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
            });
        if !open {
            self.importing = false;
            self.import_key.clear();
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

fn open_browser(url: &str) -> Result<(), String> {
    let mut child = std::process::Command::new("xdg-open")
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|err| err.to_string())?;
    std::thread::spawn(move || {
        let _ = child.wait();
    });
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::describe_accept;
    use oid4vc_wallet::wallet::Inbox;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

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
        let by_value = "openid4vp://?client_id=https%3A%2F%2Fverifier.example&response_type=vp_token";
        assert!(!super::presentation_launch(by_value));
        assert_eq!(
            super::launch_section(&[by_value.to_string()]),
            super::Section::Accept
        );
        let offer = "openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fissuer.example%2Foffer";
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
