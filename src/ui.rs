//! The `--ui` window.
//!
//! The same binary serves the command line and this window. The window lists
//! stored credentials and runs the operations the command line runs: add,
//! show, and delete a credential, read the inbox, accept an invocation URI,
//! choose a language, and register the protocol handlers.

use std::fs;
use std::path::PathBuf;

use eframe::egui;
use oid4vc_wallet::i18n::{self, t, t_args};
use oid4vc_wallet::protocol::ui_locales_of_uri;
use oid4vc_wallet::wallet::{accept, Credential, CredentialVault, Inbox, NewCredential};

use super::{install, uninstall, Failure, Options};

#[derive(Clone, Copy, PartialEq, Eq)]
enum Section {
    Credentials,
    Inbox,
    Accept,
    Language,
    Registration,
}

const NAV: &[(Section, &str)] = &[
    (Section::Credentials, "wallet.ui.credentials"),
    (Section::Inbox, "wallet.ui.inbox"),
    (Section::Accept, "wallet.ui.accept"),
    (Section::Language, "wallet.ui.language"),
    (Section::Registration, "wallet.ui.registration"),
];

struct Banner {
    error: bool,
    text: String,
}

struct InboxRow {
    name: String,
    path: PathBuf,
}

struct AcceptReport {
    text: String,
    error: bool,
}

pub(super) fn run(uris: &[String], no_save: bool) -> Result<(), Failure> {
    let uris: Vec<String> = uris.iter().filter(|uri| !uri.is_empty()).cloned().collect();
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
            Ok(Box::new(WalletApp::new(uris, no_save)))
        }),
    )
    .map_err(|err| {
        super::fail(
            t_args("wallet.ui.open_failed", &[("error", &err.to_string())]),
            1,
        )
    })
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
    add_format: String,
    add_issuer: String,
    add_path: String,
    add_document: String,
    inbox: Vec<InboxRow>,
    inbox_index: Option<usize>,
    inbox_body: String,
    accept_uri: String,
    accept_output: String,
    no_save: bool,
    accept_json: bool,
    chosen_tag: String,
    system_scope: bool,
    haip: bool,
    registration_log: String,
}

impl WalletApp {
    fn new(uris: Vec<String>, no_save: bool) -> Self {
        let mut app = Self {
            section: if uris.is_empty() {
                Section::Credentials
            } else {
                Section::Accept
            },
            banner: None,
            credentials: Vec::new(),
            selected: None,
            show_json: false,
            adding: false,
            confirm: false,
            add_format: String::new(),
            add_issuer: String::new(),
            add_path: String::new(),
            add_document: String::new(),
            inbox: Vec::new(),
            inbox_index: None,
            inbox_body: String::new(),
            accept_uri: if uris.len() == 1 {
                uris[0].clone()
            } else {
                String::new()
            },
            accept_output: String::new(),
            no_save,
            accept_json: false,
            chosen_tag: i18n::selected_offered().unwrap_or_else(|| "en".to_string()),
            system_scope: false,
            haip: false,
            registration_log: String::new(),
        };
        app.reload_credentials();
        app.reload_inbox();
        if !uris.is_empty() {
            let report = accept_all(&uris, no_save, false);
            app.accept_output = report.text.clone();
            if report.error {
                app.fail(report.text);
            }
            app.reload_inbox();
        }
        app
    }

    fn note(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            error: false,
            text: text.into(),
        });
    }

    fn fail(&mut self, text: impl Into<String>) {
        self.banner = Some(Banner {
            error: true,
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
            self.fail(report.text);
        } else {
            self.banner = None;
            self.reload_inbox();
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
            let color = if banner.error {
                egui::Color32::from_rgb(255, 150, 140)
            } else {
                egui::Color32::from_rgb(150, 220, 196)
            };
            ui.colored_label(color, &banner.text);
            ui.separator();
        }
        match self.section {
            Section::Credentials => self.credentials_page(ui),
            Section::Inbox => self.inbox_page(ui),
            Section::Accept => self.accept_page(ui),
            Section::Language => self.language_page(ui),
            Section::Registration => self.registration_page(ui),
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
        if ui.button(t("wallet.ui.refresh")).clicked() {
            self.reload_inbox();
        }
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
        if !self.accept_output.is_empty() {
            ui.add_space(8.0);
            let mut output = self.accept_output.clone();
            egui::ScrollArea::vertical()
                .id_salt("accept-output")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    ui.add(
                        egui::TextEdit::multiline(&mut output)
                            .font(egui::TextStyle::Monospace)
                            .desired_width(f32::INFINITY)
                            .desired_rows(12)
                            .interactive(false),
                    );
                });
        }
    }

    fn language_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(t("wallet.ui.language"));
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

    fn registration_page(&mut self, ui: &mut egui::Ui) {
        ui.heading(t("wallet.ui.registration"));
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

    fn dialogs(&mut self, ctx: &egui::Context) {
        self.add_dialog(ctx);
        self.delete_dialog(ctx);
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
}

impl eframe::App for WalletApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
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
}
