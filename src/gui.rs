use std::time::{Duration, Instant};

use eframe::egui;
use zeroize::Zeroize;

use crate::config::{self as app_config, HotkeyConfig};
use crate::session::{
    self, ChangeMasterError, InitialState, Session, MIN_MASTER_PASSWORD_LEN,
};
use crate::storage::{self, EncryptedVault, LegacyVerifierVault};

const CLIPBOARD_CLEAR: Duration = Duration::from_secs(30);
const MAX_LOGIN_ATTEMPTS: u32 = 5;

pub fn run() -> Result<(), eframe::Error> {
    storage::cleanup_stale_tmp();
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([900.0, 620.0])
            .with_min_inner_size([640.0, 480.0])
            .with_resizable(true),
        ..Default::default()
    };
    eframe::run_native(
        "Password Manager",
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Box::new(App::new())
        }),
    )
}

/// Quick-pick mode: shown by `passwort-manager --picker` when the
/// auto-type daemon fires the global hotkey. Lists vault entries
/// (sorted by relevance to the active window's title), lets the user
/// type to filter / arrow keys to move / Enter to pick / Esc to cancel.
/// Prints the chosen entry name to stdout and exits.
pub fn run_picker(target_title: Option<String>) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 320.0])
            .with_resizable(false)
            .with_decorations(false)
            .with_always_on_top(),
        ..Default::default()
    };
    eframe::run_native(
        "Password Manager — Pick",
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Box::new(picker::PickerApp::new(target_title))
        }),
    )
}

mod picker {
    use super::{COLOR_ACCENT, COLOR_ERROR, COLOR_MUTED};
    use crate::ipc::{self, EntryRef, Request, Response};
    use eframe::egui;

    pub struct PickerApp {
        entries: Vec<EntryRef>,
        filter: String,
        selected: usize,
        target_title: Option<String>,
        load_error: Option<String>,
    }

    impl PickerApp {
        pub fn new(target_title: Option<String>) -> Self {
            let (entries, load_error) = match ipc::rpc(&Request::ListEntries) {
                Ok(Response::Entries { mut entries }) => {
                    // Sort: entries whose name appears in the target window
                    // title come first; everything else stays in original order.
                    if let Some(t) = target_title.as_deref() {
                        let t_low = t.to_lowercase();
                        entries.sort_by_key(|e| {
                            let n = e.name.to_lowercase();
                            !(t_low.contains(&n) || n.split('.').any(|p| t_low.contains(p)))
                        });
                    }
                    (entries, None)
                }
                Ok(Response::Error { code, message }) => {
                    let msg = if code == "locked" {
                        "Vault is locked. Open the toolbar extension or the GUI to unlock.".to_string()
                    } else {
                        message
                    };
                    (Vec::new(), Some(msg))
                }
                Ok(_) => (Vec::new(), Some("unexpected response".into())),
                Err(e) => (Vec::new(), Some(e.to_string())),
            };
            Self {
                entries,
                filter: String::new(),
                selected: 0,
                target_title,
                load_error,
            }
        }

        fn filtered(&self) -> Vec<&EntryRef> {
            if self.filter.is_empty() {
                return self.entries.iter().collect();
            }
            let f = self.filter.to_lowercase();
            self.entries
                .iter()
                .filter(|e| {
                    e.name.to_lowercase().contains(&f)
                        || e.username.to_lowercase().contains(&f)
                })
                .collect()
        }
    }

    impl eframe::App for PickerApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            // Compute filtered names + selection once per frame so the
            // borrow-checker doesn't complain when we mutate self.selected.
            let filtered_names: Vec<(String, String)> = self
                .filtered()
                .into_iter()
                .map(|e| (e.name.clone(), e.username.clone()))
                .collect();
            if !filtered_names.is_empty() && self.selected >= filtered_names.len() {
                self.selected = filtered_names.len() - 1;
            }

            // Keyboard navigation
            let len = filtered_names.len();
            let pick_now: Option<String> = ctx.input(|i| {
                if i.key_pressed(egui::Key::Escape) {
                    std::process::exit(1);
                }
                if i.key_pressed(egui::Key::ArrowDown) && len > 0 {
                    self.selected = (self.selected + 1) % len;
                }
                if i.key_pressed(egui::Key::ArrowUp) && len > 0 {
                    self.selected = (self.selected + len - 1) % len;
                }
                if i.key_pressed(egui::Key::Enter) && len > 0 {
                    return Some(filtered_names[self.selected].0.clone());
                }
                None
            });
            if let Some(name) = pick_now {
                println!("{}", name);
                std::process::exit(0);
            }

            egui::CentralPanel::default().show(ctx, |ui| {
                // Header showing what window we're filling for
                if let Some(t) = &self.target_title {
                    ui.colored_label(COLOR_MUTED, format!("→ {}", t));
                    ui.add_space(4.0);
                }

                if let Some(err) = &self.load_error {
                    ui.colored_label(COLOR_ERROR, err);
                    ui.add_space(8.0);
                    if ui
                        .add_sized([100.0, 28.0], egui::Button::new("Close"))
                        .clicked()
                    {
                        std::process::exit(1);
                    }
                    return;
                }

                // Filter input — auto-focused
                let resp = ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("Type to filter…")
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                if !resp.has_focus() {
                    resp.request_focus();
                }

                ui.add_space(4.0);

                if filtered_names.is_empty() {
                    ui.colored_label(COLOR_MUTED, "No entries match.");
                    return;
                }

                egui::ScrollArea::vertical().show(ui, |ui| {
                    for (i, (name, username)) in filtered_names.iter().enumerate() {
                        let is_sel = i == self.selected;
                        let label = if username.is_empty() {
                            name.clone()
                        } else {
                            format!("{} — {}", username, name)
                        };
                        let text = if is_sel {
                            egui::RichText::new(label).color(egui::Color32::WHITE).strong()
                        } else {
                            egui::RichText::new(label)
                        };
                        let resp = ui.add_sized(
                            egui::vec2(ui.available_width(), 26.0),
                            egui::SelectableLabel::new(is_sel, text),
                        );
                        if resp.clicked() {
                            println!("{}", name);
                            std::process::exit(0);
                        }
                        if is_sel {
                            ui.painter().rect_stroke(
                                resp.rect,
                                4.0,
                                egui::Stroke::new(1.0, COLOR_ACCENT),
                            );
                        }
                    }
                });
            });
        }
    }
}

// =================== Theme ===================
fn setup_style(ctx: &egui::Context) {
    let mut style = (*ctx.style()).clone();

    let bg = egui::Color32::from_rgb(0x1e, 0x1e, 0x22);
    let bg_alt = egui::Color32::from_rgb(0x26, 0x26, 0x2c);
    let bg_panel = egui::Color32::from_rgb(0x18, 0x18, 0x1c);
    let bg_hover = egui::Color32::from_rgb(0x33, 0x33, 0x3a);
    let border = egui::Color32::from_rgb(0x33, 0x33, 0x3a);
    let text = egui::Color32::from_rgb(0xdc, 0xdd, 0xde);
    let muted = egui::Color32::from_rgb(0x8e, 0x8e, 0x96);
    let accent = egui::Color32::from_rgb(0x7c, 0x6d, 0xd8);
    let accent_soft = egui::Color32::from_rgba_premultiplied(0x44, 0x3c, 0x82, 0xa0);

    let v = &mut style.visuals;
    v.dark_mode = true;
    v.override_text_color = Some(text);
    v.window_fill = bg;
    v.panel_fill = bg;
    v.faint_bg_color = bg_alt;
    v.extreme_bg_color = bg_panel;
    v.code_bg_color = bg_alt;
    v.window_stroke = egui::Stroke::new(1.0, border);
    v.window_rounding = egui::Rounding::same(8.0);
    v.menu_rounding = egui::Rounding::same(6.0);

    v.widgets.noninteractive.bg_fill = bg_alt;
    v.widgets.noninteractive.weak_bg_fill = bg_alt;
    v.widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, border);
    v.widgets.noninteractive.fg_stroke = egui::Stroke::new(1.0, muted);
    v.widgets.noninteractive.rounding = egui::Rounding::same(5.0);

    v.widgets.inactive.bg_fill = bg_alt;
    v.widgets.inactive.weak_bg_fill = bg_alt;
    v.widgets.inactive.bg_stroke = egui::Stroke::new(1.0, border);
    v.widgets.inactive.fg_stroke = egui::Stroke::new(1.0, text);
    v.widgets.inactive.rounding = egui::Rounding::same(5.0);

    v.widgets.hovered.bg_fill = bg_hover;
    v.widgets.hovered.weak_bg_fill = bg_hover;
    v.widgets.hovered.bg_stroke = egui::Stroke::new(1.0, accent);
    v.widgets.hovered.fg_stroke = egui::Stroke::new(1.5, text);
    v.widgets.hovered.rounding = egui::Rounding::same(5.0);

    v.widgets.active.bg_fill = accent;
    v.widgets.active.weak_bg_fill = accent;
    v.widgets.active.bg_stroke = egui::Stroke::new(1.0, accent);
    v.widgets.active.fg_stroke = egui::Stroke::new(1.5, egui::Color32::WHITE);
    v.widgets.active.rounding = egui::Rounding::same(5.0);

    v.widgets.open.bg_fill = bg_hover;
    v.widgets.open.weak_bg_fill = bg_hover;
    v.widgets.open.bg_stroke = egui::Stroke::new(1.0, accent);
    v.widgets.open.fg_stroke = egui::Stroke::new(1.0, text);
    v.widgets.open.rounding = egui::Rounding::same(5.0);

    v.selection.bg_fill = accent_soft;
    v.selection.stroke = egui::Stroke::new(1.0, accent);
    v.hyperlink_color = accent;

    style.spacing.item_spacing = egui::vec2(8.0, 6.0);
    style.spacing.button_padding = egui::vec2(12.0, 6.0);
    style.spacing.window_margin = egui::Margin::symmetric(16.0, 14.0);
    style.spacing.menu_margin = egui::Margin::symmetric(8.0, 6.0);
    style.spacing.indent = 14.0;

    use egui::{FontFamily, FontId, TextStyle};
    style.text_styles = [
        (TextStyle::Heading, FontId::new(22.0, FontFamily::Proportional)),
        (TextStyle::Body, FontId::new(14.0, FontFamily::Proportional)),
        (TextStyle::Button, FontId::new(13.5, FontFamily::Proportional)),
        (TextStyle::Small, FontId::new(11.5, FontFamily::Proportional)),
        (TextStyle::Monospace, FontId::new(13.0, FontFamily::Monospace)),
    ]
    .into();

    ctx.set_style(style);
}

const COLOR_MUTED: egui::Color32 = egui::Color32::from_rgb(0x8e, 0x8e, 0x96);
const COLOR_ACCENT: egui::Color32 = egui::Color32::from_rgb(0x7c, 0x6d, 0xd8);
const COLOR_ERROR: egui::Color32 = egui::Color32::from_rgb(0xe0, 0x6c, 0x75);
const COLOR_OK: egui::Color32 = egui::Color32::from_rgb(0x98, 0xc3, 0x79);

// =================== State ===================
enum Screen {
    Setup {
        existing: Vec<crate::storage::Account>,
        password: String,
        confirm: String,
    },
    Login {
        vault: EncryptedVault,
        password: String,
        attempts_left: u32,
    },
    LegacyLogin {
        vault: LegacyVerifierVault,
        password: String,
        attempts_left: u32,
    },
    Main {
        session: Session,
        selected: Option<usize>,
        modal: Option<Modal>,
        reveal_password: bool,
    },
    Fatal(String),
}

enum Modal {
    Add {
        name: String,
        username: String,
        password: String,
        show_password: bool,
    },
    Edit {
        idx: usize,
        name: String,
        username: String,
        password: String,
        show_password: bool,
        original_name: String,
    },
    DeleteConfirm {
        idx: usize,
        name: String,
    },
    ChangeMaster {
        current: String,
        new: String,
        confirm: String,
    },
    HotkeySettings {
        current: HotkeyConfig,
        capturing: bool,
        message: Option<(String, bool)>, // (text, is_error)
    },
}

impl Drop for Modal {
    fn drop(&mut self) {
        match self {
            Modal::Add {
                name,
                username,
                password,
                ..
            } => {
                name.zeroize();
                username.zeroize();
                password.zeroize();
            }
            Modal::Edit {
                name,
                username,
                password,
                original_name,
                ..
            } => {
                name.zeroize();
                username.zeroize();
                password.zeroize();
                original_name.zeroize();
            }
            Modal::DeleteConfirm { name, .. } => {
                name.zeroize();
            }
            Modal::ChangeMaster {
                current,
                new,
                confirm,
            } => {
                current.zeroize();
                new.zeroize();
                confirm.zeroize();
            }
            Modal::HotkeySettings { .. } => {
                // No sensitive fields.
            }
        }
    }
}

struct App {
    screen: Screen,
    error: String,
    info: String,
    clipboard_clear_at: Option<Instant>,
}

impl App {
    fn new() -> Self {
        let screen = match session::initial_state() {
            InitialState::NeedsSetup(existing) => Screen::Setup {
                existing,
                password: String::new(),
                confirm: String::new(),
            },
            InitialState::NeedsLogin(vault) => Screen::Login {
                vault,
                password: String::new(),
                attempts_left: MAX_LOGIN_ATTEMPTS,
            },
            InitialState::NeedsLoginLegacy(vault) => Screen::LegacyLogin {
                vault,
                password: String::new(),
                attempts_left: MAX_LOGIN_ATTEMPTS,
            },
            InitialState::Corrupted => {
                Screen::Fatal("Vault file is unreadable or corrupted.".to_string())
            }
            InitialState::IoError(e) => Screen::Fatal(format!("Failed to read vault: {}", e)),
        };
        Self {
            screen,
            error: String::new(),
            info: String::new(),
            clipboard_clear_at: None,
        }
    }
}

// =================== Clipboard ===================
fn copy_to_clipboard(text: &str) -> Result<(), String> {
    let mut cb = arboard::Clipboard::new().map_err(|e| e.to_string())?;
    cb.set_text(text.to_string()).map_err(|e| e.to_string())?;
    Ok(())
}

fn clear_clipboard() {
    if let Ok(mut cb) = arboard::Clipboard::new() {
        let _ = cb.set_text(String::new());
    }
}

// =================== eframe::App ===================
impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if let Some(at) = self.clipboard_clear_at {
            if Instant::now() >= at {
                clear_clipboard();
                self.clipboard_clear_at = None;
                self.info = "Clipboard cleared.".to_string();
            } else {
                ctx.request_repaint_after(Duration::from_millis(500));
            }
        }

        let is_main = matches!(self.screen, Screen::Main { .. });
        if is_main {
            self.render_main_layout(ctx);
        } else {
            egui::CentralPanel::default().show(ctx, |ui| {
                self.render_centered(ui, ctx);
            });
        }
    }
}

// =================== Centered screens ===================
impl App {
    fn render_centered(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        let App {
            screen,
            error,
            info,
            ..
        } = self;
        let mut next: Option<Screen> = None;

        ui.vertical_centered(|ui| {
            ui.add_space(60.0);
            ui.allocate_ui_with_layout(
                egui::vec2(380.0, 0.0),
                egui::Layout::top_down(egui::Align::Min),
                |ui| match screen {
                    Screen::Setup {
                        existing,
                        password,
                        confirm,
                    } => {
                        next = render_setup(ui, existing, password, confirm, error, info);
                    }
                    Screen::Login {
                        vault,
                        password,
                        attempts_left,
                    } => {
                        next = render_login(ui, vault, password, attempts_left, error, info);
                    }
                    Screen::LegacyLogin {
                        vault,
                        password,
                        attempts_left,
                    } => {
                        next =
                            render_legacy_login(ui, vault, password, attempts_left, error, info);
                    }
                    Screen::Fatal(msg) => {
                        ui.heading("Something's wrong");
                        ui.add_space(8.0);
                        ui.label(msg.as_str());
                        ui.add_space(12.0);
                        if ui.button("Quit").clicked() {
                            ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    }
                    Screen::Main { .. } => {}
                },
            );
        });

        if let Some(n) = next {
            self.screen = n;
        }
    }
}

fn card_heading(ui: &mut egui::Ui, title: &str, subtitle: Option<&str>) {
    ui.heading(title);
    if let Some(s) = subtitle {
        ui.colored_label(COLOR_MUTED, s);
    }
    ui.add_space(14.0);
}

fn labeled_password_field(ui: &mut egui::Ui, label: &str, value: &mut String) -> egui::Response {
    ui.colored_label(COLOR_MUTED, label);
    ui.add(
        egui::TextEdit::singleline(value)
            .password(true)
            .desired_width(f32::INFINITY)
            .margin(egui::vec2(8.0, 6.0)),
    )
}

fn primary_button(ui: &mut egui::Ui, label: &str) -> egui::Response {
    let btn = egui::Button::new(egui::RichText::new(label).strong())
        .fill(COLOR_ACCENT)
        .min_size(egui::vec2(120.0, 32.0));
    ui.add(btn)
}

fn render_setup(
    ui: &mut egui::Ui,
    existing: &mut Vec<crate::storage::Account>,
    password: &mut String,
    confirm: &mut String,
    error: &mut String,
    info: &mut String,
) -> Option<Screen> {
    let subtitle = if existing.is_empty() {
        format!("Choose a master password (min {} characters).", MIN_MASTER_PASSWORD_LEN)
    } else {
        format!(
            "{} existing account(s) will be encrypted with your new master password.",
            existing.len()
        )
    };
    card_heading(ui, "Create your vault", Some(&subtitle));

    labeled_password_field(ui, "Master password", password);
    ui.add_space(6.0);
    labeled_password_field(ui, "Confirm master password", confirm);
    ui.add_space(14.0);

    let mut next = None;
    if primary_button(ui, "Create vault").clicked() {
        if password.len() < MIN_MASTER_PASSWORD_LEN {
            *error = format!(
                "Password must be at least {} characters.",
                MIN_MASTER_PASSWORD_LEN
            );
        } else if password != confirm {
            *error = "Passwords do not match.".to_string();
        } else {
            let pw_bytes = password.as_bytes().to_vec();
            let existing_take = std::mem::take(existing);
            password.zeroize();
            confirm.zeroize();
            match session::setup(&pw_bytes, existing_take) {
                Ok(s) => {
                    error.clear();
                    *info = "Vault created.".to_string();
                    next = Some(Screen::Main {
                        session: s,
                        selected: None,
                        modal: None,
                        reveal_password: false,
                    });
                }
                Err(e) => {
                    *error = format!("Failed to write vault: {}", e);
                }
            }
        }
    }

    render_status(ui, error, info);
    next
}

fn render_login(
    ui: &mut egui::Ui,
    vault: &EncryptedVault,
    password: &mut String,
    attempts_left: &mut u32,
    error: &mut String,
    info: &mut String,
) -> Option<Screen> {
    card_heading(ui, "Unlock vault", Some("Enter your master password."));

    let resp = labeled_password_field(ui, "Master password", password);
    let submit = (resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)))
        || {
            ui.add_space(14.0);
            primary_button(ui, "Unlock").clicked()
        };

    let mut next = None;
    if submit {
        let pw_bytes = password.as_bytes().to_vec();
        match session::login(vault, &pw_bytes) {
            Ok(s) => {
                password.zeroize();
                error.clear();
                *info = "Unlocked.".to_string();
                next = Some(Screen::Main {
                    session: s,
                    selected: None,
                    modal: None,
                    reveal_password: false,
                });
            }
            Err(_) => {
                password.zeroize();
                *attempts_left = attempts_left.saturating_sub(1);
                if *attempts_left == 0 {
                    next = Some(Screen::Fatal("Too many failed attempts.".to_string()));
                } else {
                    *error = format!(
                        "Wrong password. {} attempt(s) remaining.",
                        *attempts_left
                    );
                }
            }
        }
    }

    render_status(ui, error, info);
    next
}

fn render_legacy_login(
    ui: &mut egui::Ui,
    vault: &LegacyVerifierVault,
    password: &mut String,
    attempts_left: &mut u32,
    error: &mut String,
    info: &mut String,
) -> Option<Screen> {
    card_heading(
        ui,
        "Unlock vault",
        Some("Legacy format detected — vault will be upgraded after login."),
    );

    labeled_password_field(ui, "Master password", password);
    ui.add_space(14.0);

    let mut next = None;
    if primary_button(ui, "Unlock").clicked() {
        let pw_bytes = password.as_bytes().to_vec();
        match session::login_legacy(vault, &pw_bytes) {
            Ok(s) => {
                password.zeroize();
                error.clear();
                *info = "Unlocked. Vault upgraded.".to_string();
                next = Some(Screen::Main {
                    session: s,
                    selected: None,
                    modal: None,
                    reveal_password: false,
                });
            }
            Err(_) => {
                password.zeroize();
                *attempts_left = attempts_left.saturating_sub(1);
                if *attempts_left == 0 {
                    next = Some(Screen::Fatal("Too many failed attempts.".to_string()));
                } else {
                    *error = format!(
                        "Wrong password. {} attempt(s) remaining.",
                        *attempts_left
                    );
                }
            }
        }
    }

    render_status(ui, error, info);
    next
}

fn render_status(ui: &mut egui::Ui, error: &str, info: &str) {
    ui.add_space(10.0);
    if !error.is_empty() {
        ui.colored_label(COLOR_ERROR, error);
    } else if !info.is_empty() {
        ui.colored_label(COLOR_OK, info);
    }
}

// =================== Main layout ===================
impl App {
    fn render_main_layout(&mut self, ctx: &egui::Context) {
        let App {
            screen,
            error,
            info,
            clipboard_clear_at,
        } = self;

        let (session, selected, modal, reveal) = match screen {
            Screen::Main {
                session,
                selected,
                modal,
                reveal_password,
            } => (session, selected, modal, reveal_password),
            _ => return,
        };

        let mut next: Option<Screen> = None;
        let mut copy_request: Option<usize> = None;
        let mut lock_request = false;

        // Top bar
        egui::TopBottomPanel::top("topbar")
            .exact_height(48.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add_space(6.0);
                    ui.label(
                        egui::RichText::new("Vault")
                            .heading()
                            .color(egui::Color32::WHITE),
                    );
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            ui.add_space(4.0);
                            if ui.button("Lock").clicked() {
                                lock_request = true;
                            }
                            if ui.button("Change master").clicked() {
                                *modal = Some(Modal::ChangeMaster {
                                    current: String::new(),
                                    new: String::new(),
                                    confirm: String::new(),
                                });
                            }
                            if ui.button("Settings").clicked() {
                                *modal = Some(Modal::HotkeySettings {
                                    current: app_config::load().hotkey,
                                    capturing: false,
                                    message: None,
                                });
                            }
                        },
                    );
                });
            });

        // Sidebar
        egui::SidePanel::left("sidebar")
            .resizable(false)
            .exact_width(240.0)
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(0x18, 0x18, 0x1c))
                    .inner_margin(egui::Margin::symmetric(10.0, 12.0)),
            )
            .show(ctx, |ui| {
                let new_btn = egui::Button::new(
                    egui::RichText::new("+ New account").strong(),
                )
                .min_size(egui::vec2(ui.available_width(), 30.0))
                .fill(COLOR_ACCENT);
                if ui.add(new_btn).clicked() {
                    *modal = Some(Modal::Add {
                        name: String::new(),
                        username: String::new(),
                        password: String::new(),
                        show_password: false,
                    });
                }

                ui.add_space(10.0);
                ui.colored_label(
                    COLOR_MUTED,
                    egui::RichText::new(format!(
                        "ACCOUNTS  ({})",
                        session.accounts.len()
                    ))
                    .small(),
                );
                ui.add_space(4.0);

                if session.accounts.is_empty() {
                    ui.add_space(12.0);
                    ui.colored_label(COLOR_MUTED, "No accounts yet.");
                } else {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for (i, account) in session.accounts.iter().enumerate() {
                            let is_sel = *selected == Some(i);
                            let label = egui::RichText::new(&account.name)
                                .color(if is_sel {
                                    egui::Color32::WHITE
                                } else {
                                    egui::Color32::from_rgb(0xdc, 0xdd, 0xde)
                                });
                            let btn = egui::SelectableLabel::new(is_sel, label);
                            let resp = ui.add_sized(
                                egui::vec2(ui.available_width(), 26.0),
                                btn,
                            );
                            if resp.clicked() {
                                *selected = Some(i);
                                *reveal = false;
                            }
                            if resp.double_clicked() {
                                *selected = Some(i);
                                copy_request = Some(i);
                            }
                        }
                    });
                }
            });

        // Bottom status bar
        egui::TopBottomPanel::bottom("statusbar")
            .exact_height(28.0)
            .show(ctx, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.add_space(8.0);
                    if !error.is_empty() {
                        ui.colored_label(COLOR_ERROR, error.as_str());
                    } else if !info.is_empty() {
                        ui.colored_label(COLOR_OK, info.as_str());
                    } else {
                        ui.colored_label(
                            COLOR_MUTED,
                            format!("{} account(s) in vault", session.accounts.len()),
                        );
                    }
                });
            });

        // Central detail
        egui::CentralPanel::default()
            .frame(
                egui::Frame::default()
                    .fill(egui::Color32::from_rgb(0x1e, 0x1e, 0x22))
                    .inner_margin(egui::Margin::symmetric(28.0, 24.0)),
            )
            .show(ctx, |ui| {
                let sel_idx = match selected.as_ref().copied() {
                    Some(i) if i < session.accounts.len() => Some(i),
                    _ => None,
                };

                match sel_idx {
                    None => {
                        ui.vertical_centered(|ui| {
                            ui.add_space(80.0);
                            ui.colored_label(
                                COLOR_MUTED,
                                egui::RichText::new("Select an account").size(18.0),
                            );
                            ui.add_space(6.0);
                            ui.colored_label(
                                COLOR_MUTED,
                                "or click \u{2018}+ New account\u{2019} to create one.",
                            );
                        });
                    }
                    Some(idx) => {
                        let account = &session.accounts[idx];
                        ui.heading(&account.name);
                        ui.add_space(2.0);
                        if account.username.is_empty() {
                            ui.colored_label(COLOR_MUTED, "Stored credential");
                        } else {
                            ui.colored_label(
                                COLOR_MUTED,
                                format!("Username: {}", account.username),
                            );
                        }
                        ui.add_space(20.0);

                        ui.colored_label(COLOR_MUTED, "PASSWORD");
                        ui.add_space(4.0);

                        ui.horizontal(|ui| {
                            let display = if *reveal {
                                account.password.clone()
                            } else {
                                "\u{2022}".repeat(account.password.chars().count().max(8))
                            };
                            let mut display_mut = display;
                            ui.add_sized(
                                egui::vec2(ui.available_width() - 200.0, 28.0),
                                egui::TextEdit::singleline(&mut display_mut)
                                    .interactive(false)
                                    .font(egui::TextStyle::Monospace)
                                    .margin(egui::vec2(8.0, 6.0)),
                            );
                            if ui
                                .add_sized(
                                    egui::vec2(70.0, 28.0),
                                    egui::Button::new(if *reveal { "Hide" } else { "Show" }),
                                )
                                .clicked()
                            {
                                *reveal = !*reveal;
                            }
                            if ui
                                .add_sized(
                                    egui::vec2(110.0, 28.0),
                                    egui::Button::new(
                                        egui::RichText::new("Copy").strong(),
                                    )
                                    .fill(COLOR_ACCENT),
                                )
                                .clicked()
                            {
                                copy_request = Some(idx);
                            }
                        });

                        ui.add_space(28.0);
                        ui.separator();
                        ui.add_space(14.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_sized(egui::vec2(90.0, 30.0), egui::Button::new("Edit"))
                                .clicked()
                            {
                                *modal = Some(Modal::Edit {
                                    idx,
                                    name: account.name.clone(),
                                    username: account.username.clone(),
                                    password: account.password.clone(),
                                    show_password: false,
                                    original_name: account.name.clone(),
                                });
                            }
                            if ui
                                .add_sized(
                                    egui::vec2(90.0, 30.0),
                                    egui::Button::new(
                                        egui::RichText::new("Delete").color(COLOR_ERROR),
                                    ),
                                )
                                .clicked()
                            {
                                *modal = Some(Modal::DeleteConfirm {
                                    idx,
                                    name: account.name.clone(),
                                });
                            }
                        });
                    }
                }
            });

        // Modals
        let mut modal_taken = modal.take();
        if let Some(m) = modal_taken.as_mut() {
            let res = render_modal(ctx, m, session);
            match res {
                ModalResult::Keep => *modal = modal_taken,
                ModalResult::Close => {}
                ModalResult::CloseWithInfo(msg) => {
                    *info = msg;
                    error.clear();
                }
                ModalResult::CloseWithError(msg) => {
                    *error = msg;
                }
                ModalResult::DeleteSelected => {
                    *selected = None;
                    *info = "Account deleted.".to_string();
                    error.clear();
                }
            }
        }

        // Handle queued actions
        if let Some(idx) = copy_request {
            if idx < session.accounts.len() {
                let pw = session.accounts[idx].password.clone();
                match copy_to_clipboard(&pw) {
                    Ok(_) => {
                        *clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR);
                        *info =
                            format!("Copied. Clears in {}s.", CLIPBOARD_CLEAR.as_secs());
                        error.clear();
                    }
                    Err(e) => *error = format!("Clipboard error: {}", e),
                }
            }
        }

        if lock_request {
            if let InitialState::NeedsLogin(vault) = session::initial_state() {
                next = Some(Screen::Login {
                    vault,
                    password: String::new(),
                    attempts_left: MAX_LOGIN_ATTEMPTS,
                });
            }
        }

        if let Some(n) = next {
            self.screen = n;
        }
    }
}

// =================== Modals ===================
enum ModalResult {
    Keep,
    Close,
    CloseWithInfo(String),
    CloseWithError(String),
    DeleteSelected,
}

fn render_modal(ctx: &egui::Context, modal: &mut Modal, session: &mut Session) -> ModalResult {
    let mut result = ModalResult::Keep;
    let title = match modal {
        Modal::Add { .. } => "New account",
        Modal::Edit { .. } => "Edit account",
        Modal::DeleteConfirm { .. } => "Delete account",
        Modal::ChangeMaster { .. } => "Change master password",
        Modal::HotkeySettings { .. } => "Settings",
    };

    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(360.0)
        .show(ctx, |ui| match modal {
            Modal::Add {
                name,
                username,
                password,
                show_password,
            } => {
                ui.colored_label(COLOR_MUTED, "Name (e.g. site / app)");
                ui.add(
                    egui::TextEdit::singleline(name)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Username (optional)");
                ui.add(
                    egui::TextEdit::singleline(username)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Password");
                ui.add(
                    egui::TextEdit::singleline(password)
                        .password(!*show_password)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(4.0);
                ui.checkbox(show_password, "Show password");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let create = egui::Button::new(
                        egui::RichText::new("Create").strong(),
                    )
                    .fill(COLOR_ACCENT)
                    .min_size(egui::vec2(90.0, 28.0));
                    if ui.add(create).clicked() {
                        if name.trim().is_empty() {
                            result = ModalResult::CloseWithError(
                                "Name cannot be empty.".to_string(),
                            );
                            return;
                        }
                        let n = std::mem::take(name);
                        let u = std::mem::take(username);
                        let p = std::mem::take(password);
                        match session.add_account(n, u, p) {
                            Ok(_) => {
                                result =
                                    ModalResult::CloseWithInfo("Account added.".to_string())
                            }
                            Err(e) => {
                                result = ModalResult::CloseWithError(format!(
                                    "Failed to save: {}",
                                    e
                                ))
                            }
                        }
                    }
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                });
            }

            Modal::Edit {
                idx,
                name,
                username,
                password,
                show_password,
                original_name,
            } => {
                ui.colored_label(
                    COLOR_MUTED,
                    format!("Editing \u{201c}{}\u{201d}", original_name),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Name");
                ui.add(
                    egui::TextEdit::singleline(name)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Username");
                ui.add(
                    egui::TextEdit::singleline(username)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Password");
                ui.add(
                    egui::TextEdit::singleline(password)
                        .password(!*show_password)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(4.0);
                ui.checkbox(show_password, "Show password");
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let save = egui::Button::new(
                        egui::RichText::new("Save").strong(),
                    )
                    .fill(COLOR_ACCENT)
                    .min_size(egui::vec2(90.0, 28.0));
                    if ui.add(save).clicked() {
                        if name.trim().is_empty() {
                            result = ModalResult::CloseWithError(
                                "Name cannot be empty.".to_string(),
                            );
                            return;
                        }
                        let n = std::mem::take(name);
                        let u = std::mem::take(username);
                        let p = std::mem::take(password);
                        match session.edit_account(*idx, Some(n), Some(u), Some(p)) {
                            Ok(_) => {
                                result =
                                    ModalResult::CloseWithInfo("Account updated.".to_string())
                            }
                            Err(e) => {
                                result = ModalResult::CloseWithError(format!(
                                    "Failed to save: {}",
                                    e
                                ))
                            }
                        }
                    }
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                });
            }

            Modal::DeleteConfirm { idx, name } => {
                ui.label(format!(
                    "Delete \u{201c}{}\u{201d}? This cannot be undone.",
                    name
                ));
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let del = egui::Button::new(
                        egui::RichText::new("Delete").color(egui::Color32::WHITE).strong(),
                    )
                    .fill(COLOR_ERROR)
                    .min_size(egui::vec2(90.0, 28.0));
                    if ui.add(del).clicked() {
                        match session.delete_account(*idx) {
                            Ok(_) => result = ModalResult::DeleteSelected,
                            Err(e) => {
                                result = ModalResult::CloseWithError(format!(
                                    "Failed to save: {}",
                                    e
                                ))
                            }
                        }
                    }
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                });
            }

            Modal::ChangeMaster {
                current,
                new,
                confirm,
            } => {
                ui.colored_label(COLOR_MUTED, "Current master password");
                ui.add(
                    egui::TextEdit::singleline(current)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "New master password");
                ui.add(
                    egui::TextEdit::singleline(new)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Confirm new master password");
                ui.add(
                    egui::TextEdit::singleline(confirm)
                        .password(true)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(12.0);
                ui.horizontal(|ui| {
                    let save = egui::Button::new(
                        egui::RichText::new("Save").strong(),
                    )
                    .fill(COLOR_ACCENT)
                    .min_size(egui::vec2(90.0, 28.0));
                    if ui.add(save).clicked() {
                        if new.len() < MIN_MASTER_PASSWORD_LEN {
                            result = ModalResult::CloseWithError(format!(
                                "Password must be at least {} characters.",
                                MIN_MASTER_PASSWORD_LEN
                            ));
                            return;
                        }
                        if new != confirm {
                            result = ModalResult::CloseWithError(
                                "Passwords do not match.".to_string(),
                            );
                            return;
                        }
                        let cur_bytes = current.as_bytes().to_vec();
                        let new_bytes = new.as_bytes().to_vec();
                        match session.change_master_password(&cur_bytes, &new_bytes) {
                            Ok(_) => {
                                result = ModalResult::CloseWithInfo(
                                    "Master password changed.".to_string(),
                                )
                            }
                            Err(ChangeMasterError::WrongCurrent) => {
                                result = ModalResult::CloseWithError(
                                    "Wrong current master password.".to_string(),
                                );
                            }
                            Err(ChangeMasterError::Io(e)) => {
                                result = ModalResult::CloseWithError(format!(
                                    "Failed to save: {}",
                                    e
                                ));
                            }
                        }
                    }
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                });
            }

            Modal::HotkeySettings {
                current,
                capturing,
                message,
            } => {
                ui.colored_label(
                    COLOR_MUTED,
                    "Auto-type hotkey for native apps (e.g. Steam, Discord).",
                );
                ui.add_space(8.0);

                if *capturing {
                    ui.heading("Press your hotkey…");
                    ui.add_space(4.0);
                    ui.colored_label(
                        COLOR_MUTED,
                        "Hold modifiers (Ctrl, Alt, Shift, Super) and press a letter / digit / F-key.",
                    );
                    ui.add_space(4.0);
                    ui.colored_label(COLOR_MUTED, "Esc to cancel.");
                    ui.add_space(8.0);

                    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                        *capturing = false;
                    } else {
                        let captured = ctx.input(|i| {
                            let mods = i.modifiers;
                            for event in &i.events {
                                if let egui::Event::Key {
                                    key, pressed: true, ..
                                } = event
                                {
                                    if let Some(name) = egui_key_to_config_key(*key) {
                                        return Some((mods, name));
                                    }
                                }
                            }
                            None
                        });
                        if let Some((mods, key_name)) = captured {
                            let mut modifiers: Vec<String> = Vec::new();
                            if mods.ctrl {
                                modifiers.push("ctrl".into());
                            }
                            if mods.alt {
                                modifiers.push("alt".into());
                            }
                            if mods.shift {
                                modifiers.push("shift".into());
                            }
                            if mods.command {
                                modifiers.push("super".into());
                            }
                            // Reject Shift-only and no-modifier hotkeys: they
                            // collide with normal text input (capital letters,
                            // shifted symbols), and X11 typically refuses to
                            // grab Shift+letter anyway. Require at least one
                            // of Ctrl / Alt / Super.
                            let has_strong_modifier =
                                mods.ctrl || mods.alt || mods.command;
                            if !has_strong_modifier {
                                *message = Some((
                                    "Hotkey must include Ctrl, Alt, or Super. Shift alone collides with capital-letter typing and X11 won't grab it.".to_string(),
                                    true,
                                ));
                                *capturing = false;
                            } else {
                                *current = HotkeyConfig {
                                    modifiers,
                                    key: key_name,
                                };
                                let cfg = app_config::Config {
                                    hotkey: current.clone(),
                                };
                                match app_config::save(&cfg) {
                                    Ok(_) => {
                                        *message = Some((
                                            format!("Saved: {}", current.human()),
                                            false,
                                        ));
                                    }
                                    Err(e) => {
                                        *message =
                                            Some((format!("Save failed: {}", e), true));
                                    }
                                }
                                *capturing = false;
                            }
                        }
                    }
                } else {
                    ui.label(format!("Current hotkey: {}", current.human()));
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        let change = egui::Button::new(
                            egui::RichText::new("Change…").strong(),
                        )
                        .fill(COLOR_ACCENT)
                        .min_size(egui::vec2(110.0, 28.0));
                        if ui.add(change).clicked() {
                            *capturing = true;
                            *message = None;
                        }
                        if ui
                            .add_sized(
                                egui::vec2(110.0, 28.0),
                                egui::Button::new("Reset to default"),
                            )
                            .clicked()
                        {
                            *current = HotkeyConfig {
                                modifiers: vec!["ctrl".into(), "alt".into()],
                                key: "p".into(),
                            };
                            let cfg = app_config::Config {
                                hotkey: current.clone(),
                            };
                            match app_config::save(&cfg) {
                                Ok(_) => {
                                    *message = Some((
                                        format!("Reset to {}", current.human()),
                                        false,
                                    ))
                                }
                                Err(e) => {
                                    *message = Some((format!("Save failed: {}", e), true))
                                }
                            }
                        }
                    });
                    ui.add_space(10.0);
                    ui.colored_label(
                        COLOR_MUTED,
                        "Auto-type changes apply within ~2 seconds (the helper polls the config file).",
                    );
                    ui.add_space(2.0);
                    ui.colored_label(
                        COLOR_MUTED,
                        "Requires `xdotool` installed and `passwort-autotype` running.",
                    );
                }

                if let Some((msg, is_err)) = message {
                    ui.add_space(10.0);
                    let color = if *is_err { COLOR_ERROR } else { COLOR_OK };
                    ui.colored_label(color, msg.as_str());
                }

                ui.add_space(14.0);
                if ui
                    .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Close"))
                    .clicked()
                {
                    result = ModalResult::Close;
                }
            }
        });

    result
}

fn egui_key_to_config_key(k: egui::Key) -> Option<String> {
    use egui::Key::*;
    let s = match k {
        A => "a", B => "b", C => "c", D => "d", E => "e", F => "f",
        G => "g", H => "h", I => "i", J => "j", K => "k", L => "l",
        M => "m", N => "n", O => "o", P => "p", Q => "q", R => "r",
        S => "s", T => "t", U => "u", V => "v", W => "w", X => "x",
        Y => "y", Z => "z",
        Num0 => "0", Num1 => "1", Num2 => "2", Num3 => "3", Num4 => "4",
        Num5 => "5", Num6 => "6", Num7 => "7", Num8 => "8", Num9 => "9",
        F1 => "f1", F2 => "f2", F3 => "f3", F4 => "f4",
        F5 => "f5", F6 => "f6", F7 => "f7", F8 => "f8",
        F9 => "f9", F10 => "f10", F11 => "f11", F12 => "f12",
        Space => "space",
        Enter => "enter",
        _ => return None,
    };
    Some(s.to_string())
}
