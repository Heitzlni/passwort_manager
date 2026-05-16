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
    eprintln!("[picker] starting, target={:?}", target_title);
    eprintln!(
        "[picker] DISPLAY={:?} XDG_SESSION_TYPE={:?}",
        std::env::var_os("DISPLAY"),
        std::env::var_os("XDG_SESSION_TYPE")
    );
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([460.0, 360.0])
            .with_resizable(false)
            .with_decorations(true)
            .with_always_on_top()
            .with_title("Password Manager — Pick"),
        centered: true,
        ..Default::default()
    };
    let result = eframe::run_native(
        "Password Manager — Pick",
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            eprintln!("[picker] creator callback invoked, building PickerApp");
            Box::new(picker::PickerApp::new(target_title))
        }),
    );
    eprintln!("[picker] eframe::run_native returned: {:?}", result.as_ref().err());
    result
}

/// Quick-save mode: shown by `passwort-manager --quick-save` when the
/// auto-type daemon's save hotkey fires. Small dialog with name (pre-filled
/// from the active window's title), username, and password fields.
/// Calls the daemon's Save RPC and exits.
pub fn run_quick_save(target_title: Option<String>) -> Result<(), eframe::Error> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([420.0, 260.0])
            .with_resizable(false)
            .with_decorations(true)
            .with_always_on_top()
            .with_title("Save credential"),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "Save credential",
        options,
        Box::new(|cc| {
            setup_style(&cc.egui_ctx);
            Box::new(quick_save::QuickSaveApp::new(target_title))
        }),
    )
}

mod quick_save {
    use super::{COLOR_ACCENT, COLOR_ERROR, COLOR_MUTED, COLOR_OK};
    use crate::ipc::{self, Request, Response};
    use eframe::egui;
    use zeroize::Zeroize;

    pub struct QuickSaveApp {
        name: String,
        username: String,
        password: String,
        show_password: bool,
        message: Option<(String, bool)>, // (text, is_error)
        saved: bool,
    }

    impl QuickSaveApp {
        pub fn new(target_title: Option<String>) -> Self {
            Self {
                name: target_title
                    .map(|t| sanitize_title(&t))
                    .unwrap_or_default(),
                username: String::new(),
                password: String::new(),
                show_password: false,
                message: None,
                saved: false,
            }
        }
    }

    impl Drop for QuickSaveApp {
        fn drop(&mut self) {
            self.username.zeroize();
            self.password.zeroize();
        }
    }

    impl eframe::App for QuickSaveApp {
        fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
            if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                std::process::exit(if self.saved { 0 } else { 1 });
            }

            egui::CentralPanel::default().show(ctx, |ui| {
                ui.colored_label(COLOR_MUTED, "Save credential for the active app");
                ui.add_space(8.0);

                ui.label("Name");
                ui.add(
                    egui::TextEdit::singleline(&mut self.name)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(6.0);

                ui.label("Username");
                ui.add(
                    egui::TextEdit::singleline(&mut self.username)
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(6.0);

                ui.label("Password");
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.password)
                            .password(!self.show_password)
                            .desired_width(ui.available_width() - 70.0)
                            .margin(egui::vec2(8.0, 6.0)),
                    );
                    ui.checkbox(&mut self.show_password, "show");
                });
                ui.add_space(10.0);

                ui.horizontal(|ui| {
                    let save_btn = egui::Button::new(
                        egui::RichText::new("Save").strong(),
                    )
                    .fill(COLOR_ACCENT)
                    .min_size(egui::vec2(100.0, 28.0));
                    let save_clicked = ui.add(save_btn).clicked()
                        || ctx.input(|i| i.key_pressed(egui::Key::Enter));
                    if save_clicked {
                        if self.name.trim().is_empty() {
                            self.message = Some(("Name is required.".into(), true));
                        } else if self.password.is_empty() {
                            self.message = Some(("Password is required.".into(), true));
                        } else {
                            let req = Request::Save {
                                name: self.name.clone(),
                                username: self.username.clone(),
                                password: self.password.clone(),
                            };
                            match ipc::rpc_authed("passwort-quick-save", &req) {
                                Ok(Response::Ok) => {
                                    self.saved = true;
                                    self.message = Some((
                                        format!("Saved \u{201c}{}\u{201d}.", self.name),
                                        false,
                                    ));
                                    self.password.zeroize();
                                    self.username.zeroize();
                                }
                                Ok(Response::Error { code, message }) => {
                                    let msg = if code == "locked" {
                                        "Vault is locked. Open the toolbar or GUI to unlock, then try again.".into()
                                    } else {
                                        message
                                    };
                                    self.message = Some((msg, true));
                                }
                                Ok(_) => {
                                    self.message =
                                        Some(("Unexpected response from daemon.".into(), true))
                                }
                                Err(e) => self.message = Some((e.to_string(), true)),
                            }
                        }
                    }
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                        .clicked()
                    {
                        std::process::exit(if self.saved { 0 } else { 1 });
                    }
                });

                if let Some((msg, is_err)) = &self.message {
                    ui.add_space(8.0);
                    let color = if *is_err { COLOR_ERROR } else { COLOR_OK };
                    ui.colored_label(color, msg.as_str());
                }
            });
        }
    }

    /// Trim common window-title noise: " — Mozilla Firefox", " - Chromium",
    /// " — Login", trailing parens, and so on. Keeps the meaningful name
    /// the user is most likely to want for the entry.
    fn sanitize_title(t: &str) -> String {
        let lower_strip = [
            " - mozilla firefox",
            " — mozilla firefox",
            " - google chrome",
            " — google chrome",
            " - chromium",
            " — chromium",
            " - brave",
            " — brave",
            " - microsoft edge",
            " — microsoft edge",
            " - sign in",
            " — sign in",
            " - login",
            " — login",
            " - log in",
            " — log in",
        ];
        let mut s = t.trim().to_string();
        loop {
            let lower = s.to_lowercase();
            let mut shortened = false;
            for suffix in &lower_strip {
                if lower.ends_with(suffix) {
                    s.truncate(s.len() - suffix.len());
                    shortened = true;
                    break;
                }
            }
            if !shortened {
                break;
            }
        }
        s.trim().to_string()
    }
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
        first_frame: bool,
    }

    impl PickerApp {
        pub fn new(target_title: Option<String>) -> Self {
            let (entries, load_error) = match ipc::rpc_authed("passwort-picker", &Request::ListEntries) {
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
            eprintln!(
                "[picker] PickerApp built: {} entries, load_error={:?}",
                entries.len(),
                load_error
            );
            Self {
                entries,
                filter: String::new(),
                selected: 0,
                target_title,
                load_error,
                first_frame: true,
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
            if self.first_frame {
                self.first_frame = false;
                eprintln!("[picker] first frame — window should now be visible");
            }
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

#[derive(Clone, Copy, PartialEq, Eq)]
enum HotkeySlot {
    Fill,
    Save,
}

enum Modal {
    Add {
        name: String,
        username: String,
        password: String,
        totp_secret: String,
        notes: String,
        show_password: bool,
    },
    Edit {
        idx: usize,
        name: String,
        username: String,
        password: String,
        totp_secret: String,
        notes: String,
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
        fill: HotkeyConfig,
        save: HotkeyConfig,
        /// None = not capturing; Some(HotkeySlot) = capturing for that slot.
        capturing: Option<HotkeySlot>,
        message: Option<(String, bool)>, // (text, is_error)
    },
    Audit {
        /// Shared with the worker thread. Mutex guards a small struct of
        /// progress + accumulated results. Each frame the modal grabs the
        /// lock briefly, snapshots the state, and re-renders.
        progress: std::sync::Arc<std::sync::Mutex<AuditProgress>>,
        /// `None` until the user clicks Run. `Some(_)` once the worker is
        /// alive — kept here so it doesn't get joined/dropped while we
        /// still want results.
        worker: Option<std::thread::JoinHandle<()>>,
    },
    Export {
        /// User toggle: write a bundle (vault + config) instead of a raw vault.
        with_config: bool,
        /// Resulting backup path once the file's been written. None until
        /// the user clicks Export.
        result: Option<Result<std::path::PathBuf, String>>,
    },
    /// Live "authenticator" view: every account that has a TOTP secret,
    /// with its current 6-digit code + countdown, refreshed each second.
    /// No fields — reads from the live session every frame.
    Tokens,
    Import {
        /// Path the user picked, or empty until they click Browse.
        path: String,
        /// merge=true → add to existing; merge=false → replace.
        merge: bool,
        /// Apply imported config (only meaningful for bundle files).
        apply_config: bool,
        /// Master password for the imported file (might differ from current).
        password: String,
        /// Hide/show the password field.
        show_password: bool,
        /// Result of the last attempt: Some(Ok(message)) or Some(Err(message)).
        result: Option<Result<String, String>>,
        /// Receiver for the file picker worker thread. `None` when no
        /// picker is active. We poll this each frame; if the user picked
        /// a file (or cancelled / hit an error), we drain it back into
        /// `path`. Running the picker on a worker thread keeps any
        /// rfd / xdg-desktop-portal panic from bringing down the app and
        /// avoids fighting egui for the display-server event queue.
        chooser_rx: Option<std::sync::mpsc::Receiver<Result<Option<std::path::PathBuf>, String>>>,
    },
}

#[derive(Default)]
pub struct AuditProgress {
    pub total: usize,
    pub done: usize,
    pub results: Vec<crate::ipc::PwnedEntry>,
    pub finished: bool,
    /// Set by the worker if HIBP is disabled in config or another global
    /// failure happened — short-circuits the progress display.
    pub fatal_error: Option<String>,
}

impl Drop for Modal {
    fn drop(&mut self) {
        match self {
            Modal::Add {
                name,
                username,
                password,
                totp_secret,
                notes,
                ..
            } => {
                name.zeroize();
                username.zeroize();
                password.zeroize();
                totp_secret.zeroize();
                notes.zeroize();
            }
            Modal::Edit {
                name,
                username,
                password,
                totp_secret,
                notes,
                original_name,
                ..
            } => {
                name.zeroize();
                username.zeroize();
                password.zeroize();
                totp_secret.zeroize();
                notes.zeroize();
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
            Modal::Audit { .. } => {
                // No sensitive fields stored on this side — passwords were
                // sent to the worker thread by clone and are zeroed there.
            }
            Modal::Export { .. } => {
                // No sensitive fields — result is just a path.
            }
            Modal::Tokens => {
                // Reads live session; nothing owned here.
            }
            Modal::Import { password, path, .. } => {
                password.zeroize();
                path.zeroize();
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
        let mut totp_copy_request: Option<String> = None;
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
                    // One tiny read per top-bar paint (config is ~250 B and
                    // the main screen doesn't repaint when idle). Drives
                    // which optional buttons are shown — toggled in Settings.
                    let tb = app_config::load().toolbar;
                    ui.with_layout(
                        egui::Layout::right_to_left(egui::Align::Center),
                        |ui| {
                            ui.add_space(4.0);
                            // Always-on: Lock (security-core) and Settings
                            // (the only way back to re-enable hidden buttons).
                            if ui.button("Lock").clicked() {
                                lock_request = true;
                            }
                            if ui.button("Settings").clicked() {
                                let cfg = app_config::load();
                                *modal = Some(Modal::HotkeySettings {
                                    fill: cfg.hotkey,
                                    save: cfg.save_hotkey,
                                    capturing: None,
                                    message: None,
                                });
                            }
                            if tb.change_master && ui.button("Change master").clicked() {
                                *modal = Some(Modal::ChangeMaster {
                                    current: String::new(),
                                    new: String::new(),
                                    confirm: String::new(),
                                });
                            }
                            if tb.tokens
                                && ui
                                    .button("Tokens")
                                    .on_hover_text(
                                        "Live 2FA codes for every account that has a TOTP secret",
                                    )
                                    .clicked()
                            {
                                *modal = Some(Modal::Tokens);
                            }
                            if tb.audit
                                && ui
                                    .button("Audit")
                                    .on_hover_text(
                                        "Check every saved password against haveibeenpwned.com",
                                    )
                                    .clicked()
                            {
                                *modal = Some(Modal::Audit {
                                    progress: std::sync::Arc::new(
                                        std::sync::Mutex::new(AuditProgress::default()),
                                    ),
                                    worker: None,
                                });
                            }
                            if tb.export
                                && ui
                                    .button("Export")
                                    .on_hover_text("Save an encrypted backup of the vault")
                                    .clicked()
                            {
                                *modal = Some(Modal::Export {
                                    with_config: false,
                                    result: None,
                                });
                            }
                            if tb.import
                                && ui
                                    .button("Import")
                                    .on_hover_text(
                                        "Restore from a backup file — replace or merge into the current vault",
                                    )
                                    .clicked()
                            {
                                *modal = Some(Modal::Import {
                                    path: String::new(),
                                    merge: false,
                                    apply_config: false,
                                    password: String::new(),
                                    show_password: false,
                                    result: None,
                                    chooser_rx: None,
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
                        totp_secret: String::new(),
                        notes: String::new(),
                        show_password: false,
                    });
                }

                ui.add_space(10.0);
                // Search box. Filter string lives in egui temp memory so
                // it survives frames without threading another field
                // through Screen::Main and its constructors.
                let filter_id = egui::Id::new("account_filter");
                let mut filter: String =
                    ui.data_mut(|d| d.get_temp(filter_id).unwrap_or_default());
                let fr = ui.add(
                    egui::TextEdit::singleline(&mut filter)
                        .hint_text("Search…")
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(6.0, 4.0)),
                );
                if fr.changed() {
                    ui.data_mut(|d| d.insert_temp(filter_id, filter.clone()));
                }
                let needle = filter.trim().to_lowercase();
                let matches = |a: &crate::storage::Account| -> bool {
                    needle.is_empty()
                        || a.name.to_lowercase().contains(&needle)
                        || a.username.to_lowercase().contains(&needle)
                };
                let shown = session.accounts.iter().filter(|a| matches(a)).count();
                ui.add_space(6.0);
                ui.colored_label(
                    COLOR_MUTED,
                    egui::RichText::new(if needle.is_empty() {
                        format!("ACCOUNTS  ({})", session.accounts.len())
                    } else {
                        format!("ACCOUNTS  ({}/{})", shown, session.accounts.len())
                    })
                    .small(),
                );
                ui.add_space(4.0);

                if session.accounts.is_empty() {
                    ui.add_space(12.0);
                    ui.colored_label(COLOR_MUTED, "No accounts yet.");
                } else if shown == 0 {
                    ui.add_space(12.0);
                    ui.colored_label(COLOR_MUTED, "No matches.");
                } else {
                    egui::ScrollArea::vertical().show(ui, |ui| {
                        ui.spacing_mut().item_spacing.y = 2.0;
                        for (i, account) in session.accounts.iter().enumerate() {
                            if !matches(account) {
                                continue;
                            }
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

                        // TOTP code with countdown, refreshed every second.
                        if !account.totp_secret.is_empty() {
                            ui.add_space(20.0);
                            ui.colored_label(COLOR_MUTED, "TWO-FACTOR CODE");
                            ui.add_space(4.0);
                            match crate::crypto::totp_code(&account.totp_secret) {
                                Some((code, remaining)) => {
                                    ui.horizontal(|ui| {
                                        ui.label(
                                            egui::RichText::new(&code)
                                                .monospace()
                                                .size(22.0),
                                        );
                                        ui.colored_label(
                                            COLOR_MUTED,
                                            format!("expires in {}s", remaining),
                                        );
                                        if ui
                                            .add_sized(
                                                egui::vec2(80.0, 24.0),
                                                egui::Button::new("Copy"),
                                            )
                                            .clicked()
                                        {
                                            totp_copy_request = Some(code.clone());
                                        }
                                    });
                                    // Repaint when the countdown ticks so it stays current
                                    ctx.request_repaint_after(std::time::Duration::from_secs(1));
                                }
                                None => {
                                    ui.colored_label(
                                        COLOR_ERROR,
                                        "Invalid TOTP secret (must be Base32).",
                                    );
                                }
                            }
                        }

                        if !account.notes.is_empty() {
                            ui.add_space(20.0);
                            let reveal_id =
                                egui::Id::new(("notes_reveal", idx));
                            let mut show_notes: bool = ui
                                .data_mut(|d| d.get_temp(reveal_id))
                                .unwrap_or(false);
                            ui.horizontal(|ui| {
                                ui.colored_label(COLOR_MUTED, "NOTES / RECOVERY CODES");
                                if ui
                                    .add_sized(
                                        egui::vec2(60.0, 20.0),
                                        egui::Button::new(if show_notes {
                                            "Hide"
                                        } else {
                                            "Show"
                                        }),
                                    )
                                    .clicked()
                                {
                                    show_notes = !show_notes;
                                }
                                if ui
                                    .add_sized(
                                        egui::vec2(60.0, 20.0),
                                        egui::Button::new("Copy"),
                                    )
                                    .clicked()
                                {
                                    let _ = copy_to_clipboard(&account.notes);
                                    *clipboard_clear_at =
                                        Some(Instant::now() + CLIPBOARD_CLEAR);
                                    *info =
                                        "Notes copied (clipboard clears in 30s)."
                                            .to_string();
                                }
                            });
                            ui.add_space(4.0);
                            if show_notes {
                                let mut shown = account.notes.clone();
                                egui::ScrollArea::vertical()
                                    .max_height(120.0)
                                    .show(ui, |ui| {
                                        ui.add(
                                            egui::TextEdit::multiline(&mut shown)
                                                .interactive(false)
                                                .desired_width(f32::INFINITY)
                                                .font(egui::TextStyle::Monospace)
                                                .margin(egui::vec2(8.0, 6.0)),
                                        );
                                    });
                            } else {
                                ui.colored_label(
                                    COLOR_MUTED,
                                    "(hidden — click Show)",
                                );
                            }
                            ui.data_mut(|d| d.insert_temp(reveal_id, show_notes));
                        }

                        ui.add_space(28.0);
                        ui.separator();
                        ui.add_space(14.0);
                        let mut pwned_check_request: Option<(String, String)> = None;
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
                                    totp_secret: account.totp_secret.clone(),
                                    notes: account.notes.clone(),
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
                            if ui
                                .add_sized(
                                    egui::vec2(140.0, 30.0),
                                    egui::Button::new("Check pwned"),
                                )
                                .on_hover_text(
                                    "Query haveibeenpwned.com (k-anonymous) for this password",
                                )
                                .clicked()
                            {
                                pwned_check_request = Some((
                                    account.name.clone(),
                                    account.password.clone(),
                                ));
                            }
                        });
                        if let Some((name, password)) = pwned_check_request {
                            if !app_config::load().hibp_enabled {
                                *error = "HIBP check is disabled. Enable it in Settings first.".to_string();
                            } else {
                                // Synchronous: one HTTP request, ~200ms typical.
                                // Acceptable to block the UI briefly; for
                                // checking ALL entries use `passwortctl audit`.
                                match crate::hibp::check_password(&password) {
                                    Ok(r) if r.breach_count == 0 => {
                                        *info = format!(
                                            "\"{}\" — not found in any known breach.",
                                            name
                                        );
                                        *error = String::new();
                                    }
                                    Ok(r) => {
                                        *error = format!(
                                            "\"{}\" — password appears in {} breach{}. Change it.",
                                            name,
                                            r.breach_count,
                                            if r.breach_count == 1 { "" } else { "es" },
                                        );
                                        *info = String::new();
                                    }
                                    Err(e) => {
                                        *error = format!("HIBP check failed: {}", e);
                                        *info = String::new();
                                    }
                                }
                            }
                        }
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

        if let Some(code) = totp_copy_request {
            match copy_to_clipboard(&code) {
                Ok(_) => {
                    *clipboard_clear_at = Some(Instant::now() + CLIPBOARD_CLEAR);
                    *info = format!(
                        "TOTP code copied. Clears in {}s.",
                        CLIPBOARD_CLEAR.as_secs()
                    );
                    error.clear();
                }
                Err(e) => *error = format!("Clipboard error: {}", e),
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
        Modal::Audit { .. } => "Audit (Have I Been Pwned)",
        Modal::Export { .. } => "Export vault",
        Modal::Import { .. } => "Import vault",
        Modal::Tokens => "Authenticator — 2FA codes",
    };

    // Audit + Import + Tokens need more horizontal room.
    let default_width = match modal {
        Modal::Audit { .. } => 640.0,
        Modal::Import { .. } => 520.0,
        Modal::Tokens => 460.0,
        _ => 360.0,
    };

    egui::Window::new(title)
        .collapsible(false)
        .resizable(false)
        .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
        .default_width(default_width)
        .show(ctx, |ui| {
            // Hard-bound the content width. Without this, any child that
            // sizes itself off `ui.available_width()` (e.g. the TOTP
            // quick-add row) creates a feedback loop in an auto-sized
            // window: window grows → available_width grows → child grows →
            // window grows, every frame. Bounding it here fixes every
            // modal at once.
            ui.set_max_width(default_width);
            match modal {
            Modal::Add {
                name,
                username,
                password,
                totp_secret,
                notes,
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
                ui.horizontal(|ui| {
                    ui.checkbox(show_password, "Show password");
                    if ui.button("\u{2728} Generate").on_hover_text(
                        "Replace with a random 20-char password (~131 bits of entropy)"
                    ).clicked() {
                        *password = crate::generator::generate(
                            crate::generator::DEFAULT_LENGTH,
                            crate::generator::Charset::default(),
                        );
                        *show_password = true;
                    }
                });
                ui.add_space(8.0);
                totp_quick_add_row(ui, "add", name, username, totp_secret);
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "TOTP secret (optional, Base32)");
                ui.add(
                    egui::TextEdit::singleline(totp_secret)
                        .hint_text("e.g. JBSWY3DPEHPK3PXP")
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Notes / recovery codes (optional)");
                ui.add(
                    egui::TextEdit::multiline(notes)
                        .hint_text("2FA backup codes, PINs, security answers…")
                        .desired_width(f32::INFINITY)
                        .desired_rows(3)
                        .margin(egui::vec2(8.0, 6.0)),
                );
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
                        let t = std::mem::take(totp_secret);
                        let nt = std::mem::take(notes);
                        match session.add_account(n, u, p, t, nt) {
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
                totp_secret,
                notes,
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
                ui.horizontal(|ui| {
                    ui.checkbox(show_password, "Show password");
                    if ui.button("\u{2728} Generate").on_hover_text(
                        "Replace with a random 20-char password (~131 bits of entropy)"
                    ).clicked() {
                        *password = crate::generator::generate(
                            crate::generator::DEFAULT_LENGTH,
                            crate::generator::Charset::default(),
                        );
                        *show_password = true;
                    }
                });
                ui.add_space(8.0);
                totp_quick_add_row(ui, "edit", name, username, totp_secret);
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "TOTP secret (Base32)");
                ui.add(
                    egui::TextEdit::singleline(totp_secret)
                        .hint_text("e.g. JBSWY3DPEHPK3PXP")
                        .desired_width(f32::INFINITY)
                        .margin(egui::vec2(8.0, 6.0)),
                );
                ui.add_space(8.0);
                ui.colored_label(COLOR_MUTED, "Notes / recovery codes");
                ui.add(
                    egui::TextEdit::multiline(notes)
                        .hint_text("2FA backup codes, PINs, security answers…")
                        .desired_width(f32::INFINITY)
                        .desired_rows(3)
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
                        if name.trim().is_empty() {
                            result = ModalResult::CloseWithError(
                                "Name cannot be empty.".to_string(),
                            );
                            return;
                        }
                        let n = std::mem::take(name);
                        let u = std::mem::take(username);
                        let p = std::mem::take(password);
                        let t = std::mem::take(totp_secret);
                        let nt = std::mem::take(notes);
                        match session.edit_account(
                            *idx,
                            Some(n),
                            Some(u),
                            Some(p),
                            Some(t),
                            Some(nt),
                        ) {
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
                fill,
                save,
                capturing,
                message,
            } => {
                ui.colored_label(
                    COLOR_MUTED,
                    "Hotkeys for native-app auto-type (e.g. Steam, Discord).",
                );
                ui.add_space(8.0);

                if let Some(slot) = capturing {
                    let what = match slot {
                        HotkeySlot::Fill => "FILL hotkey",
                        HotkeySlot::Save => "SAVE hotkey",
                    };
                    ui.heading(format!("Press your {}…", what));
                    ui.add_space(4.0);
                    ui.colored_label(
                        COLOR_MUTED,
                        "Hold modifiers (Ctrl, Alt, Shift, Super) and press a letter / digit / F-key.",
                    );
                    ui.add_space(4.0);
                    ui.colored_label(COLOR_MUTED, "Esc to cancel.");
                    ui.add_space(8.0);

                    if ctx.input(|i| i.key_pressed(egui::Key::Escape)) {
                        *capturing = None;
                    } else {
                        let captured = ctx.input(|i| {
                            for event in &i.events {
                                if let egui::Event::Key {
                                    key,
                                    pressed: true,
                                    modifiers,
                                    ..
                                } = event
                                {
                                    if let Some(name) = egui_key_to_config_key(*key) {
                                        return Some((*modifiers, name));
                                    }
                                }
                            }
                            None
                        });
                        if let Some((mods, key_name)) = captured {
                            let mut modifiers: Vec<String> = Vec::new();
                            if mods.ctrl { modifiers.push("ctrl".into()); }
                            if mods.alt { modifiers.push("alt".into()); }
                            if mods.shift { modifiers.push("shift".into()); }
                            if mods.command { modifiers.push("super".into()); }
                            let has_strong = mods.ctrl || mods.alt || mods.command;
                            if !has_strong {
                                *message = Some((
                                    "Hotkey must include Ctrl, Alt, or Super.".to_string(),
                                    true,
                                ));
                                *capturing = None;
                            } else {
                                let new_hk = HotkeyConfig { modifiers, key: key_name };
                                match slot {
                                    HotkeySlot::Fill => *fill = new_hk.clone(),
                                    HotkeySlot::Save => *save = new_hk.clone(),
                                }
                                let mut cfg = app_config::load();
                                cfg.hotkey = fill.clone();
                                cfg.save_hotkey = save.clone();
                                match app_config::save(&cfg) {
                                    Ok(_) => {
                                        *message = Some((
                                            format!("Saved {}: {}", what, new_hk.human()),
                                            false,
                                        ));
                                    }
                                    Err(e) => {
                                        *message =
                                            Some((format!("Save failed: {}", e), true));
                                    }
                                }
                                *capturing = None;
                            }
                        }
                    }
                } else {
                    // Fill hotkey row
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Fill:").strong());
                        ui.label(fill.human());
                    });
                    ui.colored_label(
                        COLOR_MUTED,
                        "Pressed on a focused login field — types your saved username + password.",
                    );
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(egui::vec2(110.0, 26.0), egui::Button::new("Change…"))
                            .clicked()
                        {
                            *capturing = Some(HotkeySlot::Fill);
                            *message = None;
                        }
                    });
                    ui.add_space(12.0);

                    // Save hotkey row
                    ui.horizontal(|ui| {
                        ui.label(egui::RichText::new("Save:").strong());
                        ui.label(save.human());
                    });
                    ui.colored_label(
                        COLOR_MUTED,
                        "Pressed on a native-app login window — opens a small dialog to save the credential.",
                    );
                    ui.add_space(4.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(egui::vec2(110.0, 26.0), egui::Button::new("Change…"))
                            .clicked()
                        {
                            *capturing = Some(HotkeySlot::Save);
                            *message = None;
                        }
                    });

                    ui.add_space(12.0);
                    if ui
                        .add_sized(egui::vec2(160.0, 26.0), egui::Button::new("Reset both to default"))
                        .clicked()
                    {
                        *fill = HotkeyConfig {
                            modifiers: vec!["ctrl".into(), "alt".into()],
                            key: "p".into(),
                        };
                        *save = HotkeyConfig {
                            modifiers: vec!["ctrl".into(), "alt".into()],
                            key: "s".into(),
                        };
                        let mut cfg = app_config::load();
                        cfg.hotkey = fill.clone();
                        cfg.save_hotkey = save.clone();
                        match app_config::save(&cfg) {
                            Ok(_) => {
                                *message = Some((
                                    format!("Reset: fill={} save={}", fill.human(), save.human()),
                                    false,
                                ));
                            }
                            Err(e) => {
                                *message = Some((format!("Save failed: {}", e), true));
                            }
                        }
                    }

                    ui.add_space(8.0);
                    ui.colored_label(
                        COLOR_MUTED,
                        "Changes apply within ~2 seconds. Requires `xdotool` and `passwort-autotype` running.",
                    );
                }

                if let Some((msg, is_err)) = message {
                    ui.add_space(10.0);
                    let color = if *is_err { COLOR_ERROR } else { COLOR_OK };
                    ui.colored_label(color, msg.as_str());
                }

                // HIBP toggle — only shown when not capturing a hotkey.
                if capturing.is_none() {
                    ui.add_space(18.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(
                        egui::RichText::new("Have I Been Pwned breach check").strong(),
                    );
                    ui.colored_label(
                        COLOR_MUTED,
                        "Sends a 5-char SHA-1 prefix of each password to api.pwnedpasswords.com (k-anonymous — your passwords never leave the daemon).",
                    );
                    ui.add_space(6.0);
                    let mut cfg = app_config::load();
                    let was = cfg.hibp_enabled;
                    if ui.checkbox(&mut cfg.hibp_enabled, "Enable HIBP check").changed() {
                        match app_config::save(&cfg) {
                            Ok(_) => {
                                *message = Some((
                                    if cfg.hibp_enabled {
                                        "HIBP check enabled.".to_string()
                                    } else {
                                        "HIBP check disabled.".to_string()
                                    },
                                    false,
                                ));
                            }
                            Err(e) => {
                                cfg.hibp_enabled = was;
                                *message = Some((format!("Save failed: {}", e), true));
                            }
                        }
                    }
                    ui.add_space(4.0);
                    ui.colored_label(
                        COLOR_MUTED,
                        "To check every entry at once, run:  passwortctl audit",
                    );

                    // ---- Toolbar buttons ----
                    ui.add_space(18.0);
                    ui.separator();
                    ui.add_space(10.0);
                    ui.label(egui::RichText::new("Toolbar buttons").strong());
                    ui.colored_label(
                        COLOR_MUTED,
                        "Hide features you don't use for a cleaner top bar. \
                         Lock and Settings always stay visible.",
                    );
                    ui.add_space(6.0);
                    let mut cfg = app_config::load();
                    let before = cfg.toolbar.clone();
                    ui.checkbox(&mut cfg.toolbar.change_master, "Change master");
                    ui.checkbox(&mut cfg.toolbar.tokens, "Tokens (2FA codes)");
                    ui.checkbox(&mut cfg.toolbar.audit, "Audit (HIBP)");
                    ui.checkbox(&mut cfg.toolbar.export, "Export");
                    ui.checkbox(&mut cfg.toolbar.import, "Import");
                    if cfg.toolbar != before {
                        match app_config::save(&cfg) {
                            Ok(_) => {
                                *message =
                                    Some(("Toolbar updated.".to_string(), false));
                            }
                            Err(e) => {
                                *message =
                                    Some((format!("Save failed: {}", e), true));
                            }
                        }
                    }
                }

                ui.add_space(14.0);
                if ui
                    .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Close"))
                    .clicked()
                {
                    result = ModalResult::Close;
                }
            }

            Modal::Audit { progress, worker } => {
                // Snapshot under brief lock, render from snapshot.
                let snap = {
                    let p = progress.lock().unwrap();
                    (
                        p.total,
                        p.done,
                        p.finished,
                        p.fatal_error.clone(),
                        p.results.clone(),
                    )
                };
                let (total, done, finished, fatal, results) = snap;

                if let Some(err) = fatal {
                    ui.colored_label(COLOR_ERROR, err);
                    ui.add_space(12.0);
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Close"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                    return;
                }

                if worker.is_none() && !finished {
                    // Idle state — pre-launch screen
                    ui.colored_label(
                        COLOR_MUTED,
                        format!(
                            "About to check {} saved password{} against \
                             haveibeenpwned.com (k-anonymous). One HTTP \
                             request per entry, takes ~{} second{} total.",
                            session.accounts.len(),
                            if session.accounts.len() == 1 { "" } else { "s" },
                            session.accounts.len().max(1),
                            if session.accounts.len() == 1 { "" } else { "s" },
                        ),
                    );
                    ui.add_space(12.0);
                    ui.horizontal(|ui| {
                        if ui
                            .add_sized(
                                egui::vec2(110.0, 28.0),
                                egui::Button::new(
                                    egui::RichText::new("Run audit").strong(),
                                )
                                .fill(COLOR_ACCENT),
                            )
                            .clicked()
                        {
                            if !app_config::load().hibp_enabled {
                                let mut p = progress.lock().unwrap();
                                p.fatal_error = Some(
                                    "HIBP check is disabled in Settings. Enable it first."
                                        .to_string(),
                                );
                            } else {
                                // Snapshot (name, username, password) on the
                                // GUI thread, hand to the worker. The vault
                                // is already unlocked here so this is safe.
                                let snapshot: Vec<(String, String, String)> = session
                                    .accounts
                                    .iter()
                                    .map(|a| {
                                        (
                                            a.name.clone(),
                                            a.username.clone(),
                                            a.password.clone(),
                                        )
                                    })
                                    .collect();
                                {
                                    let mut p = progress.lock().unwrap();
                                    p.total = snapshot.len();
                                    p.done = 0;
                                    p.results.clear();
                                    p.finished = false;
                                }
                                let progress_clone = progress.clone();
                                let ctx_clone = ctx.clone();
                                let handle = std::thread::spawn(move || {
                                    for (name, username, password) in snapshot {
                                        let entry = match crate::hibp::check_password(&password) {
                                            Ok(r) => crate::ipc::PwnedEntry {
                                                name,
                                                username,
                                                breach_count: Some(r.breach_count),
                                                error: None,
                                            },
                                            Err(e) => crate::ipc::PwnedEntry {
                                                name,
                                                username,
                                                breach_count: None,
                                                error: Some(e.to_string()),
                                            },
                                        };
                                        {
                                            let mut p = progress_clone.lock().unwrap();
                                            p.results.push(entry);
                                            p.done = p.results.len();
                                        }
                                        ctx_clone.request_repaint();
                                    }
                                    {
                                        let mut p = progress_clone.lock().unwrap();
                                        p.finished = true;
                                    }
                                    ctx_clone.request_repaint();
                                });
                                *worker = Some(handle);
                            }
                        }
                        if ui
                            .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                            .clicked()
                        {
                            result = ModalResult::Close;
                        }
                    });
                } else {
                    // Running or finished — show progress + results.
                    if !finished {
                        ui.label(format!("Checked {} of {}…", done, total));
                        ctx.request_repaint_after(std::time::Duration::from_millis(200));
                    } else {
                        let bad = results
                            .iter()
                            .filter(|r| r.breach_count.unwrap_or(0) > 0)
                            .count();
                        let clean = results
                            .iter()
                            .filter(|r| r.breach_count == Some(0))
                            .count();
                        let errs = results.iter().filter(|r| r.error.is_some()).count();
                        ui.label(
                            egui::RichText::new(format!(
                                "Done. {} clean · {} compromised · {} error{}",
                                clean,
                                bad,
                                errs,
                                if errs == 1 { "" } else { "s" }
                            ))
                            .strong(),
                        );
                    }
                    ui.add_space(8.0);
                    // 240 px keeps the whole modal under ~440 px tall — safe
                    // for the smallest sensible window. Name+username gets
                    // truncated at 32 visible chars so a long URL doesn't
                    // push the right-aligned status off-screen.
                    egui::ScrollArea::vertical()
                        .max_height(240.0)
                        .auto_shrink([false, true])
                        .show(ui, |ui| {
                            for r in &results {
                                ui.horizontal(|ui| {
                                    let user = if r.username.is_empty() {
                                        String::new()
                                    } else {
                                        format!(" ({})", r.username)
                                    };
                                    let full = format!("{}{}", r.name, user);
                                    let label = truncate_chars(&full, 64);
                                    match (r.breach_count, &r.error) {
                                        (Some(0), _) => {
                                            ui.colored_label(COLOR_OK, "\u{2713}");
                                            ui.label(&label).on_hover_text(&full);
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| ui.colored_label(COLOR_MUTED, "clean"),
                                            );
                                        }
                                        (Some(n), _) => {
                                            ui.colored_label(COLOR_ERROR, "\u{26a0}");
                                            ui.label(&label).on_hover_text(&full);
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| {
                                                    ui.colored_label(
                                                        COLOR_ERROR,
                                                        format!(
                                                            "{} breach{}",
                                                            n,
                                                            if n == 1 { "" } else { "es" }
                                                        ),
                                                    )
                                                },
                                            );
                                        }
                                        (None, Some(e)) => {
                                            ui.colored_label(COLOR_MUTED, "?");
                                            ui.label(&label).on_hover_text(&full);
                                            ui.with_layout(
                                                egui::Layout::right_to_left(egui::Align::Center),
                                                |ui| ui.colored_label(
                                                    COLOR_MUTED,
                                                    truncate_chars(e, 48),
                                                ).on_hover_text(e.as_str()),
                                            );
                                        }
                                        _ => {}
                                    }
                                });
                            }
                        });
                    ui.add_space(12.0);
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Close"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                }
            }

            Modal::Export { with_config, result: out } => {
                ui.colored_label(
                    COLOR_MUTED,
                    "Copies your encrypted vault file to a backup. The file is \
                     already encrypted with your master password — safe to copy \
                     to a USB stick or cloud storage.",
                );
                ui.add_space(10.0);
                ui.checkbox(with_config, "Also include settings (hotkeys + HIBP toggle)")
                    .on_hover_text(
                        "Wraps the vault in a bundle that also carries config.json. \
                         When importing, you can choose to apply those settings on \
                         the new machine. Master password is NEVER in the export.",
                    );
                ui.add_space(10.0);
                match out {
                    None => {
                        if ui
                            .add_sized(
                                egui::vec2(140.0, 28.0),
                                egui::Button::new(
                                    egui::RichText::new("Export now").strong(),
                                )
                                .fill(COLOR_ACCENT),
                            )
                            .clicked()
                        {
                            *out = Some(do_export(*with_config));
                        }
                    }
                    Some(Ok(path)) => {
                        ui.colored_label(COLOR_OK, "\u{2713} Exported.");
                        ui.add_space(6.0);
                        ui.colored_label(COLOR_MUTED, "Saved to:");
                        let mut path_str = path.display().to_string();
                        ui.add(
                            egui::TextEdit::singleline(&mut path_str)
                                .desired_width(f32::INFINITY)
                                .font(egui::TextStyle::Monospace)
                                .interactive(false)
                                .margin(egui::vec2(8.0, 6.0)),
                        );
                        ui.add_space(6.0);
                        if ui.button("Copy path").clicked() {
                            ctx.output_mut(|o| o.copied_text = path.display().to_string());
                        }
                    }
                    Some(Err(e)) => {
                        ui.colored_label(COLOR_ERROR, format!("Export failed: {}", e));
                    }
                }
                ui.add_space(12.0);
                if ui
                    .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Close"))
                    .clicked()
                {
                    result = ModalResult::Close;
                }
            }

            Modal::Tokens => {
                let with_totp: Vec<&crate::storage::Account> = session
                    .accounts
                    .iter()
                    .filter(|a| !a.totp_secret.is_empty())
                    .collect();
                if with_totp.is_empty() {
                    ui.colored_label(
                        COLOR_MUTED,
                        "No accounts have a 2FA secret yet. Add one via \"+ New \
                         account\" → Quick-add 2FA (paste an otpauth:// URI or \
                         import its QR image).",
                    );
                } else {
                    ui.colored_label(
                        COLOR_MUTED,
                        "Live codes — refresh every 30s. Click a code to copy it.",
                    );
                    ui.add_space(8.0);
                    egui::ScrollArea::vertical().max_height(360.0).show(ui, |ui| {
                        for acc in with_totp {
                            match crate::crypto::totp_code(&acc.totp_secret) {
                                Some((code, remaining)) => {
                                    ui.horizontal(|ui| {
                                        let pretty = if code.len() == 6 {
                                            format!("{} {}", &code[..3], &code[3..])
                                        } else {
                                            code.clone()
                                        };
                                        if ui
                                            .add(
                                                egui::Button::new(
                                                    egui::RichText::new(&pretty)
                                                        .monospace()
                                                        .size(22.0)
                                                        .color(egui::Color32::WHITE),
                                                )
                                                .frame(false),
                                            )
                                            .on_hover_text("Click to copy")
                                            .clicked()
                                        {
                                            ctx.output_mut(|o| o.copied_text = code.clone());
                                        }
                                        ui.with_layout(
                                            egui::Layout::right_to_left(egui::Align::Center),
                                            |ui| {
                                                ui.colored_label(
                                                    if remaining <= 5 {
                                                        COLOR_ERROR
                                                    } else {
                                                        COLOR_MUTED
                                                    },
                                                    format!("{:>2}s", remaining),
                                                );
                                                ui.add_space(8.0);
                                                let nm = truncate_chars(&acc.name, 28);
                                                ui.label(nm).on_hover_text(&acc.name);
                                            },
                                        );
                                    });
                                    ui.separator();
                                }
                                None => {
                                    ui.horizontal(|ui| {
                                        ui.colored_label(COLOR_ERROR, "invalid secret");
                                        ui.label(truncate_chars(&acc.name, 28));
                                    });
                                    ui.separator();
                                }
                            }
                        }
                    });
                    // Keep the countdown live.
                    ctx.request_repaint_after(std::time::Duration::from_secs(1));
                }
                ui.add_space(12.0);
                if ui
                    .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Close"))
                    .clicked()
                {
                    result = ModalResult::Close;
                }
            }

            Modal::Import {
                path,
                merge,
                apply_config,
                password,
                show_password,
                result: out,
                chooser_rx,
            } => {
                ui.colored_label(
                    COLOR_MUTED,
                    "Restore from a backup file (raw vault or bundle).",
                );
                ui.add_space(10.0);

                // Drain the picker thread if it has a result ready. Done
                // before rendering so the path field reflects the latest.
                if let Some(rx) = chooser_rx.as_ref() {
                    if let Ok(res) = rx.try_recv() {
                        match res {
                            Ok(Some(p)) => *path = p.display().to_string(),
                            Ok(None) => {} // user cancelled
                            Err(e) => *out = Some(Err(format!(
                                "File picker failed: {}. Paste the path manually instead.",
                                e
                            ))),
                        }
                        *chooser_rx = None;
                    } else {
                        // Picker still running — keep repainting so we
                        // notice the moment it returns.
                        ctx.request_repaint_after(std::time::Duration::from_millis(150));
                    }
                }
                let picker_busy = chooser_rx.is_some();

                // File picker row
                ui.label("File:");
                ui.horizontal(|ui| {
                    ui.add_sized(
                        egui::vec2(ui.available_width() - 110.0, 26.0),
                        egui::TextEdit::singleline(path)
                            .hint_text("path/to/passwort-vault-….json")
                            .margin(egui::vec2(6.0, 4.0)),
                    );
                    let browse_label = if picker_busy { "Opening…" } else { "Browse…" };
                    let browse_btn = egui::Button::new(browse_label);
                    let resp = ui.add_enabled_ui(!picker_busy, |ui| {
                        ui.add_sized(egui::vec2(100.0, 26.0), browse_btn)
                    });
                    if resp.inner.clicked() {
                        let (tx, rx) = std::sync::mpsc::channel();
                        let start_dir = std::env::var_os("HOME")
                            .map(std::path::PathBuf::from)
                            .unwrap_or_else(|| std::path::PathBuf::from("."));
                        std::thread::spawn(move || {
                            // Shell out to `zenity` — installed on every
                            // GNOME / Cinnamon / MATE system as part of the
                            // base. It's a tiny, sync, native GTK dialog
                            // that doesn't need an async runtime, doesn't
                            // depend on xdg-desktop-portal being healthy,
                            // and plays nicely with egui's own X11
                            // connection. We run it in a worker thread so
                            // the GUI stays responsive while the user
                            // browses.
                            use std::process::Command;
                            let result: Result<Option<std::path::PathBuf>, String> =
                                match Command::new("zenity")
                                    .arg("--file-selection")
                                    .arg("--title=Pick a passwort backup file")
                                    .arg(format!(
                                        "--filename={}/",
                                        start_dir.display()
                                    ))
                                    .arg("--file-filter=Passwort backup | *.json")
                                    .arg("--file-filter=All files | *")
                                    .output()
                                {
                                    Ok(out) if out.status.success() => {
                                        let s = String::from_utf8_lossy(&out.stdout)
                                            .trim_end_matches(['\n', '\r'])
                                            .to_string();
                                        if s.is_empty() {
                                            Ok(None)
                                        } else {
                                            Ok(Some(std::path::PathBuf::from(s)))
                                        }
                                    }
                                    // zenity exits non-zero on cancel — that's fine.
                                    Ok(_) => Ok(None),
                                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(
                                        "zenity not installed (sudo apt install zenity). \
                                         Paste the path manually for now."
                                            .into(),
                                    ),
                                    Err(e) => Err(e.to_string()),
                                };
                            let _ = tx.send(result);
                        });
                        *chooser_rx = Some(rx);
                    }
                });
                ui.add_space(10.0);

                // Mode selector
                ui.label("Mode:");
                ui.horizontal(|ui| {
                    ui.radio_value(merge, false, "Replace");
                    ui.radio_value(merge, true, "Merge");
                });
                ui.colored_label(
                    COLOR_MUTED,
                    if *merge {
                        "Add imported accounts to your current vault. \
                         Existing entries with the same (name, username) are \
                         overwritten by the imported value. Requires the \
                         vault to be unlocked already (it is)."
                    } else {
                        "Wipe the current vault and use only the imported one. \
                         Your current vault is backed up to vault.json.pre-import \
                         first. The daemon will be locked; re-unlock with the \
                         master password used at the time of export."
                    },
                );
                ui.add_space(10.0);

                ui.checkbox(
                    apply_config,
                    "Apply settings from bundle (if file is a bundle, not a raw vault)",
                );
                ui.add_space(10.0);

                if *merge {
                    ui.label("Master password for the imported file:");
                    ui.colored_label(
                        COLOR_MUTED,
                        "If the export came from this machine, it's the same as your current one.",
                    );
                    ui.add_space(4.0);
                    ui.add(
                        egui::TextEdit::singleline(password)
                            .password(!*show_password)
                            .desired_width(f32::INFINITY)
                            .margin(egui::vec2(8.0, 6.0)),
                    );
                    ui.checkbox(show_password, "Show password");
                    ui.add_space(8.0);
                }

                ui.horizontal(|ui| {
                    let go = egui::Button::new(
                        egui::RichText::new(if *merge { "Merge" } else { "Replace" })
                            .strong(),
                    )
                    .fill(COLOR_ACCENT)
                    .min_size(egui::vec2(100.0, 28.0));
                    if ui.add(go).clicked() {
                        if path.trim().is_empty() {
                            *out = Some(Err("Pick a file first.".into()));
                        } else if *merge && password.is_empty() {
                            *out = Some(Err("Master password required for merge.".into()));
                        } else {
                            *out = Some(do_import(
                                session,
                                path.trim(),
                                *merge,
                                *apply_config,
                                password,
                            ));
                            password.zeroize();
                            *password = String::new();
                        }
                    }
                    if ui
                        .add_sized(egui::vec2(80.0, 28.0), egui::Button::new("Cancel"))
                        .clicked()
                    {
                        result = ModalResult::Close;
                    }
                });

                if let Some(out) = out {
                    ui.add_space(10.0);
                    match out {
                        Ok(msg) => ui.colored_label(COLOR_OK, msg.as_str()),
                        Err(msg) => ui.colored_label(COLOR_ERROR, msg.as_str()),
                    };
                }
            }
            }
        });

    result
}

/// "Quick add 2FA" row: paste an `otpauth://` URI or import its QR image,
/// and we fill in name / username / TOTP secret automatically. Used by
/// both the Add and Edit modals. `scope` disambiguates the transient
/// egui-memory keys so the two modals don't share a buffer.
fn totp_quick_add_row(
    ui: &mut egui::Ui,
    scope: &str,
    name: &mut String,
    username: &mut String,
    totp_secret: &mut String,
) {
    let uri_id = egui::Id::new(("totp_uri_buf", scope));
    let status_id = egui::Id::new(("totp_status", scope));
    let mut uri: String =
        ui.data_mut(|d| d.get_temp::<String>(uri_id).unwrap_or_default());
    let mut status: Option<(String, bool)> =
        ui.data_mut(|d| d.get_temp::<(String, bool)>(status_id));

    let apply = |text: &str,
                 name: &mut String,
                 username: &mut String,
                 totp_secret: &mut String|
     -> (String, bool) {
        match crate::crypto::parse_otpauth_uri(text) {
            Some(p) => {
                *totp_secret = p.secret;
                if name.trim().is_empty() {
                    *name = if !p.issuer.is_empty() {
                        p.issuer.clone()
                    } else {
                        p.account.clone()
                    };
                }
                if username.trim().is_empty() && !p.account.is_empty() {
                    *username = p.account.clone();
                }
                let warn = if p.nonstandard {
                    " (note: site uses non-default algorithm/digits/period — codes may not match)"
                } else {
                    ""
                };
                (format!("Loaded 2FA secret{}", warn), p.nonstandard)
            }
            None => (
                "Not a valid otpauth:// URI (need an otpauth://totp/… string or its QR)"
                    .to_string(),
                true,
            ),
        }
    };

    ui.colored_label(
        COLOR_MUTED,
        "Quick-add 2FA — paste the otpauth:// URI or import its QR image:",
    );
    ui.horizontal(|ui| {
        ui.add(
            egui::TextEdit::singleline(&mut uri)
                .hint_text("otpauth://totp/Issuer:account?secret=…")
                .desired_width(ui.available_width() - 190.0)
                .margin(egui::vec2(6.0, 4.0)),
        );
        if ui.add_sized(egui::vec2(70.0, 24.0), egui::Button::new("Apply")).clicked()
            && !uri.trim().is_empty()
        {
            status = Some(apply(uri.trim(), name, username, totp_secret));
        }
        if ui
            .add_sized(egui::vec2(110.0, 24.0), egui::Button::new("QR image…"))
            .clicked()
        {
            // Synchronous zenity pick. The native dialog is itself modal,
            // so a brief main-window freeze while it's open is expected
            // and fine. zenity returns promptly on pick/cancel.
            use std::process::Command;
            let start = std::env::var_os("HOME")
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| std::path::PathBuf::from("."));
            match Command::new("zenity")
                .arg("--file-selection")
                .arg("--title=Pick a 2FA QR-code image")
                .arg(format!("--filename={}/", start.display()))
                .arg("--file-filter=Images | *.png *.jpg *.jpeg *.gif *.bmp *.webp")
                .arg("--file-filter=All files | *")
                .output()
            {
                Ok(out) if out.status.success() => {
                    let p = String::from_utf8_lossy(&out.stdout)
                        .trim_end_matches(['\n', '\r'])
                        .to_string();
                    if !p.is_empty() {
                        match crate::qr::decode_file(std::path::Path::new(&p)) {
                            Ok(text) => {
                                status = Some(apply(
                                    text.trim(),
                                    name,
                                    username,
                                    totp_secret,
                                ))
                            }
                            Err(e) => status = Some((e, true)),
                        }
                    }
                }
                Ok(_) => {} // cancelled
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                    status = Some((
                        "zenity not installed (sudo apt install zenity)".to_string(),
                        true,
                    ))
                }
                Err(e) => status = Some((e.to_string(), true)),
            }
        }
    });
    if let Some((msg, is_err)) = &status {
        let color = if *is_err { COLOR_ERROR } else { COLOR_OK };
        ui.colored_label(color, msg.as_str());
    }

    ui.data_mut(|d| {
        d.insert_temp(uri_id, uri);
        match &status {
            Some(s) => d.insert_temp(status_id, s.clone()),
            None => {}
        }
    });
}

/// Truncate `s` to at most `max` characters; if it's longer, keep the
/// first `max - 1` chars and append "…". Counts unicode characters, not
/// bytes, so multi-byte names don't break.
fn truncate_chars(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        return s.to_string();
    }
    let head: String = s.chars().take(max.saturating_sub(1)).collect();
    format!("{}\u{2026}", head)
}

/// Synchronous helper used by the Export modal. Mirrors `cmd_export` in
/// ipc.rs but returns a Result the GUI can render without doing process exit.
/// `with_config=true` writes a bundle (vault + config); false writes the
/// raw EncryptedVault.
fn do_export(with_config: bool) -> Result<std::path::PathBuf, String> {
    let src = crate::storage::vault_path();
    if !src.exists() {
        return Err(format!("no vault to export at {}", src.display()));
    }
    let stamp = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    };
    let home = std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let dest = home.join(format!(
        "passwort-vault-{}{}.json",
        stamp,
        if with_config { "-bundle" } else { "" }
    ));
    if dest.exists() {
        return Err(format!(
            "refusing to overwrite existing file {}",
            dest.display()
        ));
    }
    if with_config {
        let raw = std::fs::read_to_string(&src).map_err(|e| e.to_string())?;
        let vault = crate::storage::parse_encrypted(&raw)
            .ok_or_else(|| "current vault is not the expected format".to_string())?;
        let cfg = app_config::load();
        let json = crate::portable::serialize_bundle(&vault, Some(&cfg))
            .map_err(|e| e.to_string())?;
        std::fs::write(&dest, json).map_err(|e| e.to_string())?;
    } else {
        std::fs::copy(src, &dest).map_err(|e| e.to_string())?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o600));
    }
    Ok(dest)
}

/// Synchronous helper used by the Import modal. Returns a human-readable
/// success or error message.
///
/// In MERGE mode the daemon's already-unlocked session is mutated: we
/// decrypt the imported vault with `password` and append every account
/// whose (name, username) pair isn't already present. The current key is
/// kept (not the imported file's key).
///
/// In REPLACE mode we write the imported encrypted vault verbatim to
/// disk (same shape the daemon expects), back up the previous vault to
/// `vault.json.pre-import`, and instruct the user to re-unlock.
fn do_import(
    session: &mut crate::session::Session,
    path: &str,
    merge: bool,
    apply_config: bool,
    password: &str,
) -> Result<String, String> {
    let data = std::fs::read_to_string(path).map_err(|e| format!("read failed: {}", e))?;
    let parsed = crate::portable::parse(&data).ok_or_else(|| {
        "file is not a valid passwort backup (neither a bundle nor a raw vault)".to_string()
    })?;
    let (vault, src_config) = match parsed {
        crate::portable::Parsed::Bundle(b) => (b.vault, b.config),
        crate::portable::Parsed::RawVault(v) => (v, None),
    };

    let mut messages: Vec<String> = Vec::new();

    if merge {
        let imported = crate::session::decrypt_accounts(&vault, password.as_bytes())
            .map_err(|_| "wrong master password for the imported file".to_string())?;
        match session.merge_accounts(imported) {
            Ok((added, skipped)) => messages.push(format!(
                "Merged: {} added, {} skipped (duplicates by name + username).",
                added, skipped
            )),
            Err(e) => return Err(format!("merge save failed: {}", e)),
        }
    } else {
        let dest = crate::storage::vault_path();
        if dest.exists() {
            let mut backup_os = dest.as_os_str().to_owned();
            backup_os.push(".pre-import");
            let backup = std::path::PathBuf::from(backup_os);
            let _ = std::fs::remove_file(&backup);
            std::fs::copy(dest, &backup).map_err(|e| format!("backup failed: {}", e))?;
        } else if let Some(parent) = dest.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        let vault_json = serde_json::to_string_pretty(&vault).map_err(|e| e.to_string())?;
        std::fs::write(dest, vault_json).map_err(|e| format!("write failed: {}", e))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(
                dest,
                std::fs::Permissions::from_mode(0o600),
            );
        }
        messages.push(
            "Vault replaced. Close & reopen the app, then unlock with the imported file's master password."
                .to_string(),
        );
    }

    if apply_config {
        match src_config {
            Some(cfg) => {
                app_config::save(&cfg).map_err(|e| format!("config write failed: {}", e))?;
                messages.push("Settings applied (hotkeys + HIBP toggle).".to_string());
            }
            None => messages.push(
                "(no config in the file — \"Apply settings\" was ignored.)".to_string(),
            ),
        }
    }

    Ok(messages.join(" "))
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
