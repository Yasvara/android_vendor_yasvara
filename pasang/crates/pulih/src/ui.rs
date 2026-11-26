// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Complete Interactive 4-Tab Material You UI Controller for `Pulih` Recovery
//! (Surpassing TWRP & OrangeFox!):
//! - **Home**: Hero, Bootloop Canary strip, 2×2 Bento, Quick Actions + Reboot Sheet
//! - **Files**: Full live File Manager (ALL files incl. dotfiles, symlinks, octal+rwx perms,
//!   storage switcher w/ auto-mount `/data`, drag-scroll, sort, multi-select, clipboard Copy/Move/Paste,
//!   interactive 3×3 `rwx` Chmod matrix + presets, Text/Log viewer, SHA-256, Rename/Mkdir via M3 Keyboard,
//!   Flash `.zip`/`.img`, Delete w/ Swipe-to-Confirm + Anti-Brick path guard)
//! - **Partitions**: Live mount status (`/proc/mounts`), Mount RO/RW/Unmount, FS Check (`fsck`),
//!   Backup raw `.img`, Wipe (allowlisted + Swipe-to-Confirm), Slot Switcher, UFS wear health
//! - **Tools**: Kernel & Power Tuner (4 profiles + live clocks + 60/90/120 Hz + backlight + UFS I/O + TCP),
//!   Interactive Terminal (presets + M3 Keyboard + live output), Root Modules Manager (auto-mount `/data` +
//!   per-module toggle + Safe Mode Disable-All), Device Passport (mask/reveal + export), Theme/OLED/Locale/Bypass Charge!

use crate::doctor::{guard_partition_wipe, DevicePassport, RootModule};
use crate::files::{
    apply_chmod, compute_file_sha256, create_folder, format_mode_rwx, format_size,
    is_protected_delete_path, list_directory, paste_clipboard, read_text_preview, rename_entry,
    safe_delete, ClipboardOp, EntryKind, FileEntry, SortMode,
};
use crate::hardware::{PowerTelemetry, UsbMode};
use crate::input::InputEvent;
use crate::kernel::{recommend_safe_profile, KernelSnapshot, PowerProfile};
use crate::wifi::{
    builtin_jelajah_home_html, normalize_browser_input, parse_jelajah_page, SavedWifiNetwork,
    ScannedWifi, DEFAULT_BOOKMARKS,
};
use pasang_core::html::ParsedPage;
use pasang_core::meta::PulihLock;
use pulih_gfx::font::{draw_text, draw_text_centered};
use pulih_gfx::i18n::{t, Locale, StrKey};
use pulih_gfx::m3::{
    draw_m3_bottom_sheet_chrome, draw_m3_top_sheet_chrome, M3BottomSheet, M3ScrollPhysics,
    M3TopSheet, SheetEvent,
};
use pulih_gfx::monet::{Palette, PRESET_SEEDS};
use pulih_gfx::raster::{draw_icon, fill_rounded_rect, Icon};
use pulih_gfx::widgets::{
    draw_bottom_nav, draw_m3_slider, draw_qwerty_keyboard_offset, draw_status_capsule,
    render_home_screen, KeyAction, StatusSnapshot, SwipeConfirm, Tab,
};
use pulih_gfx::{Rect, Surface};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolsView {
    Menu,
    Network,
    Browser,
    Terminal,
    RootModules,
    DevicePassport,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PendingDestructive {
    WipePartition(String),
    DeletePaths(Vec<PathBuf>),
    SwitchSlot(char),
    DisableAllModules,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyboardPurpose {
    NewFolder,
    Rename(PathBuf),
    TerminalCommand,
    BrowserUrl,
    WifiPassword(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartitionRow {
    pub name: String,
    pub mountpoint: String,
    pub fstype: String,
    pub mounted: bool,
    pub rw: bool,
    pub protected: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiCommand {
    None,
    SwitchTab(Tab),
    SetToolsView(ToolsView),
    OpenToolsView(ToolsView),
    OpenQuickSettings,
    OpenRebootSheet,
    CloseOverlay,
    ToggleHaptics,
    TestVibrate,
    SleepScreen,
    // File Manager actions
    OpenDir(PathBuf),
    GoParentDir,
    SwitchStorage(String),
    CycleSort,
    ToggleShowHidden,
    ToggleMultiSelect,
    ToggleSelectFile(PathBuf),
    OpenFileSheet(FileEntry),
    OpenChmodModal(PathBuf, u32),
    ToggleChmodBit(u32),
    SetChmodPreset(u32),
    CommitChmod,
    OpenTextViewer(PathBuf),
    ComputeSha256(PathBuf),
    CopyFiles(Vec<PathBuf>),
    MoveFiles(Vec<PathBuf>),
    PasteClipboard,
    OpenKeyboard(KeyboardPurpose, String),
    RequestDelete(Vec<PathBuf>),
    FlashZipFile(PathBuf),
    ScrollFiles(i32),
    ScrollViewer(i32),
    // Partition actions
    SelectPartition(usize),
    MountPartition { name: String, mountpoint: String, rw: bool },
    UnmountPartition { mountpoint: String },
    FsckPartition { name: String },
    BackupPartition { name: String },
    RequestWipePartition(String),
    RequestSwitchSlot,
    RefreshPartitions,
    // Kernel & Power actions
    ApplyPowerProfile(PowerProfile),
    SetRefreshHz(u32),
    SetBacklightPct(u8),
    CycleIoScheduler,
    CycleTcpCongestion,
    ToggleGpuDriver,
    ToggleWifiDriver,
    ScanWifi,
    ConnectWifi { ssid: String, psk: String },
    ImportSavedWifi,
    EnableAdbWifi,
    BrowserNavigate(String),
    BrowserBack,
    ScrollBrowser(i32),
    ToggleBypassCharge(bool),
    CycleUsbMode,
    CycleThemePreset,
    ToggleOledBlack,
    ToggleLocale,
    // Modules / Terminal / Passport / System
    RefreshModules,
    ToggleModule { id: String, disable: bool },
    RequestDisableAllModules,
    RunShellCommand(String),
    TogglePassportReveal,
    ExportPassport,
    StartSideload,
    ExecuteWipe(String),
    ExecuteDeletePaths(Vec<PathBuf>),
    ExecuteSwitchSlot(char),
    ExecuteDisableAllModules,
    RebootSystem,
    RebootRecovery,
    RebootBootloader,
    EnterFastbootd,
    PowerOff,
    CaptureScreenshot,
}

/// Top-level `Pulih` interactive UI state machine.
pub struct PulihApp {
    pub active_tab: Tab,
    pub tools_view: ToolsView,
    pub locale: Locale,
    pub palette: Palette,
    pub theme_preset_idx: usize,
    pub status: StatusSnapshot,
    pub power_profile: PowerProfile,
    pub auto_powersave_enabled: bool,
    pub low_batt_threshold_pct: u8,
    pub bypass_charge: bool,
    pub backlight_pct: u8,
    pub refresh_hz: u32,
    pub usb_mode: UsbMode,
    pub focus_index: usize,
    pub toast: Option<String>,
    pub swipe_modal: Option<(PendingDestructive, SwipeConfirm)>,
    pub lock: Option<PulihLock>,
    pub unlocked: bool,
    pub pin_buffer: String,
    // Live subsystems
    pub kernel_snap: Option<KernelSnapshot>,
    pub modules: Vec<RootModule>,
    pub passport: DevicePassport,
    pub reveal_passport_ids: bool,
    pub ufs_wear_text: String,
    pub gpu_active: bool,
    pub gpu_summary: String,
    // Wi-Fi 7 & Jelajah Browser state
    pub wifi_status_text: String,
    pub wifi_ip: Option<String>,
    pub wifi_adb_port: Option<u16>,
    pub saved_wifis: Vec<SavedWifiNetwork>,
    pub scanned_wifis: Vec<ScannedWifi>,
    pub browser_url: String,
    pub browser_history: Vec<String>,
    pub browser_page: ParsedPage,
    pub browser_scroll: M3ScrollPhysics,
    // File Manager state
    pub files_cwd: PathBuf,
    pub files_entries: Vec<FileEntry>,
    pub files_scroll: M3ScrollPhysics,
    pub files_sort: SortMode,
    pub files_show_hidden: bool,
    pub files_multi_select: bool,
    pub files_selected: BTreeSet<PathBuf>,
    pub files_clipboard: Option<ClipboardOp>,
    pub file_sheet: Option<FileEntry>,
    pub file_sheet_sha256: Option<String>,
    pub chmod_modal: Option<(PathBuf, u32)>,
    pub text_viewer: Option<(String, Vec<String>, M3ScrollPhysics)>,
    // Partition Manager state
    pub partitions: Vec<PartitionRow>,
    pub selected_partition: Option<usize>,
    // Terminal state
    pub terminal_output: Vec<String>,
    pub terminal_scroll: M3ScrollPhysics,
    // Keyboard modal state: (purpose, text, uppercase, symbols_page)
    pub keyboard_modal: Option<(KeyboardPurpose, String, bool, bool)>,
    pub keyboard_keys: Vec<(Rect, KeyAction)>,
    // Material 3 Expressive Sheet & Scroll physics
    pub bottom_sheet: M3BottomSheet,
    pub quick_settings_sheet: M3TopSheet,
    pub keyboard_sheet: M3BottomSheet,
    pub active_sheet_rect: Rect,
    pub kernel_scroll: M3ScrollPhysics,
    pub wifi_scroll: M3ScrollPhysics,
    dragging_slider: bool,
    pub brightness_slider_rect: Option<Rect>,
    pub haptics_enabled: bool,
    pub show_quick_settings: bool,
    // Hit-test layout rects
    pub nav_rects: [Rect; 4],
    pub action_rects: Vec<(Rect, UiCommand)>,
    pub swipe_rect: Rect,
    pub show_reboot_sheet: bool,
}

impl PulihApp {
    pub fn new(seed_argb: u32, oled_black: bool, locale: Locale, lock: Option<PulihLock>) -> Self {
        let unlocked = lock.is_none();
        let initial_cwd = if Path::new("/data/media/0").is_dir() {
            PathBuf::from("/data/media/0")
        } else {
            PathBuf::from("/")
        };
        let mut app = Self {
            active_tab: Tab::Home,
            tools_view: ToolsView::Menu,
            locale,
            palette: Palette::from_seed(seed_argb, oled_black),
            theme_preset_idx: 0,
            status: StatusSnapshot::default(),
            power_profile: PowerProfile::Balanced,
            auto_powersave_enabled: true,
            low_batt_threshold_pct: 15,
            bypass_charge: false,
            backlight_pct: 60,
            refresh_hz: 120,
            usb_mode: UsbMode::AutoDrp,
            focus_index: 0,
            toast: None,
            swipe_modal: None,
            lock,
            unlocked,
            pin_buffer: String::new(),
            kernel_snap: None,
            modules: Vec::new(),
            passport: DevicePassport {
                model: "POCO F7".into(),
                codename: "onyx".into(),
                serial: "unknown".into(),
                wifi_mac: "unknown".into(),
                kernel: "6.12-yasvara".into(),
                verified_boot: "orange".into(),
                active_slot: "_a".into(),
            },
            reveal_passport_ids: false,
            ufs_wear_text: "UFS 4.0 Health: OK (0-10% wear)".into(),
            gpu_active: false,
            gpu_summary: "Adreno GPU: OFF (Tap to load kgsl / Vulkan / DOOM)".into(),
            wifi_status_text: "Wi-Fi 7 (WCN7750): OFF (0 B ramdisk bloat)".into(),
            wifi_ip: None,
            wifi_adb_port: None,
            saved_wifis: Vec::new(),
            scanned_wifis: Vec::new(),
            browser_url: "pulih://home".into(),
            browser_history: Vec::new(),
            browser_page: parse_jelajah_page(builtin_jelajah_home_html()),
            browser_scroll: M3ScrollPhysics::new(),
            files_cwd: initial_cwd,
            files_entries: Vec::new(),
            files_scroll: M3ScrollPhysics::new(),
            files_sort: SortMode::Name,
            files_show_hidden: true, // Show ALL files including dotfiles by default!
            files_multi_select: false,
            files_selected: BTreeSet::new(),
            files_clipboard: None,
            file_sheet: None,
            file_sheet_sha256: None,
            chmod_modal: None,
            text_viewer: None,
            partitions: default_partition_rows(),
            selected_partition: None,
            terminal_output: vec![
                "Pulih Recovery Shell (root)".into(),
                "Tap any preset below or 'Type Command' for custom shell commands.".into(),
            ],
            terminal_scroll: M3ScrollPhysics::new(),
            keyboard_modal: None,
            keyboard_keys: Vec::new(),
            bottom_sheet: M3BottomSheet::new(),
            quick_settings_sheet: M3TopSheet::new(),
            keyboard_sheet: M3BottomSheet::new(),
            active_sheet_rect: Rect::default(),
            kernel_scroll: M3ScrollPhysics::new(),
            wifi_scroll: M3ScrollPhysics::new(),
            dragging_slider: false,
            brightness_slider_rect: None,
            haptics_enabled: true,
            show_quick_settings: false,
            nav_rects: [Rect::default(); 4],
            action_rects: Vec::new(),
            swipe_rect: Rect::default(),
            show_reboot_sheet: false,
        };
        app.reload_files();
        app
    }

    pub fn reload_files(&mut self) {
        match list_directory(&self.files_cwd, self.files_show_hidden, self.files_sort) {
            Ok(entries) => {
                self.files_entries = entries;
                self.files_scroll.reset();
            }
            Err(e) => {
                self.files_entries.clear();
                self.files_scroll.reset();
                self.toast = Some(e);
            }
        }
    }

    /// Returns `true` if any M3 spring bottom/top sheet, keyboard slide, or inertial
    /// scroll fling/overscroll rebound is currently active (keeps 120 Hz loop ticking!).
    pub fn is_animating(&self) -> bool {
        self.bottom_sheet.is_animating()
            || self.quick_settings_sheet.is_animating()
            || self.keyboard_sheet.is_animating()
            || self.files_scroll.is_animating()
            || self.browser_scroll.is_animating()
            || self.terminal_scroll.is_animating()
            || self.kernel_scroll.is_animating()
            || self.wifi_scroll.is_animating()
            || self
                .text_viewer
                .as_ref()
                .map(|(_, _, sc)| sc.is_animating())
                .unwrap_or(false)
    }

    /// Advance all M3 Expressive spring sheets & inertial scroll physics by `dt_s` seconds.
    /// Returns `true` if a frame redraw is needed!
    pub fn tick_animations(&mut self, dt_s: f32) -> bool {
        let mut changed = false;

        if self.bottom_sheet.is_animating() {
            let ev = self.bottom_sheet.step(dt_s);
            changed = true;
            if ev == SheetEvent::Dismissed {
                self.clear_bottom_modals();
            }
        }
        if self.quick_settings_sheet.is_animating() {
            let ev = self.quick_settings_sheet.step(dt_s);
            changed = true;
            if ev == SheetEvent::Dismissed {
                self.show_quick_settings = false;
            }
        }
        if self.keyboard_sheet.is_animating() {
            let ev = self.keyboard_sheet.step(dt_s);
            changed = true;
            if ev == SheetEvent::Dismissed {
                self.keyboard_modal = None;
            }
        }

        if self.files_scroll.step(dt_s) {
            changed = true;
        }
        if self.browser_scroll.step(dt_s) {
            changed = true;
        }
        if self.terminal_scroll.step(dt_s) {
            changed = true;
        }
        if self.kernel_scroll.step(dt_s) {
            changed = true;
        }
        if self.wifi_scroll.step(dt_s) {
            changed = true;
        }
        if let Some((_, _, ref mut sc)) = self.text_viewer {
            if sc.step(dt_s) {
                changed = true;
            }
        }
        changed
    }

    fn has_bottom_modal(&self) -> bool {
        self.swipe_modal.is_some()
            || self.file_sheet.is_some()
            || self.chmod_modal.is_some()
            || self.selected_partition.is_some()
            || self.show_reboot_sheet
    }

    fn clear_bottom_modals(&mut self) {
        self.swipe_modal = None;
        self.file_sheet = None;
        self.file_sheet_sha256 = None;
        self.chmod_modal = None;
        self.selected_partition = None;
        self.show_reboot_sheet = false;
        self.bottom_sheet.reset();
    }

    fn active_scroll_mut(&mut self) -> Option<&mut M3ScrollPhysics> {
        if let Some((_, _, ref mut sc)) = self.text_viewer {
            return Some(sc);
        }
        if self.show_quick_settings || self.has_bottom_modal() || self.keyboard_modal.is_some() {
            return None;
        }
        match self.active_tab {
            Tab::Files => Some(&mut self.files_scroll),
            Tab::Tools => match self.tools_view {
                ToolsView::Menu => Some(&mut self.kernel_scroll),
                ToolsView::Network => Some(&mut self.wifi_scroll),
                ToolsView::Browser => Some(&mut self.browser_scroll),
                ToolsView::Terminal => Some(&mut self.terminal_scroll),
                _ => None,
            },
            _ => None,
        }
    }

    /// Periodic telemetry update: enforces automatic low-battery `UltraPowersave`
    /// and thermal `TurboFlash` -> `Balanced` downgrade!
    pub fn update_telemetry(&mut self, power: &PowerTelemetry) -> Option<PowerProfile> {
        self.status.battery_pct = power.capacity_pct;
        self.status.charge_watts = power.watts();
        self.bypass_charge = power.bypass_charge;

        if self.auto_powersave_enabled {
            let safe = recommend_safe_profile(
                self.power_profile,
                power.capacity_pct,
                power.is_charging(),
                power.temp_tenths_c,
                self.low_batt_threshold_pct,
            );
            if safe != self.power_profile {
                self.power_profile = safe;
                self.refresh_hz = safe.target_refresh_hz();
                self.backlight_pct = safe.target_backlight_pct();
                self.toast = Some(format!("Auto Power: {}", safe.label()));
                return Some(safe);
            }
        }
        None
    }

    /// Request a destructive operation: runs `pasang_core::safety` / path guards FIRST,
    /// then opens the tactile Swipe-to-Confirm modal!
    pub fn request_destructive(&mut self, op: PendingDestructive) -> Result<(), String> {
        match &op {
            PendingDestructive::WipePartition(p) => {
                guard_partition_wipe(p).map_err(|e| e.to_string())?;
            }
            PendingDestructive::DeletePaths(paths) => {
                for p in paths {
                    if is_protected_delete_path(p) {
                        return Err(format!("BLOCKED: '{}' is a protected system path", p.display()));
                    }
                }
            }
            _ => {}
        }
        let label = match &op {
            PendingDestructive::WipePartition(p) => format!("Swipe to wipe {p}"),
            PendingDestructive::DeletePaths(paths) => {
                if paths.len() == 1 {
                    let name = paths[0]
                        .file_name()
                        .map(|n| n.to_string_lossy().to_string())
                        .unwrap_or_else(|| paths[0].display().to_string());
                    format!("Swipe to delete {name}")
                } else {
                    format!("Swipe to delete {} items", paths.len())
                }
            }
            PendingDestructive::SwitchSlot(s) => format!("Swipe to switch to Slot {s}"),
            PendingDestructive::DisableAllModules => "Swipe to disable all modules".into(),
        };
        self.swipe_modal = Some((op, SwipeConfirm::new(label)));
        self.bottom_sheet.open(360.0);
        Ok(())
    }

    pub fn submit_pin_digit(&mut self, digit: char) -> bool {
        if self.unlocked {
            return true;
        }
        if digit.is_ascii_digit() && self.pin_buffer.len() < 8 {
            self.pin_buffer.push(digit);
        }
        if let Some(ref lock) = self.lock {
            if lock.verify(&self.pin_buffer) {
                self.unlocked = true;
                self.pin_buffer.clear();
                self.toast = Some("Unlocked".into());
                return true;
            }
        }
        false
    }

    /// Convenience wrapper using monotonic clock ms (used by unit tests & simple callers).
    pub fn handle_input(&mut self, ev: InputEvent) -> UiCommand {
        use std::sync::atomic::{AtomicU64, Ordering};
        static CLOCK_MS: AtomicU64 = AtomicU64::new(1000);
        let now = CLOCK_MS.fetch_add(8, Ordering::Relaxed);
        self.handle_input_at(ev, now)
    }

    /// Process touch or physical Volume/Power input event with exact timestamp `now_ms`
    /// for 120 Hz fling velocity & M3 drag-to-dismiss sheets.
    pub fn handle_input_at(&mut self, ev: InputEvent, now_ms: u64) -> UiCommand {
        if matches!(ev, InputEvent::ScreenshotCombo) {
            return UiCommand::CaptureScreenshot;
        }
        if matches!(ev, InputEvent::PowerToggle) {
            return UiCommand::SleepScreen;
        }

        if !self.unlocked {
            return UiCommand::None;
        }

        if matches!(ev, InputEvent::PullDownQuickSettings) {
            self.dragging_slider = false;
            if self.show_quick_settings && !self.quick_settings_sheet.dismissing {
                self.quick_settings_sheet.close();
            } else {
                self.show_quick_settings = true;
                self.quick_settings_sheet.open(860.0);
            }
            return UiCommand::None;
        }

        // 1. M3 1:1 Gboard Touch Keyboard modal intercepts all touches when open
        if let Some((purpose, mut text, mut upper, mut symbols)) = self.keyboard_modal.take() {
            match ev {
                InputEvent::SwipeBack => {
                    self.keyboard_modal = Some((purpose, text, upper, symbols));
                    self.keyboard_sheet.close();
                    return UiCommand::None;
                }
                InputEvent::TouchDown { x, y } => {
                    let ev_s = self.keyboard_sheet.on_touch_down(self.active_sheet_rect, x, y, now_ms);
                    self.keyboard_modal = Some((purpose, text, upper, symbols));
                    if ev_s == SheetEvent::RequestClose {
                        return UiCommand::None;
                    }
                    return UiCommand::None;
                }
                InputEvent::TouchMove { y, .. } => {
                    let _ = self.keyboard_sheet.on_touch_move(y, now_ms);
                    self.keyboard_modal = Some((purpose, text, upper, symbols));
                    return UiCommand::None;
                }
                InputEvent::TouchUp { x, y } => {
                    let ev_s = self.keyboard_sheet.on_touch_up();
                    if ev_s == SheetEvent::RequestClose || ev_s == SheetEvent::Consumed {
                        self.keyboard_modal = Some((purpose, text, upper, symbols));
                        return UiCommand::None;
                    }
                    let hit = self
                        .keyboard_keys
                        .iter()
                        .find(|(r, _)| r.contains(x, y))
                        .map(|(_, k)| *k);
                    if let Some(key) = hit {
                        match key {
                            KeyAction::Char(c) => {
                                if text.len() < 96 {
                                    text.push(c);
                                }
                                self.keyboard_modal = Some((purpose, text, upper, symbols));
                            }
                            KeyAction::Space => {
                                if text.len() < 96 {
                                    text.push(' ');
                                }
                                self.keyboard_modal = Some((purpose, text, upper, symbols));
                            }
                            KeyAction::Backspace => {
                                text.pop();
                                self.keyboard_modal = Some((purpose, text, upper, symbols));
                            }
                            KeyAction::Shift => {
                                upper = !upper;
                                self.keyboard_modal = Some((purpose, text, upper, symbols));
                            }
                            KeyAction::Symbols => {
                                symbols = !symbols;
                                self.keyboard_modal = Some((purpose, text, upper, symbols));
                            }
                            KeyAction::Cancel => {
                                self.toast = Some("Cancelled".into());
                                self.keyboard_modal = Some((purpose, text, upper, symbols));
                                self.keyboard_sheet.close();
                            }
                            KeyAction::Enter => {
                                self.keyboard_sheet.reset();
                                return self.finish_keyboard(purpose, text);
                            }
                        }
                    } else {
                        self.keyboard_modal = Some((purpose, text, upper, symbols));
                    }
                }
                _ => {
                    self.keyboard_modal = Some((purpose, text, upper, symbols));
                }
            }
            return UiCommand::None;
        }

        // 2. Active Swipe-to-Confirm destructive bottom sheet (supports drag-down cancel too!)
        if let Some((op, mut sc)) = self.swipe_modal.take() {
            match ev {
                InputEvent::SwipeBack => {
                    self.toast = Some(t(self.locale, StrKey::Cancel).into());
                    self.swipe_modal = Some((op, sc));
                    self.bottom_sheet.close();
                    return UiCommand::None;
                }
                InputEvent::TouchDown { x, y } => {
                    if !sc.on_touch_down(self.swipe_rect, x, y) {
                        let _ = self.bottom_sheet.on_touch_down(self.active_sheet_rect, x, y, now_ms);
                    }
                    self.swipe_modal = Some((op, sc));
                    return UiCommand::None;
                }
                InputEvent::TouchMove { x, y } => {
                    if sc.dragging {
                        sc.on_touch_move(self.swipe_rect, x);
                        if sc.confirmed {
                            self.bottom_sheet.reset();
                            return match op {
                                PendingDestructive::WipePartition(p) => UiCommand::ExecuteWipe(p),
                                PendingDestructive::DeletePaths(paths) => {
                                    UiCommand::ExecuteDeletePaths(paths)
                                }
                                PendingDestructive::SwitchSlot(s) => UiCommand::ExecuteSwitchSlot(s),
                                PendingDestructive::DisableAllModules => {
                                    UiCommand::ExecuteDisableAllModules
                                }
                            };
                        }
                    } else {
                        let _ = self.bottom_sheet.on_touch_move(y, now_ms);
                    }
                    self.swipe_modal = Some((op, sc));
                    return UiCommand::None;
                }
                InputEvent::TouchUp { .. } => {
                    if sc.dragging {
                        sc.on_touch_up();
                    } else {
                        let _ = self.bottom_sheet.on_touch_up();
                    }
                    self.swipe_modal = Some((op, sc));
                    return UiCommand::None;
                }
                InputEvent::KeySelect => {
                    self.bottom_sheet.reset();
                    return match op {
                        PendingDestructive::WipePartition(p) => UiCommand::ExecuteWipe(p),
                        PendingDestructive::DeletePaths(paths) => {
                            UiCommand::ExecuteDeletePaths(paths)
                        }
                        PendingDestructive::SwitchSlot(s) => UiCommand::ExecuteSwitchSlot(s),
                        PendingDestructive::DisableAllModules => {
                            UiCommand::ExecuteDisableAllModules
                        }
                    };
                }
                _ => {
                    self.swipe_modal = Some((op, sc));
                    return UiCommand::None;
                }
            }
        }

        // 3. Interactive Brightness Slider (Home, Tools, Quick Settings)
        match ev {
            InputEvent::TouchDown { x, y } => {
                if let Some(sr) = self.brightness_slider_rect {
                    if sr.contains(x, y) {
                        self.dragging_slider = true;
                        let pct = slider_pct_from_x(sr, x);
                        self.backlight_pct = pct;
                        self.status.backlight_pct = pct;
                        return UiCommand::SetBacklightPct(pct);
                    }
                }
                self.dragging_slider = false;

                // 3a. Material 3 Top Quick Settings Sheet drag-up-to-dismiss / scrim tap close
                if self.show_quick_settings {
                    let ev_s = self
                        .quick_settings_sheet
                        .on_touch_down(self.active_sheet_rect, x, y, now_ms);
                    if ev_s != SheetEvent::None {
                        return UiCommand::None;
                    }
                }

                // 3b. Material 3 Modal Bottom Sheet drag-down-to-dismiss / scrim tap close
                if self.has_bottom_modal() {
                    let ev_s = self
                        .bottom_sheet
                        .on_touch_down(self.active_sheet_rect, x, y, now_ms);
                    if ev_s != SheetEvent::None {
                        return UiCommand::None;
                    }
                }

                // 3c. Pixel-smooth inertial list scrolling
                if let Some(scroll) = self.active_scroll_mut() {
                    scroll.on_touch_down(y, now_ms);
                }
                return UiCommand::None;
            }
            InputEvent::TouchMove { x, y } => {
                if self.dragging_slider {
                    if let Some(sr) = self.brightness_slider_rect {
                        let pct = slider_pct_from_x(sr, x);
                        if pct != self.backlight_pct {
                            self.backlight_pct = pct;
                            self.status.backlight_pct = pct;
                            return UiCommand::SetBacklightPct(pct);
                        }
                    }
                    return UiCommand::None;
                }
                if self.show_quick_settings {
                    if self.quick_settings_sheet.on_touch_move(y, now_ms) != SheetEvent::None {
                        return UiCommand::None;
                    }
                }
                if self.has_bottom_modal() {
                    if self.bottom_sheet.on_touch_move(y, now_ms) != SheetEvent::None {
                        return UiCommand::None;
                    }
                }
                if let Some(scroll) = self.active_scroll_mut() {
                    let _ = scroll.on_touch_move(y, now_ms);
                }
                return UiCommand::None;
            }
            InputEvent::TouchUp { x, .. } if self.dragging_slider => {
                self.dragging_slider = false;
                if let Some(sr) = self.brightness_slider_rect {
                    let pct = slider_pct_from_x(sr, x);
                    self.backlight_pct = pct;
                    self.status.backlight_pct = pct;
                    return UiCommand::SetBacklightPct(pct);
                }
                return UiCommand::None;
            }
            _ => {}
        }

        match ev {
            InputEvent::SwipeBack => {
                if self.show_quick_settings {
                    self.quick_settings_sheet.close();
                } else if self.text_viewer.is_some() {
                    self.text_viewer = None;
                } else if self.has_bottom_modal() {
                    self.bottom_sheet.close();
                } else if self.active_tab == Tab::Files && self.files_cwd != Path::new("/") {
                    return self.apply_internal_cmd(UiCommand::GoParentDir);
                } else if self.active_tab == Tab::Tools && self.tools_view != ToolsView::Menu {
                    self.tools_view = ToolsView::Menu;
                } else {
                    self.active_tab = Tab::Home;
                }
                UiCommand::None
            }
            InputEvent::KeyFocusPrev => {
                // Physical Volume Up: smooth scroll up in active scrollable view, or Brightness +10%
                if let Some(scroll) = self.active_scroll_mut() {
                    scroll.scroll_by(-320.0);
                    UiCommand::None
                } else {
                    let next = (self.backlight_pct.saturating_add(10)).clamp(10, 100);
                    self.backlight_pct = next;
                    self.status.backlight_pct = next;
                    UiCommand::SetBacklightPct(next)
                }
            }
            InputEvent::KeyFocusNext => {
                // Physical Volume Down: smooth scroll down in active scrollable view, or Brightness -10%
                if let Some(scroll) = self.active_scroll_mut() {
                    scroll.scroll_by(320.0);
                    UiCommand::None
                } else {
                    let next = (self.backlight_pct.saturating_sub(10)).clamp(10, 100);
                    self.backlight_pct = next;
                    self.status.backlight_pct = next;
                    UiCommand::SetBacklightPct(next)
                }
            }
            InputEvent::KeySelect => {
                if let Some((_, cmd)) = self.action_rects.get(self.focus_index).cloned() {
                    return self.apply_internal_cmd(cmd);
                }
                UiCommand::None
            }
            InputEvent::TouchUp { x, y } => {
                if self.show_quick_settings {
                    let ev_s = self.quick_settings_sheet.on_touch_up();
                    if ev_s != SheetEvent::None {
                        return UiCommand::None;
                    }
                }
                if self.has_bottom_modal() {
                    let ev_s = self.bottom_sheet.on_touch_up();
                    if ev_s != SheetEvent::None {
                        return UiCommand::None;
                    }
                }
                if let Some(scroll) = self.active_scroll_mut() {
                    if scroll.on_touch_up() {
                        // Was a scroll / fling gesture — never fire accidental item tap!
                        return UiCommand::None;
                    }
                }
                // Check active overlays / action rects FIRST so sheets override underlying nav
                for (r, cmd) in &self.action_rects {
                    if r.contains(x, y) {
                        let c = cmd.clone();
                        return self.apply_internal_cmd(c);
                    }
                }
                // Check bottom navigation tabs when no modal is open
                if !self.show_quick_settings
                    && !self.has_bottom_modal()
                    && self.text_viewer.is_none()
                {
                    let tabs = [Tab::Home, Tab::Files, Tab::Partitions, Tab::Tools];
                    for (i, r) in self.nav_rects.iter().enumerate() {
                        if r.contains(x, y) {
                            self.active_tab = tabs[i];
                            if self.active_tab == Tab::Files {
                                self.reload_files();
                            }
                            self.focus_index = 0;
                            return if self.active_tab == Tab::Partitions {
                                UiCommand::RefreshPartitions
                            } else {
                                UiCommand::None
                            };
                        }
                    }
                }
                UiCommand::None
            }
            _ => UiCommand::None,
        }
    }

    fn finish_keyboard(&mut self, purpose: KeyboardPurpose, text: String) -> UiCommand {
        let trimmed = text.trim().to_string();
        if trimmed.is_empty() {
            return UiCommand::None;
        }
        match purpose {
            KeyboardPurpose::NewFolder => match create_folder(&self.files_cwd, &trimmed) {
                Ok(_) => {
                    self.toast = Some(format!("Created folder '{trimmed}'"));
                    self.reload_files();
                }
                Err(e) => self.toast = Some(e),
            },
            KeyboardPurpose::Rename(path) => match rename_entry(&path, &trimmed) {
                Ok(_) => {
                    self.clear_bottom_modals();
                    self.toast = Some(format!("Renamed to '{trimmed}'"));
                    self.reload_files();
                }
                Err(e) => self.toast = Some(e),
            },
            KeyboardPurpose::TerminalCommand => {
                return UiCommand::RunShellCommand(trimmed);
            }
            KeyboardPurpose::BrowserUrl => {
                let url = normalize_browser_input(&trimmed);
                return UiCommand::BrowserNavigate(url);
            }
            KeyboardPurpose::WifiPassword(ssid) => {
                return UiCommand::ConnectWifi { ssid, psk: trimmed };
            }
        }
        UiCommand::None
    }

    /// Dump current live UI state + every clickable rect as clean JSON for AI / CI automation!
    pub fn dump_ui_json(&self) -> String {
        let mut items = Vec::new();
        let tab_names = ["Home", "Files", "Partitions", "Tools"];
        for (i, r) in self.nav_rects.iter().enumerate() {
            if !r.is_empty() {
                items.push(format!(
                    "{{\"kind\":\"nav\",\"label\":\"{}\",\"x\":{},\"y\":{},\"w\":{},\"h\":{},\"cx\":{},\"cy\":{}}}",
                    tab_names[i],
                    r.x,
                    r.y,
                    r.w,
                    r.h,
                    r.x + r.w / 2,
                    r.y + r.h / 2
                ));
            }
        }
        for (r, cmd) in &self.action_rects {
            let label = format!("{cmd:?}").replace('"', "'");
            items.push(format!(
                "{{\"kind\":\"action\",\"label\":\"{}\",\"x\":{},\"y\":{},\"w\":{},\"h\":{},\"cx\":{},\"cy\":{}}}",
                label,
                r.x,
                r.y,
                r.w,
                r.h,
                r.x + r.w / 2,
                r.y + r.h / 2
            ));
        }
        if let Some(sr) = self.brightness_slider_rect {
            items.push(format!(
                "{{\"kind\":\"slider\",\"label\":\"BrightnessSlider\",\"x\":{},\"y\":{},\"w\":{},\"h\":{},\"cx\":{},\"cy\":{}}}",
                sr.x,
                sr.y,
                sr.w,
                sr.h,
                sr.x + sr.w / 2,
                sr.y + sr.h / 2
            ));
        }
        let toast = self
            .toast
            .as_deref()
            .unwrap_or("")
            .replace('"', "'");
        format!(
            "{{\"tab\":\"{:?}\",\"tools_view\":\"{:?}\",\"cwd\":\"{}\",\"wifi_on\":{},\"gpu_active\":{},\"backlight_pct\":{},\"quick_settings\":{},\"haptics\":{},\"toast\":\"{}\",\"elements\":[{}]}}",
            self.active_tab,
            self.tools_view,
            self.files_cwd.display(),
            self.status.wifi_on,
            self.gpu_active,
            self.backlight_pct,
            self.show_quick_settings,
            self.haptics_enabled,
            toast,
            items.join(",")
        )
    }

    /// Handles self-contained UI commands directly and forwards hardware/OS commands to `main.rs`.
    pub fn apply_internal_cmd(&mut self, cmd: UiCommand) -> UiCommand {
        match cmd {
            UiCommand::SwitchTab(tab) => {
                self.active_tab = tab;
                self.show_quick_settings = false;
                self.quick_settings_sheet.reset();
                self.clear_bottom_modals();
                self.text_viewer = None;
                if tab == Tab::Files {
                    self.reload_files();
                }
                if tab == Tab::Partitions {
                    return UiCommand::RefreshPartitions;
                }
                UiCommand::None
            }
            UiCommand::SetToolsView(v) => {
                self.tools_view = v;
                self.show_quick_settings = false;
                self.quick_settings_sheet.reset();
                if v == ToolsView::RootModules {
                    return UiCommand::RefreshModules;
                }
                UiCommand::None
            }
            UiCommand::OpenToolsView(v) => {
                self.active_tab = Tab::Tools;
                self.tools_view = v;
                self.show_quick_settings = false;
                self.quick_settings_sheet.reset();
                self.clear_bottom_modals();
                self.text_viewer = None;
                if v == ToolsView::RootModules {
                    return UiCommand::RefreshModules;
                }
                UiCommand::None
            }
            UiCommand::OpenQuickSettings => {
                if self.show_quick_settings && !self.quick_settings_sheet.dismissing {
                    self.quick_settings_sheet.close();
                } else {
                    self.clear_bottom_modals();
                    self.show_quick_settings = true;
                    self.quick_settings_sheet.open(860.0);
                }
                UiCommand::None
            }
            UiCommand::ToggleHaptics => {
                self.haptics_enabled = !self.haptics_enabled;
                self.toast = Some(format!(
                    "Haptic Vibration: {}",
                    if self.haptics_enabled { "ON" } else { "OFF" }
                ));
                UiCommand::None
            }
            UiCommand::OpenRebootSheet => {
                self.show_quick_settings = false;
                self.quick_settings_sheet.reset();
                self.clear_bottom_modals();
                self.show_reboot_sheet = true;
                self.bottom_sheet.open(800.0);
                UiCommand::None
            }
            UiCommand::CloseOverlay => {
                if self.text_viewer.is_some() {
                    self.text_viewer = None;
                } else if self.show_quick_settings {
                    self.quick_settings_sheet.close();
                } else if self.has_bottom_modal() {
                    self.bottom_sheet.close();
                }
                UiCommand::None
            }
            UiCommand::OpenDir(p) => {
                self.files_cwd = p;
                self.files_scroll.reset();
                self.clear_bottom_modals();
                self.reload_files();
                UiCommand::None
            }
            UiCommand::GoParentDir => {
                if let Some(par) = self.files_cwd.parent() {
                    self.files_cwd = par.to_path_buf();
                    self.files_scroll.reset();
                    self.reload_files();
                }
                UiCommand::None
            }
            UiCommand::CycleSort => {
                self.files_sort = self.files_sort.next();
                self.reload_files();
                self.toast = Some(format!("Sort: {}", self.files_sort.label()));
                UiCommand::None
            }
            UiCommand::ToggleShowHidden => {
                self.files_show_hidden = !self.files_show_hidden;
                self.reload_files();
                self.toast = Some(format!(
                    "Hidden files: {}",
                    if self.files_show_hidden { "SHOWN" } else { "HIDDEN" }
                ));
                UiCommand::None
            }
            UiCommand::ToggleMultiSelect => {
                self.files_multi_select = !self.files_multi_select;
                if !self.files_multi_select {
                    self.files_selected.clear();
                }
                UiCommand::None
            }
            UiCommand::ToggleSelectFile(p) => {
                if !self.files_selected.remove(&p) {
                    self.files_selected.insert(p);
                }
                UiCommand::None
            }
            UiCommand::OpenFileSheet(entry) => {
                self.clear_bottom_modals();
                self.file_sheet_sha256 = None;
                self.file_sheet = Some(entry);
                self.bottom_sheet.open(980.0);
                UiCommand::None
            }
            UiCommand::OpenChmodModal(p, mode) => {
                self.clear_bottom_modals();
                self.chmod_modal = Some((p, mode & 0o7777));
                self.bottom_sheet.open(940.0);
                UiCommand::None
            }
            UiCommand::ToggleChmodBit(bit) => {
                if let Some((_, ref mut m)) = self.chmod_modal {
                    *m ^= bit;
                }
                UiCommand::None
            }
            UiCommand::SetChmodPreset(mode) => {
                if let Some((_, ref mut m)) = self.chmod_modal {
                    *m = mode & 0o7777;
                }
                UiCommand::None
            }
            UiCommand::CommitChmod => {
                if let Some((path, mode)) = self.chmod_modal.take() {
                    self.bottom_sheet.reset();
                    match apply_chmod(&path, mode) {
                        Ok(()) => {
                            self.toast = Some(format!(
                                "chmod {:04o} ({}) OK",
                                mode,
                                format_mode_rwx(mode)
                            ));
                            self.reload_files();
                        }
                        Err(e) => self.toast = Some(e),
                    }
                }
                UiCommand::None
            }
            UiCommand::OpenTextViewer(path) => {
                self.clear_bottom_modals();
                match read_text_preview(&path, 64 * 1024) {
                    Ok(lines) => {
                        let title = path
                            .file_name()
                            .map(|n| n.to_string_lossy().to_string())
                            .unwrap_or_else(|| path.display().to_string());
                        self.text_viewer = Some((title, lines, M3ScrollPhysics::new()));
                    }
                    Err(e) => self.toast = Some(e),
                }
                UiCommand::None
            }
            UiCommand::ComputeSha256(path) => {
                match compute_file_sha256(&path) {
                    Ok(hex) => {
                        self.file_sheet_sha256 = Some(hex);
                    }
                    Err(e) => self.toast = Some(e),
                }
                UiCommand::None
            }
            UiCommand::CopyFiles(paths) => {
                let n = paths.len();
                self.files_clipboard = Some(ClipboardOp::Copy(paths));
                self.clear_bottom_modals();
                self.files_multi_select = false;
                self.files_selected.clear();
                self.toast = Some(format!("Copied {n} item(s) - tap Paste in target dir"));
                UiCommand::None
            }
            UiCommand::MoveFiles(paths) => {
                let n = paths.len();
                self.files_clipboard = Some(ClipboardOp::Move(paths));
                self.clear_bottom_modals();
                self.files_multi_select = false;
                self.files_selected.clear();
                self.toast = Some(format!("Cut {n} item(s) - tap Paste in target dir"));
                UiCommand::None
            }
            UiCommand::PasteClipboard => {
                if let Some(op) = self.files_clipboard.take() {
                    match paste_clipboard(&op, &self.files_cwd) {
                        Ok(n) => {
                            self.toast = Some(format!("Pasted {n} item(s) OK"));
                            self.reload_files();
                        }
                        Err(e) => {
                            self.toast = Some(e);
                            self.files_clipboard = Some(op);
                        }
                    }
                }
                UiCommand::None
            }
            UiCommand::OpenKeyboard(purpose, initial) => {
                self.clear_bottom_modals();
                self.show_quick_settings = false;
                self.quick_settings_sheet.reset();
                self.keyboard_modal = Some((purpose, initial, false, false));
                self.keyboard_sheet.open(950.0);
                UiCommand::None
            }
            UiCommand::RequestDelete(paths) => {
                self.clear_bottom_modals();
                if let Err(e) = self.request_destructive(PendingDestructive::DeletePaths(paths)) {
                    self.toast = Some(e);
                }
                UiCommand::None
            }
            UiCommand::ExecuteDeletePaths(paths) => {
                let mut ok = 0;
                for p in &paths {
                    match safe_delete(p) {
                        Ok(()) => ok += 1,
                        Err(e) => {
                            self.toast = Some(e);
                            self.reload_files();
                            return UiCommand::None;
                        }
                    }
                }
                self.files_selected.clear();
                self.files_multi_select = false;
                self.toast = Some(format!("Deleted {ok} item(s)"));
                self.reload_files();
                UiCommand::None
            }
            UiCommand::ScrollFiles(delta) => {
                self.files_scroll.scroll_by(delta as f32 * 134.0);
                UiCommand::None
            }
            UiCommand::ScrollViewer(delta) => {
                if let Some((_, _, ref mut sc)) = self.text_viewer {
                    sc.scroll_by(delta as f32 * 34.0);
                }
                UiCommand::None
            }
            UiCommand::ScrollBrowser(delta) => {
                self.browser_scroll.scroll_by(delta as f32 * 80.0);
                UiCommand::None
            }
            UiCommand::BrowserBack => {
                if let Some(prev) = self.browser_history.pop() {
                    return UiCommand::BrowserNavigate(prev);
                }
                UiCommand::None
            }
            UiCommand::SelectPartition(idx) => {
                self.clear_bottom_modals();
                self.selected_partition = Some(idx);
                self.bottom_sheet.open(780.0);
                UiCommand::None
            }
            UiCommand::RequestWipePartition(p) => {
                self.clear_bottom_modals();
                if let Err(e) = self.request_destructive(PendingDestructive::WipePartition(p)) {
                    self.toast = Some(e);
                }
                UiCommand::None
            }
            UiCommand::RequestSwitchSlot => {
                self.clear_bottom_modals();
                let next_slot = if self.status.active_slot == 'A' { 'B' } else { 'A' };
                let _ = self.request_destructive(PendingDestructive::SwitchSlot(next_slot));
                UiCommand::None
            }
            UiCommand::RequestDisableAllModules => {
                self.clear_bottom_modals();
                let _ = self.request_destructive(PendingDestructive::DisableAllModules);
                UiCommand::None
            }
            UiCommand::CycleThemePreset => {
                self.theme_preset_idx = (self.theme_preset_idx + 1) % PRESET_SEEDS.len();
                let (name, seed) = PRESET_SEEDS[self.theme_preset_idx];
                self.palette = Palette::from_seed(seed, self.palette.oled_black);
                self.toast = Some(format!("Theme: {name}"));
                UiCommand::None
            }
            UiCommand::TogglePassportReveal => {
                self.reveal_passport_ids = !self.reveal_passport_ids;
                UiCommand::None
            }
            other => other,
        }
    }

    /// Render the active screen + overlays into `surface`.
    pub fn render(&mut self, surface: &mut Surface, wavy_phase: f32, flash_progress: Option<f32>) {
        self.action_rects.clear();
        self.keyboard_keys.clear();
        self.brightness_slider_rect = None;
        self.status.backlight_pct = self.backlight_pct;
        self.status.gpu_active = self.gpu_active;

        // PIN Lock screen
        if !self.unlocked {
            surface.clear(self.palette.surface);
            let cx = surface.width as i32 / 2;
            let cy = surface.height as i32 / 2;
            draw_icon(surface, Icon::Shield, cx as f32, (cy - 180) as f32, 96.0, self.palette.primary);
            draw_text_centered(surface, cx, cy - 60, "Pulih Locked - Enter PIN", 4, self.palette.on_surface);
            let dots = "*".repeat(self.pin_buffer.len());
            draw_text_centered(surface, cx, cy + 20, &dots, 5, self.palette.primary);
            return;
        }

        match self.active_tab {
            Tab::Home => {
                let layout = render_home_screen(
                    surface,
                    &self.palette,
                    &self.status,
                    self.locale,
                    wavy_phase,
                    flash_progress,
                );
                self.nav_rects = layout.nav;
                self.brightness_slider_rect = Some(layout.brightness_slider);
                self.action_rects.push((layout.status_capsule, UiCommand::OpenQuickSettings));
                self.action_rects.push((layout.bento[0], UiCommand::SwitchTab(Tab::Files)));
                self.action_rects.push((layout.bento[1], UiCommand::SwitchTab(Tab::Files)));
                self.action_rects.push((layout.bento[2], UiCommand::SwitchTab(Tab::Partitions)));
                self.action_rects.push((layout.bento[3], UiCommand::OpenToolsView(ToolsView::RootModules)));
                self.action_rects.push((layout.quick[0], UiCommand::SwitchTab(Tab::Partitions)));
                self.action_rects.push((layout.quick[1], UiCommand::SwitchTab(Tab::Partitions)));
                self.action_rects.push((layout.quick[2], UiCommand::RequestSwitchSlot));
                self.action_rects.push((layout.quick[3], UiCommand::OpenRebootSheet));
                self.action_rects.push((layout.feature_pills[0], UiCommand::OpenToolsView(ToolsView::Network)));
                self.action_rects.push((layout.feature_pills[1], UiCommand::OpenToolsView(ToolsView::Browser)));
                self.action_rects.push((layout.feature_pills[2], UiCommand::ToggleGpuDriver));
                self.action_rects.push((layout.feature_pills[3], UiCommand::SleepScreen));
            }
            Tab::Files => self.render_files_tab(surface),
            Tab::Partitions => self.render_partitions_tab(surface),
            Tab::Tools => self.render_tools_tab(surface),
        }

        // Overlays (highest priority — clear underlying action_rects so clicks stay inside modal!)
        self.active_sheet_rect = Rect::default();
        if self.show_quick_settings {
            self.render_quick_settings_sheet(surface);
        }
        if let Some(entry) = self.file_sheet.clone() {
            self.render_file_action_sheet(surface, &entry);
        }
        if let Some((path, mode)) = self.chmod_modal.clone() {
            self.render_chmod_modal(surface, &path, mode);
        }
        if self.text_viewer.is_some() {
            self.render_text_viewer(surface);
        }
        if let Some(idx) = self.selected_partition {
            if let Some(row) = self.partitions.get(idx).cloned() {
                self.render_partition_sheet(surface, &row);
            }
        }
        if self.show_reboot_sheet {
            self.render_reboot_sheet(surface);
        }
        if let Some((purpose, text, upper, symbols)) = self.keyboard_modal.clone() {
            self.render_keyboard_modal(surface, &purpose, &text, upper, symbols);
        }

        // Toast pill (when no keyboard modal obscures bottom)
        if self.keyboard_modal.is_none() {
            if let Some(ref msg) = self.toast {
                let w = surface.width as i32;
                let h = surface.height as i32;
                let tr = Rect::new(w / 14, h - 260, (w * 6) / 7, 68);
                fill_rounded_rect(surface, tr, 34.0, self.palette.secondary_container);
                let short = truncate_str(msg, 48);
                draw_text_centered(
                    surface,
                    tr.x + tr.w / 2,
                    tr.y + tr.h / 2,
                    &short,
                    2,
                    self.palette.on_secondary_container,
                );
            }
        }

        // Destructive Swipe-to-Confirm M3 Bottom Sheet (drag down to cancel!)
        if let Some((_, ref sc)) = self.swipe_modal {
            self.action_rects.clear();
            surface.darken_scrim(self.bottom_sheet.scrim_alpha());
            let w = surface.width as i32;
            let h = surface.height as i32;
            let pad = 36;
            let sheet_h = 350;
            let sheet = Rect::new(
                pad,
                h - sheet_h - 48 + self.bottom_sheet.offset_px(),
                w - pad * 2,
                sheet_h,
            );
            self.active_sheet_rect = sheet;
            draw_m3_bottom_sheet_chrome(surface, sheet, &self.palette);
            draw_text_centered(
                surface,
                sheet.x + sheet.w / 2,
                sheet.y + 84,
                "Confirm Destructive Action",
                4,
                self.palette.error,
            );
            self.swipe_rect = Rect::new(sheet.x + 36, sheet.y + 164, sheet.w - 72, 116);
            sc.draw(surface, self.swipe_rect, &self.palette, self.locale);
        }
    }

    fn render_files_tab(&mut self, surface: &mut Surface) {
        surface.clear(self.palette.surface);
        let top = draw_status_capsule(surface, &self.palette, &self.status, self.locale);
        self.action_rects.push((top, UiCommand::OpenQuickSettings));
        let w = surface.width as i32;
        let pad = (w / 36).max(20);
        let mut y = top.bottom() + 20;

        // 1. Storage Quick-Switch Pills (Root / Internal / OTG / OTA)
        let roots = [
            ("Root /", "/"),
            ("Internal", "/data/media/0"),
            ("USB OTG", "/storage/usbotg"),
            ("OTA", "/data/media/0/Yasvara/OTA"),
        ];
        let gap = 12;
        let rw = (w - pad * 2 - gap * 3) / 4;
        for (i, &(label, path)) in roots.iter().enumerate() {
            let r = Rect::new(pad + i as i32 * (rw + gap), y, rw, 72);
            let active = self.files_cwd == Path::new(path);
            let bg = if active {
                self.palette.primary
            } else {
                self.palette.surface_container_high
            };
            let fg = if active {
                self.palette.on_primary
            } else {
                self.palette.on_surface
            };
            fill_rounded_rect(surface, r, 24.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 36, label, 2, fg);
            self.action_rects
                .push((r, UiCommand::SwitchStorage(path.into())));
        }
        y += 88;

        // 2. Path Breadcrumb + Count Card
        let hdr = Rect::new(pad, y, w - pad * 2, 92);
        fill_rounded_rect(surface, hdr, 28.0, self.palette.surface_container);
        let cwd_str = truncate_str(&self.files_cwd.display().to_string(), 42);
        draw_text(surface, hdr.x + 24, hdr.y + 18, &cwd_str, 3, self.palette.primary);
        let info = format!(
            "{} items | Sort: {} | Hidden: {} | Sel: {}",
            self.files_entries.len(),
            self.files_sort.label(),
            if self.files_show_hidden { "ALL" } else { "NO" },
            self.files_selected.len()
        );
        draw_text(surface, hdr.x + 24, hdr.y + 56, &info, 2, self.palette.on_surface_variant);
        y = hdr.bottom() + 14;

        // 3. Toolbar: .. Up | Sort | Hidden | +Dir | Select | Paste/Multi-Act
        let mut tools: Vec<(&str, UiCommand, pulih_gfx::Color, pulih_gfx::Color)> = vec![
            (".. Up", UiCommand::GoParentDir, self.palette.surface_container_high, self.palette.on_surface),
            ("Sort", UiCommand::CycleSort, self.palette.surface_container_high, self.palette.on_surface),
            (
                if self.files_show_hidden { ".All" } else { "NoDot" },
                UiCommand::ToggleShowHidden,
                self.palette.surface_container_high,
                self.palette.on_surface,
            ),
            (
                "+Dir",
                UiCommand::OpenKeyboard(KeyboardPurpose::NewFolder, String::new()),
                self.palette.secondary_container,
                self.palette.on_secondary_container,
            ),
            (
                if self.files_multi_select { "Done" } else { "Sel" },
                UiCommand::ToggleMultiSelect,
                if self.files_multi_select {
                    self.palette.primary
                } else {
                    self.palette.surface_container_high
                },
                if self.files_multi_select {
                    self.palette.on_primary
                } else {
                    self.palette.on_surface
                },
            ),
        ];
        if self.files_clipboard.is_some() {
            tools.push((
                "Paste",
                UiCommand::PasteClipboard,
                self.palette.primary_container,
                self.palette.on_primary_container,
            ));
        } else if !self.files_selected.is_empty() {
            let sel: Vec<PathBuf> = self.files_selected.iter().cloned().collect();
            tools.push((
                "Copy",
                UiCommand::CopyFiles(sel.clone()),
                self.palette.primary_container,
                self.palette.on_primary_container,
            ));
            tools.push((
                "Del",
                UiCommand::RequestDelete(sel),
                self.palette.error_container,
                self.palette.on_error_container,
            ));
        }
        let tw = (w - pad * 2 - gap * (tools.len() as i32 - 1)) / tools.len() as i32;
        for (i, (lbl, cmd, bg, fg)) in tools.into_iter().enumerate() {
            let r = Rect::new(pad + i as i32 * (tw + gap), y, tw, 68);
            fill_rounded_rect(surface, r, 22.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 34, lbl, 2, fg);
            self.action_rects.push((r, cmd));
        }
        y += 84;

        // 4. Pixel-Smooth 120 Hz Inertial Scrollable Directory Entries (viewport-clipped!)
        let max_y = surface.height as i32 - 208;
        let viewport = Rect::new(pad, y, w - pad * 2, (max_y - y).max(160));
        let row_h = 122;
        let stride = row_h + 12;
        let total_content_h = self.files_entries.len() as i32 * stride;
        self.files_scroll
            .set_bounds((total_content_h - viewport.h).max(0) as f32);
        let scroll_px = self.files_scroll.scroll_px();

        if self.files_entries.is_empty() {
            let empty = Rect::new(pad, y, w - pad * 2, 110);
            fill_rounded_rect(surface, empty, 28.0, self.palette.surface_container_low);
            draw_text_centered(
                surface,
                empty.x + empty.w / 2,
                empty.y + 55,
                "(Empty directory or partition not mounted - tap Internal to auto-mount)",
                2,
                self.palette.on_surface_variant,
            );
        } else {
            surface.set_clip(viewport);
            for (idx, entry) in self.files_entries.iter().enumerate() {
                let row_y = viewport.y + idx as i32 * stride - scroll_px;
                if row_y + row_h < viewport.y {
                    continue;
                }
                if row_y > viewport.bottom() {
                    break;
                }
                let is_sel = self.files_selected.contains(&entry.path);
                let row = Rect::new(pad, row_y, w - pad * 2, row_h);
                let bg = if is_sel {
                    self.palette.primary_container
                } else {
                    self.palette.surface_container_low
                };
                fill_rounded_rect(surface, row, 26.0, bg);

                let icon = match entry.kind {
                    EntryKind::Directory => Icon::Folder,
                    EntryKind::Symlink => Icon::SwapSlot,
                    _ if entry.is_flashable_zip() || entry.is_flashable_img() => Icon::Flash,
                    _ => Icon::Storage,
                };
                let ic_col = match entry.kind {
                    EntryKind::Directory => self.palette.primary,
                    EntryKind::Symlink => self.palette.tertiary,
                    _ if entry.is_flashable_zip() || entry.is_flashable_img() => self.palette.success,
                    _ => self.palette.on_surface_variant,
                };
                draw_icon(surface, icon, (row.x + 48) as f32, (row.y + 61) as f32, 40.0, ic_col);

                let title = if let Some(ref tgt) = entry.symlink_target {
                    truncate_str(&format!("{} -> {}", entry.name, tgt), 32)
                } else {
                    truncate_str(&entry.name, 34)
                };
                let fg = if is_sel {
                    self.palette.on_primary_container
                } else {
                    self.palette.on_surface
                };
                draw_text(surface, row.x + 92, row.y + 24, &title, 3, fg);

                let sz = match entry.kind {
                    EntryKind::Directory => "DIR".to_string(),
                    EntryKind::Symlink => "LINK".to_string(),
                    _ => format_size(entry.size),
                };
                let meta = format!("{}  |  {}  {}", sz, entry.perm_octal(), entry.perm_rwx());
                draw_text(surface, row.x + 92, row.y + 72, &meta, 2, self.palette.on_surface_variant);

                // Right-side "OPS" pill
                let ops_r = Rect::new(row.right() - 148, row.y + 24, 130, 74);
                fill_rounded_rect(surface, ops_r, 22.0, self.palette.surface_container_high);
                draw_text_centered(
                    surface,
                    ops_r.x + ops_r.w / 2,
                    ops_r.y + 37,
                    "OPS",
                    2,
                    self.palette.primary,
                );
                let ops_hit = ops_r.intersect(viewport);
                if !ops_hit.is_empty() {
                    self.action_rects
                        .push((ops_hit, UiCommand::OpenFileSheet(entry.clone())));
                }

                // Main row click
                let main_r = Rect::new(row.x, row.y, row.w - 156, row.h).intersect(viewport);
                if !main_r.is_empty() {
                    let main_cmd = if self.files_multi_select {
                        UiCommand::ToggleSelectFile(entry.path.clone())
                    } else if entry.kind == EntryKind::Directory {
                        UiCommand::OpenDir(entry.path.clone())
                    } else {
                        UiCommand::OpenFileSheet(entry.clone())
                    };
                    self.action_rects.push((main_r, main_cmd));
                }
            }
            surface.reset_clip();
        }

        self.nav_rects = draw_bottom_nav(surface, &self.palette, Tab::Files, self.locale);
    }

    fn render_file_action_sheet(&mut self, surface: &mut Surface, entry: &FileEntry) {
        self.action_rects.clear();
        surface.darken_scrim(self.bottom_sheet.scrim_alpha());
        let w = surface.width as i32;
        let h = surface.height as i32;
        let pad = 28;
        let sheet_h = 980;
        let sheet = Rect::new(
            pad,
            h - sheet_h - 32 + self.bottom_sheet.offset_px(),
            w - pad * 2,
            sheet_h,
        );
        self.active_sheet_rect = sheet;
        draw_m3_bottom_sheet_chrome(surface, sheet, &self.palette);

        let title = truncate_str(&entry.name, 34);
        draw_text(surface, sheet.x + 36, sheet.y + 46, &title, 4, self.palette.on_surface);
        let sub = format!(
            "{} | {} ({})",
            format_size(entry.size),
            entry.perm_octal(),
            entry.perm_rwx()
        );
        draw_text(surface, sheet.x + 36, sheet.y + 98, &sub, 2, self.palette.primary);

        let mut y = sheet.y + 140;
        if let Some(ref sha) = self.file_sheet_sha256 {
            let line1 = &sha[..sha.len().min(32)];
            let line2 = if sha.len() > 32 { &sha[32..] } else { "" };
            draw_text(surface, sheet.x + 36, y, &format!("SHA256: {line1}"), 2, self.palette.success);
            draw_text(surface, sheet.x + 36, y + 26, &format!("        {line2}"), 2, self.palette.success);
            y += 66;
        }

        let mut actions: Vec<(&str, UiCommand, pulih_gfx::Color, pulih_gfx::Color)> = Vec::new();
        if entry.is_flashable_zip() {
            actions.push((
                "Flash OTA ZIP (Pasang CoW)",
                UiCommand::FlashZipFile(entry.path.clone()),
                self.palette.primary,
                self.palette.on_primary,
            ));
        }
        actions.push((
            "Change Permissions (Chmod rwx)",
            UiCommand::OpenChmodModal(entry.path.clone(), entry.mode),
            self.palette.primary_container,
            self.palette.on_primary_container,
        ));
        if entry.kind == EntryKind::File {
            actions.push((
                "View Text / Log",
                UiCommand::OpenTextViewer(entry.path.clone()),
                self.palette.surface_container,
                self.palette.on_surface,
            ));
            actions.push((
                "Compute SHA-256 Checksum",
                UiCommand::ComputeSha256(entry.path.clone()),
                self.palette.surface_container,
                self.palette.on_surface,
            ));
        }
        actions.push((
            "Copy to Clipboard",
            UiCommand::CopyFiles(vec![entry.path.clone()]),
            self.palette.surface_container,
            self.palette.on_surface,
        ));
        actions.push((
            "Move (Cut) to Clipboard",
            UiCommand::MoveFiles(vec![entry.path.clone()]),
            self.palette.surface_container,
            self.palette.on_surface,
        ));
        actions.push((
            "Rename",
            UiCommand::OpenKeyboard(KeyboardPurpose::Rename(entry.path.clone()), entry.name.clone()),
            self.palette.surface_container,
            self.palette.on_surface,
        ));
        actions.push((
            "Delete (Swipe Confirm)",
            UiCommand::RequestDelete(vec![entry.path.clone()]),
            self.palette.error_container,
            self.palette.on_error_container,
        ));
        actions.push((
            "Close",
            UiCommand::CloseOverlay,
            self.palette.surface_container_low,
            self.palette.on_surface_variant,
        ));

        for (label, cmd, bg, fg) in actions {
            if y + 76 > sheet.bottom() - 16 {
                break;
            }
            let r = Rect::new(sheet.x + 32, y, sheet.w - 64, 76);
            fill_rounded_rect(surface, r, 26.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 38, label, 3, fg);
            self.action_rects.push((r, cmd));
            y += 88;
        }
    }

    fn render_chmod_modal(&mut self, surface: &mut Surface, path: &Path, mode: u32) {
        self.action_rects.clear();
        surface.darken_scrim(self.bottom_sheet.scrim_alpha());
        let w = surface.width as i32;
        let h = surface.height as i32;
        let pad = 28;
        let sheet_h = 940;
        let sheet = Rect::new(
            pad,
            h - sheet_h - 40 + self.bottom_sheet.offset_px(),
            w - pad * 2,
            sheet_h,
        );
        self.active_sheet_rect = sheet;
        draw_m3_bottom_sheet_chrome(surface, sheet, &self.palette);

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| path.display().to_string());
        draw_text(surface, sheet.x + 36, sheet.y + 46, "Change Permissions (Chmod)", 4, self.palette.on_surface);
        draw_text(
            surface,
            sheet.x + 36,
            sheet.y + 98,
            &format!("{}  ->  {:04o}  ({})", truncate_str(&name, 22), mode & 0o7777, format_mode_rwx(mode)),
            3,
            self.palette.primary,
        );

        // 3x3 Interactive Owner / Group / Other R/W/X bit toggle grid
        let rows = [
            ("Owner", 0o400u32, 0o200u32, 0o100u32),
            ("Group", 0o040u32, 0o020u32, 0o010u32),
            ("Other", 0o004u32, 0o002u32, 0o001u32),
        ];
        let mut y = sheet.y + 158;
        let bw = (sheet.w - 240 - 40) / 3;
        for (who, rbit, wbit, xbit) in rows {
            draw_text(surface, sheet.x + 36, y + 32, who, 3, self.palette.on_surface);
            for (i, (lbl, bit)) in [("READ", rbit), ("WRITE", wbit), ("EXEC", xbit)].iter().enumerate() {
                let on = (mode & *bit) != 0;
                let r = Rect::new(sheet.x + 210 + i as i32 * (bw + 16), y, bw, 88);
                let bg = if on { self.palette.primary } else { self.palette.surface_container };
                let fg = if on { self.palette.on_primary } else { self.palette.on_surface_variant };
                fill_rounded_rect(surface, r, 24.0, bg);
                draw_text_centered(surface, r.x + r.w / 2, r.y + 44, lbl, 2, fg);
                self.action_rects.push((r, UiCommand::ToggleChmodBit(*bit)));
            }
            y += 108;
        }

        // 1-Tap Presets: 0644 | 0755 | 0600 | 0777
        draw_text(surface, sheet.x + 36, y + 12, "Quick Presets:", 3, self.palette.on_surface_variant);
        y += 56;
        let presets = [("0644", 0o644u32), ("0755", 0o755), ("0600", 0o600), ("0777", 0o777)];
        let pw = (sheet.w - 72 - 36) / 4;
        for (i, (lbl, val)) in presets.iter().enumerate() {
            let r = Rect::new(sheet.x + 36 + i as i32 * (pw + 12), y, pw, 84);
            let bg = if (mode & 0o777) == *val {
                self.palette.secondary_container
            } else {
                self.palette.surface_container
            };
            fill_rounded_rect(surface, r, 24.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 42, lbl, 3, self.palette.on_surface);
            self.action_rects.push((r, UiCommand::SetChmodPreset(*val)));
        }
        y += 116;

        // Apply + Cancel buttons
        let half = (sheet.w - 72 - 20) / 2;
        let cancel_r = Rect::new(sheet.x + 36, y, half, 96);
        let apply_r = Rect::new(sheet.x + 36 + half + 20, y, half, 96);
        fill_rounded_rect(surface, cancel_r, 32.0, self.palette.surface_container_low);
        fill_rounded_rect(surface, apply_r, 32.0, self.palette.primary);
        draw_text_centered(surface, cancel_r.x + cancel_r.w / 2, cancel_r.y + 48, "Cancel", 3, self.palette.on_surface);
        draw_text_centered(surface, apply_r.x + apply_r.w / 2, apply_r.y + 48, "Apply Chmod", 3, self.palette.on_primary);
        self.action_rects.push((cancel_r, UiCommand::CloseOverlay));
        self.action_rects.push((apply_r, UiCommand::CommitChmod));
    }

    fn render_text_viewer(&mut self, surface: &mut Surface) {
        let Some((title, lines, mut sc)) = self.text_viewer.take() else {
            return;
        };
        self.action_rects.clear();
        surface.clear(self.palette.surface);
        let w = surface.width as i32;
        let h = surface.height as i32;
        let pad = 28;
        let hdr = Rect::new(pad, 100, w - pad * 2, 92);
        fill_rounded_rect(surface, hdr, 28.0, self.palette.surface_container_high);
        draw_text(surface, hdr.x + 28, hdr.y + 32, &truncate_str(&title, 30), 3, self.palette.primary);
        let close_r = Rect::new(hdr.right() - 160, hdr.y + 14, 144, 64);
        fill_rounded_rect(surface, close_r, 22.0, self.palette.error_container);
        draw_text_centered(surface, close_r.x + close_r.w / 2, close_r.y + 32, "Close", 2, self.palette.on_error_container);
        self.action_rects.push((close_r, UiCommand::CloseOverlay));

        let body = Rect::new(pad, hdr.bottom() + 16, w - pad * 2, h - hdr.bottom() - 140);
        fill_rounded_rect(surface, body, 28.0, self.palette.surface_container_lowest);
        let line_h = 34;
        let content_h = lines.len() as i32 * line_h + 40;
        sc.set_bounds((content_h - body.h).max(0) as f32);
        let scroll_px = sc.scroll_px();

        let inner = Rect::new(body.x + 12, body.y + 12, body.w - 24, body.h - 24);
        surface.set_clip(inner);
        for (i, line) in lines.iter().enumerate() {
            let ly = body.y + 20 + i as i32 * line_h - scroll_px;
            if ly + line_h < inner.y {
                continue;
            }
            if ly > inner.bottom() {
                break;
            }
            draw_text(
                surface,
                body.x + 20,
                ly,
                &truncate_str(line, 92),
                2,
                self.palette.on_surface,
            );
        }
        surface.reset_clip();
        self.text_viewer = Some((title, lines, sc));
    }

    fn render_partitions_tab(&mut self, surface: &mut Surface) {
        surface.clear(self.palette.surface);
        let top = draw_status_capsule(surface, &self.palette, &self.status, self.locale);
        self.action_rects.push((top, UiCommand::OpenQuickSettings));
        let w = surface.width as i32;
        let pad = (w / 32).max(20);
        let mut y = top.bottom() + 24;

        let hdr = Rect::new(pad, y, w - pad * 2, 160);
        fill_rounded_rect(surface, hdr, 36.0, self.palette.surface_container);
        draw_text(surface, hdr.x + 32, hdr.y + 24, t(self.locale, StrKey::PartitionsMount), 4, self.palette.on_surface);
        let sub = format!(
            "super free: {:.2} GiB | Active: Slot {} | Anti-Brick: ON",
            self.status.super_free_gib, self.status.active_slot
        );
        draw_text(surface, hdr.x + 32, hdr.y + 74, &sub, 2, self.palette.success);
        draw_text(surface, hdr.x + 32, hdr.y + 112, &self.ufs_wear_text, 2, self.palette.on_surface_variant);
        y = hdr.bottom() + 18;

        // Top quick buttons: Refresh Mounts | Switch Slot
        let bw = (w - pad * 2 - 16) / 2;
        let ref_r = Rect::new(pad, y, bw, 76);
        let slot_r = Rect::new(pad + bw + 16, y, bw, 76);
        fill_rounded_rect(surface, ref_r, 24.0, self.palette.surface_container_high);
        fill_rounded_rect(surface, slot_r, 24.0, self.palette.primary_container);
        draw_text_centered(surface, ref_r.x + ref_r.w / 2, ref_r.y + 38, "Refresh Mounts", 2, self.palette.on_surface);
        draw_text_centered(surface, slot_r.x + slot_r.w / 2, slot_r.y + 38, "Switch A/B Slot", 2, self.palette.on_primary_container);
        self.action_rects.push((ref_r, UiCommand::RefreshPartitions));
        self.action_rects.push((slot_r, UiCommand::RequestSwitchSlot));
        y += 92;

        let max_y = surface.height as i32 - 220;
        for (idx, p) in self.partitions.iter().enumerate() {
            if y + 118 > max_y {
                break;
            }
            let row = Rect::new(pad, y, w - pad * 2, 118);
            fill_rounded_rect(surface, row, 28.0, self.palette.surface_container_low);
            draw_text(
                surface,
                row.x + 28,
                row.y + 24,
                &format!("{} ({})", p.name, p.mountpoint),
                3,
                self.palette.on_surface,
            );
            let badge = if p.protected {
                "HARD LOCKED (Anti-Brick Guard)"
            } else if p.mounted && p.rw {
                "MOUNTED RW"
            } else if p.mounted {
                "MOUNTED RO"
            } else {
                "UNMOUNTED (Tap for Mount/Check/Backup/Wipe)"
            };
            let bcol = if p.protected {
                self.palette.error
            } else if p.mounted {
                self.palette.success
            } else {
                self.palette.on_surface_variant
            };
            draw_text(surface, row.x + 28, row.y + 70, &format!("{} | {}", p.fstype, badge), 2, bcol);
            self.action_rects.push((row, UiCommand::SelectPartition(idx)));
            y += 132;
        }

        self.nav_rects = draw_bottom_nav(surface, &self.palette, Tab::Partitions, self.locale);
    }

    fn render_partition_sheet(&mut self, surface: &mut Surface, p: &PartitionRow) {
        self.action_rects.clear();
        surface.darken_scrim(self.bottom_sheet.scrim_alpha());
        let w = surface.width as i32;
        let h = surface.height as i32;
        let pad = 28;
        let sheet_h = 780;
        let sheet = Rect::new(
            pad,
            h - sheet_h - 40 + self.bottom_sheet.offset_px(),
            w - pad * 2,
            sheet_h,
        );
        self.active_sheet_rect = sheet;
        draw_m3_bottom_sheet_chrome(surface, sheet, &self.palette);
        draw_text(surface, sheet.x + 36, sheet.y + 46, &format!("Partition: {}", p.name), 4, self.palette.on_surface);
        draw_text(
            surface,
            sheet.x + 36,
            sheet.y + 98,
            &format!("Mount: {} | FS: {}", p.mountpoint, p.fstype),
            2,
            self.palette.primary,
        );

        let mut opts: Vec<(&str, UiCommand, pulih_gfx::Color, pulih_gfx::Color)> = vec![
            (
                "Mount Read-Write (RW)",
                UiCommand::MountPartition {
                    name: p.name.clone(),
                    mountpoint: p.mountpoint.clone(),
                    rw: true,
                },
                self.palette.primary_container,
                self.palette.on_primary_container,
            ),
            (
                "Mount Read-Only (RO)",
                UiCommand::MountPartition {
                    name: p.name.clone(),
                    mountpoint: p.mountpoint.clone(),
                    rw: false,
                },
                self.palette.surface_container,
                self.palette.on_surface,
            ),
            (
                "Unmount",
                UiCommand::UnmountPartition {
                    mountpoint: p.mountpoint.clone(),
                },
                self.palette.surface_container,
                self.palette.on_surface,
            ),
            (
                "Check & Repair FS (fsck)",
                UiCommand::FsckPartition { name: p.name.clone() },
                self.palette.surface_container,
                self.palette.on_surface,
            ),
            (
                "Dump / Backup Raw Image",
                UiCommand::BackupPartition { name: p.name.clone() },
                self.palette.secondary_container,
                self.palette.on_secondary_container,
            ),
            (
                if p.protected {
                    "Wipe BLOCKED (Anti-Brick Guard)"
                } else {
                    "Wipe Partition (Swipe Confirm)"
                },
                UiCommand::RequestWipePartition(p.name.clone()),
                self.palette.error_container,
                self.palette.on_error_container,
            ),
            (
                "Close",
                UiCommand::CloseOverlay,
                self.palette.surface_container_low,
                self.palette.on_surface_variant,
            ),
        ];

        let mut y = sheet.y + 132;
        for (lbl, cmd, bg, fg) in opts.drain(..) {
            let r = Rect::new(sheet.x + 32, y, sheet.w - 64, 76);
            fill_rounded_rect(surface, r, 24.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 38, lbl, 3, fg);
            self.action_rects.push((r, cmd));
            y += 88;
        }
    }

    fn render_tools_tab(&mut self, surface: &mut Surface) {
        surface.clear(self.palette.surface);
        let top = draw_status_capsule(surface, &self.palette, &self.status, self.locale);
        self.action_rects.push((top, UiCommand::OpenQuickSettings));
        let w = surface.width as i32;
        let pad = (w / 32).max(20);
        let mut y = top.bottom() + 20;

        // Sub-view switcher pills (2 crisp rows: Kernel/Sys | Wi-Fi 7 | Jelajah Browser ; Terminal | Modules | Passport)
        let sub_tabs = [
            ("Kernel/Sys", ToolsView::Menu),
            ("Wi-Fi 7", ToolsView::Network),
            ("Jelajah Web", ToolsView::Browser),
            ("Terminal", ToolsView::Terminal),
            ("Modules", ToolsView::RootModules),
            ("Passport", ToolsView::DevicePassport),
        ];
        let gap = 12;
        let sw = (w - pad * 2 - gap * 2) / 3;
        for (i, &(lbl, view)) in sub_tabs.iter().enumerate() {
            let col = (i % 3) as i32;
            let row = (i / 3) as i32;
            let r = Rect::new(pad + col * (sw + gap), y + row * 78, sw, 66);
            let active = self.tools_view == view;
            fill_rounded_rect(
                surface,
                r,
                22.0,
                if active { self.palette.primary } else { self.palette.surface_container_high },
            );
            draw_text_centered(
                surface,
                r.x + r.w / 2,
                r.y + 33,
                lbl,
                2,
                if active { self.palette.on_primary } else { self.palette.on_surface },
            );
            self.action_rects.push((r, UiCommand::SetToolsView(view)));
        }
        y += 164;

        match self.tools_view {
            ToolsView::Menu => self.render_tools_kernel_menu(surface, pad, y),
            ToolsView::Network => self.render_tools_network(surface, pad, y),
            ToolsView::Browser => self.render_tools_browser(surface, pad, y),
            ToolsView::Terminal => self.render_tools_terminal(surface, pad, y),
            ToolsView::RootModules => self.render_tools_modules(surface, pad, y),
            ToolsView::DevicePassport => self.render_tools_passport(surface, pad, y),
        }

        self.nav_rects = draw_bottom_nav(surface, &self.palette, Tab::Tools, self.locale);
    }

    fn render_tools_network(&mut self, surface: &mut Surface, pad: i32, mut y: i32) {
        let w = surface.width as i32;
        let h = surface.height as i32;

        // Wi-Fi 7 Hero Card
        let card = Rect::new(pad, y, w - pad * 2, 198);
        fill_rounded_rect(surface, card, 36.0, self.palette.primary_container);
        draw_icon(surface, Icon::Wifi, (card.x + 56) as f32, (card.y + 58) as f32, 48.0, self.palette.on_primary_container);
        draw_text(surface, card.x + 100, card.y + 32, "Wi-Fi 7 (WCN7750) & Network", 4, self.palette.on_primary_container);
        draw_text(surface, card.x + 100, card.y + 86, &truncate_str(&self.wifi_status_text, 44), 2, self.palette.on_primary_container);
        let ip_line = format!(
            "IP: {} | ADB Wi-Fi: {} | DNS: 1.1.1.1",
            self.wifi_ip.as_deref().unwrap_or("not connected"),
            self.wifi_adb_port.map(|p| format!(":{p}")).unwrap_or_else(|| "OFF".into())
        );
        draw_text(surface, card.x + 32, card.y + 140, &ip_line, 2, self.palette.on_primary_container);
        y = card.bottom() + 14;

        // Honest Mobile Data status pill
        let mob = Rect::new(pad, y, w - pad * 2, 84);
        fill_rounded_rect(surface, mob, 24.0, self.palette.surface_container);
        draw_text(surface, mob.x + 28, mob.y + 16, "Mobile Data (5G/LTE): N/A in Recovery", 2, self.palette.warning);
        draw_text(surface, mob.x + 28, mob.y + 48, "Cellular RIL requires full Android OS - use Wi-Fi 7 below", 2, self.palette.on_surface_variant);
        y = mob.bottom() + 14;

        // 2x2 Action buttons: Toggle Wi-Fi | Scan Nearby ; Import Saved | ADB Wi-Fi
        let bw = (w - pad * 2 - 14) / 2;
        let row1 = [
            (
                if self.status.wifi_on { "Wi-Fi 7: ON (Off)" } else { "Turn Wi-Fi 7 ON" },
                UiCommand::ToggleWifiDriver,
                self.palette.primary,
                self.palette.on_primary,
            ),
            (
                "Scan Nearby Wi-Fi",
                UiCommand::ScanWifi,
                self.palette.secondary_container,
                self.palette.on_secondary_container,
            ),
        ];
        for (i, (lbl, cmd, bg, fg)) in row1.into_iter().enumerate() {
            let r = Rect::new(pad + i as i32 * (bw + 14), y, bw, 82);
            fill_rounded_rect(surface, r, 24.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 41, lbl, 3, fg);
            self.action_rects.push((r, cmd));
        }
        y += 94;

        let row2 = [
            (
                "Import Android Wi-Fi",
                UiCommand::ImportSavedWifi,
                self.palette.surface_container_high,
                self.palette.on_surface,
            ),
            (
                "ADB Wi-Fi (:5555)",
                UiCommand::EnableAdbWifi,
                self.palette.surface_container_high,
                self.palette.on_surface,
            ),
        ];
        for (i, (lbl, cmd, bg, fg)) in row2.into_iter().enumerate() {
            let r = Rect::new(pad + i as i32 * (bw + 14), y, bw, 76);
            fill_rounded_rect(surface, r, 24.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 38, lbl, 2, fg);
            self.action_rects.push((r, cmd));
        }
        y += 92;

        // Pixel-smooth scrollable Wi-Fi Network list (Scanned + Saved Android Wi-Fi!)
        let viewport = Rect::new(pad, y, w - pad * 2, (h - y - 210).max(160));
        let mut entries: Vec<(String, String, UiCommand)> = Vec::new();
        for net in &self.scanned_wifis {
            let saved_psk = self
                .saved_wifis
                .iter()
                .find(|s| s.ssid == net.ssid)
                .map(|s| s.psk.clone());
            let sub = format!(
                "{} dBm | {}",
                net.rssi_dbm,
                if !net.secured {
                    "Open (Tap to connect)"
                } else if saved_psk.is_some() {
                    "Saved Password (1-Tap connect)"
                } else {
                    "WPA2/WPA3 (Tap to enter password)"
                }
            );
            let cmd = if !net.secured {
                UiCommand::ConnectWifi {
                    ssid: net.ssid.clone(),
                    psk: String::new(),
                }
            } else if let Some(psk) = saved_psk {
                UiCommand::ConnectWifi {
                    ssid: net.ssid.clone(),
                    psk,
                }
            } else {
                UiCommand::OpenKeyboard(KeyboardPurpose::WifiPassword(net.ssid.clone()), String::new())
            };
            entries.push((net.ssid.clone(), sub, cmd));
        }
        for saved in &self.saved_wifis {
            if !entries.iter().any(|(s, _, _)| s == &saved.ssid) {
                let cmd = UiCommand::ConnectWifi {
                    ssid: saved.ssid.clone(),
                    psk: saved.psk.clone(),
                };
                entries.push((
                    saved.ssid.clone(),
                    "Saved from Android OS (Tap to connect)".into(),
                    cmd,
                ));
            }
        }

        let row_h = 98;
        let stride = row_h + 12;
        self.wifi_scroll
            .set_bounds((entries.len() as i32 * stride - viewport.h).max(0) as f32);
        let scroll_px = self.wifi_scroll.scroll_px();

        if entries.is_empty() {
            let empty = Rect::new(pad, y, w - pad * 2, 100);
            fill_rounded_rect(surface, empty, 26.0, self.palette.surface_container_low);
            draw_text_centered(
                surface,
                empty.x + empty.w / 2,
                empty.y + 50,
                "Tap 'Turn Wi-Fi 7 ON' to boot WCN7750 & scan nearby networks",
                2,
                self.palette.on_surface_variant,
            );
        } else {
            surface.set_clip(viewport);
            for (i, (ssid, sub, cmd)) in entries.into_iter().enumerate() {
                let ry = viewport.y + i as i32 * stride - scroll_px;
                if ry + row_h < viewport.y {
                    continue;
                }
                if ry > viewport.bottom() {
                    break;
                }
                let r = Rect::new(pad, ry, w - pad * 2, row_h);
                fill_rounded_rect(surface, r, 24.0, self.palette.surface_container_low);
                draw_icon(surface, Icon::Wifi, (r.x + 44) as f32, (r.y + 49) as f32, 34.0, self.palette.primary);
                draw_text(surface, r.x + 84, r.y + 20, &truncate_str(&ssid, 34), 3, self.palette.on_surface);
                draw_text(surface, r.x + 84, r.y + 60, &truncate_str(&sub, 46), 2, self.palette.on_surface_variant);
                let hit = r.intersect(viewport);
                if !hit.is_empty() {
                    self.action_rects.push((hit, cmd));
                }
            }
            surface.reset_clip();
        }
    }

    fn render_tools_browser(&mut self, surface: &mut Surface, pad: i32, mut y: i32) {
        let w = surface.width as i32;
        let h = surface.height as i32;

        // Clickable URL / Search bar (tap -> 1:1 Android Gboard!) + Back button
        let back_r = Rect::new(pad, y, 128, 82);
        let url_r = Rect::new(pad + 140, y, w - pad * 2 - 140, 82);
        fill_rounded_rect(surface, back_r, 24.0, self.palette.surface_container_high);
        fill_rounded_rect(surface, url_r, 24.0, self.palette.surface_container_lowest);
        draw_text_centered(surface, back_r.x + back_r.w / 2, back_r.y + 41, "Back", 2, self.palette.on_surface);
        draw_text(surface, url_r.x + 24, url_r.y + 28, &truncate_str(&self.browser_url, 40), 2, self.palette.primary);
        self.action_rects.push((back_r, UiCommand::BrowserBack));
        self.action_rects.push((
            url_r,
            UiCommand::OpenKeyboard(KeyboardPurpose::BrowserUrl, self.browser_url.clone()),
        ));
        y += 96;

        // 1-Tap Bookmarks bar
        let gap = 10;
        let bw = (w - pad * 2 - gap * (DEFAULT_BOOKMARKS.len() as i32 - 1)) / DEFAULT_BOOKMARKS.len() as i32;
        for (i, &(lbl, url)) in DEFAULT_BOOKMARKS.iter().enumerate() {
            let r = Rect::new(pad + i as i32 * (bw + gap), y, bw, 64);
            fill_rounded_rect(surface, r, 20.0, self.palette.secondary_container);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 32, lbl, 2, self.palette.on_secondary_container);
            self.action_rects.push((r, UiCommand::BrowserNavigate(url.into())));
        }
        y += 78;

        // Rendered Page Title
        let title_r = Rect::new(pad, y, w - pad * 2, 72);
        fill_rounded_rect(surface, title_r, 22.0, self.palette.surface_container);
        let page_title = if self.browser_page.title.is_empty() {
            "Jelajah Fast Browser"
        } else {
            &self.browser_page.title
        };
        draw_text(surface, title_r.x + 24, title_r.y + 24, &truncate_str(page_title, 44), 3, self.palette.on_surface);
        y = title_r.bottom() + 14;

        // Pixel-smooth inertial scrollable browser viewport!
        let viewport = Rect::new(pad, y, w - pad * 2, (h - y - 208).max(200));
        let text_h = self.browser_page.text_lines.len() as i32 * 40;
        let links_h = self.browser_page.links.len() as i32 * 88;
        self.browser_scroll
            .set_bounds((text_h + links_h + 24 - viewport.h).max(0) as f32);
        let scroll_px = self.browser_scroll.scroll_px();

        surface.set_clip(viewport);
        let mut cy = viewport.y - scroll_px;
        for line in &self.browser_page.text_lines {
            if cy + 40 >= viewport.y && cy <= viewport.bottom() {
                draw_text(surface, pad + 16, cy, &truncate_str(line, 62), 2, self.palette.on_surface_variant);
            }
            cy += 40;
        }
        for link in &self.browser_page.links {
            if cy + 76 >= viewport.y && cy <= viewport.bottom() {
                let r = Rect::new(pad, cy, w - pad * 2, 76);
                let bg = if link.is_flashable {
                    self.palette.primary_container
                } else {
                    self.palette.surface_container_low
                };
                let fg = if link.is_flashable {
                    self.palette.on_primary_container
                } else {
                    self.palette.primary
                };
                fill_rounded_rect(surface, r, 22.0, bg);
                let lbl = if link.is_flashable {
                    format!("[FLASH/DL] {}", link.label)
                } else {
                    link.label.clone()
                };
                draw_text(surface, r.x + 24, r.y + 26, &truncate_str(&lbl, 48), 2, fg);
                let hit = r.intersect(viewport);
                if !hit.is_empty() {
                    self.action_rects
                        .push((hit, UiCommand::BrowserNavigate(link.href.clone())));
                }
            }
            cy += 88;
        }
        surface.reset_clip();
    }

    fn render_tools_kernel_menu(&mut self, surface: &mut Surface, pad: i32, mut y: i32) {
        let w = surface.width as i32;

        // Kernel & Power Tuner Card
        let kcard = Rect::new(pad, y, w - pad * 2, 224);
        fill_rounded_rect(surface, kcard, 36.0, self.palette.primary_container);
        draw_text(surface, kcard.x + 32, kcard.y + 24, "Kernel & Power Tuner", 4, self.palette.on_primary_container);
        let prof_line = format!(
            "Profile: {} | {}Hz | BL {}% | AutoSave <= {}%",
            self.power_profile.label(),
            self.refresh_hz,
            self.backlight_pct,
            self.low_batt_threshold_pct
        );
        draw_text(surface, kcard.x + 32, kcard.y + 78, &prof_line, 2, self.palette.on_primary_container);

        let profiles = [
            ("UltraSave", PowerProfile::UltraPowersave),
            ("Save", PowerProfile::Powersave),
            ("Balanced", PowerProfile::Balanced),
            ("Turbo", PowerProfile::TurboFlash),
        ];
        let pgap = 12;
        let pw = (kcard.w - 64 - pgap * 3) / 4;
        for (i, (short, prof)) in profiles.iter().enumerate() {
            let pr = Rect::new(kcard.x + 32 + i as i32 * (pw + pgap), kcard.y + 132, pw, 68);
            let active = *prof == self.power_profile;
            fill_rounded_rect(
                surface,
                pr,
                26.0,
                if active { self.palette.primary } else { self.palette.surface_container_high },
            );
            draw_text_centered(
                surface,
                pr.x + pr.w / 2,
                pr.y + 34,
                short,
                2,
                if active { self.palette.on_primary } else { self.palette.on_surface },
            );
            self.action_rects.push((pr, UiCommand::ApplyPowerProfile(*prof)));
        }
        y = kcard.bottom() + 18;

        // Live SM8735 CPU Cluster Clock Card
        if let Some(ref snap) = self.kernel_snap {
            let cl_h = 62 + (snap.clusters.len() as i32 * 40).max(40);
            let cl_r = Rect::new(pad, y, w - pad * 2, cl_h);
            fill_rounded_rect(surface, cl_r, 32.0, self.palette.surface_container);
            draw_text(surface, cl_r.x + 28, cl_r.y + 18, "Live CPU Clocks / UFS / TCP", 3, self.palette.on_surface);
            for (i, c) in snap.clusters.iter().enumerate() {
                let line = format!(
                    "{}: {} MHz ({}..{} MHz) [{}]",
                    c.name,
                    c.cur_freq_khz / 1000,
                    c.scaling_min_khz / 1000,
                    c.scaling_max_khz / 1000,
                    c.governor
                );
                draw_text(surface, cl_r.x + 28, cl_r.y + 58 + i as i32 * 38, &line, 2, self.palette.on_surface_variant);
            }
            y = cl_r.bottom() + 18;
        }

        // Refresh Rate (60 / 90 / 120 Hz) + Live Draggable Brightness Slider
        let rbw = (w - pad * 2 - 24) / 3;
        for (i, hz) in [60u32, 90, 120].iter().enumerate() {
            let r = Rect::new(pad + i as i32 * (rbw + 12), y, rbw, 68);
            let active = self.refresh_hz == *hz;
            fill_rounded_rect(
                surface,
                r,
                24.0,
                if active { self.palette.secondary_container } else { self.palette.surface_container_low },
            );
            draw_text_centered(surface, r.x + r.w / 2, r.y + 34, &format!("{hz} Hz"), 2, self.palette.on_surface);
            self.action_rects.push((r, UiCommand::SetRefreshHz(*hz)));
        }
        y += 82;

        let slider_r = draw_m3_slider(
            surface,
            Rect::new(pad, y, w - pad * 2, 78),
            &self.palette,
            "Brightness",
            self.backlight_pct,
        );
        self.brightness_slider_rect = Some(slider_r);
        y += 92;

        let io_sched = self
            .kernel_snap
            .as_ref()
            .and_then(|s| s.io_queue.as_ref())
            .map(|q| q.active_scheduler.as_str())
            .unwrap_or("mq-deadline");
        let tcp = self
            .kernel_snap
            .as_ref()
            .map(|s| s.tcp_active.as_str())
            .unwrap_or("bbr3");

        let rows: Vec<(String, UiCommand)> = vec![
            (self.gpu_summary.clone(), UiCommand::ToggleGpuDriver),
            (
                format!(
                    "Haptic Vibrate (si_haptic): {}  (Tap to test)",
                    if self.haptics_enabled { "ON" } else { "OFF" }
                ),
                UiCommand::TestVibrate,
            ),
            (
                format!("Bypass Charge: {}", if self.bypass_charge { "ON" } else { "OFF" }),
                UiCommand::ToggleBypassCharge(!self.bypass_charge),
            ),
            (format!("UFS Scheduler: {io_sched} (Tap to cycle)"), UiCommand::CycleIoScheduler),
            (format!("TCP Congestion: {tcp} (Tap to cycle)"), UiCommand::CycleTcpCongestion),
            (format!("USB Mode: {:?} (DRP / ADB / OTG)", self.usb_mode), UiCommand::CycleUsbMode),
            (
                format!(
                    "Theme: {} | OLED Black: {}",
                    PRESET_SEEDS[self.theme_preset_idx].0,
                    if self.palette.oled_black { "ON" } else { "OFF" }
                ),
                UiCommand::CycleThemePreset,
            ),
            (
                format!("{} (Toggle)", t(self.locale, StrKey::OledBlack)),
                UiCommand::ToggleOledBlack,
            ),
            ("Start ADB Sideload (AOSP/TWRP)".into(), UiCommand::StartSideload),
            ("Reboot Menu (System / Fastbootd / Bootloader)".into(), UiCommand::OpenRebootSheet),
        ];
        let viewport = Rect::new(pad, y, w - pad * 2, (surface.height as i32 - y - 208).max(160));
        let stride = 86;
        let total_h = rows.len() as i32 * stride;
        self.kernel_scroll
            .set_bounds((total_h - viewport.h).max(0) as f32);
        let scroll_px = self.kernel_scroll.scroll_px();
        surface.set_clip(viewport);
        for (i, (label, cmd)) in rows.into_iter().enumerate() {
            let ry = viewport.y + i as i32 * stride - scroll_px;
            if ry + 76 < viewport.y {
                continue;
            }
            if ry > viewport.bottom() {
                break;
            }
            let r = Rect::new(pad, ry, w - pad * 2, 76);
            fill_rounded_rect(surface, r, 22.0, self.palette.surface_container_low);
            draw_text(surface, r.x + 28, r.y + 26, &label, 2, self.palette.on_surface);
            let hit = r.intersect(viewport);
            if !hit.is_empty() {
                self.action_rects.push((hit, cmd));
            }
        }
        surface.reset_clip();
    }

    fn render_tools_terminal(&mut self, surface: &mut Surface, pad: i32, mut y: i32) {
        let w = surface.width as i32;
        let h = surface.height as i32;

        // Quick rescue command presets
        let presets = [
            ("dmesg", "dmesg | tail -n 20"),
            ("df -h", "df -h"),
            ("mount", "mount | head -n 20"),
            ("kernel", "twrp kernel info"),
            ("power", "twrp power status"),
            ("touch", "cat /proc/nvt_fw_version"),
        ];
        let bw = (w - pad * 2 - 24) / 3;
        for (i, &(lbl, cmd)) in presets.iter().enumerate() {
            let col = (i % 3) as i32;
            let row = (i / 3) as i32;
            let r = Rect::new(pad + col * (bw + 12), y + row * 82, bw, 70);
            fill_rounded_rect(surface, r, 22.0, self.palette.secondary_container);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 35, lbl, 2, self.palette.on_secondary_container);
            self.action_rects.push((r, UiCommand::RunShellCommand(cmd.into())));
        }
        y += 174;

        // Type custom command button (opens M3 QWERTY Keyboard)
        let type_r = Rect::new(pad, y, w - pad * 2, 84);
        fill_rounded_rect(surface, type_r, 28.0, self.palette.primary_container);
        draw_text_centered(
            surface,
            type_r.x + type_r.w / 2,
            type_r.y + 42,
            "Type Custom Shell Command (M3 Keyboard)",
            3,
            self.palette.on_primary_container,
        );
        self.action_rects.push((
            type_r,
            UiCommand::OpenKeyboard(KeyboardPurpose::TerminalCommand, String::new()),
        ));
        y += 100;

        // Pixel-smooth scrollable Console output pane
        let console_h = (h - y - 208).max(200);
        let box_r = Rect::new(pad, y, w - pad * 2, console_h);
        fill_rounded_rect(surface, box_r, 28.0, self.palette.surface_container_lowest);
        let line_h = 34;
        let content_h = self.terminal_output.len() as i32 * line_h + 40;
        self.terminal_scroll
            .set_bounds((content_h - console_h).max(0) as f32);
        let scroll_px = self.terminal_scroll.scroll_px();
        let inner = Rect::new(box_r.x + 12, box_r.y + 12, box_r.w - 24, box_r.h - 24);
        surface.set_clip(inner);
        for (i, line) in self.terminal_output.iter().enumerate() {
            let ly = box_r.y + 20 + i as i32 * line_h - scroll_px;
            if ly + line_h < inner.y {
                continue;
            }
            if ly > inner.bottom() {
                break;
            }
            draw_text(
                surface,
                box_r.x + 20,
                ly,
                &truncate_str(line, 90),
                2,
                self.palette.success,
            );
        }
        surface.reset_clip();
    }

    fn render_tools_modules(&mut self, surface: &mut Surface, pad: i32, mut y: i32) {
        let w = surface.width as i32;
        let safe_r = Rect::new(pad, y, w - pad * 2, 92);
        fill_rounded_rect(surface, safe_r, 28.0, self.palette.error_container);
        draw_text_centered(
            surface,
            safe_r.x + safe_r.w / 2,
            safe_r.y + 46,
            t(self.locale, StrKey::SafeModeDisableAll),
            3,
            self.palette.on_error_container,
        );
        self.action_rects.push((safe_r, UiCommand::RequestDisableAllModules));
        y += 108;

        if self.modules.is_empty() {
            let r = Rect::new(pad, y, w - pad * 2, 120);
            fill_rounded_rect(surface, r, 28.0, self.palette.surface_container);
            draw_text_centered(
                surface,
                r.x + r.w / 2,
                r.y + 60,
                "No Magisk / Akar / KernelSU modules found in /data/adb/modules",
                2,
                self.palette.on_surface_variant,
            );
        } else {
            let max_y = surface.height as i32 - 220;
            for m in &self.modules {
                if y + 112 > max_y {
                    break;
                }
                let r = Rect::new(pad, y, w - pad * 2, 112);
                fill_rounded_rect(surface, r, 28.0, self.palette.surface_container_low);
                draw_text(surface, r.x + 28, r.y + 24, &format!("{} ({})", m.name, m.version), 3, self.palette.on_surface);
                let state = if m.disabled { "DISABLED (Tap to enable)" } else { "ENABLED (Tap to disable)" };
                let col = if m.disabled { self.palette.error } else { self.palette.success };
                draw_text(surface, r.x + 28, r.y + 68, &format!("{} | {}", m.id, state), 2, col);
                self.action_rects.push((
                    r,
                    UiCommand::ToggleModule {
                        id: m.id.clone(),
                        disable: !m.disabled,
                    },
                ));
                y += 126;
            }
        }
    }

    fn render_tools_passport(&mut self, surface: &mut Surface, pad: i32, mut y: i32) {
        let w = surface.width as i32;
        let card = Rect::new(pad, y, w - pad * 2, 480);
        fill_rounded_rect(surface, card, 36.0, self.palette.surface_container);
        let text = self.passport.format_export(self.reveal_passport_ids);
        for (i, line) in text.lines().enumerate() {
            draw_text(surface, card.x + 32, card.y + 32 + i as i32 * 48, line, 3, self.palette.on_surface);
        }
        y = card.bottom() + 24;

        let half = (w - pad * 2 - 16) / 2;
        let rev_r = Rect::new(pad, y, half, 92);
        let exp_r = Rect::new(pad + half + 16, y, half, 92);
        fill_rounded_rect(surface, rev_r, 28.0, self.palette.secondary_container);
        fill_rounded_rect(surface, exp_r, 28.0, self.palette.primary_container);
        draw_text_centered(
            surface,
            rev_r.x + rev_r.w / 2,
            rev_r.y + 46,
            if self.reveal_passport_ids { "Mask IDs" } else { "Reveal IDs" },
            3,
            self.palette.on_secondary_container,
        );
        draw_text_centered(
            surface,
            exp_r.x + exp_r.w / 2,
            exp_r.y + 46,
            "Export .txt",
            3,
            self.palette.on_primary_container,
        );
        self.action_rects.push((rev_r, UiCommand::TogglePassportReveal));
        self.action_rects.push((exp_r, UiCommand::ExportPassport));
    }

    fn render_quick_settings_sheet(&mut self, surface: &mut Surface) {
        self.action_rects.clear();
        surface.darken_scrim(self.quick_settings_sheet.scrim_alpha());
        let w = surface.width as i32;
        let pad = 28;
        let top_y = (surface.height as i32 / 24).max(48) + 92;
        let sheet_h = 852;
        let sheet = Rect::new(
            pad,
            top_y + self.quick_settings_sheet.offset_px(),
            w - pad * 2,
            sheet_h,
        );
        self.active_sheet_rect = sheet;
        draw_m3_top_sheet_chrome(surface, sheet, &self.palette);

        draw_text(surface, sheet.x + 36, sheet.y + 34, "Quick Settings", 4, self.palette.on_surface);
        let close_r = Rect::new(sheet.right() - 180, sheet.y + 22, 148, 64);
        fill_rounded_rect(surface, close_r, 24.0, self.palette.surface_container_high);
        draw_text_centered(surface, close_r.x + close_r.w / 2, close_r.y + 32, "Close", 2, self.palette.on_surface);
        self.action_rects.push((close_r, UiCommand::CloseOverlay));

        // 1. Live Draggable Brightness Slider
        let mut y = sheet.y + 108;
        let slider_r = draw_m3_slider(
            surface,
            Rect::new(sheet.x + 32, y, sheet.w - 64, 86),
            &self.palette,
            "Brightness",
            self.backlight_pct,
        );
        self.brightness_slider_rect = Some(slider_r);
        y += 108;

        // 2. Refresh Rate Pills: 60 / 90 / 120 Hz
        let rbw = (sheet.w - 64 - 24) / 3;
        for (i, hz) in [60u32, 90, 120].iter().enumerate() {
            let r = Rect::new(sheet.x + 32 + i as i32 * (rbw + 12), y, rbw, 76);
            let active = self.refresh_hz == *hz;
            fill_rounded_rect(
                surface,
                r,
                26.0,
                if active { self.palette.primary } else { self.palette.surface_container },
            );
            draw_text_centered(
                surface,
                r.x + r.w / 2,
                r.y + 38,
                &format!("{hz} Hz"),
                3,
                if active { self.palette.on_primary } else { self.palette.on_surface },
            );
            self.action_rects.push((r, UiCommand::SetRefreshHz(*hz)));
        }
        y += 98;

        // 3. 2x3 Quick Tiles Grid (Wi-Fi 7, Jelajah Web, Adreno GPU, Vibrate Toggle, Test Vibrate, Sleep Screen)
        let tiles: [(String, UiCommand, bool); 6] = [
            (
                if self.status.wifi_on { "Wi-Fi 7: ON".into() } else { "Wi-Fi 7: OFF".into() },
                UiCommand::ToggleWifiDriver,
                self.status.wifi_on,
            ),
            (
                "Jelajah Web Browser".into(),
                UiCommand::OpenToolsView(ToolsView::Browser),
                false,
            ),
            (
                if self.gpu_active { "Adreno GPU: ON".into() } else { "Adreno GPU: OFF".into() },
                UiCommand::ToggleGpuDriver,
                self.gpu_active,
            ),
            (
                if self.haptics_enabled { "Haptics: ON".into() } else { "Haptics: OFF".into() },
                UiCommand::ToggleHaptics,
                self.haptics_enabled,
            ),
            (
                "Test Vibrate (Motor)".into(),
                UiCommand::TestVibrate,
                false,
            ),
            (
                "Turn Screen OFF".into(),
                UiCommand::SleepScreen,
                false,
            ),
        ];
        let gap = 16;
        let tw = (sheet.w - 64 - gap) / 2;
        let th = 112;
        for (idx, (lbl, cmd, active)) in tiles.into_iter().enumerate() {
            let col = (idx % 2) as i32;
            let row = (idx / 2) as i32;
            let r = Rect::new(sheet.x + 32 + col * (tw + gap), y + row * (th + gap), tw, th);
            let bg = if active { self.palette.primary_container } else { self.palette.surface_container };
            let fg = if active { self.palette.on_primary_container } else { self.palette.on_surface };
            fill_rounded_rect(surface, r, 30.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + th / 2, &lbl, 3, fg);
            self.action_rects.push((r, cmd));
        }
        y += 3 * (th + gap) + 8;

        // Bottom Reboot shortcut inside Quick Settings
        let reb_r = Rect::new(sheet.x + 32, y, sheet.w - 64, 84);
        fill_rounded_rect(surface, reb_r, 28.0, self.palette.secondary_container);
        draw_text_centered(
            surface,
            reb_r.x + reb_r.w / 2,
            reb_r.y + 42,
            "Reboot Menu (System / Fastbootd / Power Off)",
            3,
            self.palette.on_secondary_container,
        );
        self.action_rects.push((reb_r, UiCommand::OpenRebootSheet));
    }

    fn render_reboot_sheet(&mut self, surface: &mut Surface) {
        self.action_rects.clear();
        surface.darken_scrim(self.bottom_sheet.scrim_alpha());
        let w = surface.width as i32;
        let h = surface.height as i32;
        let pad = 28;
        let sheet_h = 800;
        let sheet = Rect::new(
            pad,
            h - sheet_h - 36 + self.bottom_sheet.offset_px(),
            w - pad * 2,
            sheet_h,
        );
        self.active_sheet_rect = sheet;
        draw_m3_bottom_sheet_chrome(surface, sheet, &self.palette);
        draw_text_centered(surface, sheet.x + sheet.w / 2, sheet.y + 66, t(self.locale, StrKey::Reboot), 4, self.palette.on_surface);
        let opts = [
            (t(self.locale, StrKey::RebootSystem), UiCommand::RebootSystem, self.palette.primary_container, self.palette.on_primary_container),
            ("Reboot Recovery", UiCommand::RebootRecovery, self.palette.surface_container, self.palette.on_surface),
            (t(self.locale, StrKey::RebootFastbootd), UiCommand::EnterFastbootd, self.palette.surface_container, self.palette.on_surface),
            (t(self.locale, StrKey::RebootBootloader), UiCommand::RebootBootloader, self.palette.surface_container, self.palette.on_surface),
            (t(self.locale, StrKey::PowerOff), UiCommand::PowerOff, self.palette.error_container, self.palette.on_error_container),
            (t(self.locale, StrKey::Cancel), UiCommand::CloseOverlay, self.palette.surface_container_low, self.palette.on_surface_variant),
        ];
        let mut ry = sheet.y + 116;
        for (label, cmd, bg, fg) in opts {
            let r = Rect::new(sheet.x + 32, ry, sheet.w - 64, 92);
            fill_rounded_rect(surface, r, 30.0, bg);
            draw_text_centered(surface, r.x + r.w / 2, r.y + 46, label, 3, fg);
            self.action_rects.push((r, cmd));
            ry += 106;
        }
    }

    fn render_keyboard_modal(
        &mut self,
        surface: &mut Surface,
        purpose: &KeyboardPurpose,
        text: &str,
        upper: bool,
        symbols: bool,
    ) {
        self.action_rects.clear();
        surface.darken_scrim(self.keyboard_sheet.scrim_alpha());
        let w = surface.width as i32;
        let h = surface.height as i32;
        let off_y = self.keyboard_sheet.offset_px();
        let prompt = match purpose {
            KeyboardPurpose::NewFolder => "New Folder Name:",
            KeyboardPurpose::Rename(_) => "Rename To:",
            KeyboardPurpose::TerminalCommand => "Shell Command:",
            KeyboardPurpose::BrowserUrl => "Jelajah URL or Search:",
            KeyboardPurpose::WifiPassword(ssid) => {
                // Borrow static fallback below
                let _ = ssid;
                "Wi-Fi Password (WPA2/WPA3):"
            }
        };
        let box_r = Rect::new(20, h - 946 + off_y, w - 40, 200);
        self.active_sheet_rect = Rect::new(0, box_r.y, w, h - box_r.y);
        draw_m3_bottom_sheet_chrome(surface, box_r, &self.palette);
        draw_text(surface, box_r.x + 28, box_r.y + 38, prompt, 3, self.palette.primary);

        let cancel_r = Rect::new(box_r.right() - 172, box_r.y + 24, 148, 56);
        fill_rounded_rect(surface, cancel_r, 22.0, self.palette.error_container);
        draw_text_centered(
            surface,
            cancel_r.x + cancel_r.w / 2,
            cancel_r.y + 28,
            "Cancel",
            2,
            self.palette.on_error_container,
        );

        let inp_r = Rect::new(box_r.x + 24, box_r.y + 94, box_r.w - 48, 84);
        fill_rounded_rect(surface, inp_r, 22.0, self.palette.surface_container_lowest);
        draw_text(
            surface,
            inp_r.x + 20,
            inp_r.y + 28,
            &format!("{}_", truncate_str(text, 44)),
            3,
            self.palette.on_surface,
        );
        let raw_keys = draw_qwerty_keyboard_offset(surface, &self.palette, upper, symbols, off_y);
        self.keyboard_keys = raw_keys;
        self.keyboard_keys.push((cancel_r, KeyAction::Cancel));
    }
}

fn slider_pct_from_x(r: Rect, x: i32) -> u8 {
    let span = r.w.max(1) as i64;
    let rel = (x - r.x).clamp(0, r.w) as i64;
    let pct = 5 + (rel * 95) / span;
    pct.clamp(5, 100) as u8
}

pub fn default_partition_rows() -> Vec<PartitionRow> {
    vec![
        PartitionRow {
            name: "userdata".into(),
            mountpoint: "/data".into(),
            fstype: "f2fs".into(),
            mounted: false,
            rw: false,
            protected: false,
        },
        PartitionRow {
            name: "metadata".into(),
            mountpoint: "/metadata".into(),
            fstype: "f2fs".into(),
            mounted: true,
            rw: false,
            protected: false,
        },
        PartitionRow {
            name: "usbotg".into(),
            mountpoint: "/storage/usbotg".into(),
            fstype: "auto".into(),
            mounted: false,
            rw: false,
            protected: false,
        },
        PartitionRow {
            name: "boot".into(),
            mountpoint: "/boot".into(),
            fstype: "emmc".into(),
            mounted: false,
            rw: false,
            protected: false,
        },
        PartitionRow {
            name: "recovery".into(),
            mountpoint: "/recovery".into(),
            fstype: "emmc".into(),
            mounted: false,
            rw: false,
            protected: false,
        },
        PartitionRow {
            name: "super".into(),
            mountpoint: "/super".into(),
            fstype: "lp-v10.2".into(),
            mounted: false,
            rw: false,
            protected: true,
        },
        PartitionRow {
            name: "persist".into(),
            mountpoint: "/mnt/vendor/persist".into(),
            fstype: "ext4".into(),
            mounted: false,
            rw: false,
            protected: true,
        },
        PartitionRow {
            name: "xbl_a".into(),
            mountpoint: "/bootloader".into(),
            fstype: "emmc".into(),
            mounted: false,
            rw: false,
            protected: true,
        },
    ]
}

fn truncate_str(s: &str, max_chars: usize) -> String {
    let cnt = s.chars().count();
    if cnt <= max_chars {
        s.to_string()
    } else if max_chars > 3 {
        let mut out: String = s.chars().take(max_chars - 3).collect();
        out.push_str("...");
        out
    } else {
        s.chars().take(max_chars).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn ui_blocks_protected_wipe_enforces_pin_and_triggers_auto_powersave() {
        let lock = PulihLock::create("1234", [7u8; 16], 1000).unwrap();
        let mut app = PulihApp::new(0xFF6750A4, false, Locale::EnUs, Some(lock));
        let mut surf = Surface::new(1280, 2772);

        app.render(&mut surf, 0.0, None);
        assert_eq!(app.handle_input(InputEvent::KeySelect), UiCommand::None);

        for c in "0000".chars() {
            assert!(!app.submit_pin_digit(c));
        }
        app.pin_buffer.clear();
        for c in "123".chars() {
            assert!(!app.submit_pin_digit(c));
        }
        assert!(app.submit_pin_digit('4'));
        assert!(app.unlocked);

        // Anti-brick guard blocks protected wipe right inside UI
        assert!(app.request_destructive(PendingDestructive::WipePartition("xbl_a".into())).is_err());
        assert!(app.request_destructive(PendingDestructive::WipePartition("persist".into())).is_err());

        // Safe wipe requires full swipe confirm
        assert!(app.request_destructive(PendingDestructive::WipePartition("userdata".into())).is_ok());
        app.render(&mut surf, 0.0, None);
        let sr = app.swipe_rect;
        app.handle_input(InputEvent::TouchDown { x: sr.x + 40, y: sr.y + sr.h / 2 });
        let cmd = app.handle_input(InputEvent::TouchMove { x: sr.right() - 10, y: sr.y + sr.h / 2 });
        assert_eq!(cmd, UiCommand::ExecuteWipe("userdata".into()));

        // Low battery triggers automatic UltraPowersave
        let low_bat = PowerTelemetry {
            capacity_pct: 11,
            status: "Discharging".into(),
            temp_tenths_c: 320,
            ..Default::default()
        };
        assert_eq!(app.update_telemetry(&low_bat), Some(PowerProfile::UltraPowersave));
        assert_eq!(app.power_profile, PowerProfile::UltraPowersave);
    }

    #[test]
    fn file_manager_ui_lists_dotfiles_edits_chmod_and_opens_text_viewer() {
        let tmp = std::env::temp_dir().join(format!("pulih_ui_fm_{}", std::process::id()));
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let f = tmp.join(".secret.conf");
        fs::write(&f, b"key=value\n").unwrap();

        let mut app = PulihApp::new(0xFF6750A4, false, Locale::EnUs, None);
        let mut surf = Surface::new(1280, 2772);
        app.active_tab = Tab::Files;
        app.apply_internal_cmd(UiCommand::OpenDir(tmp.clone()));
        assert!(app.files_entries.iter().any(|e| e.name == ".secret.conf"));

        // Open Chmod modal -> preset 0755 -> toggle Other Exec -> commit -> verify on real disk!
        app.apply_internal_cmd(UiCommand::OpenChmodModal(f.clone(), 0o644));
        app.apply_internal_cmd(UiCommand::SetChmodPreset(0o755));
        app.apply_internal_cmd(UiCommand::ToggleChmodBit(0o001)); // 0754
        app.render(&mut surf, 0.0, None);
        app.apply_internal_cmd(UiCommand::CommitChmod);
        assert_eq!(fs::metadata(&f).unwrap().mode() & 0o777, 0o754);

        // Open text viewer
        app.apply_internal_cmd(UiCommand::OpenTextViewer(f.clone()));
        assert!(app.text_viewer.is_some());
        app.render(&mut surf, 0.0, None);

        // Anti-brick guard blocks deleting /system via UI
        app.apply_internal_cmd(UiCommand::RequestDelete(vec![PathBuf::from("/system")]));
        assert!(app.swipe_modal.is_none());

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn brightness_slider_power_sleep_quick_settings_and_gboard_work() {
        let mut app = PulihApp::new(0xFF6750A4, false, Locale::EnUs, None);
        let mut surf = Surface::new(1280, 2772);
        app.render(&mut surf, 0.0, None);

        // 1. Power button must NEVER jump to Files — must request SleepScreen!
        assert_eq!(app.handle_input(InputEvent::PowerToggle), UiCommand::SleepScreen);
        assert_eq!(app.active_tab, Tab::Home);

        // 2. Dragging Home Brightness Slider updates backlight live
        let sr = app.brightness_slider_rect.expect("home brightness slider rect");
        let cmd_down = app.handle_input(InputEvent::TouchDown {
            x: sr.x + sr.w / 4,
            y: sr.y + sr.h / 2,
        });
        assert!(matches!(cmd_down, UiCommand::SetBacklightPct(p) if (20..=35).contains(&p)));
        let cmd_move = app.handle_input(InputEvent::TouchMove {
            x: sr.right() - 10,
            y: sr.y + sr.h / 2,
        });
        assert!(matches!(cmd_move, UiCommand::SetBacklightPct(p) if p >= 95));
        app.handle_input(InputEvent::TouchUp {
            x: sr.right() - 10,
            y: sr.y + sr.h / 2,
        });
        assert!(app.backlight_pct >= 95);

        // 3. Volume Down on Home steps backlight down by 10%
        let prev = app.backlight_pct;
        let cmd_vol = app.handle_input(InputEvent::KeyFocusNext);
        assert_eq!(cmd_vol, UiCommand::SetBacklightPct(prev.saturating_sub(10)));

        // 4. Pull-down Quick Settings renders with its own slider & tiles
        app.handle_input(InputEvent::PullDownQuickSettings);
        assert!(app.show_quick_settings);
        app.render(&mut surf, 0.0, None);
        assert!(app.brightness_slider_rect.is_some());
        assert!(app.dump_ui_json().contains("\"quick_settings\":true"));

        // 5. 1:1 Gboard keyboard types letters, toggles ?123 symbols, and submits command
        app.apply_internal_cmd(UiCommand::OpenKeyboard(
            KeyboardPurpose::TerminalCommand,
            String::new(),
        ));
        app.render(&mut surf, 0.0, None);
        let find_key = |keys: &[(Rect, KeyAction)], target: KeyAction| -> (i32, i32) {
            let (r, _) = keys.iter().find(|(_, k)| *k == target).expect("key present");
            (r.x + r.w / 2, r.y + r.h / 2)
        };
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Char('l'));
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Char('s'));
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Space);
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        // Toggle ?123 symbols page to type '-'
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Symbols);
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        app.render(&mut surf, 0.0, None);
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Char('-'));
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        // Toggle back to ABC and type 'a' then Enter
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Symbols);
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        app.render(&mut surf, 0.0, None);
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Char('a'));
        app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        let (kx, ky) = find_key(&app.keyboard_keys, KeyAction::Enter);
        let submitted = app.handle_input(InputEvent::TouchUp { x: kx, y: ky });
        assert_eq!(submitted, UiCommand::RunShellCommand("ls -a".into()));
    }
}
