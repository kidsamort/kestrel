//! Autofill into Windows applications: a focus observer, per-app rules and an
//! overlay picker anchored to the field.
//!
//! # Shape
//!
//! * [`uia`] owns the UI Automation observer thread. It registers one
//!   `EVENT_OBJECT_FOCUS` hook, describes the focused field, and is the only
//!   thread that talks to `IUIAutomationValuePattern`.
//! * This module decides whether an offer is allowed ([`should_show`]), turns
//!   an inspection into a target, places the overlay ([`anchored_origin`]) and
//!   exposes the Tauri commands the renderer uses.
//! * Rules live in the core (`autofill_apps`, schema v6) behind a second,
//!   plaintext connection to the same database: a rule is policy, not content,
//!   so it is readable before an unlock and never needs the vault key.
//!
//! # Fill policy
//!
//! Filling is always explicit: the overlay opens, the user clicks a row's
//! `Fill` button. `fill` only decides whether the overlay is *offered* on
//! focus; it never writes by itself. `off` suppresses both the offer and the
//! shortcut. A missing rule is `ask`.
//!
//! The value is decrypted in the core, handed to [`uia::Worker::fill`] as a
//! `String`, written through the value pattern, and dropped. It never enters
//! the renderer, the overlay's state, the target DTO or a log line.
//!
//! # Unsigned binary, elevated targets
//!
//! This build is unsigned. Kestrel therefore refuses to write into a process
//! whose token integrity level is above its own, and it says so in the overlay.
//! The refusal is a feature: an unsigned binary reaching into an elevated
//! window is exactly the behaviour users should not have to trust.

pub mod uia;

use std::collections::HashMap;
use std::sync::Mutex;

use kestrel_core::model::ItemSummary;
use kestrel_core::session::VaultState;
use kestrel_core::store::Store;
use serde::Serialize;
use tauri::{
    AppHandle, Manager, PhysicalPosition, State, WebviewUrl, WebviewWindow, WebviewWindowBuilder,
};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, ShortcutState};

use uia::{ElementKey, Inspection, Rect};

/// Window label of the overlay; the main window is `main`, the palette `quick`.
pub const WINDOW_LABEL: &str = "autofill";
/// The explicit offer, for applications whose rule is `ask` (the default).
pub const SHORTCUT: &str = "Ctrl+Shift+F";
/// Emitted to the overlay every time it is shown. The payload is
/// [`TargetDto`] — a description of the field, never a secret.
pub const TARGET_EVENT: &str = "autofill://target";

const WIDTH: f64 = 360.0;
const HEIGHT: f64 = 380.0;
const GAP: i32 = 6;
const MAX_ROWS: usize = 8;
const RECENT_PER_APP: usize = 5;

/// Shown instead of rows when the target runs above our integrity level.
pub const ELEVATED_REFUSAL: &str = "This window runs at a higher integrity level than \
Kestrel (an elevated app or the secure desktop). Kestrel is unsigned, so it will \
not write into it. Copy the item and paste it yourself.";

/// Shown when the target process cannot be queried at all.
pub const UNIDENTIFIED_REFUSAL: &str = "Kestrel cannot read this window's process \
(Windows denied access, which usually means it is elevated). Autofill is refused.";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AutofillStatusDto {
    /// The picker's master switch.
    pub enabled: bool,
    pub shortcut: String,
    /// Whether the system gave us the shortcut.
    pub registered: bool,
    /// Why the shortcut or the observer is unavailable, when known.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuleDto {
    pub exe: String,
    pub mode: String,
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RectDto {
    pub x: i32,
    pub y: i32,
    pub width: i32,
    pub height: i32,
}

/// What the overlay is allowed to know about the focused field.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TargetDto {
    pub exe: String,
    pub pid: u32,
    pub is_password: bool,
    pub control_type: String,
    pub automation_id: String,
    pub class_name: String,
    /// Field rectangle in physical screen pixels.
    pub rect: RectDto,
    /// `fill`, `ask` or `off` — the rule in force for `exe`.
    pub mode: String,
    /// Non-null when the field may not be filled; the overlay shows this
    /// instead of rows.
    pub refused: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SuggestDto {
    /// Items last filled into this executable during this session.
    pub recent: Vec<ItemSummary>,
    /// Search hits for the current query (the first items when it is empty).
    pub matches: Vec<ItemSummary>,
}

/// One resolved field plus the identity a fill has to re-check.
#[derive(Debug, Clone)]
struct Target {
    dto: TargetDto,
    key: ElementKey,
    hwnd: isize,
}

struct Inner {
    enabled: bool,
    registered: bool,
    error: Option<String>,
    /// The chord that offers the picker; parsed by the plugin, stored in the
    /// vault, and reported back so the UI never shows a chord nobody bound.
    chord: String,
    target: Option<Target>,
    visible: bool,
}

/// Managed state for the picker. `rules` is a dedicated connection because the
/// rule surface must work while the vault is locked; `worker` is the observer
/// thread handle.
pub struct AutofillState {
    inner: Mutex<Inner>,
    rules: Mutex<Option<Store>>,
    /// Recents are session-local by design. Schema v6 has no autofill history
    /// table, and persisting "which login was used in which application" would
    /// be a behavioural log the user never asked for.
    recents: Mutex<HashMap<String, Vec<String>>>,
    worker: Mutex<Option<std::sync::Arc<uia::Worker>>>,
}

impl AutofillState {
    fn new(
        rules: Option<Store>,
        enabled: bool,
        chord: Option<String>,
        error: Option<String>,
    ) -> AutofillState {
        AutofillState {
            inner: Mutex::new(Inner {
                enabled,
                registered: false,
                error,
                chord: chord.unwrap_or_else(|| SHORTCUT.to_string()),
                target: None,
                visible: false,
            }),
            rules: Mutex::new(rules),
            recents: Mutex::new(HashMap::new()),
            worker: Mutex::new(None),
        }
    }

    fn rule(&self, exe: &str) -> String {
        let rules = self.rules.lock().expect("autofill rules mutex");
        rules
            .as_ref()
            .and_then(|store| store.autofill_rule(exe).ok())
            .unwrap_or_else(|| "ask".to_string())
    }

    fn current_target(&self) -> Option<Target> {
        self.inner.lock().expect("autofill mutex").target.clone()
    }

    /// Hand out the observer without holding its slot across a blocking call.
    /// The focus callback runs on the observer thread and also reads state; a
    /// guard held while waiting for that thread would stall it for the timeout.
    fn worker(&self) -> Option<std::sync::Arc<uia::Worker>> {
        self.worker.lock().expect("autofill worker mutex").clone()
    }
}

/// Wire the picker into the shell. Called once from `setup`, **after**
/// `VaultState` is managed (the rule table and the vault share one database).
pub fn init(app: &mut tauri::App) -> tauri::Result<()> {
    let Some(vault) = app.try_state::<VaultState>() else {
        app.manage(AutofillState::new(
            None,
            false,
            None,
            Some("The vault is not initialised; autofill rules are unavailable.".to_string()),
        ));
        return Ok(());
    };

    // A second connection to the same SQLite file. WAL keeps readers and the
    // vault's writers from blocking each other; the rule table is tiny and is
    // written only when the user changes a setting.
    let (rules, error) = match Store::open(vault.vault_path()) {
        Ok(store) => (Some(store), None),
        Err(failure) => (
            None,
            Some(format!("Autofill rules are unavailable: {failure}")),
        ),
    };
    let enabled = rules
        .as_ref()
        .and_then(|store| store.autofill_enabled().ok())
        .unwrap_or(true);
    let chord = rules
        .as_ref()
        .and_then(|store| store.autofill_shortcut().ok().flatten());

    app.manage(AutofillState::new(rules, enabled, chord, error));
    register_shortcut(app.handle());

    let handle = app.handle().clone();
    let started = uia::Worker::start(std::process::id(), move |event| {
        on_event(&handle, event);
    });
    let state = app.state::<AutofillState>();
    match started {
        Ok(worker) => {
            *state.worker.lock().expect("autofill worker mutex") =
                Some(std::sync::Arc::new(worker));
        }
        Err(failure) => record_error(app.handle(), failure),
    }
    Ok(())
}

/// Point the rule table at another vault file.
///
/// The rules live in the vault's own database, and this state keeps a second
/// connection to it. Switching vaults without moving that connection would apply
/// the previous vault's autofill policy to the new one — a privacy bug, not a
/// stale cache.
pub fn reopen(app: &AppHandle, path: &std::path::Path) {
    let Some(state) = app.try_state::<AutofillState>() else {
        return;
    };
    match Store::open(path) {
        Ok(store) => {
            let enabled = store.autofill_enabled().unwrap_or(true);
            *state.rules.lock().expect("autofill rules mutex") = Some(store);
            let mut inner = state.inner.lock().expect("autofill mutex");
            inner.enabled = enabled;
            inner.error = None;
        }
        Err(failure) => {
            *state.rules.lock().expect("autofill rules mutex") = None;
            let mut inner = state.inner.lock().expect("autofill mutex");
            // No rules means no filling: leaving `enabled` true would let the
            // picker act on a vault whose policy nobody can read.
            inner.enabled = false;
            inner.error = Some(format!("Autofill rules are unavailable: {failure}"));
        }
    }
    // Recents name items of the previous vault; they mean nothing here.
    state
        .recents
        .lock()
        .expect("autofill recents mutex")
        .clear();
}

fn register_shortcut(app: &AppHandle) {
    let chord = {
        let state = app.state::<AutofillState>();
        let inner = state.inner.lock().expect("autofill mutex");
        inner.chord.clone()
    };
    let outcome = app
        .global_shortcut()
        .on_shortcut(chord.as_str(), |app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                on_hotkey(app);
            }
        });

    let state = app.state::<AutofillState>();
    let mut inner = state.inner.lock().expect("autofill mutex");
    match outcome {
        Ok(()) => {
            inner.registered = true;
        }
        Err(failure) => {
            inner.registered = false;
            let message = format!("{chord} is unavailable: {failure}");
            inner.error = Some(message);
        }
    }
}

fn record_error(app: &AppHandle, message: String) {
    if let Some(state) = app.try_state::<AutofillState>() {
        let mut inner = state.inner.lock().expect("autofill mutex");
        inner.error = Some(message);
    }
}

/* ------------------------------------------------------------------ rules */

/// True when an application with `rule` may be offered the overlay. `explicit`
/// means the user asked with the shortcut rather than by focusing a field.
///
/// This is the whole policy: `fill` offers on focus, `ask` only on the
/// shortcut, and `off` never. A rule the core does not recognise is treated as
/// `ask` by the store, so it can never reach here as something permissive.
pub fn should_show(rule: &str, explicit: bool) -> bool {
    match rule {
        "fill" => true,
        "off" => false,
        // `ask`, and anything unexpected, require the shortcut.
        _ => explicit,
    }
}

/// Lower-case image name: `C:\Program Files\App\APP.EXE` → `app.exe`.
///
/// The rule table is keyed by this value, so the normalisation is deliberately
/// small and total: take the last path component, trim, lower-case with the
/// ASCII rules (image names are ASCII).
pub fn normalise_exe(raw: &str) -> String {
    let name = raw
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or_default()
        .trim()
        .trim_matches('"');
    name.to_ascii_lowercase()
}

/// Whether a target at `target` RID may be written by a process at `ours`.
/// `None` means Windows would not tell us; that is a refusal, not permission.
pub fn integrity_allows(target: Option<u32>, ours: Option<u32>) -> bool {
    match (target, ours) {
        (Some(target), Some(ours)) => target <= ours,
        _ => false,
    }
}

/* --------------------------------------------------------------- geometry */

/// Top-left corner for an overlay anchored to `field`.
///
/// Preference order: below the field, then above it, then the closest edge of
/// the work area. The horizontal position is clamped so the window never hangs
/// off a monitor edge; a field near the bottom of the screen gets the overlay
/// above it instead of under the taskbar.
pub fn anchored_origin(field: Rect, overlay: (i32, i32), work: Option<Rect>) -> (i32, i32) {
    let (width, height) = overlay;
    let mut x = field.x;
    let mut y = field.y + field.height + GAP;
    if let Some(work) = work {
        if y + height > work.y + work.height {
            let above = field.y - GAP - height;
            y = if above >= work.y {
                above
            } else {
                work.y + work.height - height
            };
        }
        x = x.clamp(work.x, (work.x + work.width - width).max(work.x));
        y = y.clamp(work.y, (work.y + work.height - height).max(work.y));
    }
    (x, y)
}

fn work_area_for(app: &AppHandle, field: Rect) -> Option<Rect> {
    let (x, y) = (field.x + field.width / 2, field.y + field.height / 2);
    let monitor = app.monitor_from_point(x as f64, y as f64).ok().flatten()?;
    let area = monitor.work_area();
    Some(Rect {
        x: area.position.x,
        y: area.position.y,
        width: area.size.width as i32,
        height: area.size.height as i32,
    })
}

/* ---------------------------------------------------------------- events */

fn on_event(app: &AppHandle, event: uia::Event) {
    let Some(state) = app.try_state::<AutofillState>() else {
        return;
    };
    match event {
        uia::Event::Escape => hide_overlay(app, &state, false),
        uia::Event::Foreground { hwnd } => {
            let visible = state.inner.lock().expect("autofill mutex").visible;
            if !visible {
                return;
            }
            // The overlay itself becoming foreground is the user typing in
            // it; anything else is focus leaving the target window.
            if overlay_hwnd(app) == Some(hwnd) {
                return;
            }
            hide_overlay(app, &state, false);
        }
        uia::Event::Focus { inspection } => on_focus(app, &state, inspection),
    }
}

fn on_focus(app: &AppHandle, state: &AutofillState, inspection: Option<Inspection>) {
    if !state.inner.lock().expect("autofill mutex").enabled {
        hide_overlay(app, state, true);
        return;
    }

    let Some(vault) = app.try_state::<VaultState>() else {
        hide_overlay(app, state, true);
        return;
    };
    if vault.is_locked() {
        // Never distract with a picker that cannot resolve a value.
        hide_overlay(app, state, true);
        return;
    }

    let Some(inspection) = inspection else {
        // The focused element could not be described (no provider, or the
        // window vanished): that is a focus loss, not a new target.
        hide_overlay(app, state, true);
        return;
    };

    let mode = state.rule(&inspection.exe);
    let refused = refusal_for(&inspection);
    let fillable = uia::is_fillable(inspection.control_type_id, inspection.is_password);
    let target = Target::from_inspection(&inspection, &mode, refused);

    let mut inner = state.inner.lock().expect("autofill mutex");
    inner.target = Some(target.clone());
    let visible = inner.visible;
    drop(inner);

    if fillable && should_show(&mode, false) {
        present(app, state, target);
    } else if visible {
        // Focus moved to something that is not an offer for this app. The
        // pending target stays, so the shortcut can still reach a field that
        // was focused a moment ago.
        hide_overlay(app, state, false);
    }
}

fn refusal_for(inspection: &Inspection) -> Option<String> {
    if !inspection.integrity_ok {
        return Some(ELEVATED_REFUSAL.to_string());
    }
    if inspection.exe.is_empty() {
        return Some(UNIDENTIFIED_REFUSAL.to_string());
    }
    None
}

impl Target {
    fn from_inspection(inspection: &Inspection, mode: &str, refused: Option<String>) -> Target {
        Target {
            dto: TargetDto {
                exe: inspection.exe.clone(),
                pid: inspection.pid,
                is_password: inspection.is_password,
                control_type: inspection.control_type.to_string(),
                automation_id: inspection.automation_id.clone(),
                class_name: inspection.class_name.clone(),
                rect: RectDto {
                    x: inspection.rect.x,
                    y: inspection.rect.y,
                    width: inspection.rect.width,
                    height: inspection.rect.height,
                },
                mode: mode.to_string(),
                refused,
            },
            key: inspection.key.clone(),
            hwnd: inspection.hwnd,
        }
    }
}

fn on_hotkey(app: &AppHandle) {
    let state = app.state::<AutofillState>();
    if !state.inner.lock().expect("autofill mutex").enabled {
        return;
    }

    // Second press closes: the shortcut is also the escape hatch when the
    // overlay has been activated for typing.
    if state.inner.lock().expect("autofill mutex").visible {
        hide_overlay(app, &state, false);
        return;
    }

    let inspection = state.worker().and_then(|worker| worker.inspect());
    let Some(inspection) = inspection else {
        return;
    };
    if !uia::is_fillable(inspection.control_type_id, inspection.is_password) {
        return;
    }

    let mode = state.rule(&inspection.exe);
    if !should_show(&mode, true) {
        return;
    }
    let target = Target::from_inspection(&inspection, &mode, refusal_for(&inspection));
    present(app, &state, target);
}

/* --------------------------------------------------------------- overlay */

fn present(app: &AppHandle, state: &AutofillState, target: Target) {
    let Some(vault) = app.try_state::<VaultState>() else {
        return;
    };
    if vault.is_locked() {
        return;
    }

    state.inner.lock().expect("autofill mutex").visible = true;
    if let Some(worker) = state.worker() {
        // Escape is swallowed only while the picker is on screen.
        worker.set_gate(true);
    }

    let handle = app.clone();
    let shown = target.clone();
    let _ = app.run_on_main_thread(move || {
        if let Err(failure) = show_window(&handle, &shown) {
            record_error(
                &handle,
                format!("The autofill overlay did not open: {failure}"),
            );
        }
    });
}

fn show_window(app: &AppHandle, target: &Target) -> tauri::Result<()> {
    let window = match app.get_webview_window(WINDOW_LABEL) {
        Some(window) => window,
        None => build_window(app)?,
    };

    let work = work_area_for(
        app,
        Rect {
            x: target.dto.rect.x,
            y: target.dto.rect.y,
            width: target.dto.rect.width,
            height: target.dto.rect.height,
        },
    );
    let (x, y) = anchored_origin(
        Rect {
            x: target.dto.rect.x,
            y: target.dto.rect.y,
            width: target.dto.rect.width,
            height: target.dto.rect.height,
        },
        (WIDTH as i32, HEIGHT as i32),
        work,
    );
    window.set_position(PhysicalPosition::new(x, y))?;
    window.show()?;

    // The overlay may already be mounted; an event keeps its content in sync
    // without relying on a remount.
    let _ = tauri::Emitter::emit_to(app, WINDOW_LABEL, TARGET_EVENT, &target.dto);
    Ok(())
}

fn build_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let window = WebviewWindowBuilder::new(
        app,
        WINDOW_LABEL,
        WebviewUrl::App("index.html?window=autofill".into()),
    )
    .title("Kestrel Autofill")
    .inner_size(WIDTH, HEIGHT)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    // Never take focus by appearing: the field in the other app keeps its
    // caret, so the user does not lose their place by moving the mouse.
    .focused(false)
    .visible(false)
    .transparent(true)
    .background_color(tauri::window::Color(0, 0, 0, 0))
    .shadow(false)
    .build()?;

    apply_noactivate(&window)?;

    // A webview that already has focus (after `autofill_take_input`) hides the
    // overlay when focus leaves it. NOACTIVATE windows are never focused by
    // appearing, so this only fires for a real activation.
    let handle = app.clone();
    let focused_once = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen = focused_once.clone();
    window.on_window_event(move |event| match event {
        tauri::WindowEvent::Focused(true) => {
            seen.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        tauri::WindowEvent::Focused(false)
            if seen.swap(false, std::sync::atomic::Ordering::SeqCst) =>
        {
            if let Some(state) = handle.try_state::<AutofillState>() {
                hide_overlay(&handle, &state, false);
            }
        }
        _ => {}
    });

    Ok(window)
}

fn apply_noactivate(window: &WebviewWindow) -> tauri::Result<()> {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, SetWindowLongPtrW, GWL_EXSTYLE, WS_EX_NOACTIVATE, WS_EX_TOOLWINDOW,
    };
    let hwnd = window.hwnd()?;
    unsafe {
        let current = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
        let style = current | WS_EX_NOACTIVATE.0 | WS_EX_TOOLWINDOW.0;
        SetWindowLongPtrW(hwnd, GWL_EXSTYLE, style as isize);
    }
    Ok(())
}

/// Add or remove `WS_EX_NOACTIVATE` on a window handle.
///
/// Appearing must never take the caret (`true`), but typing requires focus
/// (`false`); nothing else about the window changes.
fn set_noactivate(hwnd: windows::Win32::Foundation::HWND, on: bool) -> windows::core::Result<()> {
    use windows::Win32::UI::WindowsAndMessaging::{
        GetWindowLongPtrW, SetWindowLongPtrW, GWL_EXSTYLE, WS_EX_NOACTIVATE,
    };
    unsafe {
        let current = GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32;
        let style = if on {
            current | WS_EX_NOACTIVATE.0
        } else {
            current & !WS_EX_NOACTIVATE.0
        };
        if style != current {
            SetWindowLongPtrW(hwnd, GWL_EXSTYLE, style as isize);
        }
    }
    Ok(())
}

fn overlay_hwnd(app: &AppHandle) -> Option<isize> {
    let window = app.get_webview_window(WINDOW_LABEL)?;
    window.hwnd().ok().map(|hwnd| hwnd.0 as isize)
}

fn hide_overlay(app: &AppHandle, state: &AutofillState, clear_target: bool) {
    {
        let mut inner = state.inner.lock().expect("autofill mutex");
        inner.visible = false;
        if clear_target {
            inner.target = None;
        }
    }
    if let Some(worker) = state.worker() {
        worker.set_gate(false);
    }
    let handle = app.clone();
    let _ = app.run_on_main_thread(move || {
        if let Some(window) = handle.get_webview_window(WINDOW_LABEL) {
            // Restore the never-activate style before hiding, so the next
            // appearance cannot take the caret either.
            if let Ok(hwnd) = window.hwnd() {
                let _ = set_noactivate(hwnd, true);
            }
            let _ = window.hide();
        }
    });
}

/* --------------------------------------------------------------- commands */

/// Picker state for Settings: the master switch, the shortcut and any error.
#[tauri::command]
pub fn autofill_status(state: State<'_, AutofillState>) -> AutofillStatusDto {
    let inner = state.inner.lock().expect("autofill mutex");
    AutofillStatusDto {
        enabled: inner.enabled,
        shortcut: inner.chord.clone(),
        registered: inner.registered,
        error: inner.error.clone(),
    }
}

/// Rebind the offer chord. The old one is released first, and an unparseable
/// chord is refused before anything is touched.
#[tauri::command]
pub fn autofill_set_shortcut(app: AppHandle, chord: String) -> Result<AutofillStatusDto, String> {
    let trimmed = chord.trim().to_string();
    if trimmed
        .parse::<tauri_plugin_global_shortcut::Shortcut>()
        .is_err()
    {
        return Err(format!("{trimmed} is not a chord this system accepts"));
    }
    let previous = {
        let state = app.state::<AutofillState>();
        let inner = state.inner.lock().expect("autofill mutex");
        inner.chord.clone()
    };
    if previous == trimmed {
        return Ok(autofill_status(app.state::<AutofillState>()));
    }
    let _ = app.global_shortcut().unregister(previous.as_str());
    {
        let state = app.state::<AutofillState>();
        let mut inner = state.inner.lock().expect("autofill mutex");
        inner.chord = trimmed.clone();
        inner.registered = false;
        inner.error = None;
    }
    if let Some(state) = app.try_state::<AutofillState>() {
        if let Some(store) = state.rules.lock().expect("autofill rules mutex").as_ref() {
            store
                .set_autofill_shortcut(&trimmed)
                .map_err(|error| error.to_string())?;
        }
    }
    register_shortcut(&app);
    Ok(autofill_status(app.state::<AutofillState>()))
}

/// Turn the focus observer and the shortcut offers on or off. The per-app rule
/// still applies; this is the switch for the feature as a whole.
#[tauri::command]
pub fn autofill_set_enabled(
    app: AppHandle,
    state: State<'_, AutofillState>,
    enabled: bool,
) -> Result<AutofillStatusDto, String> {
    if let Some(store) = state.rules.lock().expect("autofill rules mutex").as_ref() {
        store
            .set_autofill_enabled(enabled)
            .map_err(|error| error.to_string())?;
    }
    state.inner.lock().expect("autofill mutex").enabled = enabled;
    if !enabled {
        hide_overlay(&app, &state, true);
    }
    Ok(autofill_status(state))
}

/// Every explicit per-app rule, alphabetically. Applications without a row are
/// `ask` and are deliberately not listed here.
#[tauri::command]
pub fn autofill_rules(state: State<'_, AutofillState>) -> Result<Vec<RuleDto>, String> {
    let rules = state.rules.lock().expect("autofill rules mutex");
    let store = rules.as_ref().ok_or_else(|| {
        "Autofill rules are unavailable (the vault is not initialised).".to_string()
    })?;
    let rows = store.autofill_rules().map_err(|error| error.to_string())?;
    Ok(rows
        .into_iter()
        .map(|(exe, mode, updated_at)| RuleDto {
            exe,
            mode,
            updated_at,
        })
        .collect())
}

/// Set the rule for `exe` (`fill`, `ask`, `off`) and return the new table.
#[tauri::command]
pub fn autofill_set_rule(
    state: State<'_, AutofillState>,
    exe: String,
    mode: String,
) -> Result<Vec<RuleDto>, String> {
    if exe.trim().is_empty() {
        return Err("Enter the executable name, for example notepad.exe.".to_string());
    }
    if exe.contains('\\') || exe.contains('/') {
        return Err("Use the image name (notepad.exe), not a full path.".to_string());
    }
    let exe = normalise_exe(&exe);
    {
        let rules = state.rules.lock().expect("autofill rules mutex");
        let store = rules.as_ref().ok_or_else(|| {
            "Autofill rules are unavailable (the vault is not initialised).".to_string()
        })?;
        store
            .set_autofill_rule(&exe, &mode)
            .map_err(|error| error.to_string())?;
    }
    autofill_rules(state)
}

/// Remove `exe`'s row, so it falls back to the default (`ask`).
#[tauri::command]
pub fn autofill_reset_rule(
    state: State<'_, AutofillState>,
    exe: String,
) -> Result<Vec<RuleDto>, String> {
    {
        let rules = state.rules.lock().expect("autofill rules mutex");
        let store = rules.as_ref().ok_or_else(|| {
            "Autofill rules are unavailable (the vault is not initialised).".to_string()
        })?;
        store
            .clear_autofill_rule(&normalise_exe(&exe))
            .map_err(|error| error.to_string())?;
    }
    autofill_rules(state)
}

/// The target the overlay was last shown for. The overlay asks once on mount,
/// so a fast focus change cannot leave it blank.
#[tauri::command]
pub fn autofill_target(state: State<'_, AutofillState>) -> Option<TargetDto> {
    state
        .inner
        .lock()
        .expect("autofill mutex")
        .target
        .as_ref()
        .map(|target| target.dto.clone())
}

/// Rows for the overlay: recent fills for this executable plus search hits.
/// Only summaries cross the bridge; field values stay in the core.
#[tauri::command]
pub async fn autofill_suggest(app: AppHandle, query: String) -> Result<SuggestDto, String> {
    tauri::async_runtime::spawn_blocking(move || suggest_blocking(&app, &query))
        .await
        .map_err(|error| error.to_string())?
}

fn suggest_blocking(app: &AppHandle, query: &str) -> Result<SuggestDto, String> {
    let state = app.state::<AutofillState>();
    let target = state
        .current_target()
        .ok_or_else(|| "No field is focused; open the picker again.".to_string())?;
    if let Some(refusal) = target.dto.refused {
        return Err(refusal.clone());
    }
    let vault = app.state::<VaultState>();
    if vault.is_locked() {
        return Err("The vault is locked.".to_string());
    }

    let page = vault
        .list_page(query, None, false, MAX_ROWS, 0)
        .map_err(|error| error.to_string())?;

    let ids = state
        .recents
        .lock()
        .expect("autofill recents mutex")
        .get(&target.dto.exe)
        .cloned()
        .unwrap_or_default();
    let mut recent = Vec::new();
    for id in ids {
        if let Ok(item) = vault.get_quiet(&id) {
            recent.push(item.summary());
        }
    }

    Ok(SuggestDto {
        recent,
        matches: page.items,
    })
}

/// Fill one field of one item into the focused field.
///
/// `field` is `password` or `username`. The value is read here, inside the
/// process, and passed straight to the observer; it is never serialized.
#[tauri::command]
pub async fn autofill_fill(app: AppHandle, item_id: String, field: String) -> Result<(), String> {
    tauri::async_runtime::spawn_blocking(move || fill_blocking(&app, &item_id, &field))
        .await
        .map_err(|error| error.to_string())?
}

fn fill_blocking(app: &AppHandle, item_id: &str, field: &str) -> Result<(), String> {
    if field != "password" && field != "username" {
        return Err(format!(
            "Autofill supports username and password, not {field}."
        ));
    }

    let state = app.state::<AutofillState>();
    let worker = state
        .worker()
        .ok_or_else(|| "The UI Automation observer is not running.".to_string())?;

    let target = state
        .current_target()
        .ok_or_else(|| "No field is focused; open the picker again.".to_string())?;
    if let Some(refusal) = target.dto.refused.clone() {
        return Err(refusal);
    }
    // Re-read the rule: Settings may have changed it while the overlay was
    // already on screen, and "off" must win at the moment of the write.
    let mode = state.rule(&target.dto.exe);
    if !should_show(&mode, true) {
        return Err(format!(
            "Autofill is off for {}. Change the rule in Settings → Autofill.",
            target.dto.exe
        ));
    }

    let vault = app.state::<VaultState>();
    vault.touch();
    let item = vault.get(item_id).map_err(|error| error.to_string())?;
    let value = item
        .fields
        .iter()
        .find(|candidate| candidate.kind == field)
        .map(|candidate| candidate.value.clone())
        .ok_or_else(|| format!("This item has no {field} field."))?;
    if value.is_empty() {
        return Err(format!("This item's {field} field is empty."));
    }

    worker.fill(value, target.key.clone())?;

    {
        let mut recents = state.recents.lock().expect("autofill recents mutex");
        let entries = recents.entry(target.dto.exe.clone()).or_default();
        entries.retain(|id| id != item_id);
        entries.insert(0, item_id.to_string());
        entries.truncate(RECENT_PER_APP);
    }

    hide_overlay(app, &state, false);
    restore_target_focus(target.hwnd);
    Ok(())
}

/// Give the caret back to the application after the user filled from the
/// overlay's own search box. Best effort: Windows may keep the foreground
/// where it is, and that is not an error.
fn restore_target_focus(hwnd: isize) {
    if hwnd == 0 {
        return;
    }
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::SetForegroundWindow;
    unsafe {
        let target = HWND(hwnd as *mut core::ffi::c_void);
        if !target.0.is_null() {
            let _ = SetForegroundWindow(target);
        }
    }
}

/// Hide the overlay without clearing the target (Escape, blur, focus loss).
#[tauri::command]
pub fn autofill_dismiss(app: AppHandle, state: State<'_, AutofillState>) -> Result<(), String> {
    hide_overlay(&app, &state, false);
    Ok(())
}

/// Activate the overlay so its search field accepts typing.
///
/// `WS_EX_NOACTIVATE` is what keeps the picker from stealing the caret when it
/// appears — and it is also what makes it impossible to focus, so the style has
/// to come off for the typing part. The exception is explicit (a click inside
/// the overlay) and is reverted by [`hide_overlay`]: the window goes back to
/// never activating on its own.
#[tauri::command]
pub fn autofill_take_input(app: AppHandle) -> Result<(), String> {
    let window = app
        .get_webview_window(WINDOW_LABEL)
        .ok_or_else(|| "The overlay is not open.".to_string())?;
    let hwnd = window.hwnd().map_err(|error| error.to_string())?;

    set_noactivate(hwnd, false).map_err(|error| error.to_string())?;

    use windows::Win32::UI::WindowsAndMessaging::{GetForegroundWindow, SetForegroundWindow};
    unsafe {
        let _ = SetForegroundWindow(hwnd);
        if GetForegroundWindow() != hwnd {
            // Put the style back: a window that failed to activate must keep
            // its promise of never taking focus.
            let _ = set_noactivate(hwnd, true);
            return Err("Windows kept focus in the other window; click the app's field and use the shortcut instead.".to_string());
        }
    }
    let _ = window.set_focus();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The picker can only be typed into if the style really comes off, and it
    /// can only keep the caret if the style really goes back on. A window that
    /// is created hidden is enough to read the bit back.
    #[test]
    fn the_noactivate_style_toggles_both_ways() {
        use windows::Win32::UI::WindowsAndMessaging::{
            CreateWindowExW, DestroyWindow, GetWindowLongPtrW, GWL_EXSTYLE, WS_EX_NOACTIVATE,
            WS_POPUP,
        };
        let class = windows::core::w!("STATIC");
        let hwnd = unsafe {
            CreateWindowExW(
                WS_EX_NOACTIVATE,
                class,
                windows::core::w!("kestrel-style-probe"),
                WS_POPUP,
                0,
                0,
                10,
                10,
                None,
                None,
                None,
                None,
            )
        }
        .expect("probe window");
        let style = || unsafe { GetWindowLongPtrW(hwnd, GWL_EXSTYLE) as u32 };
        assert_ne!(style() & WS_EX_NOACTIVATE.0, 0, "created without the style");

        set_noactivate(hwnd, false).expect("clear the style");
        assert_eq!(style() & WS_EX_NOACTIVATE.0, 0, "style did not come off");

        set_noactivate(hwnd, true).expect("restore the style");
        assert_ne!(style() & WS_EX_NOACTIVATE.0, 0, "style did not go back on");

        unsafe {
            let _ = DestroyWindow(hwnd);
        }
    }

    fn work() -> Rect {
        Rect {
            x: 0,
            y: 0,
            width: 1920,
            height: 1040,
        }
    }

    fn field(x: i32, y: i32) -> Rect {
        Rect {
            x,
            y,
            width: 220,
            height: 28,
        }
    }

    #[test]
    fn missing_rule_is_ask_through_the_core() {
        // The rule policy lives in the core; this checks the wire value the
        // picker actually reads (a missing row is `ask`, never `fill`).
        let path = std::env::temp_dir().join(format!("kestrel-autofill-rule-{}.db", uuid_like()));
        let store = Store::open(&path).expect("store opens");
        assert_eq!(store.autofill_rule("notepad.exe").unwrap(), "ask");
        store.set_autofill_rule("notepad.exe", "fill").unwrap();
        assert_eq!(store.autofill_rule("notepad.exe").unwrap(), "fill");
        assert!(should_show(
            &store.autofill_rule("notepad.exe").unwrap(),
            false
        ));
        store.set_autofill_rule("notepad.exe", "off").unwrap();
        assert_eq!(store.autofill_rule("notepad.exe").unwrap(), "off");
        assert!(!should_show(
            &store.autofill_rule("notepad.exe").unwrap(),
            true
        ));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("db-wal"));
        let _ = std::fs::remove_file(path.with_extension("db-shm"));
    }

    #[test]
    fn off_suppresses_even_the_explicit_offer() {
        assert!(!should_show("off", false));
        assert!(!should_show("off", true));
    }

    #[test]
    fn ask_needs_the_shortcut_and_fill_offers_on_focus() {
        assert!(!should_show("ask", false));
        assert!(should_show("ask", true));
        assert!(should_show("fill", false));
        assert!(should_show("fill", true));
    }

    #[test]
    fn image_names_are_reduced_to_a_lower_case_file_name() {
        assert_eq!(normalise_exe(r"C:\Program Files\Acme\Acme.EXE"), "acme.exe");
        assert_eq!(normalise_exe("/usr/local/bin/Foo"), "foo");
        assert_eq!(normalise_exe("  Notepad.Exe  "), "notepad.exe");
        assert_eq!(normalise_exe("\"C:\\App\\App.exe\""), "app.exe");
        assert_eq!(normalise_exe(""), "");
    }

    #[test]
    fn a_higher_integrity_target_is_refused() {
        assert!(!integrity_allows(Some(0x3000), Some(0x2000)));
        assert!(!integrity_allows(Some(0x4000), Some(0x1000)));
        assert!(integrity_allows(Some(0x2000), Some(0x2000)));
        assert!(integrity_allows(Some(0x1000), Some(0x2000)));
        // Unknown is not permission.
        assert!(!integrity_allows(None, Some(0x2000)));
        assert!(!integrity_allows(Some(0x2000), None));
    }

    #[test]
    fn overlay_sits_below_the_field() {
        assert_eq!(
            anchored_origin(field(100, 100), (360, 380), Some(work())),
            (100, 134)
        );
    }

    #[test]
    fn overlay_flips_above_a_field_near_the_bottom() {
        // Field ends at 1008; below would start at 1014 and run past 1040.
        let (_, y) = anchored_origin(field(100, 980), (360, 380), Some(work()));
        assert_eq!(y, 980 - GAP - 380);
    }

    #[test]
    fn overlay_is_clamped_inside_the_work_area() {
        // Near the right edge: 1800 + 360 > 1920.
        let (x, _) = anchored_origin(field(1800, 100), (360, 380), Some(work()));
        assert_eq!(x, 1920 - 360);
        // A field on a monitor left of the primary one keeps its negative x.
        let (x, y) = anchored_origin(
            field(-1900, -20),
            (360, 380),
            Some(Rect {
                x: -1920,
                y: 0,
                width: 1920,
                height: 1040,
            }),
        );
        assert_eq!(x, -1900);
        assert_eq!(y, 14);
    }

    #[test]
    fn overlay_never_hangs_off_the_top_or_bottom() {
        // A tall overlay on a short work area: clamp to the area, not above it.
        let (_, y) = anchored_origin(field(0, -40), (360, 900), Some(work()));
        assert_eq!(y, 0);
    }

    /// `uuid` is a core dependency; the kestrel crate does not need it for one
    /// temporary name, so derive an unpredictable-enough suffix from the clock.
    fn uuid_like() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|value| value.as_nanos())
            .unwrap_or_default()
    }
}
