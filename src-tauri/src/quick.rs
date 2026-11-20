//! Quick-access palette: a second, 420 px always-on-top window behind one
//! global shortcut (`Ctrl+Shift+Space`).
//!
//! The window is created lazily on first use, hidden rather than destroyed, and
//! centred on whichever monitor the pointer is on. It is a plain webview URL
//! (`index.html?window=quick`); the React side branches on that query and mounts
//! `QuickAccess`.
//!
//! # Shared session
//!
//! Both windows receive the **same managed [`VaultState`]** from the shell, so
//! unlocking in either one unlocks the other, and locking in the main window
//! locks the palette. Nothing is duplicated: the palette reads items through the
//! existing `list_items` command and copies through [`quick_copy_login`], which
//! resolves the field id inside the core — a password value never reaches this
//! window's renderer.
//!
//! # Failure policy
//!
//! Registering a system-wide hotkey can fail (another application owns the
//! chord). That failure is recorded in [`QuickStatus`] and surfaced through the
//! `quick_status` command; `init` never panics and the palette stays reachable
//! from the main window through `quick_open`.

use std::sync::Mutex;

use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::Store;
use serde::Serialize;
use tauri::{
    AppHandle, Emitter, Manager, PhysicalPosition, State, WebviewUrl, WebviewWindow,
    WebviewWindowBuilder, Wry,
};
use tauri_plugin_global_shortcut::{GlobalShortcut, GlobalShortcutExt, ShortcutState};

/// Window label for the palette. The main window's label is `main`.
pub const WINDOW_LABEL: &str = "quick";
const MAIN_LABEL: &str = "main";
/// The chord the palette is bound to until the person picks another one.
pub const SHORTCUT: &str = "Ctrl+Shift+Space";
const WIDTH: f64 = 420.0;
const HEIGHT: f64 = 560.0;

/// Emitted to the palette window every time it is shown, so the renderer can
/// re-read the vault state and refocus the search field.
pub const SHOWN_EVENT: &str = "quick://shown";
/// Emitted to the main window with `{ id: string | null }` when the palette asks
/// it to reveal an item.
pub const OPEN_ITEM_EVENT: &str = "quick://open-item";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickStatusDto {
    /// The user's preference: keep the chord bound. Off means the palette is
    /// only reachable from Settings, and the OS never sees a hotkey.
    pub enabled: bool,
    /// True when the chord is owned by this process and the handler is attached.
    pub registered: bool,
    pub shortcut: String,
    /// Why registration failed; `None` on success.
    pub error: Option<String>,
}

#[derive(Serialize, Clone)]
struct OpenItemPayload {
    id: Option<String>,
}

struct QuickStatusInner {
    /// On by default: a password manager whose palette needs a trip to Settings
    /// first is a worse product than one with a hotkey.
    enabled: bool,
    registered: bool,
    error: Option<String>,
    /// The chord in force. Parsed by the plugin, stored in the vault, and
    /// reported back so the UI never shows a chord that is not registered.
    chord: String,
}

impl Default for QuickStatusInner {
    fn default() -> Self {
        Self {
            enabled: true,
            registered: false,
            error: None,
            chord: SHORTCUT.to_string(),
        }
    }
}

/// Managed state reported by `quick_status`. Survives a failed registration so
/// the UI can explain the degraded state instead of pretending the hotkey works.
#[derive(Default)]
pub struct QuickStatus {
    inner: Mutex<QuickStatusInner>,
}

/// Wire the palette into the shell. Called once from the app's `setup` hook,
/// after `VaultState` is managed.
///
/// Registers the global-shortcut plugin when the builder did not already do so,
/// binds [`SHORTCUT`] to the toggle, and records the outcome for `quick_status`.
/// The window itself is not built here: the first hotkey press or `quick_open`
/// creates it.
pub fn init(app: &mut tauri::App) -> tauri::Result<()> {
    app.manage(QuickStatus::default());

    // Prefer the builder registration (`tauri::Builder::plugin`) so plugin setup
    // runs in the normal phase; fall back to registering it here when this
    // module is initialised on its own.
    if app.try_state::<GlobalShortcut<Wry>>().is_none() {
        app.handle()
            .plugin(tauri_plugin_global_shortcut::Builder::new().build())?;
    }

    register_shortcut(app.handle());
    Ok(())
}

fn register_shortcut(app: &AppHandle) {
    let chord = {
        let status = app.state::<QuickStatus>();
        let inner = status.inner.lock().expect("quick status mutex");
        inner.chord.clone()
    };
    let outcome = app
        .global_shortcut()
        .on_shortcut(chord.as_str(), |app, _shortcut, event| {
            if event.state == ShortcutState::Pressed {
                toggle(app);
            }
        });

    let status = app.state::<QuickStatus>();
    let mut inner = status.inner.lock().expect("quick status mutex");
    match outcome {
        Ok(()) => {
            inner.registered = true;
            inner.error = None;
        }
        Err(error) => {
            inner.registered = false;
            inner.error = Some(error.to_string());
        }
    }
}

/// Build the palette window hidden. The first `show` positions it, so a
/// monitor change between launches is picked up rather than baked in.
fn build_window(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    WebviewWindowBuilder::new(
        app,
        WINDOW_LABEL,
        WebviewUrl::App("index.html?window=quick".into()),
    )
    .title("Kestrel Quick Access")
    .inner_size(WIDTH, HEIGHT)
    .decorations(false)
    .always_on_top(true)
    .skip_taskbar(true)
    .resizable(false)
    .maximizable(false)
    .minimizable(false)
    // Transparent so Windows cannot draw its own light frame around the card;
    // the rounded surface and its shadow live in quick.css. The webview also
    // needs an explicit clear background, or it paints its default grey behind
    // the rounded corners.
    .transparent(true)
    .background_color(tauri::window::Color(0, 0, 0, 0))
    .shadow(false)
    .visible(false)
    .focused(false)
    .build()
}

fn show_or_build(app: &AppHandle) -> tauri::Result<WebviewWindow> {
    let window = match app.get_webview_window(WINDOW_LABEL) {
        Some(window) => window,
        None => build_window(app)?,
    };
    place_on_cursor_monitor(app, &window)?;
    window.show()?;
    window.set_focus()?;
    let _ = app.emit_to(WINDOW_LABEL, SHOWN_EVENT, ());
    Ok(window)
}

/// Hotkey behaviour: the second press hides the palette when it already has
/// focus, otherwise it brings it forward. A visible but unfocused palette (the
/// user clicked elsewhere) is raised instead of closed.
fn toggle(app: &AppHandle) {
    let Some(window) = app.get_webview_window(WINDOW_LABEL) else {
        let _ = show_or_build(app);
        return;
    };
    let visible = window.is_visible().unwrap_or(false);
    let focused = window.is_focused().unwrap_or(false);
    if visible && focused {
        let _ = window.hide();
    } else {
        let _ = show_or_build(app);
    }
}

/// Centre the palette on the monitor under the pointer, so a multi-monitor
/// setup opens it where the user is looking.
fn place_on_cursor_monitor(app: &AppHandle, window: &WebviewWindow) -> tauri::Result<()> {
    let monitor = match app.cursor_position() {
        Ok(cursor) => app
            .monitor_from_point(cursor.x, cursor.y)?
            .or(app.primary_monitor()?),
        Err(_) => app.primary_monitor()?,
    };
    let Some(monitor) = monitor else {
        return Ok(());
    };
    let size = window.outer_size()?;
    let (x, y) = centered_origin(
        (monitor.position().x, monitor.position().y),
        (monitor.size().width, monitor.size().height),
        (size.width, size.height),
    );
    window.set_position(PhysicalPosition::new(x, y))
}

/// Top-left corner (physical pixels) that centres `window_size` on a monitor
/// whose origin can be negative (monitors left of or above the primary one).
///
/// Pure arithmetic, kept out of [`place_on_cursor_monitor`] so multi-monitor
/// placement is testable without a window server.
fn centered_origin(
    monitor_pos: (i32, i32),
    monitor_size: (u32, u32),
    window_size: (u32, u32),
) -> (i32, i32) {
    let clamp = |value: i64| value.clamp(i32::MIN as i64, i32::MAX as i64) as i32;
    let x = monitor_pos.0 as i64 + (monitor_size.0 as i64 - window_size.0 as i64) / 2;
    let y = monitor_pos.1 as i64 + (monitor_size.1 as i64 - window_size.1 as i64) / 2;
    (clamp(x), clamp(y))
}

/// Show and focus the palette (used by the main window's menu or a Settings
/// toggle). Same path the hotkey takes.
#[tauri::command]
pub async fn quick_open(app: AppHandle) -> Result<(), String> {
    on_main(app, |handle| {
        if let Err(error) = show_or_build(&handle) {
            record_error(&handle, error.to_string());
        }
    })
}

/// Window creation and focus must happen on the event-loop thread; a command
/// body may run elsewhere. Queueing is also why this returns before the window
/// exists — failures land in [`QuickStatus`], which the UI already reads.
fn on_main(app: AppHandle, work: impl FnOnce(AppHandle) + Send + 'static) -> Result<(), String> {
    let handle = app.clone();
    app.run_on_main_thread(move || work(handle))
        .map_err(|e| e.to_string())
}

fn record_error(app: &AppHandle, message: String) {
    if let Some(status) = app.try_state::<QuickStatus>() {
        if let Ok(mut inner) = status.inner.lock() {
            inner.error = Some(message);
        }
    }
}

/// Hide the palette without destroying it: the next open is instant.
#[tauri::command]
pub async fn quick_hide(app: AppHandle) -> Result<(), String> {
    on_main(app, |handle| {
        if let Some(window) = handle.get_webview_window(WINDOW_LABEL) {
            if let Err(error) = window.hide() {
                record_error(&handle, error.to_string());
            }
        }
    })
}

/// Registration state for Settings and for the palette's own footer.
#[tauri::command]
pub fn quick_status(status: State<'_, QuickStatus>) -> QuickStatusDto {
    let inner = status.inner.lock().expect("quick status mutex");
    QuickStatusDto {
        enabled: inner.enabled,
        registered: inner.registered,
        shortcut: inner.chord.clone(),
        error: inner.error.clone(),
    }
}

/// Bind or release the chord and remember the choice in the vault.
///
/// The preference is stored beside the other policy rows (`meta`), so the next
/// launch starts where this one ended. A vault that is not open yet keeps the
/// default until [`apply_stored_preference`] runs.
#[tauri::command]
pub fn quick_set_enabled(app: AppHandle, enabled: bool) -> Result<QuickStatusDto, String> {
    if let Some(path) = selected_vault(&app) {
        Store::open(path)
            .map_err(|error| error.to_string())?
            .set_quick_access_enabled(enabled)
            .map_err(|error| error.to_string())?;
    }
    Ok(bind(app, enabled))
}

/// Apply the stored switch to a vault that was just selected or opened.
///
/// Called after the vault state is managed and after a vault is opened, so a
/// chord the user released last time stays released. A vault with no stored row
/// gets the default: bound.
pub fn apply_stored_preference(app: &AppHandle) {
    let Some(path) = selected_vault(app) else {
        return;
    };
    let (enabled, chord) = match Store::open(path) {
        Ok(store) => (
            store.quick_access_enabled().unwrap_or(true),
            store.quick_shortcut().ok().flatten(),
        ),
        Err(_) => (true, None),
    };
    if let Some(chord) = chord {
        if chord
            .parse::<tauri_plugin_global_shortcut::Shortcut>()
            .is_ok()
        {
            let status = app.state::<QuickStatus>();
            let mut inner = status.inner.lock().expect("quick status mutex");
            inner.chord = chord;
        }
    }
    bind(app.clone(), enabled);
}

/// Rebind the palette chord. The old chord is released first: a chord that is
/// still owned cannot be taken again, and a failed new one must not leave the
/// palette bound to neither.
#[tauri::command]
pub fn quick_set_shortcut(app: AppHandle, chord: String) -> Result<QuickStatusDto, String> {
    let trimmed = chord.trim().to_string();
    if trimmed
        .parse::<tauri_plugin_global_shortcut::Shortcut>()
        .is_err()
    {
        return Err(format!("{trimmed} is not a chord this system accepts"));
    }
    let previous = {
        let status = app.state::<QuickStatus>();
        let inner = status.inner.lock().expect("quick status mutex");
        inner.chord.clone()
    };
    if previous == trimmed {
        return Ok(quick_status(app.state::<QuickStatus>()));
    }
    let _ = app.global_shortcut().unregister(previous.as_str());
    {
        let status = app.state::<QuickStatus>();
        let mut inner = status.inner.lock().expect("quick status mutex");
        inner.chord = trimmed.clone();
        inner.registered = false;
        inner.error = None;
    }
    if let Some(path) = selected_vault(&app) {
        Store::open(path)
            .map_err(|error| error.to_string())?
            .set_quick_shortcut(&trimmed)
            .map_err(|error| error.to_string())?;
    }
    let enabled = {
        let status = app.state::<QuickStatus>();
        let inner = status.inner.lock().expect("quick status mutex");
        inner.enabled
    };
    if enabled {
        register_shortcut(&app);
    }
    Ok(quick_status(app.state::<QuickStatus>()))
}

/// The vault file this process is looking at, if any.
fn selected_vault(app: &AppHandle) -> Option<std::path::PathBuf> {
    app.try_state::<VaultState>().and_then(|state| state.path())
}

/// Set the switch and act on it, without touching storage.
fn bind(app: AppHandle, enabled: bool) -> QuickStatusDto {
    {
        let status = app.state::<QuickStatus>();
        let mut inner = status.inner.lock().expect("quick status mutex");
        inner.enabled = enabled;
    }
    if enabled {
        register_shortcut(&app);
    } else {
        let chord = {
            let status = app.state::<QuickStatus>();
            let inner = status.inner.lock().expect("quick status mutex");
            inner.chord.clone()
        };
        let outcome = app.global_shortcut().unregister(chord.as_str());
        let status = app.state::<QuickStatus>();
        let mut inner = status.inner.lock().expect("quick status mutex");
        match outcome {
            Ok(()) => {
                inner.registered = false;
                inner.error = None;
            }
            Err(error) => inner.error = Some(error.to_string()),
        }
    }
    quick_status(app.state::<QuickStatus>())
}

/// Hand the item back to the main window: focus it, emit
/// [`OPEN_ITEM_EVENT`] with `{ id }` (`null` when the palette only wants the
/// main window raised), then hide the palette.
#[tauri::command]
pub async fn quick_focus_main(app: AppHandle, item_id: Option<String>) -> Result<(), String> {
    let payload = OpenItemPayload { id: item_id };
    let emit = payload.clone();
    on_main(app.clone(), move |handle| {
        if let Some(main) = handle.get_webview_window(MAIN_LABEL) {
            let _ = main.show();
            let _ = main.unminimize();
            let _ = main.set_focus();
        }
        let _ = handle.emit_to(MAIN_LABEL, OPEN_ITEM_EVENT, emit);
        if let Some(window) = handle.get_webview_window(WINDOW_LABEL) {
            let _ = window.hide();
        }
    })
}

/// Copy a login's username or password without the value ever entering the
/// palette's renderer: the core resolves the field, then runs its normal
/// clipboard write (which schedules the timed wipe).
#[tauri::command]
pub fn quick_copy_login(
    state: State<'_, VaultState>,
    item_id: String,
    field: String,
) -> Result<(), String> {
    copy_login_field(&state, &item_id, &field).map_err(|e| e.to_string())
}

fn copy_login_field(state: &VaultState, item_id: &str, field: &str) -> Result<(), VaultError> {
    let kind = match field {
        "username" => "username",
        "password" => "password",
        other => {
            return Err(VaultError::Invalid(format!(
                "quick copy supports username and password, not {other}"
            )))
        }
    };
    state.touch();
    let item = state.get(item_id)?;
    let field_id = item
        .fields
        .iter()
        .find(|candidate| candidate.kind == kind)
        .map(|candidate| candidate.id.clone())
        .ok_or(VaultError::FieldNotFound)?;
    state.copy_field(item_id, &field_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortcut_parses_as_registered() {
        let parsed = SHORTCUT.parse::<tauri_plugin_global_shortcut::Shortcut>();
        assert!(parsed.is_ok(), "{SHORTCUT} must be a valid chord");
    }

    #[test]
    fn centres_on_the_primary_monitor() {
        assert_eq!(
            centered_origin((0, 0), (1920, 1080), (420, 560)),
            (750, 260)
        );
    }

    #[test]
    fn centres_on_a_monitor_left_of_the_primary_one() {
        // A 1920-wide monitor placed at x = -1920 (negative desktop origin).
        assert_eq!(
            centered_origin((-1920, 0), (1920, 1080), (420, 560)),
            (-1170, 260)
        );
    }

    #[test]
    fn centres_on_a_monitor_above_the_primary_one() {
        assert_eq!(
            centered_origin((0, -1440), (2560, 1440), (420, 560)),
            (1070, -1000)
        );
    }

    #[test]
    fn odd_remainders_bias_left_and_up() {
        // 1366 - 420 = 946, /2 = 473; 768 - 560 = 208, /2 = 104.
        assert_eq!(centered_origin((0, 0), (1366, 768), (420, 560)), (473, 104));
    }
}
