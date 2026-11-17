//! Kestrel desktop shell.
//!
//! The shell is thin on purpose: it owns the window, the IPC surface and the
//! auto-lock watchdog. All cryptography and storage live in `kestrel-core`.

mod agent;
mod autofill;
mod browser;
mod commands;
mod commands_account;
mod commands_attachments;
mod commands_audit;
mod commands_history;
mod commands_portability;
mod commands_recovery;
mod commands_sync;
mod sync_scheduler;
mod vault_location;
mod commands_trash;
mod commands_vaults;
mod dialogs;
mod recovery_pdf;
mod passkeys;
mod quick;
mod sdk;

use kestrel_core::session::VaultState;
use std::time::Duration;
use tauri::menu::{Menu, MenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::Manager;

/// Bring the main window back. `attention` flashes the taskbar button, which is
/// the only signal left when Windows refuses the foreground switch — it is for
/// the second-launch path, where the user expects something to happen, not for
/// a tray click that already has the cursor on it.
fn show_main(app: &tauri::AppHandle, attention: bool) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.unminimize();
        let _ = window.show();
        let _ = window.set_focus();
        if attention {
            let _ = window.request_user_attention(Some(tauri::UserAttentionType::Critical));
        }
    }
}

/// Notification-area icon: open, lock, quit. Without it a hidden window has no
/// way back except relaunching, which looks like the app died.
fn build_tray(app: &tauri::App) -> tauri::Result<()> {
    let open = MenuItem::with_id(app, "open", "Open Kestrel", true, None::<&str>)?;
    let lock = MenuItem::with_id(app, "lock", "Lock vault", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Quit", true, None::<&str>)?;
    let menu = Menu::with_items(app, &[&open, &lock, &quit])?;

    let mut builder = TrayIconBuilder::new()
        .tooltip("Kestrel")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id().as_ref() {
            "open" => show_main(app, false),
            "lock" => {
                let state = app.state::<VaultState>();
                if state.lock().is_ok() {
                    let _ = tauri::Emitter::emit(app, "vault://locked", ());
                }
            }
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle(), false);
            }
        });
    if let Some(icon) = app.default_window_icon() {
        builder = builder.icon(icon.clone());
    }
    builder.build(app)?;
    Ok(())
}

pub fn run() {
    tauri::Builder::default()
        // Registered first: a second launch hands its argv to the running
        // instance and exits, instead of failing to create a webview against a
        // WebView2 user-data folder another process already owns.
        .plugin(tauri_plugin_single_instance::init(|app, _argv, _cwd| {
            show_main(app, true);
        }))
        .plugin(tauri_plugin_global_shortcut::Builder::new().build())
        // Closing the window hides it: the process, the session and the global
        // hotkey stay alive, and the tray icon is the way back in.
        .on_window_event(|window, event| {
            if window.label() != "main" {
                return;
            }
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                api.prevent_close();
                let _ = window.hide();
                if let Some(quick) = window.app_handle().get_webview_window("quick") {
                    let _ = quick.hide();
                }
            }
        })
        .setup(|app| {
            quick::init(app)?;
            build_tray(app)?;
            // `KESTREL_DATA_DIR` keeps a second instance (tests, a live
            // demonstration) off the real vault without moving it aside: its
            // own database and its own browser-bridge files. The named pipes
            // (`kestrel-sdk`, `openssh-ssh-agent`, `kestrel-passkeys`) are
            // machine-wide on purpose, so run one instance at a time.
            let data_dir = match std::env::var_os("KESTREL_DATA_DIR") {
                Some(dir) => std::path::PathBuf::from(dir),
                None => app
                    .path()
                    .app_data_dir()
                    .expect("app data directory is available"),
            };
            std::fs::create_dir_all(&data_dir).ok();
            // The vault is a file the user names and places. The config remembers
            // which one, and a build from before that change keeps its data by
            // adopting the old fixed path once.
            let location = vault_location::VaultLocation::new(data_dir.clone());
            let mut remembered = location.last();
            if remembered.is_none() {
                let legacy = data_dir.join("kestrel.db");
                if legacy.exists() && location.remember(&legacy).is_ok() {
                    remembered = Some(legacy);
                }
            }
            // A remembered file that has been moved or deleted is a normal state
            // the gate explains, not a crash — and it must not be *recreated*:
            // `Store::open` creates a missing file, so the existence check comes
            // first. The path stays in the config, which is how the gate can say
            // "this file is not here" instead of pretending it is a first run.
            let state = match remembered.filter(|path| path.is_file()) {
                Some(path) => VaultState::open(path)
                    .or_else(|_| VaultState::unselected())
                    .expect("an empty vault state is always constructible"),
                None => {
                    VaultState::unselected().expect("an empty vault state is always constructible")
                }
            };
            app.manage(state);
            app.manage(location);
            // The chord's on/off switch lives in the vault; apply it now that
            // the state exists. A vault that is locked still answers: the row is
            // policy, not content.
            quick::apply_stored_preference(app.handle());
            // Windows calls the passkey DLL whenever a site asks for a key; the
            // server has to be listening before that, not after a card is opened.
            passkeys::start_server(app.handle());
            // Automatic sync: one background thread for the process. It reads
            // `auto_interval` on every wake, so the toggle needs no restart, and
            // it does nothing while the vault is locked. It holds the app handle
            // rather than the state, because `VaultState` is not cloneable and
            // the state is resolved per run.
            sync_scheduler::SyncScheduler::start(app.handle().clone());
            // The app autofill picker shares the vault database for its rules
            // and never touches a value itself: a fill resolves inside the
            // core and goes straight into the target field.
            autofill::init(app)?;
            // The SSH agent starts with the app and stops on exit. If another
            // process owns `\\.\pipe\openssh-ssh-agent` (e.g. the OpenSSH agent
            // service), `start` records that instead of hijacking the name.
            let agent = agent::AgentHandle::start(app.handle());
            app.manage(agent);

            // CLI/SDK automation surface: same lifetime as the app. Pairing is
            // minted on demand from Settings; the pipe starts unpaired.
            let sdk = sdk::SdkHandle::start(app.handle());
            app.manage(sdk);

            // Auto-lock watchdog: runs in the Rust core, so a frozen or
            // compromised renderer cannot keep the vault open.
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(Duration::from_secs(5));
                let state = handle.state::<VaultState>();
                if let Ok(true) = state.maybe_autolock() {
                    let _ = tauri::Emitter::emit(&handle, "vault://locked", ());
                }
            });
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::vault_state,
            commands::vault_location,
            commands::vault_pick_folder,
            commands::vault_create_at,
            commands::vault_open_at,
            commands::vault_reveal_folder,
            commands::folder_reveal,
            commands::recovery_save_pdf,
            commands::vault_pick_file,
            commands::recovery_read_kit,
            commands::unlock_vault,
            commands::lock_vault,
            commands::touch_vault,
            commands::set_autolock,
            commands::item_grants,
            commands::item_set_grants,
            commands::item_audit,
            commands::cli_tokens,
            commands::cli_revoke,
            commands_account::account_revoke_device,
            commands::set_clipboard_clear,
            commands::open_url,
            commands::list_items,
            commands::list_items_page,
            commands::item_counts,
            commands::get_item,
            commands::create_item,
            commands::save_item,
            commands::item_totp,
            commands::copy_field,
            commands::copy_text,
            commands::generate_password,
            commands::change_password,
            commands::hello_status,
            commands::hello_enroll,
            commands::hello_disable,
            commands::hello_unlock,
            commands::app_meta,
            agent::agent_status,
            commands_vaults::vaults_list,
            commands_vaults::vault_create,
            commands_vaults::vault_switch,
            commands_vaults::vault_rename,
            commands_history::history_list,
            commands_history::history_get,
            commands_history::history_restore,
            commands_attachments::attachment_list,
            commands_attachments::attachment_add,
            commands_attachments::attachment_read,
            commands_attachments::attachment_save_as,
            commands_attachments::attachment_remove,
            commands_trash::trash_list,
            commands_trash::trash_item,
            commands_trash::restore_item,
            commands_trash::purge_item,
            commands_trash::empty_trash,
            commands_portability::import_preview,
            commands_portability::import_items,
            commands_portability::export_items,
            commands_portability::export_1pux,
            commands_account::account_status,
            commands_account::account_create,
            commands_account::account_secret_key,
            commands_account::account_enrol_code,
            commands_account::account_seal_for_device,
            commands_account::account_devices,
            commands_account::account_device_identity,
            commands_account::account_enroll_claim,
            commands_sync::sync_status,
            commands_sync::sync_configure,
            commands_sync::sync_forget,
            commands_sync::sync_now,
            commands_sync::sync_conflicts,
            commands_sync::sync_resolve,
            commands_sync::sync_set_auto,
            commands_sync::sync_register,
            commands_sync::sync_invite,
            commands_sync::sync_enroll_offer,
            commands_sync::sync_enroll_ack,
            commands_sync::sync_enroll_accept,
            commands_recovery::recovery_status,
            commands_recovery::recovery_create,
            commands_recovery::recovery_unlock,
            commands_recovery::recovery_complete,
            commands_recovery::recovery_finish,
            commands_audit::audit_report,
            commands_audit::audit_check_breaches,
            quick::quick_open,
            quick::quick_hide,
            quick::quick_status,
            quick::quick_set_enabled,
            quick::quick_set_shortcut,
            quick::quick_focus_main,
            quick::quick_copy_login,
            sdk::sdk_status,
            sdk::sdk_pair,
            sdk::mcp_status,
            sdk::mcp_inventory,
            sdk::mcp_pair,
            sdk::mcp_audit,
            sdk::mcp_revoke,
            autofill::autofill_status,
            autofill::autofill_set_enabled,
            autofill::autofill_set_shortcut,
            autofill::autofill_rules,
            autofill::autofill_set_rule,
            autofill::autofill_reset_rule,
            autofill::autofill_target,
            autofill::autofill_suggest,
            autofill::autofill_fill,
            autofill::autofill_dismiss,
            autofill::autofill_take_input,
            browser::browser_status,
            browser::browser_install,
            browser::browser_uninstall,
            browser::browser_rules,
            browser::browser_set_rule,
            browser::browser_reset_rule,
            passkeys::passkeys_status,
            passkeys::passkeys_register_plugin,
            passkeys::passkeys_unregister_plugin,
            passkeys::passkeys_for_item,
            passkeys::passkeys_remove,
            passkeys::passkeys_answer_approval,
        ])
        .build(tauri::generate_context!())
        .expect("Kestrel failed to start")
        .run(|app, event| {
            // Release the pipe before the process goes away so a restart does
            // not race the old accept loop for the name.
            if let tauri::RunEvent::Exit = event {
                app.state::<agent::AgentHandle>().stop();
                app.state::<sdk::SdkHandle>().stop();
                // Joins the sync thread, so a run in flight cannot outlive the
                // vault it is writing to.
                sync_scheduler::stop_sync();
            }
        });
}
