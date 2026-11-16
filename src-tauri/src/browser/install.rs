//! Native messaging host registration (HKCU only).
//!
//! Chrome and Edge find a native messaging host through a registry value whose
//! data is the absolute path of a JSON manifest:
//!
//! ```text
//! HKCU\Software\Google\Chrome\NativeMessagingHosts\com.kestrel.bridge
//! HKCU\Software\Microsoft\Edge\NativeMessagingHosts\com.kestrel.bridge
//! ```
//!
//! Both are written, because the same extension runs in either browser. The
//! manifest lives under `%APPDATA%\app.kestrel.vault\nm_hosts\` and names the
//! `kestrel-nmhost.exe` that sits next to Kestrel. Everything here is
//! reversible: uninstall deletes the two values and the manifest, and leaves
//! no machine-wide state behind.
//!
//! The registration is per-user on purpose. An HKLM entry would need an
//! elevation prompt and would claim the host for every account on the machine;
//! HKCU matches the vault's own model (one user, one key).

use serde_json::{json, Value};
use std::ffi::c_void;
use std::path::{Path, PathBuf};

/// The name the extension uses with `chrome.runtime.connectNative`.
pub const HOST_NAME: &str = "com.kestrel.bridge";

/// Where Edge and Chrome look for per-user native messaging hosts.
const REGISTRY_ROOTS: [&str; 2] = [
    r"Software\Google\Chrome\NativeMessagingHosts",
    r"Software\Microsoft\Edge\NativeMessagingHosts",
];

/// Firefox keeps its per-user hosts under its own key and names the allowed
/// extension by Gecko id instead of by `chrome-extension://` origin.
const FIREFOX_ROOT: &str = r"Software\Mozilla\NativeMessagingHosts";

/// The Gecko id from `extension/manifest.json` (`browser_specific_settings`).
pub const FIREFOX_EXTENSION_ID: &str = "bridge@kestrel";

pub fn data_dir() -> Result<PathBuf, String> {
    // Same override the shell uses for the database: a second instance must not
    // read or write the real profile's bridge token and native-messaging
    // manifest. (`KESTREL_DATA_DIR` moves the database too; see `lib.rs`.)
    if let Some(dir) = std::env::var_os("KESTREL_DATA_DIR") {
        return Ok(PathBuf::from(dir));
    }
    let appdata = std::env::var_os("APPDATA")
        .ok_or_else(|| "APPDATA is not set; cannot locate the Kestrel data directory".to_string())?;
    Ok(PathBuf::from(appdata).join("app.kestrel.vault"))
}

pub fn manifest_path() -> Result<PathBuf, String> {
    Ok(data_dir()?.join("nm_hosts").join(format!("{HOST_NAME}.json")))
}

/// Firefox reads a different manifest: `allowed_extensions`, not origins.
pub fn firefox_manifest_path() -> Result<PathBuf, String> {
    Ok(data_dir()?
        .join("nm_hosts")
        .join(format!("{HOST_NAME}.firefox.json")))
}

/// `kestrel-nmhost.exe` next to the running shell. In a dev build this is
/// `target/debug/`; in an installed build it is the app directory.
///
/// `KESTREL_NMHOST_PATH` is a development/live-check override: the shell's own
/// test binary lives two directories below the host, so the tests cannot infer
/// it the way the app does.
pub fn host_binary() -> PathBuf {
    if let Some(explicit) = std::env::var_os("KESTREL_NMHOST_PATH") {
        return PathBuf::from(explicit);
    }
    std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(|dir| dir.join("kestrel-nmhost.exe")))
        .unwrap_or_else(|| PathBuf::from("kestrel-nmhost.exe"))
}

/// The manifest body. `allowed_origins` is exactly one extension id plus the
/// trailing slash Chrome requires; anything else is not allowed to connect.
pub fn manifest(host_binary: &Path, extension_id: &str) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Kestrel browser bridge. Origin rules are enforced in Kestrel; the host only forwards.",
        "path": host_binary.to_string_lossy(),
        "type": "stdio",
        "allowed_origins": [format!("chrome-extension://{extension_id}/")],
    })
}

/// The Firefox manifest body. Firefox refuses `allowed_origins` outright, so
/// the same host binary is described twice: once for Chromium, once for Gecko.
pub fn firefox_manifest(host_binary: &Path) -> Value {
    json!({
        "name": HOST_NAME,
        "description": "Kestrel browser bridge. Origin rules are enforced in Kestrel; the host only forwards.",
        "path": host_binary.to_string_lossy(),
        "type": "stdio",
        "allowed_extensions": [FIREFOX_EXTENSION_ID],
    })
}

/// Write the manifest and both registry values.
///
/// The manifest is written first: if a registry write fails, the caller's
/// rollback removes the manifest and the value that did land. A failed
/// registration never leaves a token minted for a host that cannot start.
pub fn register(extension_id: &str) -> Result<PathBuf, String> {
    let binary = host_binary();
    if !binary.is_file() {
        return Err(format!(
            "kestrel-nmhost.exe was not found next to Kestrel ({}). Build the native host first.",
            binary.display()
        ));
    }
    let path = manifest_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
    }
    let body = serde_json::to_vec_pretty(&manifest(&binary, extension_id))
        .map_err(|error| format!("cannot encode the host manifest: {error}"))?;
    std::fs::write(&path, body)
        .map_err(|error| format!("cannot write {}: {error}", path.display()))?;

    let gecko_path = firefox_manifest_path()?;
    let gecko_body = serde_json::to_vec_pretty(&firefox_manifest(&binary))
        .map_err(|error| format!("cannot encode the Firefox host manifest: {error}"))?;
    std::fs::write(&gecko_path, gecko_body)
        .map_err(|error| format!("cannot write {}: {error}", gecko_path.display()))?;

    let mut written = Vec::new();
    let mut roots: Vec<String> = REGISTRY_ROOTS.iter().map(|root| root.to_string()).collect();
    roots.push(FIREFOX_ROOT.to_string());
    for root in roots {
        let key = format!(r"{root}\{HOST_NAME}");
        let target = if root == FIREFOX_ROOT {
            &gecko_path
        } else {
            &path
        };
        match set_default_string(&key, &target.to_string_lossy()) {
            Ok(()) => written.push(key),
            Err(error) => {
                for key in written {
                    let _ = delete_value(&key);
                }
                let _ = std::fs::remove_file(&path);
                let _ = std::fs::remove_file(&gecko_path);
                return Err(error);
            }
        }
    }
    Ok(path)
}

/// Remove both registry values and the manifest. Missing pieces are success:
/// uninstall is idempotent.
pub fn unregister() -> Result<(), String> {
    let mut first_error = None;
    for root in REGISTRY_ROOTS {
        let key = format!(r"{root}\{HOST_NAME}");
        if let Err(error) = delete_value(&key) {
            first_error.get_or_insert(error);
        }
    }
    if let Err(error) = delete_value(&format!(r"{FIREFOX_ROOT}\{HOST_NAME}")) {
        first_error.get_or_insert(error);
    }
    for path in [manifest_path(), firefox_manifest_path()].into_iter().flatten() {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                first_error.get_or_insert(format!("cannot remove {}: {error}", path.display()));
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

/// Which browsers currently point at an existing manifest.
pub fn registrations() -> (bool, bool, bool) {
    let chromium = manifest_path().ok();
    let gecko = firefox_manifest_path().ok();
    let points_at = |key: &str, path: Option<&PathBuf>| -> bool {
        let Some(path) = path.filter(|path| path.is_file()) else {
            return false;
        };
        let expected = path.to_string_lossy().to_lowercase();
        default_string(key)
            .ok()
            .flatten()
            .is_some_and(|value| value.to_lowercase() == expected)
    };
    let chrome = points_at(&format!(r"{}\{HOST_NAME}", REGISTRY_ROOTS[0]), chromium.as_ref());
    let edge = points_at(&format!(r"{}\{HOST_NAME}", REGISTRY_ROOTS[1]), chromium.as_ref());
    let firefox = points_at(&format!(r"{FIREFOX_ROOT}\{HOST_NAME}"), gecko.as_ref());
    (chrome, edge, firefox)
}

/* ------------------------------------------------------------- registry FFI */

type Hkey = *mut c_void;
const HKEY_CURRENT_USER: Hkey = 0x80000001u32 as isize as Hkey;
const KEY_SET_VALUE: u32 = 0x0002;
const REG_SZ: u32 = 1;
const RRF_RT_REG_SZ: u32 = 0x0000_0002;
const ERROR_SUCCESS: i32 = 0;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_MORE_DATA: i32 = 234;

#[link(name = "advapi32")]
extern "system" {
    fn RegCreateKeyExW(
        hkey: Hkey,
        subkey: *const u16,
        reserved: u32,
        class: *mut u16,
        options: u32,
        desired: u32,
        attributes: *const c_void,
        result: *mut Hkey,
        disposition: *mut u32,
    ) -> i32;
    fn RegSetValueExW(
        hkey: Hkey,
        name: *const u16,
        reserved: u32,
        kind: u32,
        data: *const u8,
        bytes: u32,
    ) -> i32;
    fn RegGetValueW(
        hkey: Hkey,
        subkey: *const u16,
        value: *const u16,
        flags: u32,
        kind: *mut u32,
        data: *mut c_void,
        bytes: *mut u32,
    ) -> i32;
    fn RegDeleteKeyValueW(hkey: Hkey, subkey: *const u16, value: *const u16) -> i32;
    fn RegCloseKey(hkey: Hkey) -> i32;
}

fn set_default_string(key: &str, value: &str) -> Result<(), String> {
    let wide_key = wide(key);
    let mut handle: Hkey = std::ptr::null_mut();
    let mut disposition = 0u32;
    let status = unsafe {
        RegCreateKeyExW(
            HKEY_CURRENT_USER,
            wide_key.as_ptr(),
            0,
            std::ptr::null_mut(),
            0,
            KEY_SET_VALUE,
            std::ptr::null(),
            &mut handle,
            &mut disposition,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot open HKCU\\{key} (Windows code {status})"
        ));
    }
    let data: Vec<u16> = value.encode_utf16().chain(std::iter::once(0)).collect();
    let status = unsafe {
        RegSetValueExW(
            handle,
            std::ptr::null(),
            0,
            REG_SZ,
            data.as_ptr().cast::<u8>(),
            (data.len() * 2) as u32,
        )
    };
    unsafe {
        RegCloseKey(handle);
    }
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot write HKCU\\{key} (Windows code {status})"
        ));
    }
    Ok(())
}

fn default_string(key: &str) -> Result<Option<String>, String> {
    let wide_key = wide(key);
    let mut size = 0u32;
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            wide_key.as_ptr(),
            std::ptr::null(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            &mut size,
        )
    };
    if status == ERROR_FILE_NOT_FOUND {
        return Ok(None);
    }
    if status != ERROR_SUCCESS && status != ERROR_MORE_DATA {
        return Err(format!(
            "cannot read HKCU\\{key} (Windows code {status})"
        ));
    }
    let mut buffer = vec![0u16; (size as usize).div_ceil(2).max(1)];
    let status = unsafe {
        RegGetValueW(
            HKEY_CURRENT_USER,
            wide_key.as_ptr(),
            std::ptr::null(),
            RRF_RT_REG_SZ,
            std::ptr::null_mut(),
            buffer.as_mut_ptr().cast::<c_void>(),
            &mut size,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(format!(
            "cannot read HKCU\\{key} (Windows code {status})"
        ));
    }
    let len = buffer.iter().position(|unit| *unit == 0).unwrap_or(0);
    Ok(Some(String::from_utf16_lossy(&buffer[..len])))
}

fn delete_value(key: &str) -> Result<(), String> {
    let wide_key = wide(key);
    let status = unsafe {
        RegDeleteKeyValueW(
            HKEY_CURRENT_USER,
            wide_key.as_ptr(),
            std::ptr::null(),
        )
    };
    if status == ERROR_SUCCESS || status == ERROR_FILE_NOT_FOUND {
        Ok(())
    } else {
        Err(format!(
            "cannot remove HKCU\\{key} (Windows code {status})"
        ))
    }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}
