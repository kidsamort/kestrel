//! Registry registration and the `WebAuthnPlugin.dll` calls behind the
//! explicit Settings commands.
//!
//! Only `HKCU\Software\Classes\CLSID\{…}` is written. Nothing touches HKLM,
//! nothing happens at install time, and every write is reachable only from
//! [`shell command passkeys_register_plugin`]. Unregistration removes the
//! same tree recursively and verifies that it is gone.
//!
//! The Win32 calls are declared by hand: the shell's `windows-sys` feature set
//! does not include `Win32_System_Registry`, and adding one line to a shared
//! manifest is the parent's call, not a module's.

use crate::PLUGIN_CLSID_TEXT;
use std::ffi::{c_void, OsStr};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

type Hkey = *mut c_void;

const HKEY_CURRENT_USER: Hkey = -2147483647i32 as isize as Hkey;
const KEY_WRITE: u32 = 0x20006;
const KEY_READ: u32 = 0x2_0019;
const REG_SZ: u32 = 1;
const ERROR_FILE_NOT_FOUND: i32 = 2;
const ERROR_SUCCESS: i32 = 0;

#[link(name = "advapi32")]
unsafe extern "system" {
    fn RegCreateKeyExW(
        key: Hkey,
        sub_key: *const u16,
        reserved: u32,
        class: *const u16,
        options: u32,
        desired: u32,
        security: *const c_void,
        out: *mut Hkey,
        disposition: *mut u32,
    ) -> i32;
    fn RegOpenKeyExW(
        key: Hkey,
        sub_key: *const u16,
        options: u32,
        desired: u32,
        out: *mut Hkey,
    ) -> i32;
    fn RegSetValueExW(
        key: Hkey,
        name: *const u16,
        reserved: u32,
        kind: u32,
        data: *const u8,
        bytes: u32,
    ) -> i32;
    fn RegQueryValueExW(
        key: Hkey,
        name: *const u16,
        reserved: *mut u32,
        kind: *mut u32,
        data: *mut u8,
        bytes: *mut u32,
    ) -> i32;
    fn RegDeleteTreeW(key: Hkey, sub_key: *const u16) -> i32;
    fn RegCloseKey(key: Hkey) -> i32;
}

#[link(name = "kernel32")]
unsafe extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *const c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

/// `{6B9A7C4E-1F2D-4E83-9B6A-3C5D7E8F9A01}`, upper-case for the registry.
pub const CLSID_KEY: &str = r"Software\Classes\CLSID\{6B9A7C4E-1F2D-4E83-9B6A-3C5D7E8F9A01}";
const INPROC_KEY: &str = r"Software\Classes\CLSID\{6B9A7C4E-1F2D-4E83-9B6A-3C5D7E8F9A01}\InprocServer32";

/// `webauthnplugin.h` spells the DLL `WebAuthnPlugin.dll`; older preview builds
/// shipped the same functions in `webauthn.dll`, so both are tried.
const PLUGIN_DLLS: [&str; 2] = ["webauthnplugin.dll", "webauthn.dll"];

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("registry call failed (Windows code {0})")]
    Win32(i32),
    #[error("the WebAuthn plugin API is not present on this Windows build")]
    MissingApi,
    #[error("the plugin DLL is not next to kestrel.exe: {0}")]
    MissingDll(String),
}

/// The DLL Windows will load for the registered CLSID.
pub fn plugin_dll_path() -> Result<PathBuf, RegistryError> {
    let exe = std::env::current_exe()
        .map_err(|error| RegistryError::MissingDll(error.to_string()))?;
    let directory = exe
        .parent()
        .ok_or_else(|| RegistryError::MissingDll("kestrel.exe has no parent directory".into()))?;
    Ok(directory.join("kestrel_passkey.dll"))
}

fn wide(text: &str) -> Vec<u16> {
    OsStr::new(text)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

/// Write the CLSID tree. Returns the path that was written.
pub fn register(dll: &Path) -> Result<(), RegistryError> {
    if !dll.is_file() {
        return Err(RegistryError::MissingDll(dll.display().to_string()));
    }
    let dll_text = dll.display().to_string();
    let clsid = wide(CLSID_KEY);
    let inproc = wide(INPROC_KEY);
    let default_value = wide("");
    let dll_value = wide(&dll_text);
    let display_name = wide("Kestrel Passkey Provider");
    let threading_name = wide("ThreadingModel");
    let threading_value = wide("Both");

    unsafe {
        let mut root: Hkey = std::ptr::null_mut();
        let mut disposition = 0u32;
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            clsid.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut root,
            &mut disposition,
        );
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }
        // A display name on the CLSID itself is what the Windows UI shows when
        // it describes the provider.
        let name_bytes = (display_name.len() * 2) as u32;
        let status = RegSetValueExW(
            root,
            default_value.as_ptr(),
            0,
            REG_SZ,
            display_name.as_ptr().cast(),
            name_bytes,
        );
        RegCloseKey(root);
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }

        let mut inproc_key: Hkey = std::ptr::null_mut();
        let mut disposition = 0u32;
        let status = RegCreateKeyExW(
            HKEY_CURRENT_USER,
            inproc.as_ptr(),
            0,
            std::ptr::null(),
            0,
            KEY_WRITE,
            std::ptr::null(),
            &mut inproc_key,
            &mut disposition,
        );
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }
        let dll_bytes = (dll_value.len() * 2) as u32;
        let status = RegSetValueExW(
            inproc_key,
            default_value.as_ptr(),
            0,
            REG_SZ,
            dll_value.as_ptr().cast(),
            dll_bytes,
        );
        if status == ERROR_SUCCESS {
            let model_bytes = (threading_value.len() * 2) as u32;
            let status = RegSetValueExW(
                inproc_key,
                threading_name.as_ptr(),
                0,
                REG_SZ,
                threading_value.as_ptr().cast(),
                model_bytes,
            );
            if status != ERROR_SUCCESS {
                RegCloseKey(inproc_key);
                return Err(RegistryError::Win32(status));
            }
        }
        RegCloseKey(inproc_key);
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }
    }
    Ok(())
}

fn read_default(hive_key: Hkey) -> Result<Option<String>, RegistryError> {
    unsafe {
        let mut kind = 0u32;
        let mut bytes = 0u32;
        let status = RegQueryValueExW(
            hive_key,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut kind,
            std::ptr::null_mut(),
            &mut bytes,
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }
        if kind != REG_SZ || bytes < 2 {
            return Ok(None);
        }
        let mut buffer = vec![0u8; bytes as usize];
        let status = RegQueryValueExW(
            hive_key,
            std::ptr::null(),
            std::ptr::null_mut(),
            &mut kind,
            buffer.as_mut_ptr(),
            &mut bytes,
        );
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }
        let units: Vec<u16> = buffer
            .chunks_exact(2)
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
            .collect();
        let length = units.iter().position(|unit| *unit == 0).unwrap_or(units.len());
        Ok(Some(String::from_utf16_lossy(&units[..length])))
    }
}

/// Read the DLL path back from `InprocServer32`, if the key exists.
pub fn registered_dll() -> Result<Option<String>, RegistryError> {
    let inproc = wide(INPROC_KEY);
    unsafe {
        let mut key: Hkey = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            inproc.as_ptr(),
            0,
            KEY_READ,
            &mut key,
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(None);
        }
        if status != ERROR_SUCCESS {
            return Err(RegistryError::Win32(status));
        }
        let value = read_default(key);
        RegCloseKey(key);
        value
    }
}

/// Whether the CLSID key exists at all. A key without `InprocServer32` is
/// reported as not registered: Windows could not instantiate it.
pub fn is_registered() -> Result<bool, RegistryError> {
    Ok(registered_dll()?.is_some())
}

/// Delete the whole CLSID tree and verify it is gone.
pub fn unregister() -> Result<bool, RegistryError> {
    let clsid = wide(CLSID_KEY);
    unsafe {
        let status = RegDeleteTreeW(HKEY_CURRENT_USER, clsid.as_ptr());
        if status != ERROR_SUCCESS && status != ERROR_FILE_NOT_FOUND {
            return Err(RegistryError::Win32(status));
        }
        let mut key: Hkey = std::ptr::null_mut();
        let status = RegOpenKeyExW(
            HKEY_CURRENT_USER,
            clsid.as_ptr(),
            0,
            KEY_READ,
            &mut key,
        );
        if status == ERROR_FILE_NOT_FOUND {
            return Ok(false);
        }
        if status == ERROR_SUCCESS {
            RegCloseKey(key);
            return Ok(true);
        }
        Err(RegistryError::Win32(status))
    }
}

/* ------------------------------------------------------- plugin API bridge */

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Guid {
    pub data1: u32,
    pub data2: u16,
    pub data3: u16,
    pub data4: [u8; 8],
}

/// The CLSID in its in-memory layout. The text form is the single source of
/// truth; [`plugin_clsid`] parses it so the two can never drift.
pub fn plugin_clsid() -> Guid {
    let hex: String = PLUGIN_CLSID_TEXT.chars().filter(|c| *c != '-').collect();
    assert_eq!(hex.len(), 32, "CLSID text is 32 hex digits");
    let byte = |index: usize| u8::from_str_radix(&hex[index..index + 2], 16).expect("CLSID hex");
    Guid {
        data1: u32::from_be_bytes([byte(0), byte(2), byte(4), byte(6)]),
        data2: u16::from_be_bytes([byte(8), byte(10)]),
        data3: u16::from_be_bytes([byte(12), byte(14)]),
        data4: [
            byte(16),
            byte(18),
            byte(20),
            byte(22),
            byte(24),
            byte(26),
            byte(28),
            byte(30),
        ],
    }
}

#[repr(C)]
struct AddAuthenticatorOptions {
    authenticator_name: *const u16,
    clsid: *const Guid,
    plugin_rp_id: *const u16,
    light_logo_svg: *const u16,
    dark_logo_svg: *const u16,
    authenticator_info_len: u32,
    authenticator_info: *const u8,
    supported_rp_count: u32,
    supported_rp_ids: *const *const u16,
}

#[repr(C)]
struct AddAuthenticatorResponse {
    key_len: u32,
    key: *mut u8,
}

type AddAuthenticator = unsafe extern "system" fn(
    *const AddAuthenticatorOptions,
    *mut *mut AddAuthenticatorResponse,
) -> i32;
type RemoveAuthenticator = unsafe extern "system" fn(*const Guid) -> i32;
type GetAuthenticatorState = unsafe extern "system" fn(*const Guid, *mut u32) -> i32;
type FreeAddResponse = unsafe extern "system" fn(*mut AddAuthenticatorResponse);

struct PluginApi {
    module: *mut c_void,
    add: AddAuthenticator,
    remove: RemoveAuthenticator,
    state: GetAuthenticatorState,
    free: FreeAddResponse,
}

impl Drop for PluginApi {
    fn drop(&mut self) {
        unsafe {
            FreeLibrary(self.module);
        }
    }
}

impl PluginApi {
    fn load() -> Result<PluginApi, RegistryError> {
        for name in PLUGIN_DLLS {
            let module_name = wide(name);
            unsafe {
                let module = LoadLibraryW(module_name.as_ptr());
                if module.is_null() {
                    continue;
                }
                let add = GetProcAddress(module, c"WebAuthNPluginAddAuthenticator".as_ptr().cast());
                let remove =
                    GetProcAddress(module, c"WebAuthNPluginRemoveAuthenticator".as_ptr().cast());
                let state =
                    GetProcAddress(module, c"WebAuthNPluginGetAuthenticatorState".as_ptr().cast());
                let free = GetProcAddress(
                    module,
                    c"WebAuthNPluginFreeAddAuthenticatorResponse".as_ptr().cast(),
                );
                if add.is_null() || remove.is_null() || state.is_null() || free.is_null() {
                    FreeLibrary(module);
                    continue;
                }
                return Ok(PluginApi {
                    module,
                    add: std::mem::transmute(add),
                    remove: std::mem::transmute(remove),
                    state: std::mem::transmute(state),
                    free: std::mem::transmute(free),
                });
            }
        }
        Err(RegistryError::MissingApi)
    }

    /// Add the authenticator and return the HRESULT. A returned key is freed
    /// immediately: this engine does not verify Windows' per-request signature.
    fn add_authenticator(&self) -> i32 {
        let clsid = plugin_clsid();
        let name = wide("Kestrel");
        let info = crate::webauthn::authenticator_get_info();
        let options = AddAuthenticatorOptions {
            authenticator_name: name.as_ptr(),
            clsid: &clsid,
            plugin_rp_id: std::ptr::null(),
            light_logo_svg: std::ptr::null(),
            dark_logo_svg: std::ptr::null(),
            authenticator_info_len: info.len() as u32,
            authenticator_info: info.as_ptr(),
            supported_rp_count: 0,
            supported_rp_ids: std::ptr::null(),
        };
        let mut response: *mut AddAuthenticatorResponse = std::ptr::null_mut();
        unsafe {
            let result = (self.add)(&options, &mut response);
            if !response.is_null() {
                (self.free)(response);
            }
            result
        }
    }

    fn remove_authenticator(&self) -> i32 {
        let clsid = plugin_clsid();
        unsafe { (self.remove)(&clsid) }
    }

    fn authenticator_state(&self) -> (i32, Option<u32>) {
        let clsid = plugin_clsid();
        let mut state = 0u32;
        let result = unsafe { (self.state)(&clsid, &mut state) };
        (result, (result == 0).then_some(state))
    }
}

/// Result of asking Windows to route WebAuthn to the plugin.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsRegistration {
    /// `None` when the API or DLL is absent.
    pub hresult: Option<i32>,
    /// `Some(0)` disabled, `Some(1)` enabled; read back after the add.
    pub state: Option<u32>,
    pub error: Option<String>,
}

/// Call `WebAuthNPluginAddAuthenticator`, then read the state back.
pub fn add_to_windows() -> WindowsRegistration {
    match PluginApi::load() {
        Ok(api) => {
            let hresult = api.add_authenticator();
            let (_, state) = api.authenticator_state();
            WindowsRegistration {
                hresult: Some(hresult),
                state,
                error: None,
            }
        }
        Err(error) => WindowsRegistration {
            hresult: None,
            state: None,
            error: Some(error.to_string()),
        },
    }
}

/// Call `WebAuthNPluginRemoveAuthenticator`. Absent API is reported, not
/// treated as success.
pub fn remove_from_windows() -> WindowsRegistration {
    match PluginApi::load() {
        Ok(api) => WindowsRegistration {
            hresult: Some(api.remove_authenticator()),
            state: api.authenticator_state().1,
            error: None,
        },
        Err(error) => WindowsRegistration {
            hresult: None,
            state: None,
            error: Some(error.to_string()),
        },
    }
}

/// Read the state without changing anything, for the settings card.
pub fn windows_state() -> WindowsRegistration {
    match PluginApi::load() {
        Ok(api) => {
            let (hresult, state) = api.authenticator_state();
            WindowsRegistration {
                hresult: Some(hresult),
                state,
                error: None,
            }
        }
        Err(error) => WindowsRegistration {
            hresult: None,
            state: None,
            error: Some(error.to_string()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clsid_text_and_memory_form_agree() {
        let clsid = plugin_clsid();
        assert_eq!(clsid.data1, 0x6b9a_7c4e);
        assert_eq!(clsid.data2, 0x1f2d);
        assert_eq!(clsid.data3, 0x4e83);
        assert_eq!(
            clsid.data4,
            [0x9b, 0x6a, 0x3c, 0x5d, 0x7e, 0x8f, 0x9a, 0x01]
        );
        assert_eq!(std::mem::size_of::<Guid>(), 16);
        assert!(CLSID_KEY.ends_with("6B9A7C4E-1F2D-4E83-9B6A-3C5D7E8F9A01}"));
        // Exact x64 layout of WEBAUTHN_PLUGIN_ADD_AUTHENTICATOR_OPTIONS.
        assert_eq!(std::mem::offset_of!(AddAuthenticatorOptions, clsid), 8);
        assert_eq!(
            std::mem::offset_of!(AddAuthenticatorOptions, authenticator_info_len),
            40
        );
        assert_eq!(
            std::mem::offset_of!(AddAuthenticatorOptions, authenticator_info),
            48
        );
        assert_eq!(
            std::mem::offset_of!(AddAuthenticatorOptions, supported_rp_count),
            56
        );
        assert_eq!(
            std::mem::offset_of!(AddAuthenticatorOptions, supported_rp_ids),
            64
        );
        assert_eq!(std::mem::size_of::<AddAuthenticatorOptions>(), 72);
    }

    /// The live acceptance run: write the real HKCU key, read it back, delete
    /// it, and prove the read is empty. Ignored by default because a unit test
    /// should not leave state in the user's registry if the process is killed.
    #[test]
    #[ignore = "writes HKCU; run explicitly for the live registration proof"]
    fn hkcu_registration_round_trip() {
        let dll = std::env::var_os("KESTREL_PASSKEY_DLL")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::current_exe().expect("test binary path"));
        assert!(dll.is_file(), "DLL under test exists: {}", dll.display());
        let before = registered_dll().expect("read before");
        if let Some(existing) = &before {
            // Never clobber a registration that points at a different file.
            assert_eq!(
                existing,
                &dll.display().to_string(),
                "refusing to overwrite an unrelated registration"
            );
        }
        register(&dll).expect("register");
        let read = registered_dll().expect("read back").expect("key present");
        println!("registered InprocServer32 = {read}");
        assert_eq!(read, dll.display().to_string());
        assert!(is_registered().expect("is_registered"));

        let present = unregister().expect("unregister");
        println!("present after unregister = {present}");
        assert!(!present);
        assert_eq!(registered_dll().expect("read after"), None);
    }

    /// Exercise the Windows plugin API against a real HKCU registration. The
    /// result is printed rather than asserted: this environment may not ship
    /// `WebAuthnPlugin.dll` or may refuse an unsigned provider, and the honest
    /// answer is part of the acceptance record.
    #[test]
    #[ignore = "registers a provider with Windows; run explicitly"]
    fn hkcu_add_remove_and_windows_api() {
        let dll = std::env::var_os("KESTREL_PASSKEY_DLL")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|| std::env::current_exe().expect("test binary path"));
        assert!(dll.is_file(), "DLL under test exists: {}", dll.display());
        register(&dll).expect("register");
        let before = windows_state();
        println!("state before add = {before:?}");
        let added = add_to_windows();
        println!("add = {added:?}");
        let removed = remove_from_windows();
        println!("remove = {removed:?}");
        let present = unregister().expect("unregister");
        println!("registry present after unregister = {present}");
        assert!(!present);
    }
}
