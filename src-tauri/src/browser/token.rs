//! The bridge token file.
//!
//! The extension's native host is started by the browser, so it cannot receive
//! a token from the renderer. Kestrel therefore writes the one `Browser` token
//! to `bridge.token` next to the vault, protected by a **protected DACL with a
//! single ACE for the current user** (`D:P(A;;GA;;;<sid>)`). That is the same
//! user-only rule the SDK pipe uses; Administrators, SYSTEM and other users are
//! not granted a read.
//!
//! This file is a secret at rest, and the card says so. It grants only what
//! `browser_sites` allows: list matching items, and reveal one login field
//! where the origin rule is `fill`. While the vault is locked every browser op
//! answers `locked`, so the file on its own reveals nothing.
//!
//! The file is deleted on uninstall and its digest is forgotten.

use std::ffi::c_void;
use std::path::Path;
use std::ptr::null_mut;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, GENERIC_WRITE, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FlushFileBuffers, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug, thiserror::Error)]
pub enum TokenError {
    #[error("bridge token path has no parent directory")]
    NoParent,
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Windows refused the certificate-free file write (code {0})")]
    Win32(u32),
}

/// Write `token` to `path`, replacing any previous file.
///
/// The old file is removed first because `CreateFileW(CREATE_ALWAYS)` keeps an
/// existing file's DACL; deleting and recreating is what makes the protected
/// descriptor apply every time, not just the first install.
pub fn write(path: &Path, token: &str) -> Result<(), TokenError> {
    let parent = path.parent().ok_or(TokenError::NoParent)?;
    std::fs::create_dir_all(parent)?;
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(TokenError::Io(error)),
    }

    let sid = current_user_sid()?;
    let descriptor = descriptor_for_user(&sid)?;
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let wide_path = wide(&path.to_string_lossy());
    let handle = unsafe {
        CreateFileW(
            wide_path.as_ptr(),
            GENERIC_WRITE,
            0,
            &attributes,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(TokenError::Win32(unsafe { GetLastError() }));
    }
    let bytes = token.as_bytes();
    let mut written = 0u32;
    let ok = unsafe { WriteFile(handle, bytes.as_ptr(), bytes.len() as u32, &mut written, null_mut()) };
    unsafe {
        FlushFileBuffers(handle);
        CloseHandle(handle);
    }
    drop(descriptor);
    if ok == 0 || written as usize != bytes.len() {
        return Err(TokenError::Win32(unsafe { GetLastError() }));
    }
    Ok(())
}

/// Read the token back, trimming whitespace. `Ok(None)` means the file does
/// not exist; a broken file is an error, never a guess.
pub fn read(path: &Path) -> Result<Option<String>, TokenError> {
    match std::fs::read_to_string(path) {
        Ok(text) => {
            let text = text.trim().to_string();
            Ok((!text.is_empty()).then_some(text))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(TokenError::Io(error)),
    }
}

/// Delete the token file. Missing is success: uninstall must be idempotent.
pub fn remove(path: &Path) -> Result<bool, TokenError> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(TokenError::Io(error)),
    }
}

/// The current process token's SID as `S-1-5-...`.
fn current_user_sid() -> Result<String, TokenError> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(TokenError::Win32(GetLastError()));
        }
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            CloseHandle(token);
            return Err(TokenError::Win32(GetLastError()));
        }
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        ) == 0
        {
            CloseHandle(token);
            return Err(TokenError::Win32(GetLastError()));
        }
        CloseHandle(token);
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return Err(TokenError::Win32(GetLastError()));
        }
        let sid = wide_to_string(text);
        LocalFree(text.cast());
        Ok(sid)
    }
}

struct Descriptor(PSECURITY_DESCRIPTOR);

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

/// `D:P(A;;GA;;;<sid>)`: a protected DACL (no inherited ACEs) with exactly one
/// full-access entry for the current user.
fn descriptor_for_user(sid: &str) -> Result<Descriptor, TokenError> {
    let sddl = wide(&format!("D:P(A;;GA;;;{sid})"));
    let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
    let mut size = 0u32;
    let ok = unsafe {
        ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            &mut size,
        )
    };
    if ok == 0 {
        return Err(TokenError::Win32(unsafe { GetLastError() }));
    }
    Ok(Descriptor(descriptor))
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_to_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    while unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) })
}

/// The DACL of `path` as SDDL, proving what the kernel stored. Test-only: the
/// release binary never reads a file's security descriptor.
#[cfg(test)]
pub fn dacl_sddl(path: &Path) -> Result<String, TokenError> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetNamedSecurityInfoW,
        SE_FILE_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    let wide_path = wide(&path.to_string_lossy());
    unsafe {
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let code = GetNamedSecurityInfoW(
            wide_path.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION as u32,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        );
        if code != 0 {
            return Err(TokenError::Win32(code));
        }
        let mut text = null_mut();
        let mut len = 0u32;
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION as u32,
            &mut text,
            &mut len,
        );
        let result = if ok == 0 {
            Err(TokenError::Win32(GetLastError()))
        } else {
            Ok(wide_to_string(text))
        };
        if !text.is_null() {
            LocalFree(text.cast());
        }
        LocalFree(descriptor.cast());
        result
    }
}
