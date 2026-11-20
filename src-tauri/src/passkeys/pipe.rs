//! Named-pipe transport between `kestrel_passkey.dll` and the running app.
//!
//! The pipe is user-only (`D:P` with a single full-access ACE for the token
//! user) and starts only from `passkeys_register_plugin`. It carries CTAP2
//! requests and responses; no credential scalar and no vault key is ever part
//! of a frame.
//!
//! The accept loop is blocking on purpose. There is at most one client at a
//! time (Windows' WebAuthn broker), and unregistration stops the loop by
//! connecting a zero-byte client to wake `ConnectNamedPipe`, which then sees the
//! stop flag on its next iteration.

use crate::passkeys::service;
use std::ffi::c_void;
use std::io::{Read, Write};
use std::os::windows::io::FromRawHandle;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use tauri::AppHandle;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_PIPE_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, FILE_FLAG_FIRST_PIPE_INSTANCE, PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Same name as [`kestrel_passkey::ipc::PIPE_PATH`]; the engine crate is the
/// source of truth for the frame format, this module owns the kernel object.
pub const PIPE_PATH: &str = kestrel_passkey::ipc::PIPE_PATH;
const BUFFER_SIZE: u32 = kestrel_passkey::ipc::MAX_FRAME as u32;

#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    #[error("the passkey pipe is already owned by another process")]
    AlreadyRunning,
    #[error("named pipe error (Windows code {0})")]
    Win32(u32),
    #[error("could not start the passkey thread: {0}")]
    Spawn(#[from] std::io::Error),
    #[error("SDDL failed: {0}")]
    Descriptor(u32),
}

struct Handle(HANDLE);

unsafe impl Send for Handle {}

impl Handle {
    fn new(raw: HANDLE) -> Option<Handle> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Handle(raw))
        }
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

struct Descriptor(PSECURITY_DESCRIPTOR);

unsafe impl Send for Descriptor {}

impl Drop for Descriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

/// A running pipe. Dropping it stops the accept loop.
pub struct Server {
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Server {
    pub fn start(app: AppHandle) -> Result<Server, PipeError> {
        let descriptor = user_only_descriptor()?;
        let pipe = create_instance(&descriptor)?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("kestrel-passkeys".into())
            .spawn(move || accept_loop(pipe, app, thread_stop))?;
        Ok(Server {
            stop,
            thread: Some(thread),
        })
    }

    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Wake a blocked `ConnectNamedPipe`. The client is closed immediately,
        // so the server's read sees EOF and the next loop check exits.
        if let Ok(mut wake) = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE_PATH)
        {
            let _ = wake.write_all(&[]);
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if self.thread.is_some() {
            self.shutdown();
        }
    }
}

fn accept_loop(pipe: Handle, app: AppHandle, stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let connected = unsafe {
            ConnectNamedPipe(pipe.0, null_mut()) != 0 || GetLastError() == ERROR_PIPE_CONNECTED
        };
        if !connected {
            if stop.load(Ordering::SeqCst) {
                break;
            }
            continue;
        }
        serve_one(&pipe, &app);
        unsafe {
            DisconnectNamedPipe(pipe.0);
        }
    }
}

fn serve_one(pipe: &Handle, app: &AppHandle) {
    // Duplicate the handle as a std::fs::File so Read/Write get the blocking
    // semantics the pipe was created with. The guard closes on return; the
    // listener itself stays open for the next connection.
    let mut stream = unsafe { std::fs::File::from_raw_handle(pipe.0) };
    let result = (|| -> std::io::Result<()> {
        let mut header = [0u8; 5];
        match stream.read_exact(&mut header) {
            Ok(()) => {}
            // A wake connection or an early disconnect is not an error.
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(error) => return Err(error),
        }
        let length = u32::from_le_bytes([header[1], header[2], header[3], header[4]]) as usize;
        if length > kestrel_passkey::ipc::MAX_FRAME {
            return Ok(());
        }
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body)?;
        let (status, response) = service::handle(app, header[0], &body);
        stream.write_all(&kestrel_passkey::ipc::response(status, &response))?;
        stream.flush()?;
        let _ = unsafe { FlushFileBuffers(pipe.0) };
        Ok(())
    })();
    let _ = result;
    // The File guard would close the listener handle; forget it so only the
    // owning `Handle` closes the kernel object.
    std::mem::forget(stream);
}

fn wide_to_string(value: *const u16) -> String {
    if value.is_null() {
        return String::new();
    }
    let mut len = 0usize;
    // SAFETY: the SDK returns a NUL-terminated UTF-16 string.
    while unsafe { *value.add(len) } != 0 {
        len += 1;
    }
    String::from_utf16_lossy(unsafe { std::slice::from_raw_parts(value, len) })
}

fn create_instance(descriptor: &Descriptor) -> Result<Handle, PipeError> {
    let name: Vec<u16> = PIPE_PATH.encode_utf16().chain(std::iter::once(0)).collect();
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let raw = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            1,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            &attributes,
        )
    };
    match Handle::new(raw) {
        Some(handle) => Ok(handle),
        None => {
            let code = unsafe { GetLastError() };
            if code == ERROR_ACCESS_DENIED {
                Err(PipeError::AlreadyRunning)
            } else {
                Err(PipeError::Win32(code))
            }
        }
    }
}

/// SDDL `D:P(A;;GA;;;<current user SID>)`: a protected DACL granting exactly
/// the token user full access. Inherited ACEs cannot widen it.
fn user_only_descriptor() -> Result<Descriptor, PipeError> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(PipeError::Win32(GetLastError()));
        }
        let token = Handle::new(token).ok_or_else(|| PipeError::Win32(GetLastError()))?;
        let mut needed = 0u32;
        GetTokenInformation(token.0, TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(PipeError::Win32(GetLastError()));
        }
        // TOKEN_USER contains a pointer, so the buffer must be pointer-aligned;
        // a Vec<u8> only guarantees byte alignment.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(PipeError::Win32(GetLastError()));
        }
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid_text: *mut u16 = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_text) == 0 {
            return Err(PipeError::Win32(GetLastError()));
        }
        let sid = wide_to_string(sid_text);
        LocalFree(sid_text.cast());
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let sddl: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            SDDL_REVISION_1,
            &mut descriptor,
            null_mut(),
        ) == 0
        {
            return Err(PipeError::Descriptor(GetLastError()));
        }
        Ok(Descriptor(descriptor))
    }
}
