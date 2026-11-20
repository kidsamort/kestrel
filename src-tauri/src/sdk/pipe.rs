//! Named-pipe transport for the CLI/SDK surface.
//!
//! This is deliberately the same design as `src-tauri/src/agent/pipe.rs`:
//!
//! * **Only the current user may connect.** The first instance is created with
//!   a protected DACL (`D:P`) holding a single full-access ACE for the token
//!   user's SID. Without it, a named pipe inherits the default DACL and any
//!   local account could open the automation surface.
//! * **We never steal the pipe.** `FILE_FLAG_FIRST_PIPE_INSTANCE` makes a
//!   second owner fail instead of silently sharing clients, and
//!   `PIPE_REJECT_REMOTE_CLIENTS` keeps the pipe off SMB.
//! * **Shutdown cannot hang.** All I/O is overlapped and waits on one shared,
//!   manual-reset stop event, so `stop()` wakes the accept loop and every
//!   connection thread without closing handles under a blocked syscall.
//!
//! Framing is the protocol's: one JSON object per line. The request side is
//! capped at [`MAX_REQUEST_LEN`] bytes per line, so a client cannot make the
//! server allocate without bound.

use crate::sdk::protocol::{self, Auth, SdkBackend, SdkError};
use std::ffi::c_void;
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, LocalFree, ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_HANDLE_EOF,
    ERROR_IO_PENDING, ERROR_NO_DATA, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED, HANDLE,
    INVALID_HANDLE_VALUE, WAIT_FAILED, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, TokenUser, PSECURITY_DESCRIPTOR, SECURITY_ATTRIBUTES, TOKEN_QUERY,
    TOKEN_USER,
};
use windows_sys::Win32::Storage::FileSystem::{
    FlushFileBuffers, ReadFile, WriteFile, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED,
    PIPE_ACCESS_DUPLEX,
};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, GetCurrentProcess, OpenProcessToken, SetEvent, WaitForMultipleObjects,
    WaitForSingleObject, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// The pipe the CLI and SDK clients connect to.
pub const PIPE_PATH: &str = r"\\.\pipe\kestrel-sdk";

/// Kernel buffer per direction. Requests are short; `run` responses are bounded
/// by the protocol's capture cap, which is larger, but a byte-mode pipe hands
/// data over as the writer produces it, so the buffer is not the frame limit.
const BUFFER_SIZE: u32 = 8192;

/// Size of one overlapped read. Lines are assembled in a caller-owned buffer.
const READ_CHUNK: usize = 4096;

#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    #[error("the SDK pipe {0} is already owned by another process")]
    AlreadyRunning(String),
    #[error("named pipe error (Windows code {0})")]
    Win32(u32),
    #[error("could not start the SDK thread: {0}")]
    Spawn(#[from] std::io::Error),
}

/// Everything a connection needs. Built once by the module and shared by every
/// connection thread.
pub struct Shared {
    pub backend: Arc<dyn SdkBackend>,
    pub auth: Arc<Auth>,
    /// Set by `Server::stop`; the backend also watches it to kill a child that
    /// would otherwise keep the exit path waiting.
    pub stop: Arc<AtomicBool>,
}

/// A kernel handle closed on drop.
struct Handle(HANDLE);

// SAFETY: a HANDLE is a plain kernel-object reference; the Win32 calls made
// with it (events, pipes, tokens) are documented as thread-safe.
unsafe impl Send for Handle {}
unsafe impl Sync for Handle {}

impl Handle {
    fn new(raw: HANDLE) -> Option<Handle> {
        if raw.is_null() || raw == INVALID_HANDLE_VALUE {
            None
        } else {
            Some(Handle(raw))
        }
    }

    fn raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for Handle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

/// Owned security descriptor from `LocalAlloc`; used only by the accept thread.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

unsafe impl Send for SecurityDescriptor {}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

/// Why a connection stopped. `Stopped` is a normal shutdown; the rest mean the
/// client went away or the call failed.
#[derive(Debug)]
enum ConnError {
    Stopped,
    Closed,
    Win32,
}

/// A running SDK pipe: accept thread, connection threads, stop event.
pub struct Server {
    stop: Arc<AtomicBool>,
    event: Arc<Handle>,
    thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Server {
    /// Create the first instance (so "already in use" surfaces here) and start
    /// accepting connections.
    pub fn start(shared: Arc<Shared>) -> Result<Server, PipeError> {
        Server::start_named(PIPE_PATH, shared)
    }

    /// Same as [`Server::start`] but on an explicit pipe name. The tests use a
    /// unique name so a running Kestrel instance cannot collide with them.
    pub(crate) fn start_named(name: &str, shared: Arc<Shared>) -> Result<Server, PipeError> {
        let descriptor = user_only_descriptor()?;
        let first = create_instance(name, &descriptor, true)?;
        let event = Arc::new(manual_event()?);
        let stop = Arc::clone(&shared.stop);
        let workers = Arc::new(Mutex::new(Vec::new()));

        let thread_name = name.to_string();
        let thread_event = Arc::clone(&event);
        let thread_workers = Arc::clone(&workers);
        let thread_stop = Arc::clone(&stop);
        let thread = std::thread::Builder::new()
            .name("kestrel-sdk".into())
            .spawn(move || {
                accept_loop(
                    &thread_name,
                    first,
                    &descriptor,
                    shared,
                    &thread_stop,
                    &thread_event,
                    &thread_workers,
                )
            })?;

        Ok(Server {
            stop,
            event,
            thread: Some(thread),
            workers,
        })
    }

    /// Stop accepting, wake every blocked connection and wait for the threads.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        unsafe { SetEvent(self.event.raw()) };
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let workers = std::mem::take(&mut *self.workers.lock().expect("sdk worker list"));
        for worker in workers {
            let _ = worker.join();
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

/* ------------------------------------------------------------------ server */

#[allow(clippy::too_many_arguments)]
fn accept_loop(
    name: &str,
    initial: Handle,
    descriptor: &SecurityDescriptor,
    shared: Arc<Shared>,
    stop: &Arc<AtomicBool>,
    event: &Arc<Handle>,
    workers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    let Ok(connect_event) = auto_event() else {
        return;
    };
    let mut pipe = Some(initial);
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Some(current) = pipe.take() else { break };
        match connect(current.raw(), &connect_event, event) {
            Ok(()) => {
                let worker_event = Arc::clone(event);
                let worker_shared = Arc::clone(&shared);
                let spawned = std::thread::Builder::new()
                    .name("kestrel-sdk-conn".into())
                    .spawn(move || {
                        serve_connection(current.raw(), &worker_event, &worker_shared);
                        // `current` drops here, after `DisconnectNamedPipe`.
                    });
                if let Ok(handle) = spawned {
                    let mut workers = workers.lock().expect("sdk worker list");
                    // Short-lived clients would otherwise leave a growing list
                    // of join handles for the life of the process.
                    workers.retain(|worker| !worker.is_finished());
                    workers.push(handle);
                }
            }
            Err(ConnError::Stopped) => break,
            Err(_) => {}
        }
        // Have the next instance ready before the worker answers, so a client
        // connecting right after the current one is not told the pipe is busy.
        match create_instance(name, descriptor, false) {
            Ok(next) => pipe = Some(next),
            Err(_) => break,
        }
    }
}

fn serve_connection(pipe: HANDLE, stop: &Handle, shared: &Shared) {
    let Ok(io_event) = auto_event() else {
        unsafe { DisconnectNamedPipe(pipe) };
        return;
    };
    let mut pending = Vec::new();
    loop {
        if unsafe { WaitForSingleObject(stop.raw(), 0) } == WAIT_OBJECT_0 {
            break;
        }
        match read_line(pipe, stop, &io_event, &mut pending) {
            Ok(Some(line)) => {
                let response = match protocol::parse_request(&line) {
                    Ok(request) => protocol::respond(
                        &shared.auth,
                        shared.backend.as_ref(),
                        &request,
                        PIPE_PATH,
                    ),
                    Err(error) => protocol::error_response(&error),
                };
                if write_response(pipe, stop, &io_event, &response).is_err() {
                    break;
                }
                unsafe { FlushFileBuffers(pipe) };
            }
            Ok(None) => break,
            // The stream cannot be resynchronised after an over-long line:
            // answer the one coded error the protocol allows and hang up.
            Err(LineError::TooLarge) => {
                let response = protocol::error_response(&SdkError::BadRequest(format!(
                    "request exceeds {} bytes",
                    protocol::MAX_REQUEST_LEN
                )));
                if write_response(pipe, stop, &io_event, &response).is_ok() {
                    // Deliver before closing: `DisconnectNamedPipe` discards
                    // whatever the client has not read yet.
                    unsafe { FlushFileBuffers(pipe) };
                }
                break;
            }
            Err(LineError::Failed) => break,
        }
    }
    unsafe { DisconnectNamedPipe(pipe) };
}

/// Serialise one response and write it with its newline delimiter.
fn write_response(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    response: &serde_json::Value,
) -> Result<(), ConnError> {
    let mut bytes = serde_json::to_vec(response).unwrap_or_else(|_| {
        br#"{"ok":false,"error":"internal","message":"response could not be serialised"}"#.to_vec()
    });
    bytes.push(b'\n');
    write_all(pipe, stop, io_event, &bytes)
}

/* ------------------------------------------------------------------ frames */

/// Why a request line could not be read.
enum LineError {
    TooLarge,
    Failed,
}

impl From<ConnError> for LineError {
    fn from(_: ConnError) -> Self {
        LineError::Failed
    }
}

/// Read one newline-terminated line. `Ok(None)` is a clean EOF between lines.
/// `pending` keeps the bytes of a partially received line across calls.
fn read_line(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    pending: &mut Vec<u8>,
) -> Result<Option<Vec<u8>>, LineError> {
    loop {
        if let Some(position) = pending.iter().position(|byte| *byte == b'\n') {
            let mut line: Vec<u8> = pending.drain(..=position).collect();
            line.pop();
            // Tolerate CRLF from a client that writes text mode.
            if line.last() == Some(&b'\r') {
                line.pop();
            }
            return Ok(Some(line));
        }
        if pending.len() > protocol::MAX_REQUEST_LEN {
            return Err(LineError::TooLarge);
        }
        let mut chunk = [0u8; READ_CHUNK];
        match read_some(pipe, stop, io_event, &mut chunk)? {
            // `None` is EOF or a closed peer; partial data is an error.
            Some(0) | None => {
                return if pending.is_empty() {
                    Ok(None)
                } else {
                    Err(LineError::Failed)
                };
            }
            Some(read) => pending.extend_from_slice(&chunk[..read]),
        }
    }
}

fn read_some(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    buf: &mut [u8],
) -> Result<Option<usize>, ConnError> {
    let overlapped = overlapped(io_event.raw());
    let mut transferred = 0u32;
    // SAFETY: buffer and OVERLAPPED outlive the call and the pipe carries
    // FILE_FLAG_OVERLAPPED, so a pending read is completed or cancelled below.
    let ok = unsafe {
        ReadFile(
            pipe,
            buf.as_mut_ptr(),
            buf.len() as u32,
            &mut transferred,
            &overlapped as *const OVERLAPPED as *mut OVERLAPPED,
        )
    };
    if ok != 0 {
        return Ok(finish_read(transferred));
    }
    let code = last_error();
    if code == ERROR_IO_PENDING {
        let transferred = complete(pipe, io_event, stop, &overlapped)?;
        return Ok(finish_read(transferred));
    }
    if is_peer_closed(code) {
        return Ok(None);
    }
    Err(ConnError::Win32)
}

fn finish_read(transferred: u32) -> Option<usize> {
    if transferred == 0 {
        None
    } else {
        Some(transferred as usize)
    }
}

fn write_all(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    mut buf: &[u8],
) -> Result<(), ConnError> {
    while !buf.is_empty() {
        let written = write_some(pipe, stop, io_event, buf)?;
        if written == 0 {
            return Err(ConnError::Closed);
        }
        buf = &buf[written..];
    }
    Ok(())
}

fn write_some(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    buf: &[u8],
) -> Result<usize, ConnError> {
    let overlapped = overlapped(io_event.raw());
    let mut transferred = 0u32;
    let ok = unsafe {
        WriteFile(
            pipe,
            buf.as_ptr(),
            buf.len() as u32,
            &mut transferred,
            &overlapped as *const OVERLAPPED as *mut OVERLAPPED,
        )
    };
    if ok != 0 {
        return Ok(transferred as usize);
    }
    let code = last_error();
    if code == ERROR_IO_PENDING {
        return complete(pipe, io_event, stop, &overlapped).map(|n| n as usize);
    }
    if is_peer_closed(code) {
        return Err(ConnError::Closed);
    }
    Err(ConnError::Win32)
}

/// Wait for an overlapped operation, or for the server to stop.
fn complete(
    pipe: HANDLE,
    io_event: &Handle,
    stop: &Handle,
    overlapped: &OVERLAPPED,
) -> Result<u32, ConnError> {
    let handles = [stop.raw(), io_event.raw()];
    let index = unsafe { WaitForMultipleObjects(2, handles.as_ptr(), 0, INFINITE) };
    match index {
        WAIT_FAILED => Err(ConnError::Win32),
        WAIT_OBJECT_0 => {
            // Shutting down: cancel, then wait for the cancellation so the
            // stack OVERLAPPED is no longer referenced by the kernel.
            unsafe { CancelIoEx(pipe, overlapped) };
            let mut ignored = 0u32;
            unsafe { GetOverlappedResult(pipe, overlapped, &mut ignored, 1) };
            Err(ConnError::Stopped)
        }
        _ if index == WAIT_OBJECT_0 + 1 => {
            let mut transferred = 0u32;
            if unsafe { GetOverlappedResult(pipe, overlapped, &mut transferred, 0) } == 0 {
                let code = last_error();
                if is_peer_closed(code) {
                    Err(ConnError::Closed)
                } else {
                    Err(ConnError::Win32)
                }
            } else {
                Ok(transferred)
            }
        }
        _ => Err(ConnError::Win32),
    }
}

fn connect(pipe: HANDLE, io_event: &Handle, stop: &Handle) -> Result<(), ConnError> {
    let overlapped = overlapped(io_event.raw());
    if unsafe { ConnectNamedPipe(pipe, &overlapped as *const OVERLAPPED as *mut OVERLAPPED) } != 0 {
        return Ok(());
    }
    let code = last_error();
    match code {
        // The client connected between CreateNamedPipe and ConnectNamedPipe.
        ERROR_PIPE_CONNECTED => Ok(()),
        ERROR_IO_PENDING => complete(pipe, io_event, stop, &overlapped).map(|_| ()),
        _ => Err(ConnError::Win32),
    }
}

fn is_peer_closed(code: u32) -> bool {
    matches!(
        code,
        ERROR_BROKEN_PIPE | ERROR_PIPE_NOT_CONNECTED | ERROR_NO_DATA | ERROR_HANDLE_EOF
    )
}

/* ------------------------------------------------------------------ win32 */

fn create_instance(
    name: &str,
    descriptor: &SecurityDescriptor,
    first: bool,
) -> Result<Handle, PipeError> {
    let path = name.to_string();
    let name = wide(name);
    let mut open_mode = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
    if first {
        open_mode |= FILE_FLAG_FIRST_PIPE_INSTANCE;
    }
    let attributes = SECURITY_ATTRIBUTES {
        nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.0,
        bInheritHandle: 0,
    };
    let pipe = unsafe {
        CreateNamedPipeW(
            name.as_ptr(),
            open_mode,
            PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_UNLIMITED_INSTANCES,
            BUFFER_SIZE,
            BUFFER_SIZE,
            0,
            &attributes,
        )
    };
    if pipe == INVALID_HANDLE_VALUE {
        let code = last_error();
        // With FILE_FLAG_FIRST_PIPE_INSTANCE an existing name surfaces as
        // access denied: another process already owns the pipe.
        if first && code == ERROR_ACCESS_DENIED {
            return Err(PipeError::AlreadyRunning(path));
        }
        return Err(PipeError::Win32(code));
    }
    Handle::new(pipe).ok_or(PipeError::Win32(ERROR_ACCESS_DENIED))
}

/// Auto-reset event: suitable for one overlapped operation at a time.
fn auto_event() -> Result<Handle, u32> {
    let event = unsafe { CreateEventW(null(), 0, 0, null()) };
    Handle::new(event).ok_or_else(last_error)
}

/// Manual-reset event: stays signaled so every blocked thread observes a stop.
fn manual_event() -> Result<Handle, PipeError> {
    let event = unsafe { CreateEventW(null(), 1, 0, null()) };
    Handle::new(event).ok_or_else(|| PipeError::Win32(last_error()))
}

fn overlapped(event: HANDLE) -> OVERLAPPED {
    // SAFETY: OVERLAPPED is a plain C struct; zero is its documented initial
    // state and the union field may be zero.
    let mut value: OVERLAPPED = unsafe { std::mem::zeroed() };
    value.hEvent = event;
    value
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn wide(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
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
    let slice = unsafe { std::slice::from_raw_parts(value, len) };
    String::from_utf16_lossy(slice)
}

/// Current process token's user SID as `S-1-5-...`.
fn current_user_sid() -> Result<String, PipeError> {
    unsafe {
        let mut token: HANDLE = null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(PipeError::Win32(last_error()));
        }
        let token = Handle::new(token).ok_or_else(|| PipeError::Win32(last_error()))?;

        let mut needed = 0u32;
        GetTokenInformation(token.raw(), TokenUser, null_mut(), 0, &mut needed);
        if needed == 0 {
            return Err(PipeError::Win32(last_error()));
        }
        // Over-allocate in 8-byte words so the returned TOKEN_USER is properly
        // aligned; `Vec<u8>` only guarantees byte alignment.
        let mut buffer = vec![0u64; (needed as usize).div_ceil(8)];
        if GetTokenInformation(
            token.raw(),
            TokenUser,
            buffer.as_mut_ptr().cast::<c_void>(),
            needed,
            &mut needed,
        ) == 0
        {
            return Err(PipeError::Win32(last_error()));
        }
        // SAFETY: the buffer holds a TOKEN_USER whose SID lives in the same
        // allocation, which stays alive for the whole call.
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut sid_text: *mut u16 = null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut sid_text) == 0 {
            return Err(PipeError::Win32(last_error()));
        }
        let sid = wide_to_string(sid_text);
        LocalFree(sid_text.cast());
        Ok(sid)
    }
}

/// A protected DACL with exactly one full-access ACE: the current user.
fn user_only_descriptor() -> Result<SecurityDescriptor, PipeError> {
    let sid = current_user_sid()?;
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
        return Err(PipeError::Win32(last_error()));
    }
    Ok(SecurityDescriptor(descriptor))
}
