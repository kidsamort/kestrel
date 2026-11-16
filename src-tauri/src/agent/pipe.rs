//! Named-pipe transport for the SSH agent (Windows).
//!
//! `ssh`, `git` and `ssh-add` look for the agent at
//! `\\.\pipe\openssh-ssh-agent` (or `SSH_AUTH_SOCK`), so this module owns that
//! exact pipe name. It implements the platform-neutral
//! [`Listener`](super::transport::Listener) and
//! [`Stream`](super::transport::Stream) traits; the accept loop and framing
//! live in [`super::transport`].
//!
//! Two properties matter as much as the protocol itself:
//!
//! * **Only the current user may connect.** A named pipe created without a
//!   security descriptor gets the default DACL, which grants `Everyone`. We
//!   therefore build a protected DACL with a single full-access ACE for the
//!   token user's SID. `D:P` stops inherited ACEs from widening it.
//! * **We never steal the pipe.** The first instance is created with
//!   `FILE_FLAG_FIRST_PIPE_INSTANCE`, so if the OpenSSH agent service or another
//!   copy of Kestrel already owns the name, creation fails instead of silently
//!   hijacking traffic meant for the other agent.
//!
//! All I/O is overlapped and waits on a shared, manual-reset stop event: that is
//! what lets `stop()` unblock the accept loop and every connection thread
//! without closing handles out from under a blocked syscall.

use super::transport::{Listener, Stream};
use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::ptr::{null, null_mut};
use std::sync::{Arc, Mutex};
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
    CreateEventW, GetCurrentProcess, OpenProcessToken, SetEvent, WaitForMultipleObjects, INFINITE,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};

/// The well-known OpenSSH agent pipe on Windows.
pub const PIPE_PATH: &str = r"\\.\pipe\openssh-ssh-agent";

/// Per-instance buffer. Frames are at most `protocol::MAX_FRAME_LEN`; 4 KiB is
/// enough for the identity and sign traffic this agent serves.
const BUFFER_SIZE: u32 = 4096;

/// Pipe-layer failure, translated into [`std::io::Error`] at the transport
/// boundary. `Spawn` is gone with the accept loop: thread creation now belongs
/// to `transport::Server` and is already an `io::Error`.
#[derive(Debug, thiserror::Error)]
pub enum PipeError {
    #[error("the SSH agent pipe {0} is already owned by another process")]
    AlreadyRunning(String),
    #[error("named pipe error (Windows code {0})")]
    Win32(u32),
}

impl PipeError {
    fn into_io(self) -> io::Error {
        match self {
            PipeError::AlreadyRunning(path) => io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("the SSH agent pipe {path} is already owned by another process"),
            ),
            PipeError::Win32(code) => io::Error::from_raw_os_error(code as i32),
        }
    }
}

impl From<PipeError> for io::Error {
    fn from(error: PipeError) -> io::Error {
        error.into_io()
    }
}

/// A kernel handle closed on drop. Raw `HANDLE`s are process-wide references and
/// safe to use from any thread; events and pipes both support concurrent use.
struct Handle(HANDLE);

// SAFETY: a HANDLE is a plain kernel-object reference; the Win32 calls we make
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

/// Owned `SECURITY_DESCRIPTOR` allocation from `LocalAlloc` (via the SDDL
/// conversion). Read by `CreateNamedPipeW` from the accept thread; never
/// mutated after construction.
struct SecurityDescriptor(PSECURITY_DESCRIPTOR);

unsafe impl Send for SecurityDescriptor {}
// SAFETY: the descriptor is immutable after `user_only_descriptor`; the only
// consumers (`CreateNamedPipeW`) read it.
unsafe impl Sync for SecurityDescriptor {}

impl Drop for SecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe { LocalFree(self.0.cast()) };
        }
    }
}

/// Why a connection stopped. `Stopped` means the agent is shutting down; every
/// other variant means the client went away or the call failed.
#[derive(Debug)]
enum ConnError {
    Stopped,
    Closed,
    /// A Win32 call failed. The code is already classified by the caller
    /// (`is_peer_closed` or an explicit branch), so it is not carried further:
    /// the agent protocol has no error channel to report it on.
    Win32,
}

/* ------------------------------------------------------------------ listener */

/// The Windows agent endpoint: one named-pipe instance waiting for a client at
/// a time, all carrying the user-only DACL.
pub struct PipeListener {
    /// Pipe name exactly as given to `CreateNamedPipeW`.
    name: String,
    /// The endpoint `agent_status` reports (the same name as a path).
    path: PathBuf,
    descriptor: SecurityDescriptor,
    /// Manual-reset event shared with every stream: shutdown wakes all of them.
    stop: Arc<Handle>,
    /// Auto-reset event used for `ConnectNamedPipe`'s overlapped wait.
    event: Handle,
    /// The instance the next `accept` waits on. `None` means no further accept
    /// is possible (shutdown or a failed `CreateNamedPipeW`).
    pending: Mutex<Option<Handle>>,
}

impl PipeListener {
    /// Claim the pipe and create its first instance. Fails with
    /// [`io::ErrorKind::AddrInUse`] when another process already owns the name.
    pub fn bind(path: &Path) -> io::Result<PipeListener> {
        let name = path.to_string_lossy().into_owned();
        let descriptor = user_only_descriptor()?;
        let first = create_instance(&name, &descriptor, true)?;
        let stop = Arc::new(manual_event()?);
        let event = auto_event().map_err(|code| io::Error::from_raw_os_error(code as i32))?;
        Ok(PipeListener {
            name,
            path: path.to_path_buf(),
            descriptor,
            stop,
            event,
            pending: Mutex::new(Some(first)),
        })
    }

    /// Create the instance the *next* `accept` will wait on, so a client
    /// connecting right behind the current one is not told the pipe is busy.
    fn arm_next(&self) -> Result<(), PipeError> {
        let next = create_instance(&self.name, &self.descriptor, false)?;
        *self.pending.lock().expect("pipe instance") = Some(next);
        Ok(())
    }
}

impl Listener for PipeListener {
    fn accept(&self) -> io::Result<Option<Box<dyn Stream>>> {
        loop {
            let instance = {
                let mut pending = self.pending.lock().expect("pipe instance");
                pending.take()
            };
            let Some(pipe) = instance else {
                return Ok(None);
            };
            match connect(pipe.raw(), &self.event, &self.stop) {
                Ok(()) => {
                    let io_event = match auto_event() {
                        Ok(event) => event,
                        Err(code) => {
                            unsafe { DisconnectNamedPipe(pipe.raw()) };
                            // Keep the accept loop alive for the next client.
                            if self.arm_next().is_err() {
                                return Ok(None);
                            }
                            return Err(io::Error::from_raw_os_error(code as i32));
                        }
                    };
                    // A failure here means no further client can be accepted;
                    // the connection we already have is still served, and the
                    // next `accept` reports the listener as spent.
                    let _ = self.arm_next();
                    return Ok(Some(Box::new(PipeStream {
                        pipe,
                        io_event,
                        stop: Arc::clone(&self.stop),
                    })));
                }
                // Shutting down: the overlapped connect was cancelled.
                Err(ConnError::Stopped) => return Ok(None),
                // A failed connect leaves that instance unusable; create a
                // fresh one and wait on it instead.
                Err(_) => {
                    if self.arm_next().is_err() {
                        return Ok(None);
                    }
                }
            }
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn interrupt(&self) {
        unsafe { SetEvent(self.stop.raw()) };
    }
}

/* -------------------------------------------------------------------- stream */

/// One connected client pipe. Reads and writes are overlapped and abort when
/// the shared stop event fires, which is how `stop()` wakes a blocked worker.
struct PipeStream {
    pipe: Handle,
    io_event: Handle,
    stop: Arc<Handle>,
}

impl Read for PipeStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match read_some(self.pipe.raw(), &self.stop, &self.io_event, buf) {
            Ok(Some(count)) => Ok(count),
            // Zero-byte read: the client closed between requests.
            Ok(None) => Ok(0),
            Err(ConnError::Closed) => Ok(0),
            Err(ConnError::Stopped) => Err(stopped()),
            Err(ConnError::Win32) => Err(pipe_failure("read")),
        }
    }
}

impl Write for PipeStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match write_some(self.pipe.raw(), &self.stop, &self.io_event, buf) {
            Ok(count) => Ok(count),
            Err(ConnError::Closed) => Ok(0),
            Err(ConnError::Stopped) => Err(stopped()),
            Err(ConnError::Win32) => Err(pipe_failure("write")),
        }
    }

    /// `FlushFileBuffers` is what makes a reply visible to the client before
    /// `DisconnectNamedPipe`, matching the old connection loop exactly.
    fn flush(&mut self) -> io::Result<()> {
        unsafe { FlushFileBuffers(self.pipe.raw()) };
        Ok(())
    }
}

impl Drop for PipeStream {
    fn drop(&mut self) {
        unsafe { DisconnectNamedPipe(self.pipe.raw()) };
    }
}

/// The agent is shutting down: an error, not EOF, so the frame loop breaks
/// without treating it as a normal end of session.
fn stopped() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "the SSH agent is stopping",
    )
}

fn pipe_failure(operation: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::Other,
        format!("the SSH agent pipe {operation} failed"),
    )
}

/* ------------------------------------------------------------------- reads */

fn read_some(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    buf: &mut [u8],
) -> Result<Option<usize>, ConnError> {
    let overlapped = overlapped(io_event.raw());
    let mut transferred = 0u32;
    // SAFETY: buffer and OVERLAPPED outlive the call, and the pipe carries
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

fn write_some(
    pipe: HANDLE,
    stop: &Handle,
    io_event: &Handle,
    buf: &[u8],
) -> Result<usize, ConnError> {
    let overlapped = overlapped(io_event.raw());
    let mut transferred = 0u32;
    // SAFETY: same contract as `read_some`.
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

/// Wait for an overlapped operation to finish, or for the agent to stop.
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
        // Shutting down: cancel, then wait for the cancellation to complete so
        // the OVERLAPPED on our stack is no longer referenced by the kernel.
        WAIT_OBJECT_0 => {
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

/* ------------------------------------------------------------------- win32 */

fn create_instance(
    name: &str,
    descriptor: &SecurityDescriptor,
    first: bool,
) -> Result<Handle, PipeError> {
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
        // With FILE_FLAG_FIRST_PIPE_INSTANCE, an existing name surfaces as
        // access denied: another agent already owns the pipe.
        if first && code == ERROR_ACCESS_DENIED {
            return Err(PipeError::AlreadyRunning(wide_to_string(&name)));
        }
        return Err(PipeError::Win32(code));
    }
    Handle::new(pipe).ok_or(PipeError::Win32(ERROR_ACCESS_DENIED))
}

/// Auto-reset event: suitable for one overlapped operation at a time. `Err` is
/// the Windows error code.
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

fn wide_to_string(value: &[u16]) -> String {
    let end = value
        .iter()
        .position(|unit| *unit == 0)
        .unwrap_or(value.len());
    String::from_utf16_lossy(&value[..end])
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
        // aligned; a `Vec<u8>` only guarantees byte alignment.
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
        let sid = wide_to_string_from_ptr(sid_text);
        LocalFree(sid_text.cast());
        Ok(sid)
    }
}

/// `ConvertSidToStringSidW`'s output is NUL-terminated; copy it out.
fn wide_to_string_from_ptr(value: *const u16) -> String {
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

/// The SID the pipe DACL is built from, for the live test's assertion.
#[cfg(test)]
pub fn current_user_sid_for_test() -> Result<String, PipeError> {
    current_user_sid()
}

#[cfg(test)]
use std::os::windows::io::RawHandle;

/// Read back the DACL of a connected pipe handle as SDDL. Test-only: it is how
/// the live test proves the kernel, not the code under test, holds the ACL.
#[cfg(test)]
pub fn dacl_sddl(handle: RawHandle) -> Result<String, PipeError> {
    use windows_sys::Win32::Security::Authorization::{
        ConvertSecurityDescriptorToStringSecurityDescriptorW, GetSecurityInfo, SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::DACL_SECURITY_INFORMATION;

    unsafe {
        let mut descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let code = GetSecurityInfo(
            handle as HANDLE,
            SE_KERNEL_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            null_mut(),
            null_mut(),
            &mut descriptor,
        );
        if code != 0 {
            return Err(PipeError::Win32(code));
        }
        let mut text: *mut u16 = null_mut();
        let mut len = 0u32;
        let ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(
            descriptor,
            SDDL_REVISION_1,
            DACL_SECURITY_INFORMATION,
            &mut text,
            &mut len,
        );
        let result = if ok == 0 {
            Err(PipeError::Win32(last_error()))
        } else {
            Ok(wide_to_string_from_ptr(text))
        };
        if !text.is_null() {
            LocalFree(text.cast());
        }
        LocalFree(descriptor.cast());
        result
    }
}
