//! Client side of `\\.\pipe\kestrel-sdk`.
//!
//! The framing on the pipe is Kestrel's own: one JSON object per line, request
//! → response, one request per connection. This is the same client shape
//! `kestrel-cli` and `kestrel-mcp` use; the host does not invent a second one.
//!
//! The pipe name is a constant because the app owns it. A test can call
//! [`round_trip_at`] with a unique test pipe, which is how the framing and a
//! real connection are exercised without an app.

use serde_json::Value;
use std::ffi::c_void;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::windows::io::{FromRawHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::time::Duration;
use windows_sys::Win32::Foundation::{
    GetLastError, GENERIC_READ, GENERIC_WRITE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{CreateFileW, OPEN_EXISTING};

/// The pipe the app serves.
pub const PIPE_PATH: &str = r"\\.\pipe\kestrel-sdk";

/// A response bigger than this is a server bug or a hostile peer; the bridge
/// never asks for a payload close to it.
const MAX_RESPONSE: usize = 4 * 1024 * 1024;

/// Open the pipe, waiting out `ERROR_PIPE_BUSY`.
///
/// The app creates the next instance only after a client has connected, so a
/// request that lands in that window sees a busy pipe. That is scheduling, not
/// failure, which is why the retry is bounded and the error still names Kestrel.
fn open(path: &str) -> Result<std::fs::File, String> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let wide: Vec<u16> = path.encode_utf16().chain(std::iter::once(0)).collect();
    for attempt in 0..20 {
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                0,
                null(),
                OPEN_EXISTING,
                0,
                null_mut::<c_void>(),
            )
        };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(unsafe { std::fs::File::from_raw_handle(handle as RawHandle) });
        }
        let code = unsafe { GetLastError() };
        if code as i32 == ERROR_PIPE_BUSY {
            std::thread::sleep(Duration::from_millis(50 * (attempt + 1)));
            continue;
        }
        return Err(format!(
            "cannot open {path}: Windows error {code} — is Kestrel running?"
        ));
    }
    Err(format!(
        "cannot open {path}: every instance stayed busy — is another client running?"
    ))
}

/// One request/response round trip on the production pipe.
pub fn round_trip(request: &Value) -> Result<Value, String> {
    round_trip_at(PIPE_PATH, request)
}

/// One round trip on an explicit pipe path. Production passes [`PIPE_PATH`];
/// tests pass a private name.
pub fn round_trip_at(path: &str, request: &Value) -> Result<Value, String> {
    let stream = open(path)?;
    let mut writer = &stream;
    let mut line = serde_json::to_vec(request)
        .map_err(|error| format!("cannot encode the request: {error}"))?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .map_err(|error| format!("cannot send the request: {error}"))?;
    writer.flush().ok();

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .by_ref()
        .take(MAX_RESPONSE as u64 + 1)
        .read_line(&mut response)
        .map_err(|error| format!("cannot read the response: {error}"))?;
    if response.is_empty() {
        return Err("Kestrel closed the pipe without a response".into());
    }
    if !response.ends_with('\n') || response.len() > MAX_RESPONSE {
        return Err("Kestrel's response was not a bounded line".into());
    }
    serde_json::from_str(&response).map_err(|error| format!("malformed response: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::ptr::{null, null_mut};
    use windows_sys::Win32::Foundation::{
        CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE, ERROR_PIPE_CONNECTED,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        FlushFileBuffers, ReadFile, WriteFile, PIPE_ACCESS_DUPLEX,
    };
    use windows_sys::Win32::System::Pipes::{
        ConnectNamedPipe, CreateNamedPipeW, DisconnectNamedPipe, PIPE_READMODE_BYTE,
        PIPE_TYPE_BYTE, PIPE_WAIT,
    };

    struct Server {
        name: String,
        thread: std::thread::JoinHandle<Value>,
    }

    impl Server {
        fn start() -> Server {
            let name = format!(
                r"\\.\pipe\kestrel-nmhost-test-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            );
            let pipe = name.clone();
            let thread = std::thread::spawn(move || serve(&pipe));
            // Give CreateNamedPipeW a moment to publish the name; the client's
            // own busy-retry covers the race either way.
            std::thread::sleep(Duration::from_millis(20));
            Server { name, thread }
        }
    }

    fn serve(name: &str) -> Value {
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        let handle: HANDLE = unsafe {
            CreateNamedPipeW(
                wide.as_ptr(),
                PIPE_ACCESS_DUPLEX,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT,
                1,
                64 * 1024,
                64 * 1024,
                0,
                null(),
            )
        };
        assert_ne!(handle, INVALID_HANDLE_VALUE, "test pipe was not created");
        let connected = unsafe { ConnectNamedPipe(handle, null_mut()) };
        if connected == 0 {
            let code = unsafe { GetLastError() };
            assert_eq!(code, ERROR_PIPE_CONNECTED, "connect failed: {code}");
        }
        let mut request = Vec::new();
        let mut buffer = [0u8; 4096];
        loop {
            let mut read = 0u32;
            let ok = unsafe {
                ReadFile(
                    handle,
                    buffer.as_mut_ptr(),
                    buffer.len() as u32,
                    &mut read,
                    null_mut(),
                )
            };
            assert_ne!(ok, 0, "read failed");
            request.extend_from_slice(&buffer[..read as usize]);
            if request.contains(&b'\n') {
                break;
            }
        }
        let line = std::str::from_utf8(&request[..request.len() - 1]).expect("utf-8");
        let value: Value = serde_json::from_str(line).expect("request json");
        let response = b"{\"ok\":true,\"mode\":\"fill\",\"items\":[]}\n";
        let mut written = 0u32;
        let ok = unsafe {
            WriteFile(
                handle,
                response.as_ptr(),
                response.len() as u32,
                &mut written,
                null_mut(),
            )
        };
        assert_ne!(ok, 0, "write failed");
        assert_eq!(written as usize, response.len(), "short write");
        // Blocks until the client has read every byte. With the newline in
        // the response, that is the line this test asserts on; without it the
        // disconnect would discard the unread body.
        unsafe {
            FlushFileBuffers(handle);
        }
        unsafe {
            DisconnectNamedPipe(handle);
            CloseHandle(handle);
        }
        value
    }

    #[test]
    fn the_pipe_path_is_the_documented_one() {
        assert_eq!(PIPE_PATH, r"\\.\pipe\kestrel-sdk");
    }

    #[test]
    fn a_round_trip_reaches_a_fake_server() {
        let server = Server::start();
        let request = json!({
            "op": "browser.items",
            "origin": "https://example.com",
            "token": "bridge-token",
        });
        let response = round_trip_at(&server.name, &request).expect("round trip");
        assert_eq!(response["ok"], json!(true));
        assert_eq!(response["mode"], json!("fill"));
        let seen = server.thread.join().expect("server thread");
        assert_eq!(seen, request, "the server saw the request unchanged");
    }

    #[test]
    fn a_missing_pipe_is_an_error_not_a_panic() {
        let missing = format!(
            r"\\.\pipe\kestrel-nmhost-missing-{}",
            std::process::id()
        );
        let error = round_trip_at(&missing, &json!({"op": "browser.status"}))
            .expect_err("no server");
        assert!(error.contains("Kestrel running"), "{error}");
    }
}
