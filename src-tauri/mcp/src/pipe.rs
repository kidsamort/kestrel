//! Client side of `\\.\pipe\kestrel-sdk`.
//!
//! The framing is the shell's, not this binary's: one JSON object per line,
//! request → response. It is the same lift as `kestrel-cli`'s client, kept here
//! as a copy on purpose — a separate crate that shared the vault's code would
//! not be a separate client.
//!
//! Nothing in this module interprets a response beyond "did the pipe answer".
//! The ops this binary sends are `status`, `secrets.list` and `items.reveal`;
//! the server decides what is allowed.

use serde_json::Value;
use std::io::{BufRead, BufReader, Write};

/// The pipe the app serves.
pub const PIPE_PATH: &str = r"\\.\pipe\kestrel-sdk";

/// A failed round trip. The message is written for the MCP client (and the
/// person reading its transcript), never for a machine to branch on: the
/// server's own error codes arrive inside a successful response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PipeError(pub String);

impl std::fmt::Display for PipeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for PipeError {}

/// The one thing this binary needs from its environment: a way to ask the app.
pub trait Backend {
    fn call(&self, request: &Value) -> Result<Value, PipeError>;
}

/// The real backend: a fresh connection per request.
///
/// The shell accepts one request per connection and hangs up after answering
/// (`run` is the only op that holds it), so a request is a connect, a write, a
/// line, and a close. Keeping it per-call also means a restarted app is picked
/// up by the next tool call instead of a stale handle.
pub struct KestrelPipe;

impl Backend for KestrelPipe {
    fn call(&self, request: &Value) -> Result<Value, PipeError> {
        round_trip(request)
    }
}

/// Open the pipe, waiting out `ERROR_PIPE_BUSY`.
///
/// The server creates the next instance only after a client has connected, so a
/// client that arrives in that window sees a busy pipe. That is a millisecond of
/// scheduling, not a failure.
pub fn open_pipe() -> Result<std::fs::File, PipeError> {
    const ERROR_PIPE_BUSY: i32 = 231;
    for attempt in 0..20 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE_PATH)
        {
            Ok(stream) => return Ok(stream),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                std::thread::sleep(std::time::Duration::from_millis(50 * (attempt + 1)));
            }
            Err(error) => {
                return Err(PipeError(format!(
                    "cannot open {PIPE_PATH}: {error} — is Kestrel running?"
                )))
            }
        }
    }
    Err(PipeError(format!(
        "cannot open {PIPE_PATH}: every instance stayed busy — is another client running?"
    )))
}

fn round_trip(request: &Value) -> Result<Value, PipeError> {
    let stream = open_pipe()?;
    let mut writer = &stream;
    let mut line =
        serde_json::to_vec(request).map_err(|error| PipeError(format!("request: {error}")))?;
    line.push(b'\n');
    writer
        .write_all(&line)
        .map_err(|error| PipeError(format!("cannot send the request: {error}")))?;
    writer.flush().ok();

    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    reader
        .read_line(&mut response)
        .map_err(|error| PipeError(format!("cannot read the response: {error}")))?;
    if response.trim().is_empty() {
        return Err(PipeError(
            "Kestrel closed the pipe without a response".into(),
        ));
    }
    serde_json::from_str(&response)
        .map_err(|error| PipeError(format!("malformed response: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_pipe_path_is_the_documented_one() {
        // A wrong path here would be a client that looks connected to nothing.
        assert_eq!(PIPE_PATH, r"\\.\pipe\kestrel-sdk");
    }

    #[test]
    fn a_missing_pipe_is_an_error_not_a_panic() {
        // Only runs when the app is not serving; if it is, this is a success and
        // the test says nothing either way. The point is the error type.
        let result = open_pipe();
        match result {
            Ok(_) => {}
            Err(error) => assert!(error.0.contains(PIPE_PATH), "{error}"),
        }
    }
}
