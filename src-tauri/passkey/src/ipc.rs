//! Frame protocol between the Windows WebAuthn plugin DLL and the Kestrel
//! process.
//!
//! The DLL is loaded into the WebAuthn broker's process and has no access to
//! the vault. It forwards the raw CTAP2 bytes Windows handed it; the shell, in
//! the process that holds the unlocked session, parses them, signs with the
//! credential it resolves from the encrypted store, and returns the raw CTAP2
//! response. The private key never crosses this boundary in either direction.
//!
//! Framing is deliberately tiny and length-prefixed:
//!
//! ```text
//! request:  op:u8  len:u32 little-endian  payload:len bytes
//! response: status:u8  len:u32 little-endian  payload:len bytes
//! ```
//!
//! The length is bounded before allocating so a broken or hostile peer cannot
//! make either side reserve gigabytes.

use std::io::{Read, Write};

/// Pipe name. User-only DACL is applied by the server side in the shell.
pub const PIPE_PATH: &str = r"\\.\pipe\kestrel-passkeys";

/// Upper bound for one CTAP2 message. The CTAP2 default `maxMsgSize` is 1024,
/// but the plugin ABI carries a whole CBOR request; 64 KiB is the same bound
/// the SDK pipe uses and leaves plenty of room while staying finite.
pub const MAX_FRAME: usize = 64 * 1024;

pub const OP_STATUS: u8 = 0;
pub const OP_MAKE_CREDENTIAL: u8 = 1;
pub const OP_GET_ASSERTION: u8 = 2;

pub const STATUS_OK: u8 = 0;
pub const STATUS_ERROR: u8 = 1;
pub const STATUS_LOCKED: u8 = 2;

#[derive(Debug)]
pub enum IpcError {
    /// The Kestrel process is not running or has not registered the plugin.
    Unavailable(String),
    Io(std::io::Error),
    /// A frame declared a length above [`MAX_FRAME`] or was truncated.
    BadFrame,
    /// The peer answered with a status this build does not understand.
    BadStatus(u8),
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpcError::Unavailable(why) => write!(f, "Kestrel is unavailable: {why}"),
            IpcError::Io(error) => write!(f, "pipe error: {error}"),
            IpcError::BadFrame => f.write_str("malformed passkey pipe frame"),
            IpcError::BadStatus(status) => write!(f, "unknown passkey pipe status {status}"),
        }
    }
}

impl std::error::Error for IpcError {}

impl From<std::io::Error> for IpcError {
    fn from(value: std::io::Error) -> Self {
        IpcError::Io(value)
    }
}

/// Build a request frame.
pub fn request(op: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_FRAME);
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(op);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

/// Build a response frame.
pub fn response(status: u8, payload: &[u8]) -> Vec<u8> {
    debug_assert!(payload.len() <= MAX_FRAME);
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(status);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(payload);
    out
}

fn header(bytes: &[u8]) -> Result<(u8, usize), IpcError> {
    if bytes.len() < 5 {
        return Err(IpcError::BadFrame);
    }
    let length = u32::from_le_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]) as usize;
    if length > MAX_FRAME {
        return Err(IpcError::BadFrame);
    }
    Ok((bytes[0], length))
}

/// Split a complete request/response frame.
pub fn parse_frame(bytes: &[u8]) -> Result<(u8, &[u8]), IpcError> {
    let (tag, length) = header(bytes)?;
    if bytes.len() != 5 + length {
        return Err(IpcError::BadFrame);
    }
    Ok((tag, &bytes[5..]))
}

fn read_exact(pipe: &mut std::fs::File, buffer: &mut [u8]) -> Result<(), IpcError> {
    pipe.read_exact(buffer)?;
    Ok(())
}

/// Send one operation to the Kestrel process and read its status plus payload.
///
/// Every byte read is bounded by [`MAX_FRAME`]; a short read is an error, not a
/// partially accepted message.
pub fn call(op: u8, payload: &[u8]) -> Result<(u8, Vec<u8>), IpcError> {
    if payload.len() > MAX_FRAME {
        return Err(IpcError::BadFrame);
    }
    let mut pipe = open_pipe()?;
    pipe.write_all(&request(op, payload))?;
    pipe.flush()?;

    let mut head = [0u8; 5];
    read_exact(&mut pipe, &mut head)?;
    let (status, length) = header(&head)?;
    let mut body = vec![0u8; length];
    read_exact(&mut pipe, &mut body)?;
    match status {
        STATUS_OK | STATUS_ERROR | STATUS_LOCKED => Ok((status, body)),
        other => Err(IpcError::BadStatus(other)),
    }
}

/// `CreateFile` on a named pipe returns `ERROR_PIPE_BUSY` (231) when the one
/// instance is serving another caller. Wait for it briefly instead of failing
/// the ceremony outright; two WebAuthn operations can be in flight while the
/// vault resolves one at a time.
fn open_pipe() -> Result<std::fs::File, IpcError> {
    const ERROR_PIPE_BUSY: i32 = 231;
    let mut last = None;
    for _ in 0..40 {
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(PIPE_PATH)
        {
            Ok(pipe) => return Ok(pipe),
            Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) => {
                last = Some(error.to_string());
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            Err(error) => return Err(IpcError::Unavailable(error.to_string())),
        }
    }
    Err(IpcError::Unavailable(
        last.unwrap_or_else(|| "pipe stayed busy".to_string()),
    ))
}

/// The `GetLockStatus` answer. Any failure to reach the process counts as
/// locked: an assertion must not be attempted against a vault we cannot see.
pub fn query_locked() -> bool {
    match call(OP_STATUS, &[]) {
        Ok((STATUS_OK, body)) => body.first() != Some(&0),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_round_trip_exact_bytes() {
        let frame = request(OP_MAKE_CREDENTIAL, &[0xaa, 0xbb]);
        assert_eq!(frame, vec![1, 2, 0, 0, 0, 0xaa, 0xbb]);
        assert_eq!(
            parse_frame(&frame).unwrap(),
            (OP_MAKE_CREDENTIAL, &[0xaa, 0xbb][..])
        );

        let reply = response(STATUS_LOCKED, &[]);
        assert_eq!(reply, vec![2, 0, 0, 0, 0]);
        assert_eq!(parse_frame(&reply).unwrap(), (STATUS_LOCKED, &[][..]));
    }

    #[test]
    fn malformed_frames_are_refused() {
        assert!(matches!(parse_frame(&[]), Err(IpcError::BadFrame)));
        assert!(matches!(
            parse_frame(&[1, 2, 0, 0, 0, 0xaa]),
            Err(IpcError::BadFrame)
        ));
        assert!(matches!(
            parse_frame(&[1, 0xff, 0xff, 0, 0]),
            Err(IpcError::BadFrame)
        ));
    }

    #[test]
    fn the_pipe_name_is_the_documented_one() {
        assert_eq!(PIPE_PATH, r"\\.\pipe\kestrel-passkeys");
    }
}
