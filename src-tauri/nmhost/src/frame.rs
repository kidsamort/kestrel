//! Native messaging framing.
//!
//! Chrome and Edge start a host and exchange messages as a 4-byte
//! **little-endian** length followed by that many UTF-8 bytes. The length is a
//! prefix, not a delimiter: a read on a pipe may return any number of bytes, so
//! the reader loops until the whole frame arrives.
//!
//! Two bounds matter:
//!
//! * A frame larger than [`MAX_MESSAGE`] is refused before its body is read.
//!   Allocating `length` bytes because a caller wrote a number is how a host
//!   becomes a memory amplifier.
//! * A zero-length frame is refused: there is no JSON object in it.
//!
//! On a clean end of input the reader returns `Ok(None)`; a truncated frame is
//! an error, because the extension died mid-message rather than closing.

use std::io::{ErrorKind, Read, Write};

/// 1 MiB. Chrome's documented limit for a message *from* a host is 1 MB; the
/// bridge never needs anything close, and using one bound for both directions
/// keeps the code honest.
pub const MAX_MESSAGE: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FrameError {
    #[error("message of {0} bytes exceeds the {MAX_MESSAGE}-byte limit")]
    TooLarge(usize),
    #[error("message length is zero")]
    Empty,
    #[error("message ended after {read} of {expected} bytes")]
    Truncated { read: usize, expected: usize },
    #[error("io error: {0}")]
    Io(String),
    #[error("json error: {0}")]
    Json(String),
}

impl From<std::io::Error> for FrameError {
    fn from(error: std::io::Error) -> FrameError {
        FrameError::Io(error.to_string())
    }
}

/// Read one frame. `Ok(None)` is a clean EOF at a message boundary.
pub fn read<R: Read>(reader: &mut R) -> Result<Option<Vec<u8>>, FrameError> {
    let mut prefix = [0u8; 4];
    let mut filled = 0usize;
    while filled < prefix.len() {
        match reader.read(&mut prefix[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(None);
                }
                return Err(FrameError::Truncated {
                    read: filled,
                    expected: prefix.len(),
                });
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    let length = u32::from_le_bytes(prefix) as usize;
    if length == 0 {
        return Err(FrameError::Empty);
    }
    if length > MAX_MESSAGE {
        return Err(FrameError::TooLarge(length));
    }
    let mut body = vec![0u8; length];
    let mut filled = 0usize;
    while filled < length {
        match reader.read(&mut body[filled..]) {
            Ok(0) => {
                return Err(FrameError::Truncated {
                    read: filled,
                    expected: length,
                })
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(error) => return Err(error.into()),
        }
    }
    Ok(Some(body))
}

/// Write one frame: length prefix, then the serialized JSON value.
pub fn write<W: Write>(writer: &mut W, value: &serde_json::Value) -> Result<(), FrameError> {
    let body = serde_json::to_vec(value).map_err(|error| FrameError::Json(error.to_string()))?;
    if body.len() > MAX_MESSAGE {
        return Err(FrameError::TooLarge(body.len()));
    }
    let length = (body.len() as u32).to_le_bytes();
    writer.write_all(&length)?;
    writer.write_all(&body)?;
    writer.flush()?;
    Ok(())
}

/// Write a prepared byte body. Used by tests; production always goes through
/// [`write`] so the prefix and the body cannot disagree.
#[cfg(test)]
pub fn write_bytes<W: Write>(writer: &mut W, body: &[u8]) -> Result<(), FrameError> {
    if body.len() > MAX_MESSAGE {
        return Err(FrameError::TooLarge(body.len()));
    }
    writer.write_all(&(body.len() as u32).to_le_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;

    /// A reader that yields one byte per call, so every loop in `read` has to
    /// handle a short read. A real pipe does this routinely.
    struct OneByte<'a> {
        bytes: &'a [u8],
        at: usize,
    }

    impl Read for OneByte<'_> {
        fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
            if self.at >= self.bytes.len() {
                return Ok(0);
            }
            buffer[0] = self.bytes[self.at];
            self.at += 1;
            Ok(1)
        }
    }

    #[test]
    fn the_prefix_is_four_little_endian_bytes() {
        let mut buffer = Vec::new();
        let value = json!({"op": "browser.items", "origin": "https://example.com"});
        write(&mut buffer, &value).expect("frame");
        let body = serde_json::to_vec(&value).unwrap();
        assert_eq!(&buffer[..4], &(body.len() as u32).to_le_bytes());
        assert_eq!(&buffer[4..], body.as_slice());
    }

    #[test]
    fn a_split_read_still_yields_the_whole_message() {
        let mut encoded = Vec::new();
        write_bytes(&mut encoded, br#"{"op":"browser.status"}"#).unwrap();
        let mut reader = OneByte {
            bytes: &encoded,
            at: 0,
        };
        let body = read(&mut reader).expect("frame").expect("a message");
        assert_eq!(body, br#"{"op":"browser.status"}"#);
        assert!(read(&mut reader).expect("clean eof").is_none());
    }

    #[test]
    fn two_messages_in_one_stream_are_two_frames() {
        let mut encoded = Vec::new();
        write_bytes(&mut encoded, b"{\"a\":1}").unwrap();
        write_bytes(&mut encoded, b"{\"b\":2}").unwrap();
        let mut cursor = Cursor::new(encoded);
        assert_eq!(read(&mut cursor).unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(read(&mut cursor).unwrap().unwrap(), b"{\"b\":2}");
        assert!(read(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn an_oversized_length_is_refused_before_the_body() {
        // Only the prefix exists: a reader that would block on the body must
        // never be asked for one.
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&((MAX_MESSAGE as u32) + 1).to_le_bytes());
        let mut cursor = Cursor::new(prefix);
        assert_eq!(
            read(&mut cursor),
            Err(FrameError::TooLarge(MAX_MESSAGE + 1))
        );
        assert_eq!(cursor.position(), 4, "the body was not read");
    }

    #[test]
    fn a_truncated_frame_is_an_error() {
        let mut encoded = Vec::new();
        write_bytes(&mut encoded, b"{\"op\":\"x\"}").unwrap();
        encoded.pop();
        let mut cursor = Cursor::new(encoded);
        assert_eq!(
            read(&mut cursor),
            Err(FrameError::Truncated {
                read: 9,
                expected: 10
            })
        );
    }

    #[test]
    fn zero_length_and_empty_input_are_different() {
        let mut zero = Cursor::new(0u32.to_le_bytes().to_vec());
        assert_eq!(read(&mut zero), Err(FrameError::Empty));
        let mut empty = Cursor::new(Vec::<u8>::new());
        assert_eq!(read(&mut empty), Ok(None));
    }
}
