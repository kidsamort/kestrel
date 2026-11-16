//! Lowercase hex, the only encoding the engine needs beyond JSON.
//!
//! `PROTOCOL.md` carries ciphertext as lowercase hex and the engine stores the
//! sealed bodies the store gives it as opaque bytes. The workspace keeps `hex`
//! out of this crate's dependency list on purpose — the engine is the seam
//! between the vault and the wire, not a general-purpose toolkit — so the two
//! functions live here and are tested directly.

use crate::error::EngineError;

const DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Lowercase hex, two characters per byte.
pub(crate) fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(char::from(DIGITS[usize::from(byte >> 4)]));
        out.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    out
}

/// Decode lowercase or uppercase hex.
///
/// An odd length or a non-hex character is [`EngineError::Hex`]; nothing is
/// skipped and no partial value is returned, because a truncated ciphertext
/// would only fail later as an authentication error with a misleading cause.
pub(crate) fn decode(text: &str) -> Result<Vec<u8>, EngineError> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(2) {
        let len = bytes.len();
        return Err(EngineError::Hex(format!(
            "odd number of digits in {len} characters"
        )));
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let high = digit(pair[0]).ok_or_else(|| EngineError::Hex(non_hex(text)))?;
        let low = digit(pair[1]).ok_or_else(|| EngineError::Hex(non_hex(text)))?;
        out.push((high << 4) | low);
    }
    Ok(out)
}

fn non_hex(text: &str) -> String {
    // The text is a ciphertext or an id; it is safe to quote and short enough
    // to be useful, but cap it so a corrupt megabyte does not become a message.
    let shown: String = text.chars().take(48).collect();
    format!("{shown:?} is not hex")
}

fn digit(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_and_normalises_case() {
        assert_eq!(encode(&[0x00, 0x0f, 0xa5, 0xff]), "000fa5ff");
        assert_eq!(decode("000fa5ff").expect("lowercase"), vec![0, 15, 165, 255]);
        assert_eq!(decode("000FA5FF").expect("uppercase"), vec![0, 15, 165, 255]);
        assert!(decode("").expect("empty is empty").is_empty());
    }

    #[test]
    fn rejects_odd_and_non_hex_input() {
        assert!(matches!(decode("abc"), Err(EngineError::Hex(_))));
        assert!(matches!(decode("zz"), Err(EngineError::Hex(_))));
        assert!(matches!(decode("00 00"), Err(EngineError::Hex(_))));
    }
}
