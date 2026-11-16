//! Minimal definite-length CBOR (RFC 8949) used by CTAP2 and COSE.
//!
//! Only what CTAP2 needs is implemented: unsigned/negative integers, byte
//! strings, text strings, arrays, maps, booleans and null. Indefinite lengths,
//! tags and floating point are rejected rather than guessed at, because every
//! one of them would change the byte layout of a credential response.
//!
//! Encoding follows the CTAP2 canonical rule: map keys are sorted by encoded
//! length and then bytewise, so the same request always produces the same
//! bytes.

use std::fmt;

/// A decoded CBOR item.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    Uint(u64),
    /// A negative integer, stored as its mathematical value (-1, -7, …).
    NegInt(i64),
    Bytes(Vec<u8>),
    Text(String),
    Array(Vec<Value>),
    /// Insertion order is preserved while decoding; encoding re-sorts keys
    /// canonically, so a round trip through [`encode`] is deterministic.
    Map(Vec<(Value, Value)>),
    Bool(bool),
    Null,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CborError {
    /// Ran out of bytes in the middle of an item.
    UnexpectedEof,
    /// A major type or additional-information value this decoder does not
    /// implement (tags, indefinite lengths, floats, simple values).
    Unsupported(u8),
    /// A length prefix that does not fit the remaining input or the platform.
    BadLength,
    /// Bytes that are not valid UTF-8 inside a text string.
    BadText,
    /// Trailing bytes after the one item the caller asked for.
    TrailingBytes,
    /// Nesting deeper than [`MAX_DEPTH`].
    TooDeep,
}

impl fmt::Display for CborError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CborError::UnexpectedEof => f.write_str("truncated CBOR"),
            CborError::Unsupported(major) => write!(f, "unsupported CBOR item (major {major})"),
            CborError::BadLength => f.write_str("invalid CBOR length"),
            CborError::BadText => f.write_str("invalid UTF-8 in CBOR text"),
            CborError::TrailingBytes => f.write_str("trailing bytes after CBOR item"),
            CborError::TooDeep => f.write_str("CBOR nesting too deep"),
        }
    }
}

impl std::error::Error for CborError {}

/// Bounded nesting. A credential request is at most a handful of levels; this
/// stops a hostile 64 KiB request from recursing the stack.
pub const MAX_DEPTH: usize = 16;

/* ------------------------------------------------------------------ decode */

/// Decode exactly one item. Trailing bytes are an error, so a request cannot
/// smuggle a second message past the parser.
pub fn decode(input: &[u8]) -> Result<Value, CborError> {
    let mut cursor = Cursor { bytes: input, at: 0 };
    let value = cursor.item(0)?;
    if cursor.at != input.len() {
        return Err(CborError::TrailingBytes);
    }
    Ok(value)
}

struct Cursor<'a> {
    bytes: &'a [u8],
    at: usize,
}

impl Cursor<'_> {
    fn take(&mut self, len: usize) -> Result<&[u8], CborError> {
        let end = self.at.checked_add(len).ok_or(CborError::BadLength)?;
        if end > self.bytes.len() {
            return Err(CborError::UnexpectedEof);
        }
        let slice = &self.bytes[self.at..end];
        self.at = end;
        Ok(slice)
    }

    fn byte(&mut self) -> Result<u8, CborError> {
        Ok(self.take(1)?[0])
    }

    fn length(&mut self, info: u8) -> Result<usize, CborError> {
        let raw = match info {
            0..=23 => u64::from(info),
            24 => u64::from(self.byte()?),
            25 => {
                let bytes = self.take(2)?;
                u64::from(u16::from_be_bytes([bytes[0], bytes[1]]))
            }
            26 => {
                let bytes = self.take(4)?;
                u64::from(u32::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3],
                ]))
            }
            27 => {
                let bytes = self.take(8)?;
                u64::from_be_bytes([
                    bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                ])
            }
            31 => return Err(CborError::Unsupported(31)),
            other => return Err(CborError::Unsupported(other)),
        };
        usize::try_from(raw).map_err(|_| CborError::BadLength)
    }

    fn item(&mut self, depth: usize) -> Result<Value, CborError> {
        if depth > MAX_DEPTH {
            return Err(CborError::TooDeep);
        }
        let head = self.byte()?;
        let major = head >> 5;
        let info = head & 0x1f;
        match major {
            0 => Ok(Value::Uint(self.length(info)? as u64)),
            1 => {
                let magnitude = self.length(info)? as u64;
                let value = -1i128 - i128::from(magnitude);
                i64::try_from(value)
                    .map(Value::NegInt)
                    .map_err(|_| CborError::BadLength)
            }
            2 => {
                let len = self.length(info)?;
                Ok(Value::Bytes(self.take(len)?.to_vec()))
            }
            3 => {
                let len = self.length(info)?;
                let text =
                    std::str::from_utf8(self.take(len)?).map_err(|_| CborError::BadText)?;
                Ok(Value::Text(text.to_string()))
            }
            4 => {
                let len = self.length(info)?;
                // Every item is at least one byte; check before allocating a
                // vector sized by an attacker-controlled length.
                if len > self.bytes.len() - self.at {
                    return Err(CborError::BadLength);
                }
                let mut items = Vec::with_capacity(len);
                for _ in 0..len {
                    items.push(self.item(depth + 1)?);
                }
                Ok(Value::Array(items))
            }
            5 => {
                let len = self.length(info)?;
                if len > (self.bytes.len() - self.at) / 2 {
                    return Err(CborError::BadLength);
                }
                let mut pairs = Vec::with_capacity(len);
                for _ in 0..len {
                    let key = self.item(depth + 1)?;
                    let value = self.item(depth + 1)?;
                    pairs.push((key, value));
                }
                Ok(Value::Map(pairs))
            }
            6 => Err(CborError::Unsupported(6)),
            7 => match info {
                20 => Ok(Value::Bool(false)),
                21 => Ok(Value::Bool(true)),
                22 => Ok(Value::Null),
                other => Err(CborError::Unsupported(other)),
            },
            _ => unreachable!("major type is three bits"),
        }
    }
}

/* ------------------------------------------------------------------ encode */

/// Encode one item with canonical map ordering.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::new();
    write_value(value, &mut out);
    out
}

fn write_header(major: u8, value: u64, out: &mut Vec<u8>) {
    let major = major << 5;
    match value {
        0..=23 => out.push(major | value as u8),
        24..=0xff => {
            out.push(major | 24);
            out.push(value as u8);
        }
        0x100..=0xffff => {
            out.push(major | 25);
            out.extend_from_slice(&(value as u16).to_be_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(major | 26);
            out.extend_from_slice(&(value as u32).to_be_bytes());
        }
        _ => {
            out.push(major | 27);
            out.extend_from_slice(&value.to_be_bytes());
        }
    }
}

fn write_value(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Uint(number) => write_header(0, *number, out),
        Value::NegInt(number) => {
            debug_assert!(*number < 0);
            write_header(1, (-1 - i128::from(*number)) as u64, out);
        }
        Value::Bytes(bytes) => {
            write_header(2, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
        }
        Value::Text(text) => {
            write_header(3, text.len() as u64, out);
            out.extend_from_slice(text.as_bytes());
        }
        Value::Array(items) => {
            write_header(4, items.len() as u64, out);
            for item in items {
                write_value(item, out);
            }
        }
        Value::Map(pairs) => {
            // Canonical CBOR: sort by the encoded key, shorter first, then
            // bytewise. Sorting by the encoded bytes alone would order a
            // one-byte key after a two-byte key that starts with 0x00, so the
            // length is compared first.
            let mut encoded: Vec<(Vec<u8>, &Value)> = pairs
                .iter()
                .map(|(key, value)| {
                    let mut bytes = Vec::new();
                    write_value(key, &mut bytes);
                    (bytes, value)
                })
                .collect();
            encoded.sort_by(|left, right| {
                left.0
                    .len()
                    .cmp(&right.0.len())
                    .then_with(|| left.0.cmp(&right.0))
            });
            write_header(5, encoded.len() as u64, out);
            for (key_bytes, value) in encoded {
                out.extend_from_slice(&key_bytes);
                write_value(value, out);
            }
        }
        Value::Bool(true) => out.push(0xf5),
        Value::Bool(false) => out.push(0xf4),
        Value::Null => out.push(0xf6),
    }
}

/* ------------------------------------------------------------------ helpers */

impl Value {
    /// Look up an integer-keyed map entry (CTAP2 uses numeric keys).
    pub fn get(&self, key: i64) -> Option<&Value> {
        let Value::Map(pairs) = self else {
            return None;
        };
        pairs.iter().find_map(|(candidate, value)| match candidate {
            Value::Uint(number) if i64::try_from(*number).ok() == Some(key) => Some(value),
            Value::NegInt(number) if *number == key => Some(value),
            _ => None,
        })
    }

    /// Look up a text-keyed map entry (COSE and nested WebAuthn maps).
    pub fn get_text(&self, key: &str) -> Option<&Value> {
        let Value::Map(pairs) = self else {
            return None;
        };
        pairs.iter().find_map(|(candidate, value)| match candidate {
            Value::Text(candidate) if candidate == key => Some(value),
            _ => None,
        })
    }

    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(bytes) => Some(bytes),
            _ => None,
        }
    }

    pub fn as_text(&self) -> Option<&str> {
        match self {
            Value::Text(text) => Some(text),
            _ => None,
        }
    }

    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Uint(number) => i64::try_from(*number).ok(),
            Value::NegInt(number) => Some(*number),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(value) => Some(*value),
            _ => None,
        }
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(items) => Some(items),
            _ => None,
        }
    }

    pub fn as_map(&self) -> Option<&[(Value, Value)]> {
        match self {
            Value::Map(pairs) => Some(pairs),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integers_round_trip_at_every_width() {
        for number in [0u64, 23, 24, 255, 256, 65_535, 65_536, u64::from(u32::MAX)] {
            let encoded = encode(&Value::Uint(number));
            assert_eq!(decode(&encoded).unwrap(), Value::Uint(number), "{number}");
        }
        for number in [-1i64, -24, -25, -256, -257, -65_536, -65_537] {
            let encoded = encode(&Value::NegInt(number));
            assert_eq!(decode(&encoded).unwrap(), Value::NegInt(number), "{number}");
        }
    }

    #[test]
    fn exact_wire_bytes_for_small_items() {
        assert_eq!(encode(&Value::Uint(0)), vec![0x00]);
        assert_eq!(encode(&Value::Uint(23)), vec![0x17]);
        assert_eq!(encode(&Value::Uint(24)), vec![0x18, 0x18]);
        assert_eq!(encode(&Value::NegInt(-7)), vec![0x26]);
        assert_eq!(encode(&Value::Bytes(vec![1, 2, 3])), vec![0x43, 1, 2, 3]);
        assert_eq!(encode(&Value::Text("hi".into())), vec![0x62, b'h', b'i']);
        assert_eq!(encode(&Value::Bool(true)), vec![0xf5]);
        assert_eq!(encode(&Value::Null), vec![0xf6]);
        assert_eq!(
            encode(&Value::Array(vec![Value::Uint(1), Value::Uint(2)])),
            vec![0x82, 0x01, 0x02]
        );
    }

    #[test]
    fn maps_encode_canonically() {
        // Keys 1 (0x01), -1 (0x20), "a" (0x61 0x61): sorted by length then bytes.
        let map = Value::Map(vec![
            (Value::Text("a".into()), Value::Uint(3)),
            (Value::NegInt(-1), Value::Uint(2)),
            (Value::Uint(1), Value::Uint(1)),
        ]);
        assert_eq!(
            encode(&map),
            vec![0xa3, 0x01, 0x01, 0x20, 0x02, 0x61, 0x61, 0x03]
        );
    }

    #[test]
    fn malformed_cbor_is_refused() {
        // Truncated byte string.
        assert_eq!(decode(&[0x43, 1, 2]), Err(CborError::UnexpectedEof));
        // Indefinite-length byte string.
        assert_eq!(decode(&[0x5f, 0x41, 0x01, 0xff]), Err(CborError::Unsupported(31)));
        // Tag (major 6).
        assert_eq!(decode(&[0xc0, 0x01]), Err(CborError::Unsupported(6)));
        // Float16 (major 7, info 25).
        assert_eq!(decode(&[0xf9, 0x00, 0x00]), Err(CborError::Unsupported(25)));
        // Array length pointing past the end.
        assert_eq!(decode(&[0x85, 0x01]), Err(CborError::BadLength));
        // Two items where one was promised.
        assert_eq!(decode(&[0x01, 0x02]), Err(CborError::TrailingBytes));
        // Invalid UTF-8 text.
        assert_eq!(decode(&[0x61, 0xff]), Err(CborError::BadText));
        // Empty input.
        assert_eq!(decode(&[]), Err(CborError::UnexpectedEof));
    }

    #[test]
    fn deep_nesting_is_refused() {
        let mut bytes = vec![0x81; MAX_DEPTH + 2];
        bytes.push(0x00);
        assert_eq!(decode(&bytes), Err(CborError::TooDeep));
    }

    #[test]
    fn map_helpers_see_numeric_keys() {
        let value = decode(&[0xa2, 0x01, 0x18, 0x2a, 0x20, 0x61, b'x']).unwrap();
        assert_eq!(value.get(1).and_then(Value::as_int), Some(42));
        assert_eq!(value.get(-1).and_then(Value::as_text), Some("x"));
        assert_eq!(value.get(2), None);
    }
}
