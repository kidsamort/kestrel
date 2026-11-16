//! OpenSSH agent protocol, the subset Kestrel serves.
//!
//! Wire format is `draft-miller-ssh-agent`: a `u32` big-endian length followed
//! by a payload whose first byte is the message number. Only two requests are
//! answered — `REQUEST_IDENTITIES` (11) and `SIGN_REQUEST` (13) — which is all
//! `ssh`, `git` and `ssh-add` need. Everything else gets `SSH_AGENT_FAILURE`,
//! as the protocol requires for unknown messages.
//!
//! The module is transport-free on purpose: the handlers are pure functions of
//! (backend, request bytes), so the protocol can be tested without a pipe.

use std::fmt;

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;

/// Largest request frame accepted, `u32` length field included. A sign request
/// carries a key blob (~51 bytes) and the data to sign, which for git commit
/// signing is well under a kilobyte; 128 KiB leaves room for large payloads
/// without letting a client make the agent allocate unbounded memory.
pub const MAX_FRAME_LEN: usize = 128 * 1024;

/// `SIGN_REQUEST` flag asking for an `rsa-sha2-256` signature (RFC 8332 § 3).
/// Only RSA keys read these flags; the default when neither is set is SHA-256.
pub const SSH_AGENT_RSA_SHA2_256: u32 = 2;

/// `SIGN_REQUEST` flag asking for an `rsa-sha2-512` signature (RFC 8332 § 3).
pub const SSH_AGENT_RSA_SHA2_512: u32 = 4;

/// Why a backend could not answer. The wire has no distinct error code, so the
/// transport turns every variant into `SSH_AGENT_FAILURE`; the distinction is
/// for logging and for the settings card.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AgentError {
    /// The vault is locked: no session, so no key may be used.
    Locked,
    /// The vault could not be read (store error, uninitialised, ...).
    Unavailable,
}

/// One key as `IDENTITIES_ANSWER` presents it: the SSH public key blob exactly
/// as it is sent on the wire, plus a comment shown by `ssh-add -l`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentIdentity {
    pub key_blob: Vec<u8>,
    pub comment: String,
}

/// Everything the protocol layer needs from the vault. Implementations hold the
/// session; the handler never caches keys itself.
pub trait AgentBackend: Send + Sync {
    /// Keys currently offered, in a stable order.
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError>;

    /// Sign `data` with the key whose public blob equals `key_blob`. `Ok(None)`
    /// means "no such key" (the client gets `SSH_AGENT_FAILURE`); `flags` are
    /// the `SIGN_REQUEST` flags, which select the RSA hash and are ignored by
    /// key types that only have one signature algorithm.
    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Option<Vec<u8>>, AgentError>;
}

/// A frame length outside the accepted range. Either way the connection cannot
/// be resynchronised, so the caller answers `SSH_AGENT_FAILURE` and closes it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    Empty,
    TooLarge(usize),
}

impl fmt::Display for FrameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FrameError::Empty => write!(f, "empty agent frame"),
            FrameError::TooLarge(len) => write!(f, "agent frame of {len} bytes is too large"),
        }
    }
}

/// Validate the `u32` length prefix of a request.
pub fn frame_length(header: &[u8; 4]) -> Result<usize, FrameError> {
    let len = u32::from_be_bytes(*header) as usize;
    if len == 0 {
        return Err(FrameError::Empty);
    }
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    Ok(len)
}

/// Prefix `payload` with its big-endian `u32` length.
pub fn frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

/// The one-byte `SSH_AGENT_FAILURE`, framed.
pub fn failure() -> Vec<u8> {
    frame(&[SSH_AGENT_FAILURE])
}

/// Build the signature blob the agent protocol puts inside `SIGN_RESPONSE`:
/// the algorithm name and the raw signature as two SSH strings. `algorithm` is
/// the name the signature was produced under (`ssh-ed25519`,
/// `ecdsa-sha2-nistp256`, `rsa-sha2-256`, ...), and `signature` is already in
/// that algorithm's wire encoding (raw bytes for Ed25519/RSA, `mpint r, s` for
/// ECDSA).
pub fn signature_blob(algorithm: &str, signature: &[u8]) -> Vec<u8> {
    let mut w = Writer::new();
    w.string(algorithm.as_bytes());
    w.string(signature);
    w.finish()
}

/// Handle one request payload (without its length prefix) and return the framed
/// response ready to write back.
pub fn handle_request(backend: &dyn AgentBackend, request: &[u8]) -> Vec<u8> {
    let mut reader = Reader::new(request);
    match reader.u8() {
        // A well-formed identities request is exactly one byte. Trailing data
        // means the client and the agent disagree on the framing, so refuse.
        Some(SSH_AGENTC_REQUEST_IDENTITIES) if reader.is_empty() => identities_answer(backend),
        Some(SSH_AGENTC_SIGN_REQUEST) => {
            let parsed = (reader.string(), reader.string(), reader.u32());
            let (Some(key_blob), Some(data), Some(flags)) = parsed else {
                return failure();
            };
            if !reader.is_empty() {
                return failure();
            }
            match backend.sign(key_blob, data, flags) {
                Ok(Some(signature)) => {
                    let mut w = Writer::with_message(SSH_AGENT_SIGN_RESPONSE);
                    w.string(&signature);
                    frame(&w.finish())
                }
                _ => failure(),
            }
        }
        _ => failure(),
    }
}

fn identities_answer(backend: &dyn AgentBackend) -> Vec<u8> {
    let Ok(identities) = backend.identities() else {
        return failure();
    };
    let mut w = Writer::with_message(SSH_AGENT_IDENTITIES_ANSWER);
    // A vault cannot hold 4 billion keys; the cast is lossless in practice.
    w.u32(identities.len() as u32);
    for identity in &identities {
        w.string(&identity.key_blob);
        w.string(identity.comment.as_bytes());
    }
    frame(&w.finish())
}

/// Minimal SSH wire writer: bytes, `u32`, and length-prefixed strings.
struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Writer {
        Writer { buf: Vec::new() }
    }

    fn with_message(message: u8) -> Writer {
        let mut w = Writer::new();
        w.u8(message);
        w
    }

    fn u8(&mut self, value: u8) {
        self.buf.push(value);
    }

    fn u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_be_bytes());
    }

    fn string(&mut self, value: &[u8]) {
        self.u32(value.len() as u32);
        self.buf.extend_from_slice(value);
    }

    fn finish(self) -> Vec<u8> {
        self.buf
    }
}

/// Minimal SSH wire reader; `None` is a truncated field.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Reader<'a> {
        Reader { data, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.data.len()
    }

    fn u8(&mut self) -> Option<u8> {
        let byte = *self.data.get(self.pos)?;
        self.pos += 1;
        Some(byte)
    }

    fn u32(&mut self) -> Option<u32> {
        let end = self.pos.checked_add(4)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn string(&mut self) -> Option<&'a [u8]> {
        let len = self.u32()? as usize;
        let end = self.pos.checked_add(len)?;
        let bytes = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct FakeBackend {
        identities: Vec<AgentIdentity>,
        signature: Vec<u8>,
        error: Option<AgentError>,
        last_flags: std::sync::atomic::AtomicU32,
    }

    impl AgentBackend for FakeBackend {
        fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
            match self.error {
                Some(e) => Err(e),
                None => Ok(self.identities.clone()),
            }
        }

        fn sign(
            &self,
            key_blob: &[u8],
            data: &[u8],
            flags: u32,
        ) -> Result<Option<Vec<u8>>, AgentError> {
            self.last_flags.store(flags, std::sync::atomic::Ordering::Relaxed);
            if let Some(e) = self.error {
                return Err(e);
            }
            if self.identities.iter().any(|i| i.key_blob == key_blob) && data == b"payload" {
                Ok(Some(self.signature.clone()))
            } else {
                Ok(None)
            }
        }
    }

    fn key_blob() -> Vec<u8> {
        let mut w = Writer::new();
        w.string(b"ssh-ed25519");
        w.string(&[7u8; 32]);
        w.finish()
    }

    fn backend() -> FakeBackend {
        FakeBackend {
            identities: vec![AgentIdentity {
                key_blob: key_blob(),
                comment: "kestrel: test key".into(),
            }],
            signature: signature_blob("ssh-ed25519", &[9u8; 64]),
            ..FakeBackend::default()
        }
    }

    fn sign_request(key: &[u8], data: &[u8], flags: u32, trailing: &[u8]) -> Vec<u8> {
        let mut w = Writer::with_message(SSH_AGENTC_SIGN_REQUEST);
        w.string(key);
        w.string(data);
        w.u32(flags);
        for byte in trailing {
            w.u8(*byte);
        }
        w.finish()
    }

    fn payload(response: &[u8]) -> &[u8] {
        let len = u32::from_be_bytes([response[0], response[1], response[2], response[3]]) as usize;
        assert_eq!(len, response.len() - 4, "frame length must match body");
        &response[4..]
    }

    #[test]
    fn identities_round_trip() {
        let backend = backend();
        let response = handle_request(&backend, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        let body = payload(&response);
        let mut reader = Reader::new(body);
        assert_eq!(reader.u8(), Some(SSH_AGENT_IDENTITIES_ANSWER));
        assert_eq!(reader.u32(), Some(1));
        assert_eq!(reader.string(), Some(key_blob().as_slice()));
        assert_eq!(reader.string(), Some(b"kestrel: test key".as_slice()));
        assert!(reader.is_empty());
    }

    #[test]
    fn identities_answer_for_empty_vault_is_not_a_failure() {
        let backend = FakeBackend::default();
        let response = handle_request(&backend, &[SSH_AGENTC_REQUEST_IDENTITIES]);
        let body = payload(&response);
        assert_eq!(body[0], SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&body[1..], &[0, 0, 0, 0]);
    }

    #[test]
    fn sign_round_trip() {
        let backend = backend();
        let request = sign_request(&key_blob(), b"payload", 0x4, &[]);
        let response = handle_request(&backend, &request);
        let body = payload(&response);
        let mut reader = Reader::new(body);
        assert_eq!(reader.u8(), Some(SSH_AGENT_SIGN_RESPONSE));
        let blob = reader.string().expect("signature blob");
        assert!(reader.is_empty());
        assert_eq!(
            backend.last_flags.load(std::sync::atomic::Ordering::Relaxed),
            0x4
        );

        let mut inner = Reader::new(blob);
        assert_eq!(inner.string(), Some(b"ssh-ed25519".as_slice()));
        assert_eq!(inner.string(), Some([9u8; 64].as_slice()));
        assert!(inner.is_empty());
    }

    #[test]
    fn unknown_key_and_wrong_message_fail() {
        let backend = backend();
        let unknown_key = sign_request(b"not-a-key", b"payload", 0, &[]);
        assert_eq!(
            handle_request(&backend, &unknown_key),
            failure(),
            "unknown key must be a failure"
        );
        assert_eq!(
            handle_request(&backend, &[99]),
            failure(),
            "unknown message number must be a failure"
        );
        assert_eq!(
            handle_request(&backend, &[]),
            failure(),
            "empty request must be a failure"
        );
    }

    #[test]
    fn malformed_requests_fail() {
        let backend = backend();
        // Truncated: no data, no flags.
        let mut partial = Writer::with_message(SSH_AGENTC_SIGN_REQUEST);
        partial.string(&key_blob());
        assert_eq!(handle_request(&backend, &partial.finish()), failure());

        // Extra trailing bytes break framing.
        let trailing = sign_request(&key_blob(), b"payload", 0, &[0]);
        assert_eq!(handle_request(&backend, &trailing), failure());

        // Identities request with trailing junk.
        assert_eq!(
            handle_request(&backend, &[SSH_AGENTC_REQUEST_IDENTITIES, 0]),
            failure()
        );
    }

    #[test]
    fn locked_backend_fails_every_request() {
        let mut backend = backend();
        backend.error = Some(AgentError::Locked);
        assert_eq!(
            handle_request(&backend, &[SSH_AGENTC_REQUEST_IDENTITIES]),
            failure()
        );
        let request = sign_request(&key_blob(), b"payload", 0, &[]);
        assert_eq!(handle_request(&backend, &request), failure());
    }

    #[test]
    fn oversized_and_empty_frames_are_rejected() {
        assert_eq!(frame_length(&[0, 0, 0, 0]), Err(FrameError::Empty));
        let too_big = ((MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        assert_eq!(
            frame_length(&too_big),
            Err(FrameError::TooLarge(MAX_FRAME_LEN + 1))
        );
        assert_eq!(frame_length(&(MAX_FRAME_LEN as u32).to_be_bytes()), Ok(MAX_FRAME_LEN));
        assert_eq!(frame_length(&[0, 0, 0, 1]), Ok(1));
    }

    #[test]
    fn failure_frame_is_a_framed_single_byte() {
        assert_eq!(failure(), vec![0, 0, 0, 1, SSH_AGENT_FAILURE]);
    }
}
