//! SSH agent: serve Ed25519, RSA and ECDSA keys from the unlocked vault over
//! the OpenSSH agent protocol, without ever exporting the key material.
//!
//! `ssh` and `git` reach the agent through one platform endpoint: the named
//! pipe `\\.\pipe\openssh-ssh-agent` on Windows, a user-private Unix domain
//! socket elsewhere. `transport.rs` owns the accept loop and framing behind the
//! [`transport::Listener`] / [`transport::Stream`] traits, `pipe.rs` implements
//! the Windows pipe with its user-only ACL, `protocol.rs` owns the message
//! format, and this module is the bridge to the vault:
//!
//! * keys are read through [`VaultState`] on every request, so the agent stops
//!   answering the moment the vault locks and never holds a key of its own;
//! * only `sshKey` items with a parseable, unencrypted Ed25519, RSA or ECDSA
//!   private key in the `sshPrivateKey` field are served — everything else is
//!   skipped and reported on the settings card instead of guessed at;
//! * RSA signatures follow the hash the client names in `SIGN_REQUEST`
//!   (`rsa-sha2-256` unless it asks for `rsa-sha2-512`), while the identity is
//!   always the `ssh-rsa` public blob;
//! * an item the user turned off for the agent is filtered out before it is
//!   offered, using the `agent_keys` policy table in the same vault database;
//! * the endpoint starts with the app and is stopped on exit.

#[cfg(windows)]
pub mod pipe;
pub mod protocol;
pub mod transport;

use kestrel_core::model::Item;
use kestrel_core::session::{VaultError, VaultState};
use kestrel_core::store::Store;
use protocol::{AgentBackend, AgentError, AgentIdentity};
use rsa::sha2::{Digest as _, Sha256, Sha512};
use serde::Serialize;
use signature::Signer as _;
use ssh_key::{Algorithm, HashAlg, PrivateKey};
use std::sync::{Arc, Mutex};
use tauri::{AppHandle, Manager, State};

/// Field whose value holds the OpenSSH-format private key.
pub const PRIVATE_KEY_FIELD: &str = "sshPrivateKey";

/// Skipped-key reason for an item the user turned off for the agent.
pub const NOT_SERVED_REASON: &str = "turned off for the SSH agent";

/// One item the agent refuses to serve, with the reason shown in Settings.
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SkippedKey {
    pub title: String,
    pub reason: String,
}

/// Snapshot for `agent_status`.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentStatus {
    /// The endpoint exists and the accept loop is running.
    pub running: bool,
    /// The path clients connect to: the named pipe on Windows, the Unix
    /// domain socket elsewhere. The settings card shows this verbatim.
    pub pipe: String,
    /// Keys that would currently be offered (zero while locked).
    pub key_count: usize,
    pub locked: bool,
    /// `sshKey` items that are not servable, with why.
    pub skipped: Vec<SkippedKey>,
    /// Why the agent is not serving: another process owns the endpoint, or the
    /// key policy could not be read.
    pub error: Option<String>,
}

/// A parsed key plus the identity bytes the protocol presents for it.
struct AgentKey {
    identity: AgentIdentity,
    key: PrivateKey,
}

struct KeySet {
    keys: Vec<AgentKey>,
    skipped: Vec<SkippedKey>,
}

/// Where the live session comes from. Production uses Tauri's managed
/// `VaultState`; tests point at a scratch vault directly so no app is needed.
enum VaultSource {
    App(AppHandle),
    #[cfg(test)]
    Direct(Arc<VaultState>),
}

impl VaultSource {
    fn read<T>(&self, read: impl FnOnce(&VaultState) -> T) -> T {
        match self {
            VaultSource::App(app) => read(app.state::<VaultState>().inner()),
            #[cfg(test)]
            VaultSource::Direct(state) => read(state),
        }
    }
}

/// The protocol backend. It holds no keys: each request re-reads the vault,
/// which is what makes locking the vault immediately revoke the agent.
struct VaultBackend {
    source: VaultSource,
}

impl AgentBackend for VaultBackend {
    fn identities(&self) -> Result<Vec<AgentIdentity>, AgentError> {
        let keys = self.source.read(load_keys)?;
        Ok(keys.keys.into_iter().map(|key| key.identity).collect())
    }

    fn sign(
        &self,
        key_blob: &[u8],
        data: &[u8],
        flags: u32,
    ) -> Result<Option<Vec<u8>>, AgentError> {
        let keys = self.source.read(load_keys)?;
        let Some(found) = keys
            .keys
            .iter()
            .find(|candidate| candidate.identity.key_blob == key_blob)
        else {
            return Ok(None);
        };
        Ok(signature(&found.key, data, flags)
            .map(|(algorithm, bytes)| protocol::signature_blob(algorithm.as_str(), &bytes)))
    }
}

/// Owns the agent listener for the process lifetime.
pub struct AgentHandle {
    server: Mutex<Option<transport::Server>>,
    startup_error: Mutex<Option<String>>,
}

impl AgentHandle {
    /// Start the agent against the app's managed session.
    pub fn start(app: &AppHandle) -> AgentHandle {
        Self::launch(Arc::new(VaultBackend {
            source: VaultSource::App(app.clone()),
        }))
    }

    #[cfg(test)]
    fn start_with_vault(state: Arc<VaultState>) -> AgentHandle {
        Self::launch(Arc::new(VaultBackend {
            source: VaultSource::Direct(state),
        }))
    }

    fn launch(backend: Arc<VaultBackend>) -> AgentHandle {
        let (server, error) = match transport::Server::start(backend) {
            Ok(server) => (Some(server), None),
            Err(error) => (None, Some(error.to_string())),
        };
        AgentHandle {
            server: Mutex::new(server),
            startup_error: Mutex::new(error),
        }
    }

    /// Stop the endpoint and wait for its threads. Idempotent.
    pub fn stop(&self) {
        let server = self.server.lock().expect("agent server mutex").take();
        if let Some(server) = server {
            server.stop();
        }
    }

    /// State plus a live key scan. Never returns key material.
    pub fn status(&self, state: &VaultState) -> AgentStatus {
        let server = self.server.lock().expect("agent server mutex");
        let running = server.is_some();
        // The path clients must use: the bound endpoint when the agent is
        // serving, otherwise the one this platform would have claimed.
        let pipe = server
            .as_ref()
            .map(transport::Server::path)
            .unwrap_or_else(transport::agent_path)
            .display()
            .to_string();
        drop(server);
        let mut status = AgentStatus {
            running,
            pipe,
            key_count: 0,
            locked: true,
            skipped: Vec::new(),
            error: self
                .startup_error
                .lock()
                .expect("agent error mutex")
                .clone(),
        };
        match load_keys(state) {
            Ok(keys) => {
                status.key_count = keys.keys.len();
                status.skipped = keys.skipped;
                status.locked = false;
            }
            // An expired or locked session is the documented idle state.
            Err(AgentError::Locked) => {}
            // Anything else means the agent cannot read its own policy, and
            // that must be visible instead of looking like an empty vault.
            Err(AgentError::Unavailable) => {
                if status.error.is_none() {
                    status.error = Some("the SSH agent could not read its key policy".to_string());
                }
            }
        }
        status
    }
}

/// `agent_status` command: the endpoint path clients use, whether it is
/// serving, and how many keys the unlocked vault currently offers.
#[tauri::command]
pub fn agent_status(state: State<'_, VaultState>, agent: State<'_, AgentHandle>) -> AgentStatus {
    agent.status(state.inner())
}

/* ------------------------------------------------------------------- vault */

fn load_keys(state: &VaultState) -> Result<KeySet, AgentError> {
    // The core watchdog runs every five seconds; checking here as well means a
    // session that expired a moment ago can never sign one last time.
    if state.maybe_autolock().map_err(map_error)? {
        return Err(AgentError::Locked);
    }
    // Quiet read: the pipe must not extend the idle timer, or any client that
    // polls the agent would keep the vault unlocked forever.
    let items = state.ssh_items_quiet().map_err(map_error)?;
    // The "not served" toggle lives in the vault database, so the agent opens
    // its own connection to it — the same second-connection arrangement the
    // autofill rules use, and the session API stays untouched. Reopening per
    // request keeps the flag live and keeps a previous vault's policy from
    // applying after a vault switch. A failed read refuses the request: the
    // point of the table is that a disabled key never leaves the agent, so
    // guessing "served" on error would defeat it.
    let path = state.vault_path();
    if path.as_os_str().is_empty() {
        return Err(AgentError::Unavailable);
    }
    let store = Store::open(path).map_err(|_| AgentError::Unavailable)?;
    let mut keys = Vec::new();
    let mut skipped = Vec::new();
    for item in items {
        let served = store
            .agent_served(&item.id)
            .map_err(|_| AgentError::Unavailable)?;
        if !served {
            skipped.push(SkippedKey {
                title: item.title,
                reason: NOT_SERVED_REASON.to_string(),
            });
            continue;
        }
        match key_from_item(&item) {
            Ok(key) => keys.push(key),
            // A key this build cannot use is reported, never guessed at.
            Err(reason) => skipped.push(SkippedKey {
                title: item.title,
                reason,
            }),
        }
    }
    Ok(KeySet { keys, skipped })
}

/// Whether the agent knows how to sign with `algorithm`.
fn servable(algorithm: &Algorithm) -> bool {
    matches!(
        algorithm,
        Algorithm::Ed25519 | Algorithm::Ecdsa { .. } | Algorithm::Rsa { .. }
    )
}

fn key_from_item(item: &Item) -> Result<AgentKey, String> {
    let field = item
        .fields
        .iter()
        .find(|field| field.kind == PRIVATE_KEY_FIELD)
        .ok_or_else(|| format!("no {PRIVATE_KEY_FIELD} field"))?;
    let text = field.value.trim();
    if text.is_empty() {
        return Err("the private key field is empty".into());
    }
    let key =
        PrivateKey::from_openssh(text).map_err(|_| "not an OpenSSH private key".to_string())?;
    if key.is_encrypted() {
        return Err("passphrase-protected keys cannot be served".into());
    }
    let algorithm = key.algorithm();
    if !servable(&algorithm) {
        return Err(format!(
            "{} keys are not supported; the agent serves Ed25519, RSA and ECDSA",
            algorithm.as_str()
        ));
    }
    let key_blob = key
        .public_key()
        .to_bytes()
        .map_err(|error| format!("could not encode the public key: {error}"))?;
    let comment = if item.title.trim().is_empty() {
        key.fingerprint(HashAlg::Sha256).to_string()
    } else {
        item.title.clone()
    };
    Ok(AgentKey {
        identity: AgentIdentity { key_blob, comment },
        key,
    })
}

/// Signature over the agent's `data` field, plus the algorithm the response
/// must advertise. RSA has two algorithms and the client chooses between them
/// with the request flags; Ed25519 and ECDSA keys have exactly one and ignore
/// the flags.
fn signature(key: &PrivateKey, data: &[u8], flags: u32) -> Option<(Algorithm, Vec<u8>)> {
    match key.algorithm() {
        Algorithm::Rsa { .. } => {
            let pair = key.key_data().rsa()?;
            let private = rsa_private_key(pair)?;
            let hash = rsa_hash(flags);
            // `rsa-sha2-*` is RSASSA-PKCS1-v1_5 over the named digest, and
            // `Pkcs1v15Sign` expects that digest rather than the message. The
            // private-key operation is blinded with a fresh RNG because a local
            // client chooses the payload, and unblinded operations leak timing.
            let digest = match hash {
                HashAlg::Sha256 => Sha256::digest(data).to_vec(),
                HashAlg::Sha512 => Sha512::digest(data).to_vec(),
                // `HashAlg` is `#[non_exhaustive]`; `rsa_hash` yields only the
                // two RSA hashes above.
                _ => return None,
            };
            let padding = match hash {
                HashAlg::Sha256 => rsa::Pkcs1v15Sign::new::<Sha256>(),
                HashAlg::Sha512 => rsa::Pkcs1v15Sign::new::<Sha512>(),
                _ => return None,
            };
            let mut rng = ssh_key::rand_core::OsRng;
            let bytes = private.sign_with_rng(&mut rng, padding, &digest).ok()?;
            Some((Algorithm::Rsa { hash: Some(hash) }, bytes))
        }
        // `ssh-key` produces the algorithm-tagged signature for the key type,
        // including the `mpint r, s` encoding ECDSA needs on the wire.
        _ => key
            .try_sign(data)
            .ok()
            .map(|signature| (signature.algorithm(), signature.as_bytes().to_vec())),
    }
}

/// `rsa-sha2-256` unless the client explicitly asks for `rsa-sha2-512`. A
/// client setting both (or a flag we do not know) gets the safe default, which
/// is also what RFC 8332 asks of an agent that sees no hash choice.
fn rsa_hash(flags: u32) -> HashAlg {
    match flags & (protocol::SSH_AGENT_RSA_SHA2_256 | protocol::SSH_AGENT_RSA_SHA2_512) {
        protocol::SSH_AGENT_RSA_SHA2_512 => HashAlg::Sha512,
        _ => HashAlg::Sha256,
    }
}

/// Rebuild the `rsa` crate's private key from the OpenSSH components.
///
/// `ssh-key` 0.6.7's own `TryFrom<&RsaKeypair>` passes `p` where `q` belongs,
/// which fails the crate's component validation, so the key is assembled from
/// the modulus and both primes directly.
fn rsa_private_key(pair: &ssh_key::private::RsaKeypair) -> Option<rsa::RsaPrivateKey> {
    fn big(mpint: &ssh_key::Mpint) -> Option<rsa::BigUint> {
        mpint.as_positive_bytes().map(rsa::BigUint::from_bytes_be)
    }
    rsa::RsaPrivateKey::from_components(
        big(&pair.public.n)?,
        big(&pair.public.e)?,
        big(&pair.private.d)?,
        vec![big(&pair.private.p)?, big(&pair.private.q)?],
    )
    .ok()
}

fn map_error(error: VaultError) -> AgentError {
    match error {
        VaultError::Locked => AgentError::Locked,
        _ => AgentError::Unavailable,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kestrel_core::model::Category;
    use ssh_key::EcdsaCurve;
    use std::io::{Read, Write};
    #[cfg(windows)]
    use std::os::windows::io::AsRawHandle;
    use std::path::PathBuf;

    const PASSWORD: &str = "correct horse battery staple";

    fn scratch_vault(tag: &str) -> (Arc<VaultState>, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-agent-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let state = VaultState::open(dir.join("kestrel.db")).expect("vault opens");
        state.create(PASSWORD).expect("vault created");
        (Arc::new(state), dir)
    }

    fn new_ed25519() -> PrivateKey {
        PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).expect("key")
    }

    /// A 2048-bit key keeps the test quick; `PrivateKey::random` would generate
    /// the 4096-bit default.
    fn new_rsa() -> PrivateKey {
        let pair = ssh_key::private::RsaKeypair::random(&mut ssh_key::rand_core::OsRng, 2048)
            .expect("rsa keypair");
        PrivateKey::from(pair)
    }

    fn backend(state: &Arc<VaultState>) -> VaultBackend {
        VaultBackend {
            source: VaultSource::Direct(Arc::clone(state)),
        }
    }

    fn status_of(state: &VaultState) -> AgentStatus {
        AgentHandle {
            server: Mutex::new(None),
            startup_error: Mutex::new(None),
        }
        .status(state)
    }

    /// Store an `sshKey` item and return the id the agent policy table uses.
    fn add_key(state: &VaultState, title: &str, key: &PrivateKey) -> String {
        let mut item = Item::new(Category::SshKey, title.to_string());
        let field = item
            .fields
            .iter_mut()
            .find(|field| field.kind == PRIVATE_KEY_FIELD)
            .expect("ssh key category has a private key field");
        field.value = key
            .to_openssh(ssh_key::LineEnding::LF)
            .expect("openssh encoding")
            .to_string();
        state.save(item).expect("item saved").id
    }

    fn push_string(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u32).to_be_bytes());
        out.extend_from_slice(value);
    }

    fn sign_request(key_blob: &[u8], data: &[u8]) -> Vec<u8> {
        let mut body = vec![protocol::SSH_AGENTC_SIGN_REQUEST];
        push_string(&mut body, key_blob);
        push_string(&mut body, data);
        body.extend_from_slice(&0u32.to_be_bytes());
        protocol::frame(&body)
    }

    /// Read one framed response off the pipe.
    fn read_frame(stream: &mut std::fs::File) -> Vec<u8> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).expect("response header");
        let len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("response body");
        body
    }

    fn read_string(body: &[u8], offset: &mut usize) -> Vec<u8> {
        let len = u32::from_be_bytes([
            body[*offset],
            body[*offset + 1],
            body[*offset + 2],
            body[*offset + 3],
        ]) as usize;
        *offset += 4;
        let value = body[*offset..*offset + len].to_vec();
        *offset += len;
        value
    }

    /// Send a `SIGN_REQUEST` through the protocol handler and return the
    /// signature blob, so the flags travel the same path a real client uses.
    fn sign_over_wire(
        backend: &VaultBackend,
        key: &PrivateKey,
        data: &[u8],
        flags: u32,
    ) -> Vec<u8> {
        let mut body = vec![protocol::SSH_AGENTC_SIGN_REQUEST];
        push_string(&mut body, &key.public_key().to_bytes().expect("blob"));
        push_string(&mut body, data);
        body.extend_from_slice(&flags.to_be_bytes());

        let framed = protocol::handle_request(backend, &body);
        let body = &framed[4..];
        assert_eq!(
            body[0],
            protocol::SSH_AGENT_SIGN_RESPONSE,
            "the agent must answer a sign request"
        );
        let mut offset = 1;
        read_string(body, &mut offset)
    }

    /// Algorithm name from a signature blob, after checking the blob is exactly
    /// `string(algorithm) string(signature)`.
    fn signature_algorithm(blob: &[u8]) -> String {
        let mut offset = 0;
        let algorithm = String::from_utf8(read_string(blob, &mut offset)).expect("utf8 algorithm");
        let _ = read_string(blob, &mut offset);
        assert_eq!(offset, blob.len(), "signature blob has exactly two strings");
        algorithm
    }

    /// Verify a complete signature blob against the public half of `key` with
    /// `ssh-key`'s own verifier, so the algorithm name and the digest must
    /// agree with the bytes that were signed. The call is fully qualified
    /// because `PublicKey` also has an inherent `verify` for SSH signatures.
    fn verify(key: &PrivateKey, data: &[u8], blob: &[u8]) {
        let signature = ssh_key::Signature::try_from(blob).expect("signature blob decodes");
        signature::Verifier::verify(key.public_key(), data, &signature)
            .expect("signature verifies against the public key");
    }

    #[test]
    fn encrypted_keys_are_reported_not_guessed() {
        let (state, dir) = scratch_vault("skips");
        let good = new_ed25519();
        add_key(&state, "served key", &good);
        let encrypted = new_ed25519()
            .encrypt(&mut ssh_key::rand_core::OsRng, "hunter2")
            .expect("encrypted key");
        add_key(&state, "protected key", &encrypted);

        let backend = backend(&state);
        let identities = backend.identities().expect("identities");
        assert_eq!(identities.len(), 1, "only the plain key is served");
        assert_eq!(
            identities[0].key_blob,
            good.public_key().to_bytes().unwrap()
        );
        assert_eq!(identities[0].comment, "served key");

        let status = status_of(&state);
        assert!(!status.running, "no pipe was started for this test");
        assert_eq!(status.key_count, 1);
        assert!(!status.locked);
        assert_eq!(status.skipped.len(), 1);
        assert_eq!(status.skipped[0].title, "protected key");
        assert!(status.skipped[0].reason.contains("passphrase"));
        assert!(
            !status.skipped[0].reason.contains("Ed25519"),
            "the refusal must not blame the now-supported key type: {}",
            status.skipped[0].reason
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn signing_needs_an_unlocked_vault() {
        let (state, dir) = scratch_vault("locked");
        let key = new_ed25519();
        add_key(&state, "signing key", &key);
        let backend = backend(&state);
        let blob = key.public_key().to_bytes().expect("blob");

        let signature_blob = backend
            .sign(&blob, b"commit payload", 0)
            .expect("sign")
            .expect("known key signs");
        // The blob is `string("ssh-ed25519") string(signature)`.
        let mut offset = 0;
        assert_eq!(
            read_string(&signature_blob, &mut offset),
            b"ssh-ed25519".to_vec()
        );
        let raw = read_string(&signature_blob, &mut offset);
        assert_eq!(raw.len(), 64);
        assert_eq!(offset, signature_blob.len());
        verify(&key, b"commit payload", &signature_blob);

        state.lock().expect("lock");
        assert_eq!(
            backend.identities(),
            Err(AgentError::Locked),
            "a locked vault must not even list keys"
        );
        assert_eq!(
            backend.sign(&blob, b"commit payload", 0),
            Err(AgentError::Locked)
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn rsa_keys_sign_with_the_hash_the_client_asked_for() {
        let (state, dir) = scratch_vault("rsa");
        let key = new_rsa();
        add_key(&state, "rsa key", &key);
        let backend = backend(&state);

        let identities = backend.identities().expect("identities");
        assert_eq!(identities.len(), 1, "a plain RSA key must be served");
        // The identity stays `ssh-rsa`, whatever hash the client picks.
        let mut offset = 0;
        assert_eq!(
            read_string(&identities[0].key_blob, &mut offset),
            b"ssh-rsa".to_vec()
        );
        assert_eq!(identities[0].comment, "rsa key");

        let cases = [
            (0, "rsa-sha2-256"), // RFC 8332: SHA-256 when the client names none
            (protocol::SSH_AGENT_RSA_SHA2_256, "rsa-sha2-256"),
            (protocol::SSH_AGENT_RSA_SHA2_512, "rsa-sha2-512"),
        ];
        for (flags, expected) in cases {
            let blob = sign_over_wire(&backend, &key, b"rsa payload", flags);
            assert_eq!(
                signature_algorithm(&blob),
                expected,
                "flags {flags:#x} must select {expected}"
            );
            verify(&key, b"rsa payload", &blob);
        }

        // The signature covers `data`, not a fixed digest: another payload
        // must not verify under the same key.
        let blob = sign_over_wire(&backend, &key, b"rsa payload", 0);
        let signature = ssh_key::Signature::try_from(blob.as_slice()).expect("signature decodes");
        assert!(
            signature::Verifier::verify(key.public_key(), b"other payload", &signature).is_err(),
            "a signature for another payload must not verify"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn ecdsa_keys_sign_on_every_enabled_curve() {
        let (state, dir) = scratch_vault("ecdsa");
        let mut keys = Vec::new();
        for curve in [
            EcdsaCurve::NistP256,
            EcdsaCurve::NistP384,
            EcdsaCurve::NistP521,
        ] {
            let key =
                PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ecdsa { curve })
                    .expect("ecdsa key");
            add_key(&state, &format!("ecdsa {}", curve.as_str()), &key);
            keys.push((key, format!("ecdsa-sha2-{}", curve.as_str())));
        }
        let backend = backend(&state);
        assert_eq!(backend.identities().expect("identities").len(), 3);

        for (index, (key, algorithm)) in keys.iter().enumerate() {
            // RSA flags must not change an ECDSA signature algorithm.
            let flags = if index == 1 {
                protocol::SSH_AGENT_RSA_SHA2_512
            } else {
                0
            };
            let blob = sign_over_wire(&backend, key, b"ecdsa payload", flags);
            assert_eq!(signature_algorithm(&blob), *algorithm);
            verify(key, b"ecdsa payload", &blob);
        }

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_key_turned_off_is_neither_listed_nor_used() {
        let (state, dir) = scratch_vault("served");
        let hidden = new_ed25519();
        let shown = new_ed25519();
        let hidden_id = add_key(&state, "hidden key", &hidden);
        add_key(&state, "shown key", &shown);

        let store = Store::open(state.vault_path()).expect("policy store");
        assert!(
            store.agent_served(&hidden_id).expect("default"),
            "a key without a row is served"
        );
        store
            .set_agent_served(&hidden_id, false)
            .expect("turn the key off");

        let backend = backend(&state);
        let identities = backend.identities().expect("identities");
        assert_eq!(identities.len(), 1, "the disabled key must not be listed");
        assert_eq!(
            identities[0].key_blob,
            shown.public_key().to_bytes().expect("blob")
        );

        let hidden_blob = hidden.public_key().to_bytes().expect("blob");
        assert_eq!(
            backend.sign(&hidden_blob, b"payload", 0),
            Ok(None),
            "the disabled key must not sign even when the client knows its blob"
        );

        let status = status_of(&state);
        assert_eq!(status.key_count, 1);
        assert!(
            status.skipped.contains(&SkippedKey {
                title: "hidden key".to_string(),
                reason: NOT_SERVED_REASON.to_string(),
            }),
            "the settings card must say why the key is not offered: {:?}",
            status.skipped
        );

        store
            .set_agent_served(&hidden_id, true)
            .expect("turn the key back on");
        assert_eq!(
            backend.identities().expect("identities").len(),
            2,
            "turning the key back on must restore it without a restart"
        );
        assert!(status_of(&state).skipped.is_empty());

        let _ = std::fs::remove_dir_all(dir);
    }

    /// End-to-end over the real pipe: start the agent, connect as a client,
    /// inspect the DACL the kernel applied, then list, sign, fail an unknown
    /// message, exceed the frame cap, and confirm locking revokes the agent.
    ///
    /// Skips (rather than fails) when the pipe belongs to someone else — e.g.
    /// the OpenSSH agent service is running on this machine.
    ///
    /// Windows-only: the DACL assertion and `ssh-add`'s default endpoint are
    /// both properties of the named-pipe transport. The Unix socket has its
    /// own tests in `transport.rs`.
    #[cfg(windows)]
    #[test]
    fn live_agent_pipe_end_to_end() {
        let (state, dir) = scratch_vault("live");
        let key = new_ed25519();
        add_key(&state, "live test key", &key);
        let handle = AgentHandle::start_with_vault(Arc::clone(&state));
        let status = handle.status(&state);
        if !status.running {
            let reason = status.error.unwrap_or_default();
            assert!(
                reason.contains("already owned"),
                "agent must start unless another process owns the pipe: {reason}"
            );
            eprintln!("skipping live agent test: {reason}");
            let _ = std::fs::remove_dir_all(dir);
            return;
        }
        assert_eq!(status.key_count, 1);
        assert_eq!(status.pipe, pipe::PIPE_PATH);

        let mut client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe::PIPE_PATH)
            .expect("connect to the agent pipe");

        // The ACL the kernel actually stored: one ACE, current user only.
        let dacl = pipe::dacl_sddl(client.as_raw_handle()).expect("dacl");
        let sid = pipe::current_user_sid_for_test().expect("user sid");
        assert!(dacl.starts_with("D:P"), "DACL must be protected: {dacl}");
        assert_eq!(dacl.matches('(').count(), 1, "exactly one ACE: {dacl}");
        assert!(dacl.contains(&sid), "ACE must name the user: {dacl}");
        assert!(!dacl.contains(";;;WD"), "Everyone must not appear: {dacl}");
        assert!(!dacl.contains(";;;BU"), "Users must not appear: {dacl}");

        // External client check: the real OpenSSH `ssh-add` speaks our pipe.
        // `SSH_AUTH_SOCK` is removed so it falls back to the Windows default
        // pipe, which is exactly the one under test.
        match std::process::Command::new("ssh-add")
            .arg("-l")
            .env_remove("SSH_AUTH_SOCK")
            .output()
        {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    output.status.success(),
                    "ssh-add -l failed ({:?}): {stdout}{stderr}",
                    output.status
                );
                assert!(
                    stdout.contains("live test key"),
                    "ssh-add -l did not list the vault key: {stdout}"
                );
                eprintln!("ssh-add -l output: {}", stdout.trim());
            }
            Err(error) => {
                eprintln!("ssh-add not available, external client check skipped: {error}")
            }
        }

        // REQUEST_IDENTITIES -> IDENTITIES_ANSWER with the vault key.
        client
            .write_all(&protocol::frame(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]))
            .expect("write identities");
        let response = read_frame(&mut client);
        assert_eq!(response[0], protocol::SSH_AGENT_IDENTITIES_ANSWER);
        let count = u32::from_be_bytes([response[1], response[2], response[3], response[4]]);
        assert_eq!(count, 1);
        let mut offset = 5;
        assert_eq!(
            read_string(&response, &mut offset),
            key.public_key().to_bytes().expect("blob")
        );
        assert_eq!(
            String::from_utf8(read_string(&response, &mut offset)).expect("utf8"),
            "live test key"
        );

        // SIGN_REQUEST -> SIGN_RESPONSE, verified against the public key.
        let message = b"git commit payload";
        client
            .write_all(&sign_request(
                &key.public_key().to_bytes().expect("blob"),
                message,
            ))
            .expect("write sign");
        let response = read_frame(&mut client);
        assert_eq!(response[0], protocol::SSH_AGENT_SIGN_RESPONSE);
        let mut offset = 1;
        let blob = read_string(&response, &mut offset);
        let mut blob_offset = 0;
        assert_eq!(
            read_string(&blob, &mut blob_offset),
            b"ssh-ed25519".to_vec()
        );
        assert_eq!(
            read_string(&blob, &mut blob_offset).len(),
            64,
            "Ed25519 signatures are raw 64-byte values"
        );
        assert_eq!(blob_offset, blob.len());
        verify(&key, message, &blob);

        // Unknown message number -> SSH_AGENT_FAILURE, connection stays usable.
        client
            .write_all(&protocol::frame(&[99]))
            .expect("write unknown");
        assert_eq!(read_frame(&mut client), vec![protocol::SSH_AGENT_FAILURE]);

        // Oversized frame -> SSH_AGENT_FAILURE, then the agent hangs up.
        let oversized = ((protocol::MAX_FRAME_LEN + 1) as u32).to_be_bytes();
        client.write_all(&oversized).expect("write oversized");
        assert_eq!(read_frame(&mut client), vec![protocol::SSH_AGENT_FAILURE]);
        let mut tail = Vec::new();
        let _ = client.read_to_end(&mut tail);
        drop(client);

        // A locked vault fails the next handshake.
        state.lock().expect("lock");
        let mut client = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(pipe::PIPE_PATH)
            .expect("reconnect");
        client
            .write_all(&protocol::frame(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]))
            .expect("write identities while locked");
        assert_eq!(read_frame(&mut client), vec![protocol::SSH_AGENT_FAILURE]);
        drop(client);

        handle.stop();
        let _ = std::fs::remove_dir_all(dir);
    }
}
