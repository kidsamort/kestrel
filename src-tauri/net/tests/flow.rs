//! End-to-end tests: the real service on an ephemeral port, driven entirely
//! through [`SyncClient`] over a real TCP socket.
//!
//! Nothing about the server is mocked. Each test starts `kestrel-sync` in a
//! thread with its own SQLite file and blob directory, learns the port it
//! actually bound, and talks to it with the client under test. Plain http to
//! `127.0.0.1` is allowed by the client without `allow_insecure`, which is
//! exactly the policy a loopback development service needs. The one piece of
//! scaffolding is [`VersionRewriter`], used only by the `426` test: a v1 client
//! always sends `X-Kestrel-Protocol: 1` (correctly), so the only way to see the
//! service's `426` through the real code path is to put a byte-level relay in
//! front of it that changes that one header value to `2`. Everything else —
//! routing, authentication, storage, the response — is the real server's.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use kestrel_net::{
    ClientConfig, Clock, ConflictCode, Error, PushOp, PushRequest, SyncClient, UnauthorizedCode,
};
use kestrel_sync::{Config as ServerConfig, Server};

const ACCOUNT_ID: &str = "00112233445566778899aabbccddeeff";
const DEVICE_A: &str = "0a1b2c3d4e5f60718293a4b5c6d7e8f9";
const DEVICE_B: &str = "1a2b3c4d5e6f708192a3b4c5d6e7f809";
/// The example from `PROTOCOL.md`; the service hashes it, so its shape is the
/// only thing that matters here.
const CODE: &str = "SCMD-EGZL-WINB-XGGC-26KW-JG6V-VSCW-BZA3-2ER2-6NFD-U4GQ-PE2P-UMDQ-O";

/// A device identity: a fixed Ed25519 seed and the id it registers under.
struct Identity {
    device_id: &'static str,
    seed: [u8; 32],
    name: &'static str,
}

const ALICE: Identity = Identity {
    device_id: DEVICE_A,
    seed: [7u8; 32],
    name: "Ana's laptop",
};

const BOB: Identity = Identity {
    device_id: DEVICE_B,
    seed: [9u8; 32],
    name: "Ana's phone",
};

fn client(base_url: &str, identity: &Identity) -> SyncClient {
    SyncClient::new(ClientConfig {
        base_url: base_url.to_string(),
        account_id: ACCOUNT_ID.to_string(),
        device_id: identity.device_id.to_string(),
        signing_key: identity.seed,
        // The server listens on 127.0.0.1, which the client accepts without
        // this override: plain http is allowed for loopback and nothing else.
        allow_insecure: false,
    })
    .expect("the test client is configured")
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock after the epoch")
        .as_secs() as i64
}

// ---------------------------------------------------------------------------
// The real server, in-process on an ephemeral port
// ---------------------------------------------------------------------------

struct TestServer {
    addr: SocketAddr,
    db_path: PathBuf,
    blob_dir: PathBuf,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
    thread: Option<JoinHandle<()>>,
}

impl TestServer {
    fn start() -> TestServer {
        let db_path = temp_db_path();
        let blob_dir = db_path.with_extension("blobs");
        let config = ServerConfig {
            addr: "127.0.0.1:0".parse().expect("valid address"),
            db_path: db_path.clone(),
            blob_dir: blob_dir.clone(),
            ..ServerConfig::default()
        };

        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(async move {
                let server = Server::bind(config).await.expect("the store opens and the socket binds");
                addr_tx.send(server.local_addr()).expect("address reported");
                server
                    .run(async move {
                        let _ = stop_rx.await;
                    })
                    .await
                    .expect("the server runs until asked to stop");
            });
        });

        let addr = addr_rx.recv().expect("the server started");
        TestServer {
            addr,
            db_path,
            blob_dir,
            stop: Some(stop_tx),
            thread: Some(thread),
        }
    }
}

impl Drop for TestServer {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let path = self.db_path.to_string_lossy().to_string();
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{path}{suffix}"));
        }
        let _ = std::fs::remove_dir_all(&self.blob_dir);
    }
}

static DB_COUNTER: AtomicU64 = AtomicU64::new(0);

fn temp_db_path() -> PathBuf {
    let unique = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "kestrel-net-test-{}-{unique}.db",
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// Flow: create, enrol, push, pull, conflict, tombstone
// ---------------------------------------------------------------------------

#[test]
fn the_whole_flow_over_real_tcp() {
    let server = TestServer::start();
    let base = format!("http://{}", server.addr);
    let alice = client(&base, &ALICE);

    // --- account creation ---------------------------------------------------
    let created = alice.create_account([0x11; 32], ALICE.name).expect("create account");
    assert_eq!(created.account_id, ACCOUNT_ID);
    assert_eq!(created.account_id, alice.account_id());

    match alice
        .create_account([0x11; 32], ALICE.name)
        .expect_err("the account id is taken")
    {
        Error::Conflict { code, .. } => assert_eq!(code, ConflictCode::AccountExists),
        other => panic!("expected AccountExists, got {other}"),
    }

    let state = alice.state().expect("state");
    assert_eq!(state.account_id, ACCOUNT_ID);
    assert_eq!(state.devices.len(), 1);
    assert_eq!(state.devices[0].device_id, DEVICE_A);
    assert_eq!(state.devices[0].device_name, ALICE.name);
    assert_eq!(state.items, 0);
    assert_eq!(state.bytes, 0);

    // --- enrolment ----------------------------------------------------------
    let sealed = b"sealed-account-key";
    let expires_at = unix_now() + 600;
    alice
        .enroll_offer(DEVICE_B, CODE, sealed, expires_at)
        .expect("offer the sealed key to the phone");

    let bob = client(&base, &BOB);
    let claim = bob
        .enroll_claim(CODE, [0x55; 32], BOB.name)
        .expect("the phone claims the code");
    assert_eq!(claim.account_id, ACCOUNT_ID);
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(&claim.sealed)
            .expect("sealed is base64"),
        sealed
    );
    // The claiming device is not a device yet, so it is not in its own list.
    assert_eq!(claim.devices.len(), 1);
    assert_eq!(claim.devices[0].device_id, DEVICE_A);

    alice.enroll_ack(DEVICE_B).expect("ack");
    alice.enroll_ack(DEVICE_B).expect("ack is idempotent");

    // The phone's own key now authenticates.
    let state = bob.state().expect("the claimed device is enrolled after ack");
    assert_eq!(state.devices.len(), 2);
    assert!(state
        .devices
        .iter()
        .any(|device| device.device_id == DEVICE_B && device.device_name == BOB.name));

    // --- push and pull ------------------------------------------------------
    let item = "0123456789abcdef0123456789abcdef";
    let mut alice_clock = Clock::new();
    alice_clock.insert(DEVICE_A.to_string(), 1);

    let pushed = alice
        .push(PushRequest {
            ops: vec![PushOp::live(item, alice_clock.clone(), "aabbcc")],
        })
        .expect("push");
    assert_eq!(pushed.applied, [item]);
    assert!(pushed.conflicts.is_empty());

    let page = bob.pull(0, None).expect("pull");
    assert_eq!(page.ops.len(), 1);
    assert_eq!(page.ops[0].seq, 1);
    assert_eq!(page.ops[0].item_id, item);
    assert_eq!(page.ops[0].ciphertext, "aabbcc");
    assert!(!page.ops[0].deleted);
    assert_eq!(page.ops[0].clock, alice_clock);
    assert_eq!(page.next_seq, 1);
    assert!(!page.has_more);
    let after_first = page.next_seq;

    // --- a genuinely concurrent write --------------------------------------
    let mut bob_clock = Clock::new();
    bob_clock.insert(DEVICE_B.to_string(), 1);

    let conflicted = bob
        .push(PushRequest {
            ops: vec![PushOp::live(item, bob_clock.clone(), "ddeeff")],
        })
        .expect("push");
    assert!(conflicted.applied.is_empty(), "a concurrent write is not applied");
    assert_eq!(conflicted.conflicts.len(), 1);
    assert_eq!(conflicted.conflicts[0].clock, alice_clock, "the server kept Alice's row");
    assert_eq!(conflicted.conflicts[0].ciphertext, "aabbcc");

    // The client merges and pushes a clock that dominates both.
    let mut merged = alice_clock.clone();
    merged.extend(bob_clock.iter().map(|(device, counter)| (device.clone(), *counter)));

    let merged_push = bob
        .push(PushRequest {
            ops: vec![PushOp::live(item, merged.clone(), "ddeeff")],
        })
        .expect("push the merge");
    assert_eq!(merged_push.applied, [item]);
    assert!(merged_push.conflicts.is_empty());

    let page = alice.pull(after_first, None).expect("pull the merge");
    assert_eq!(page.ops.len(), 1);
    assert_eq!(page.ops[0].item_id, item);
    assert_eq!(page.ops[0].ciphertext, "ddeeff");
    assert_eq!(page.ops[0].clock, merged);
    assert!(page.ops[0].seq > after_first, "the update moved to the end of the log");

    // --- a tombstone --------------------------------------------------------
    let tombstone_item = "deleted-item";
    let mut clock = Clock::new();
    clock.insert(DEVICE_A.to_string(), 2);
    let pushed = alice
        .push(PushRequest {
            ops: vec![PushOp::live(tombstone_item, clock, "00")],
        })
        .expect("write the item before deleting it");
    assert_eq!(pushed.applied, [tombstone_item]);

    let mut clock = Clock::new();
    clock.insert(DEVICE_A.to_string(), 3);
    let pushed = alice
        .push(PushRequest {
            ops: vec![PushOp::tombstone(tombstone_item, clock)],
        })
        .expect("push the tombstone");
    assert_eq!(pushed.applied, [tombstone_item]);

    // --- paging and the tombstone on the wire ------------------------------
    let first = bob.pull(0, Some(1)).expect("a one-row page");
    assert_eq!(first.ops.len(), 1);
    assert!(first.has_more);
    assert_eq!(first.next_seq, first.ops[0].seq);

    let all = bob.pull(0, Some(1000)).expect("the whole log");
    assert_eq!(all.ops.len(), 2, "one row per item, at its latest seq");
    assert!(!all.has_more);

    let tombstone = all
        .ops
        .iter()
        .find(|op| op.item_id == tombstone_item)
        .expect("the tombstone is returned like any other op");
    assert!(tombstone.deleted);
    assert_eq!(tombstone.ciphertext, "");
    assert_eq!(tombstone.clock.get(DEVICE_A), Some(&3));

    let live = all
        .ops
        .iter()
        .find(|op| op.item_id == item)
        .expect("the live item is present");
    assert!(!live.deleted);
    assert_eq!(live.ciphertext, "ddeeff");

    let state = bob.state().expect("final state");
    assert_eq!(state.items, 2, "tombstones are rows too");
    assert_eq!(state.bytes, 3, "only the live ciphertext contributes bytes");

    // --- revocation ---------------------------------------------------------
    assert_eq!(
        state
            .devices
            .iter()
            .find(|device| device.device_id == DEVICE_B)
            .expect("the phone is listed")
            .revoked_at,
        None,
        "a live device has no revocation time"
    );

    alice.revoke_device(DEVICE_B).expect("revoke the phone");
    match bob.state().expect_err("the revoked device is refused") {
        Error::Rejected { code, .. } => assert_eq!(code, "device_revoked"),
        other => panic!("expected device_revoked, got {other}"),
    }

    let state = alice.state().expect("the desktop still works");
    let phone = state
        .devices
        .iter()
        .find(|device| device.device_id == DEVICE_B)
        .expect("the revoked row is kept");
    assert!(phone.revoked_at.is_some(), "the row records when it was revoked");

    // A device cannot revoke itself through this client either: the service
    // refuses, and the typed error survives.
    match alice.revoke_device(DEVICE_A).expect_err("self-revoke is refused") {
        Error::Rejected { code, .. } => assert_eq!(code, "invalid_field"),
        other => panic!("expected a rejection, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// Authentication failures
// ---------------------------------------------------------------------------

#[test]
fn a_wrong_signing_key_is_a_typed_401() {
    let server = TestServer::start();
    let base = format!("http://{}", server.addr);
    let alice = client(&base, &ALICE);
    alice.create_account([0x11; 32], ALICE.name).expect("create account");

    // The right device id, the wrong key: the signature does not verify.
    let impostor = SyncClient::new(ClientConfig {
        base_url: base.clone(),
        account_id: ACCOUNT_ID.to_string(),
        device_id: DEVICE_A.to_string(),
        signing_key: [0xAA; 32],
        allow_insecure: false,
    })
    .expect("configuration is valid");
    match impostor.state().expect_err("the key is not Alice's") {
        Error::Unauthorized { code, message } => {
            assert_eq!(code, UnauthorizedCode::BadSignature);
            assert!(!message.is_empty());
        }
        other => panic!("expected a bad-signature 401, got {other}"),
    }

    // A device id nobody registered: a different 401, and the client says so.
    let stranger = SyncClient::new(ClientConfig {
        base_url: base,
        account_id: ACCOUNT_ID.to_string(),
        device_id: "deadbeefdeadbeefdeadbeefdeadbeef".to_string(),
        signing_key: [0xBB; 32],
        allow_insecure: false,
    })
    .expect("configuration is valid");
    match stranger.state().expect_err("the device is unknown") {
        Error::Unauthorized { code, .. } => assert_eq!(code, UnauthorizedCode::UnknownDevice),
        other => panic!("expected an unknown-device 401, got {other}"),
    }
}

// ---------------------------------------------------------------------------
// 426, through a relay that asks for protocol 2
// ---------------------------------------------------------------------------

#[test]
fn a_protocol_version_mismatch_is_reported() {
    let server = TestServer::start();
    let relay = VersionRewriter::start(server.addr);
    let alice = client(&format!("http://{}", relay.addr), &ALICE);

    match alice.state().expect_err("the service refuses protocol 2") {
        Error::ProtocolVersion {
            code,
            server_protocol,
            message,
        } => {
            assert_eq!(code, "unsupported_protocol");
            assert_eq!(server_protocol.as_deref(), Some("1"), "the service says what it speaks");
            assert!(message.contains("protocol"), "{message}");
        }
        other => panic!("expected a protocol-version error, got {other}"),
    }
}

/// A single-request TCP relay that rewrites `X-Kestrel-Protocol: 1` to `2`.
///
/// The replacement is byte-for-byte the same length, and it adds
/// `Connection: close` so one connection carries one request and the response
/// has a definite end. The upstream response is forwarded untouched.
struct VersionRewriter {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl VersionRewriter {
    fn start(upstream: SocketAddr) -> VersionRewriter {
        let listener = TcpListener::bind("127.0.0.1:0").expect("relay binds");
        let addr = listener.local_addr().expect("relay address");
        listener.set_nonblocking(true).expect("nonblocking listener");

        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let thread = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        stream.set_nonblocking(false).expect("blocking connection");
                        relay_one(stream, upstream);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });

        VersionRewriter {
            addr,
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for VersionRewriter {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn relay_one(mut client: TcpStream, upstream: SocketAddr) {
    let _ = client.set_read_timeout(Some(Duration::from_secs(10)));

    let Some(request_head) = read_head(&mut client) else {
        return;
    };
    let original = String::from_utf8_lossy(&request_head).to_string();
    let rewritten = original.replacen("X-Kestrel-Protocol: 1", "X-Kestrel-Protocol: 2", 1);
    // Trim only the blank line that ends the head, then add our own header with
    // its own CRLF. Trimming all four characters would glue `Connection: close`
    // onto the last header and the server would read one merged value.
    let rewritten = format!(
        "{}\r\nConnection: close\r\n\r\n",
        rewritten.trim_end_matches("\r\n\r\n")
    );

    let mut request_body = vec![0u8; content_length(&original)];
    if !request_body.is_empty() && client.read_exact(&mut request_body).is_err() {
        return;
    }

    let Ok(mut server) = TcpStream::connect(upstream) else {
        return;
    };
    let _ = server.set_read_timeout(Some(Duration::from_secs(10)));
    if server.write_all(rewritten.as_bytes()).is_err()
        || server.write_all(&request_body).is_err()
    {
        return;
    }

    // Read the response by its Content-Length instead of waiting for the
    // server to close: the service answers every route with a `Full` body, so
    // the length is always present, and a definite end keeps this relay from
    // stalling on a pooled connection.
    let Some(response_head) = read_head(&mut server) else {
        return;
    };
    let head_text = String::from_utf8_lossy(&response_head).to_string();
    let mut response_body = vec![0u8; content_length(&head_text)];
    if !response_body.is_empty() && server.read_exact(&mut response_body).is_err() {
        return;
    }

    let _ = client.write_all(&response_head);
    let _ = client.write_all(&response_body);
}

fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match stream.read(&mut byte) {
            Ok(0) => return None,
            Ok(_) => head.push(byte[0]),
            Err(_) => return None,
        }
    }
    Some(head)
}

fn content_length(head: &str) -> usize {
    for line in head.split("\r\n") {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().unwrap_or(0);
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// Construction-time transport policy, exercised against the same client type
// ---------------------------------------------------------------------------

#[test]
fn a_plain_http_remote_is_refused_before_a_socket_is_opened() {
    let error = match SyncClient::new(ClientConfig {
        base_url: "http://sync.example.com".to_string(),
        account_id: ACCOUNT_ID.to_string(),
        device_id: DEVICE_A.to_string(),
        signing_key: ALICE.seed,
        allow_insecure: false,
    }) {
        Ok(_) => panic!("a remote plain-http vault endpoint must be refused"),
        Err(error) => error,
    };
    assert!(matches!(
        error,
        kestrel_net::ConfigError::InsecureTransport { .. }
    ));
    assert!(error.to_string().contains("allow_insecure"), "{error}");
}
