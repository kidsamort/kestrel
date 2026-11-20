//! End-to-end tests.
//!
//! Each test starts the real service on `127.0.0.1:0` in its own thread, with
//! its own SQLite file, and talks to it with `ureq` — a separate HTTP client
//! implementation, not the server's own types. Nothing here is mocked: the
//! bytes go over a TCP socket.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread::JoinHandle;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use kestrel_sync::config::Config;
use kestrel_sync::Server;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

const PROTOCOL: &str = "1";
const ACCOUNT: &str = "00112233445566778899aabbccddeeff";

// ---------------------------------------------------------------------------
// Harness
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
        TestServer::start_with(Config {
            addr: "127.0.0.1:0".parse().expect("valid address"),
            blob_dir: db_path.with_extension("blobs"),
            db_path,
            ..Config::default()
        })
    }

    fn start_with(config: Config) -> TestServer {
        let db_path = config.db_path.clone();
        let blob_dir = config.blob_dir.clone();
        let (addr_tx, addr_rx) = std::sync::mpsc::channel();
        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();

        let thread = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("tokio runtime");
            runtime.block_on(async move {
                let server = Server::bind(config).await.expect("server binds");
                addr_tx.send(server.local_addr()).expect("address sent");
                server
                    .run(async move {
                        let _ = stop_rx.await;
                    })
                    .await
                    .expect("server runs");
            });
        });

        let addr = addr_rx.recv().expect("server started");
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
        "kestrel-sync-test-{}-{unique}.db",
        std::process::id()
    ))
}

// ---------------------------------------------------------------------------
// Client side of the protocol
// ---------------------------------------------------------------------------

struct Device {
    id: String,
    signing: SigningKey,
    agreement: [u8; 32],
    name: String,
}

impl Device {
    fn new(seed: u8, name: &str) -> Device {
        let signing = SigningKey::from_bytes(&[seed; 32]);
        let digest = Sha256::digest(signing.verifying_key().to_bytes());
        Device {
            id: hex::encode(&digest[..16]),
            signing,
            agreement: [seed; 32],
            name: name.to_string(),
        }
    }

    fn signing_pub(&self) -> String {
        hex::encode(self.signing.verifying_key().to_bytes())
    }

    fn agreement_pub(&self) -> String {
        hex::encode(self.agreement)
    }

    /// A valid 32-hex id that is not this device: used as a second entry in a
    /// vector clock. The server treats clock keys as data, not identities.
    fn foreign_clock_device(&self) -> String {
        hex::encode(Sha256::digest(format!("clock/{}", self.id))[..16].to_vec())
    }
}

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);

fn nonce() -> String {
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    let nonce = format!("{:016x}{:016x}", std::process::id(), counter);
    assert_eq!(nonce.len(), 32);
    nonce
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock after epoch")
        .as_secs() as i64
}

fn header_for(
    device_id: &str,
    key: &SigningKey,
    method: &str,
    target: &str,
    body: &str,
    timestamp: i64,
    nonce: &str,
) -> String {
    let digest = hex::encode(Sha256::digest(body.as_bytes()));
    let message = format!("kestrel-sync/v1\n{method}\n{target}\n{digest}\n{timestamp}\n{nonce}");
    let signature = key.sign(message.as_bytes());
    format!(
        "Kestrel {device_id}.{timestamp}.{nonce}.{}",
        hex::encode(signature.to_bytes())
    )
}

struct Reply {
    status: u16,
    body: String,
    allow: Option<String>,
    protocol: Option<String>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_str(&self.body)
            .unwrap_or_else(|error| panic!("body is not JSON ({error}): {}", self.body))
    }

    fn error_code(&self) -> String {
        self.json()["error"]
            .as_str()
            .unwrap_or_else(|| panic!("no error code in {}", self.body))
            .to_string()
    }
}

fn request(
    server: &TestServer,
    method: &str,
    target: &str,
    body: Option<&str>,
    authorization: Option<&str>,
    protocol: Option<&str>,
) -> Reply {
    let url = format!("http://{}{}", server.addr, target);
    let agent = ureq::AgentBuilder::new().redirects(0).build();
    let mut pending = agent.request(method, &url);
    if let Some(protocol) = protocol {
        pending = pending.set("X-Kestrel-Protocol", protocol);
    }
    if let Some(authorization) = authorization {
        pending = pending.set("Authorization", authorization);
    }

    let result = match body {
        Some(body) => pending
            .set("Content-Type", "application/json")
            .send_string(body),
        None => pending.call(),
    };

    let response = match result {
        Ok(response) => response,
        Err(ureq::Error::Status(_, response)) => response,
        Err(ureq::Error::Transport(error)) => {
            panic!("transport error for {method} {target}: {error}")
        }
    };

    let status = response.status();
    let allow = response.header("Allow").map(str::to_owned);
    let protocol = response.header("X-Kestrel-Protocol").map(str::to_owned);
    let body = response
        .into_string()
        .unwrap_or_else(|error| panic!("response body unreadable: {error}"));
    Reply {
        status,
        body,
        allow,
        protocol,
    }
}

/// Signs exactly the bytes that go on the wire: `body` is both what the
/// signature covers and what the request carries.
fn authed(
    server: &TestServer,
    device: &Device,
    method: &str,
    target: &str,
    body: Option<&str>,
) -> Reply {
    let signed_body = body.unwrap_or("");
    let header = header_for(
        &device.id,
        &device.signing,
        method,
        target,
        signed_body,
        unix_now(),
        &nonce(),
    );
    request(server, method, target, body, Some(&header), Some(PROTOCOL))
}

fn create_account(server: &TestServer, account_id: &str, device: &Device) -> Reply {
    let body = json!({
        "account_id": account_id,
        "device_id": device.id,
        "device_signing_pub": device.signing_pub(),
        "device_agreement_pub": device.agreement_pub(),
        "device_name": device.name,
    })
    .to_string();
    request(
        server,
        "POST",
        "/v1/accounts",
        Some(&body),
        None,
        Some(PROTOCOL),
    )
}

fn clock(entries: &[(&str, u64)]) -> Value {
    let mut map = Map::new();
    for (device, counter) in entries {
        map.insert((*device).to_string(), json!(counter));
    }
    Value::Object(map)
}

fn op(item_id: &str, clock: Value, deleted: bool, ciphertext: &str) -> Value {
    json!({
        "item_id": item_id,
        "clock": clock,
        "deleted": deleted,
        "ciphertext": ciphertext,
    })
}

fn push(server: &TestServer, device: &Device, ops: Vec<Value>) -> Reply {
    let body = json!({ "ops": ops }).to_string();
    authed(server, device, "POST", "/v1/sync/push", Some(&body))
}

fn pull(server: &TestServer, device: &Device, query: &str) -> Reply {
    authed(
        server,
        device,
        "GET",
        &format!("/v1/sync/pull{query}"),
        None,
    )
}

fn state(server: &TestServer, device: &Device) -> Reply {
    authed(server, device, "GET", "/v1/sync/state", None)
}

fn ops(reply: &Reply) -> Vec<Value> {
    reply.json()["ops"]
        .as_array()
        .unwrap_or_else(|| panic!("no ops array in {}", reply.body))
        .clone()
}

fn revoke(server: &TestServer, actor: &Device, target_device_id: &str) -> Reply {
    authed(
        server,
        actor,
        "DELETE",
        &format!("/v1/devices/{target_device_id}"),
        None,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn account_creation_rejects_duplicates() {
    let server = TestServer::start();
    let device = Device::new(1, "desktop");

    let created = create_account(&server, ACCOUNT, &device);
    assert_eq!(created.status, 201, "body: {}", created.body);
    assert_eq!(created.json()["account_id"], ACCOUNT);
    assert_eq!(created.protocol.as_deref(), Some(PROTOCOL));

    let again = create_account(&server, ACCOUNT, &device);
    assert_eq!(again.status, 409);
    assert_eq!(again.error_code(), "account_exists");

    let second_device = Device::new(2, "laptop");
    let same_account = create_account(&server, ACCOUNT, &second_device);
    assert_eq!(same_account.status, 409);
    assert_eq!(same_account.error_code(), "account_exists");

    let other_account = "ffeeddccbbaa99887766554433221100";
    let same_device = create_account(&server, other_account, &device);
    assert_eq!(same_device.status, 409);
    assert_eq!(same_device.error_code(), "device_conflict");
}

#[test]
fn enrolment_flow_reaches_a_working_second_device() {
    let server = TestServer::start();
    let desktop = Device::new(1, "desktop");
    let phone = Device::new(2, "phone");
    assert_eq!(create_account(&server, ACCOUNT, &desktop).status, 201);

    // An offer that outlives the protocol's one-hour cap is refused.
    let code = "482913";
    let code_hash = hex::encode(Sha256::digest(code.as_bytes()));
    let sealed = base64::engine::general_purpose::STANDARD.encode(b"sealed-account-key");
    let too_long = json!({
        "code_hash": code_hash,
        "sealed": sealed,
        "expires_at": unix_now() + 7200,
        "new_device_id": phone.id,
    })
    .to_string();
    let refused = authed(
        &server,
        &desktop,
        "POST",
        "/v1/enroll/offer",
        Some(&too_long),
    );
    assert_eq!(refused.status, 400, "body: {}", refused.body);
    assert_eq!(refused.error_code(), "invalid_field");

    let offer = json!({
        "code_hash": code_hash,
        "sealed": sealed,
        "expires_at": unix_now() + 600,
        "new_device_id": phone.id,
    })
    .to_string();
    let offered = authed(&server, &desktop, "POST", "/v1/enroll/offer", Some(&offer));
    assert_eq!(offered.status, 200, "body: {}", offered.body);
    assert_eq!(offered.json(), json!({}));

    // A second offer for the same device is a normal retry: the row already
    // exists with `acked_at` NULL, and reading that NULL into an integer used to
    // turn the retry into a 500.
    let repeated = authed(&server, &desktop, "POST", "/v1/enroll/offer", Some(&offer));
    assert_eq!(repeated.status, 200, "body: {}", repeated.body);

    // An offer from an unauthenticated caller is a 401, not an offer.
    let unauthenticated = request(
        &server,
        "POST",
        "/v1/enroll/offer",
        Some(&offer),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(unauthenticated.status, 401);

    // The claiming device must exist in the offer: a different device id with
    // the right code finds nothing.
    let stranger = Device::new(3, "stranger");
    let wrong_claim = json!({
        "code": code,
        "device_id": stranger.id,
        "device_signing_pub": stranger.signing_pub(),
        "device_agreement_pub": stranger.agreement_pub(),
        "device_name": stranger.name,
    })
    .to_string();
    let rejected = request(
        &server,
        "POST",
        "/v1/enroll/claim",
        Some(&wrong_claim),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(rejected.status, 400, "body: {}", rejected.body);
    assert_eq!(rejected.error_code(), "invalid_code");

    // The real claim is unauthenticated: the code is the credential.
    let claim = json!({
        "code": code,
        "device_id": phone.id,
        "device_signing_pub": phone.signing_pub(),
        "device_agreement_pub": phone.agreement_pub(),
        "device_name": phone.name,
    })
    .to_string();
    let claimed = request(
        &server,
        "POST",
        "/v1/enroll/claim",
        Some(&claim),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(claimed.status, 200, "body: {}", claimed.body);
    let claimed = claimed.json();
    assert_eq!(claimed["account_id"], ACCOUNT);
    assert_eq!(claimed["sealed"], sealed);
    let devices = claimed["devices"].as_array().expect("devices array");
    assert_eq!(devices.len(), 1, "only the existing device is listed");
    assert_eq!(devices[0]["device_id"], desktop.id);

    // Claimed is not enrolled: the new device cannot authenticate yet.
    let before_ack = state(&server, &phone);
    assert_eq!(before_ack.status, 401);
    assert_eq!(before_ack.error_code(), "unknown_device");

    let ack = json!({ "new_device_id": phone.id }).to_string();
    let acked = authed(&server, &desktop, "POST", "/v1/enroll/ack", Some(&ack));
    assert_eq!(acked.status, 200, "body: {}", acked.body);

    // Now the phone's key works, and it sees both devices.
    let after_ack = state(&server, &phone);
    assert_eq!(after_ack.status, 200, "body: {}", after_ack.body);
    assert_eq!(after_ack.json()["account_id"], ACCOUNT);
    let devices = after_ack.json()["devices"]
        .as_array()
        .expect("devices")
        .clone();
    assert_eq!(devices.len(), 2);
    let ids: Vec<&str> = devices
        .iter()
        .map(|device| device["device_id"].as_str().expect("device id"))
        .collect();
    assert!(ids.contains(&desktop.id.as_str()));
    assert!(ids.contains(&phone.id.as_str()));

    // The phone can write, and the desktop can read the write.
    let pushed = push(
        &server,
        &phone,
        vec![op("item-phone", clock(&[(&phone.id, 1)]), false, "0102")],
    );
    assert_eq!(pushed.status, 200, "body: {}", pushed.body);
    assert_eq!(pushed.json()["applied"], json!(["item-phone"]));

    let pulled = pull(&server, &desktop, "?since=0");
    assert_eq!(pulled.status, 200);
    let pulled_ops = ops(&pulled);
    assert_eq!(pulled_ops.len(), 1);
    assert_eq!(pulled_ops[0]["item_id"], "item-phone");

    // A device that is already enrolled cannot be offered again.
    let again = authed(&server, &desktop, "POST", "/v1/enroll/offer", Some(&offer));
    assert_eq!(again.status, 409);
    assert_eq!(again.error_code(), "already_enrolled");
}

#[test]
fn revoked_device_is_refused_and_its_row_is_kept() {
    let server = TestServer::start();
    let desktop = Device::new(1, "desktop");
    let phone = Device::new(2, "phone");
    assert_eq!(create_account(&server, ACCOUNT, &desktop).status, 201);

    // Enrol the phone through the real offer/claim/ack flow.
    let code = "482913";
    let code_hash = hex::encode(Sha256::digest(code.as_bytes()));
    let sealed = base64::engine::general_purpose::STANDARD.encode(b"sealed-account-key");
    let offer = json!({
        "code_hash": code_hash,
        "sealed": sealed,
        "expires_at": unix_now() + 600,
        "new_device_id": phone.id,
    })
    .to_string();
    assert_eq!(
        authed(&server, &desktop, "POST", "/v1/enroll/offer", Some(&offer)).status,
        200
    );
    let claim = json!({
        "code": code,
        "device_id": phone.id,
        "device_signing_pub": phone.signing_pub(),
        "device_agreement_pub": phone.agreement_pub(),
        "device_name": phone.name,
    })
    .to_string();
    assert_eq!(
        request(
            &server,
            "POST",
            "/v1/enroll/claim",
            Some(&claim),
            None,
            Some(PROTOCOL)
        )
        .status,
        200
    );
    let ack = json!({ "new_device_id": phone.id }).to_string();
    assert_eq!(
        authed(&server, &desktop, "POST", "/v1/enroll/ack", Some(&ack)).status,
        200
    );

    // The live phone signs successfully before the revocation.
    let live = state(&server, &phone);
    assert_eq!(live.status, 200, "body: {}", live.body);
    assert_eq!(
        push(
            &server,
            &phone,
            vec![op("item-phone", clock(&[(&phone.id, 1)]), false, "0102")],
        )
        .status,
        200
    );

    // A live device of the same account revokes it. The row stays and the
    // response carries the server's time, not a client-supplied one.
    let revoked = revoke(&server, &desktop, &phone.id);
    assert_eq!(revoked.status, 200, "body: {}", revoked.body);
    let revoked = revoked.json();
    assert_eq!(revoked["device_id"], phone.id);
    let revoked_at = revoked["revoked_at"].as_u64().expect("revoked_at");
    assert!(revoked_at > 0);

    // The same signature is now refused on every data route, with the stable
    // `device_revoked` code rather than a generic unauthorized.
    for reply in [
        state(&server, &phone),
        pull(&server, &phone, "?since=0"),
        push(
            &server,
            &phone,
            vec![op("item-phone", clock(&[(&phone.id, 2)]), false, "0304")],
        ),
    ] {
        assert_eq!(reply.status, 403, "body: {}", reply.body);
        assert_eq!(reply.error_code(), "device_revoked");
    }

    // A revoked device cannot revoke the device that is still live.
    let refused = revoke(&server, &phone, &desktop.id);
    assert_eq!(refused.status, 403);
    assert_eq!(refused.error_code(), "device_revoked");

    // The desktop still works, and the account lists the revoked row with its
    // timestamp. That row is the audit trail: it is not deleted.
    let snapshot = state(&server, &desktop);
    assert_eq!(snapshot.status, 200, "body: {}", snapshot.body);
    let devices = snapshot.json()["devices"]
        .as_array()
        .expect("devices")
        .clone();
    assert_eq!(devices.len(), 2);
    let phone_row = devices
        .iter()
        .find(|device| device["device_id"] == phone.id)
        .expect("the revoked device is still listed");
    assert_eq!(phone_row["revoked_at"], revoked_at);
    let desktop_row = devices
        .iter()
        .find(|device| device["device_id"] == desktop.id)
        .expect("the live device is listed");
    assert!(desktop_row.get("revoked_at").is_none() || desktop_row["revoked_at"].is_null());
    assert_eq!(
        snapshot.json()["items"],
        1,
        "the phone's earlier write is kept"
    );

    // Retrying is idempotent and does not move the timestamp.
    let repeated = revoke(&server, &desktop, &phone.id);
    assert_eq!(repeated.status, 200, "body: {}", repeated.body);
    assert_eq!(repeated.json()["revoked_at"], revoked_at);

    // Nobody can revoke themselves: that would leave no signing device.
    let self_revoke = revoke(&server, &desktop, &desktop.id);
    assert_eq!(self_revoke.status, 400, "body: {}", self_revoke.body);
    assert_eq!(self_revoke.error_code(), "invalid_field");

    // A device id outside this account is not found, and the response does not
    // say whether it exists somewhere else.
    let stranger = Device::new(3, "stranger");
    assert_eq!(
        create_account(&server, "ffeeddccbbaa99887766554433221100", &stranger).status,
        201
    );
    let foreign = revoke(&server, &stranger, &phone.id);
    assert_eq!(foreign.status, 404);
    assert_eq!(foreign.error_code(), "not_found");
}

#[test]
fn push_pull_tombstone_and_state() {
    let server = TestServer::start();
    let device = Device::new(1, "desktop");
    assert_eq!(create_account(&server, ACCOUNT, &device).status, 201);

    let pushed = push(
        &server,
        &device,
        vec![
            op("item-0001", clock(&[(&device.id, 1)]), false, "0102"),
            op("item-0002", clock(&[(&device.id, 1)]), false, "0304"),
        ],
    );
    assert_eq!(pushed.status, 200, "body: {}", pushed.body);
    assert_eq!(pushed.json()["applied"], json!(["item-0001", "item-0002"]));
    assert_eq!(pushed.json()["conflicts"], json!([]));

    let first_pull = pull(&server, &device, "?since=0");
    assert_eq!(first_pull.status, 200);
    let body = first_pull.json();
    let pulled = ops(&first_pull);
    assert_eq!(pulled.len(), 2);
    assert_eq!(pulled[0]["seq"], 1);
    assert_eq!(pulled[0]["item_id"], "item-0001");
    assert_eq!(pulled[0]["ciphertext"], "0102");
    assert_eq!(pulled[0]["deleted"], false);
    assert_eq!(pulled[1]["seq"], 2);
    assert_eq!(pulled[1]["item_id"], "item-0002");
    assert_eq!(body["next_seq"], 2);
    assert_eq!(body["has_more"], false);

    // `since` is exclusive, and a small page reports has_more.
    let page = pull(&server, &device, "?since=0&limit=1");
    assert_eq!(page.status, 200);
    assert_eq!(ops(&page).len(), 1);
    assert_eq!(page.json()["has_more"], true);
    assert_eq!(page.json()["next_seq"], 1);

    let second_pull = pull(&server, &device, "?since=1");
    assert_eq!(ops(&second_pull).len(), 1);
    assert_eq!(ops(&second_pull)[0]["item_id"], "item-0002");

    // A delete is an op with an empty ciphertext, stored and pulled back as a
    // tombstone with a fresh seq.
    let deleted = push(
        &server,
        &device,
        vec![op("item-0001", clock(&[(&device.id, 2)]), true, "")],
    );
    assert_eq!(deleted.status, 200, "body: {}", deleted.body);
    assert_eq!(deleted.json()["applied"], json!(["item-0001"]));

    let tombstones = pull(&server, &device, "?since=2");
    assert_eq!(tombstones.status, 200);
    let pulled = ops(&tombstones);
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0]["seq"], 3);
    assert_eq!(pulled[0]["item_id"], "item-0001");
    assert_eq!(pulled[0]["deleted"], true);
    assert_eq!(pulled[0]["ciphertext"], "");

    // Pulling from zero shows the item at its new revision, not twice.
    let all = pull(&server, &device, "?since=0");
    let pulled = ops(&all);
    assert_eq!(pulled.len(), 2);
    assert_eq!(pulled[0]["item_id"], "item-0002");
    assert_eq!(pulled[1]["item_id"], "item-0001");
    assert_eq!(pulled[1]["deleted"], true);

    // State counts rows and bytes, and nothing else: two item rows, two bytes
    // (the tombstone contributes zero).
    let snapshot = state(&server, &device);
    assert_eq!(snapshot.status, 200);
    let snapshot = snapshot.json();
    let mut keys: Vec<&str> = snapshot
        .as_object()
        .expect("object")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["account_id", "bytes", "devices", "items"]);
    assert_eq!(snapshot["items"], 2);
    assert_eq!(snapshot["bytes"], 2);

    // A `since` past the end is an empty page that does not move backwards.
    let empty = pull(&server, &device, "?since=99");
    assert_eq!(empty.status, 200);
    assert_eq!(ops(&empty).len(), 0);
    assert_eq!(empty.json()["next_seq"], 99);
    assert_eq!(empty.json()["has_more"], false);
}

#[test]
fn concurrent_clocks_are_reported_not_merged() {
    let server = TestServer::start();
    let device = Device::new(1, "desktop");
    assert_eq!(create_account(&server, ACCOUNT, &device).status, 201);
    let other = device.foreign_clock_device();

    let first = push(
        &server,
        &device,
        vec![op("item-0001", clock(&[(&device.id, 2)]), false, "aa")],
    );
    assert_eq!(first.status, 200);
    assert_eq!(first.json()["applied"], json!(["item-0001"]));

    // Concurrent: neither {A:2} nor {B:1} dominates the other.
    let concurrent = push(
        &server,
        &device,
        vec![op("item-0001", clock(&[(&other, 1)]), false, "bb")],
    );
    assert_eq!(concurrent.status, 200, "body: {}", concurrent.body);
    let concurrent = concurrent.json();
    assert_eq!(concurrent["applied"], json!([]));
    let conflicts = concurrent["conflicts"].as_array().expect("conflicts");
    assert_eq!(conflicts.len(), 1);
    assert_eq!(conflicts[0]["item_id"], "item-0001");
    assert_eq!(conflicts[0]["ciphertext"], "aa");
    assert_eq!(conflicts[0]["clock"][&device.id], 2);
    assert_eq!(conflicts[0]["deleted"], false);

    // The stored op is untouched: the server did not merge anything.
    let stored = pull(&server, &device, "?since=0");
    let stored = ops(&stored);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0]["ciphertext"], "aa");
    assert_eq!(stored[0]["clock"][&device.id], 2);

    // The merged clock dominates both and is applied.
    let merged = push(
        &server,
        &device,
        vec![op(
            "item-0001",
            clock(&[(&device.id, 2), (&other, 1)]),
            false,
            "cc",
        )],
    );
    assert_eq!(merged.status, 200);
    assert_eq!(merged.json()["applied"], json!(["item-0001"]));
    assert_eq!(merged.json()["conflicts"], json!([]));

    let pulled = ops(&pull(&server, &device, "?since=1"));
    assert_eq!(pulled.len(), 1);
    assert_eq!(pulled[0]["ciphertext"], "cc");
    assert_eq!(pulled[0]["clock"][&other], 1);

    // Re-sending the same clock and payload is idempotent, not a conflict.
    let idempotent = push(
        &server,
        &device,
        vec![op(
            "item-0001",
            clock(&[(&device.id, 2), (&other, 1)]),
            false,
            "cc",
        )],
    );
    assert_eq!(idempotent.status, 200);
    assert_eq!(idempotent.json()["applied"], json!(["item-0001"]));
    assert_eq!(idempotent.json()["conflicts"], json!([]));

    // Same clock, different payload cannot be ordered by the clock, so it is a
    // conflict too: the client must not silently lose one side.
    let same_clock = push(
        &server,
        &device,
        vec![op(
            "item-0001",
            clock(&[(&device.id, 2), (&other, 1)]),
            false,
            "dd",
        )],
    );
    assert_eq!(same_clock.status, 200);
    assert_eq!(same_clock.json()["applied"], json!([]));
    assert_eq!(same_clock.json()["conflicts"][0]["ciphertext"], "cc");

    // An older clock is ignored: the sender is behind and will pull.
    let older = push(
        &server,
        &device,
        vec![op("item-0001", clock(&[(&device.id, 1)]), false, "ee")],
    );
    assert_eq!(older.status, 200);
    assert_eq!(older.json()["applied"], json!([]));
    assert_eq!(older.json()["conflicts"], json!([]));
    assert_eq!(ops(&pull(&server, &device, "?since=2")).len(), 0);
}

#[test]
fn authentication_rejections() {
    let server = TestServer::start();
    let device = Device::new(1, "desktop");
    assert_eq!(create_account(&server, ACCOUNT, &device).status, 201);
    let target = "/v1/sync/state";

    let missing = request(&server, "GET", target, None, None, Some(PROTOCOL));
    assert_eq!(missing.status, 401);
    assert_eq!(missing.error_code(), "unauthorized");

    let malformed = request(
        &server,
        "GET",
        target,
        None,
        Some("Kestrel nope"),
        Some(PROTOCOL),
    );
    assert_eq!(malformed.status, 401);
    assert_eq!(malformed.error_code(), "unauthorized");

    let unknown = Device::new(9, "ghost");
    let header = header_for(
        &unknown.id,
        &device.signing,
        "GET",
        target,
        "",
        unix_now(),
        &nonce(),
    );
    let unknown_reply = request(&server, "GET", target, None, Some(&header), Some(PROTOCOL));
    assert_eq!(unknown_reply.status, 401);
    assert_eq!(unknown_reply.error_code(), "unknown_device");

    // The right device id with the wrong key: the signature cannot verify.
    let impostor = SigningKey::from_bytes(&[42u8; 32]);
    let header = header_for(
        &device.id,
        &impostor,
        "GET",
        target,
        "",
        unix_now(),
        &nonce(),
    );
    let bad = request(&server, "GET", target, None, Some(&header), Some(PROTOCOL));
    assert_eq!(bad.status, 401);
    assert_eq!(bad.error_code(), "bad_signature");

    // A signature over a different body does not cover this one.
    let header = header_for(
        &device.id,
        &device.signing,
        "GET",
        target,
        "{}",
        unix_now(),
        &nonce(),
    );
    let wrong_body = request(&server, "GET", target, None, Some(&header), Some(PROTOCOL));
    assert_eq!(wrong_body.status, 401);
    assert_eq!(wrong_body.error_code(), "bad_signature");

    let stale = header_for(
        &device.id,
        &device.signing,
        "GET",
        target,
        "",
        unix_now() - 400,
        &nonce(),
    );
    let stale_reply = request(&server, "GET", target, None, Some(&stale), Some(PROTOCOL));
    assert_eq!(stale_reply.status, 401);
    assert_eq!(stale_reply.error_code(), "stale_timestamp");

    let future = header_for(
        &device.id,
        &device.signing,
        "GET",
        target,
        "",
        unix_now() + 400,
        &nonce(),
    );
    let future_reply = request(&server, "GET", target, None, Some(&future), Some(PROTOCOL));
    assert_eq!(future_reply.status, 401);
    assert_eq!(future_reply.error_code(), "stale_timestamp");

    // Replay: the same signed request twice. The first is accepted, the second
    // is refused with a distinct code.
    let reused = header_for(
        &device.id,
        &device.signing,
        "GET",
        target,
        "",
        unix_now(),
        &nonce(),
    );
    let first = request(&server, "GET", target, None, Some(&reused), Some(PROTOCOL));
    assert_eq!(first.status, 200, "body: {}", first.body);
    let replayed = request(&server, "GET", target, None, Some(&reused), Some(PROTOCOL));
    assert_eq!(replayed.status, 401);
    assert_eq!(replayed.error_code(), "replay");
}

#[test]
fn routing_body_limit_and_protocol_version() {
    let server = TestServer::start();

    let huge = "x".repeat(Config::default().max_body + 1);
    let too_large = request(
        &server,
        "POST",
        "/v1/accounts",
        Some(&huge),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(too_large.status, 413, "body: {}", too_large.body);
    assert_eq!(too_large.error_code(), "body_too_large");

    let unknown = request(&server, "GET", "/v1/nope", None, None, Some(PROTOCOL));
    assert_eq!(unknown.status, 404);
    assert_eq!(unknown.error_code(), "not_found");

    let wrong_method = request(&server, "GET", "/v1/accounts", None, None, Some(PROTOCOL));
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.error_code(), "method_not_allowed");
    assert_eq!(wrong_method.allow.as_deref(), Some("POST"));

    let wrong_method = request(
        &server,
        "DELETE",
        "/v1/sync/push",
        None,
        None,
        Some(PROTOCOL),
    );
    assert_eq!(wrong_method.status, 405);
    assert_eq!(wrong_method.allow.as_deref(), Some("POST"));

    let future_protocol = request(&server, "POST", "/v1/accounts", Some("{}"), None, Some("2"));
    assert_eq!(
        future_protocol.status, 426,
        "body: {}",
        future_protocol.body
    );
    assert_eq!(future_protocol.error_code(), "unsupported_protocol");

    let malformed = request(
        &server,
        "POST",
        "/v1/accounts",
        Some("{not json"),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(malformed.status, 400);
    assert_eq!(malformed.error_code(), "invalid_body");

    let device = Device::new(1, "desktop");
    let unknown_field = json!({
        "account_id": ACCOUNT,
        "device_id": device.id,
        "device_signing_pub": device.signing_pub(),
        "device_agreement_pub": device.agreement_pub(),
        "device_name": device.name,
        "extra": true,
    })
    .to_string();
    let rejected = request(
        &server,
        "POST",
        "/v1/accounts",
        Some(&unknown_field),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(rejected.error_code(), "invalid_body");

    let bad_id = json!({
        "account_id": "short",
        "device_id": device.id,
        "device_signing_pub": device.signing_pub(),
        "device_agreement_pub": device.agreement_pub(),
        "device_name": device.name,
    })
    .to_string();
    let rejected = request(
        &server,
        "POST",
        "/v1/accounts",
        Some(&bad_id),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(rejected.status, 400);
    assert_eq!(rejected.error_code(), "invalid_field");

    // A small-order key can never verify anything (`verify_strict` refuses it),
    // so registering one would create a device that is broken from birth.
    let weak_key = format!("01{}", "00".repeat(31));
    let weak = json!({
        "account_id": "aa11223344556677889900aabbccddee",
        "device_id": device.id,
        "device_signing_pub": weak_key,
        "device_agreement_pub": device.agreement_pub(),
        "device_name": device.name,
    })
    .to_string();
    let rejected = request(
        &server,
        "POST",
        "/v1/accounts",
        Some(&weak),
        None,
        Some(PROTOCOL),
    );
    assert_eq!(rejected.status, 400, "body: {}", rejected.body);
    assert_eq!(rejected.error_code(), "invalid_field");

    // A body just under the limit is accepted by the size check and then
    // rejected for content, which proves the limit is exact and not a guess.
    assert_eq!(create_account(&server, ACCOUNT, &device).status, 201);
}

#[test]
fn a_v1_database_gains_revocation_without_losing_its_devices() {
    let db_path = temp_db_path();
    let blob_dir = db_path.with_extension("blobs");
    {
        // The v1 device table: no `revoked_at`. The service must add the column
        // in place and keep the row, because upgrading a live deployment cannot
        // mean re-enrolling every device.
        let conn = rusqlite::Connection::open(&db_path).expect("open old database");
        conn.execute_batch(
            "CREATE TABLE accounts (
                 account_id TEXT PRIMARY KEY,
                 created_at INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE devices (
                 device_id     TEXT PRIMARY KEY,
                 account_id    TEXT NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
                 signing_pub   BLOB NOT NULL,
                 agreement_pub BLOB NOT NULL,
                 name          TEXT NOT NULL,
                 created_at    INTEGER NOT NULL
             ) WITHOUT ROWID;
             CREATE TABLE meta (
                 key   TEXT PRIMARY KEY,
                 value TEXT NOT NULL
             ) WITHOUT ROWID;
             INSERT INTO meta(key, value) VALUES('schema_version', '1');
             INSERT INTO accounts(account_id, created_at) VALUES('00112233445566778899aabbccddeeff', 1);
             INSERT INTO devices
                 (device_id, account_id, signing_pub, agreement_pub, name, created_at)
             VALUES('0a1b2c3d4e5f60718293a4b5c6d7e8f9',
                    '00112233445566778899aabbccddeeff',
                    zeroblob(32), zeroblob(32), 'old desktop', 1);",
        )
        .expect("write the v1 shape");
    }

    let server = TestServer::start_with(Config {
        addr: "127.0.0.1:0".parse().expect("valid address"),
        blob_dir,
        db_path: db_path.clone(),
        ..Config::default()
    });

    let conn = rusqlite::Connection::open(&server.db_path).expect("open migrated database");
    let mut info = conn
        .prepare("PRAGMA table_info(devices)")
        .expect("devices schema");
    let columns: Vec<String> = info
        .query_map([], |row| row.get::<_, String>(1))
        .expect("column rows")
        .map(|column| column.expect("column"))
        .collect();
    assert!(
        columns.iter().any(|column| column == "revoked_at"),
        "the new column exists: {columns:?}"
    );
    let (name, revoked_at): (String, Option<i64>) = conn
        .query_row(
            "SELECT name, revoked_at FROM devices WHERE device_id = '0a1b2c3d4e5f60718293a4b5c6d7e8f9'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .expect("the v1 device survived");
    assert_eq!(name, "old desktop");
    assert_eq!(
        revoked_at, None,
        "an existing device is not retroactively revoked"
    );
    let version: String = conn
        .query_row(
            "SELECT value FROM meta WHERE key = 'schema_version'",
            [],
            |row| row.get(0),
        )
        .expect("schema version");
    assert_eq!(version, "2");
}

#[test]
fn schema_has_no_content_columns() {
    let server = TestServer::start();
    let device = Device::new(1, "desktop");
    assert_eq!(create_account(&server, ACCOUNT, &device).status, 201);
    let pushed = push(
        &server,
        &device,
        vec![op("item-0001", clock(&[(&device.id, 1)]), false, "0102")],
    );
    assert_eq!(pushed.status, 200, "body: {}", pushed.body);

    let connection = rusqlite::Connection::open(&server.db_path).expect("open the database");
    let mut items = connection
        .prepare("PRAGMA table_info(items)")
        .expect("items schema");
    let columns: Vec<String> = items
        .query_map([], |row| row.get::<_, String>(1))
        .expect("column rows")
        .map(|column| column.expect("column"))
        .collect();
    assert_eq!(
        columns,
        vec![
            "account_id",
            "item_id",
            "seq",
            "clock",
            "deleted",
            "blob",
            "size",
            "updated_at",
        ],
        "the items table is the one that carries vault data; it must stay opaque"
    );

    // The row points at a content-addressed blob; the ciphertext is on disk,
    // under a name derived from the ciphertext, and nowhere else.
    let hash: String = connection
        .query_row(
            "SELECT blob FROM items WHERE item_id = 'item-0001'",
            [],
            |row| row.get(0),
        )
        .expect("blob reference");
    assert_eq!(hash, hex::encode(Sha256::digest([0x01_u8, 0x02])));
    let blob_path = server.blob_dir.join(&hash[..2]).join(&hash);
    assert_eq!(
        std::fs::read(&blob_path).expect("blob file exists"),
        vec![0x01, 0x02]
    );

    // No table may grow a column that could hold a title, a URL, a username, a
    // category, a tag or a field name.
    let forbidden = [
        "title", "url", "username", "category", "tag", "field", "note",
    ];
    let mut tables = connection
        .prepare("SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'")
        .expect("table list");
    let names: Vec<String> = tables
        .query_map([], |row| row.get::<_, String>(0))
        .expect("table rows")
        .map(|name| name.expect("name"))
        .collect();
    assert!(!names.is_empty());
    for table in names {
        let mut info = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .expect("table info");
        let columns: Vec<String> = info
            .query_map([], |row| row.get::<_, String>(1))
            .expect("column rows")
            .map(|column| column.expect("column"))
            .collect();
        for column in columns {
            assert!(
                !forbidden.contains(&column.to_ascii_lowercase().as_str()),
                "{table}.{column} looks like content the server must never store"
            );
        }
    }
}
