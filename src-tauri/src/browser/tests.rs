//! Browser-bridge tests: origin grammar, rule defaults, token scope, and the
//! ACL the kernel actually applied to the token file.
//!
//! The policy tests go through [`crate::sdk::protocol::respond`] with a
//! backend that consults a real `browser_sites` table, so a refusal is observed
//! on the wire (`{"ok":false,"error":...}`) rather than as a private return
//! value.

use super::*;
use crate::sdk::protocol::{
    self, Auth, BrowserItem, BrowserStatus, ItemMeta, Request, RunOutput, SdkBackend, SdkError,
    SecretItem,
};
use kestrel_core::store::Store;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

const PIPE: &str = r"\\.\pipe\kestrel-sdk";

struct TempStore {
    path: PathBuf,
    /// `Mutex`: `SdkBackend` is `Send + Sync`, and `rusqlite::Connection`
    /// is neither. The lock also matches how the real backend serialises
    /// access through the session.
    store: Arc<Mutex<Store>>,
}

impl TempStore {
    fn new(tag: &str) -> TempStore {
        let path = std::env::temp_dir().join(format!(
            "kestrel-browser-{tag}-{}-{}.db",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let store = Store::open(&path).expect("store opens");
        TempStore {
            path,
            store: Arc::new(Mutex::new(store)),
        }
    }

    fn rule(&self, origin: &str) -> String {
        self.store
            .lock()
            .unwrap()
            .browser_rule(origin)
            .expect("rule reads")
    }

    fn set_rule(&self, origin: &str, mode: &str) {
        self.store
            .lock()
            .unwrap()
            .set_browser_rule(origin, mode)
            .expect("rule writes");
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
        let _ = std::fs::remove_file(self.path.with_extension("db-wal"));
        let _ = std::fs::remove_file(self.path.with_extension("db-shm"));
    }
}

/// Backend double whose browser policy is the real store's rule.
struct PolicyBackend {
    store: Arc<Mutex<Store>>,
}

impl SdkBackend for PolicyBackend {
    fn unlocked(&self) -> bool {
        true
    }

    fn items(&self) -> Result<Vec<ItemMeta>, SdkError> {
        Ok(Vec::new())
    }

    fn copy(&self, _item_id: &str, _field: &str) -> Result<(), SdkError> {
        Ok(())
    }

    fn run(&self, _argv: &[String], _env: &[protocol::EnvBinding]) -> Result<RunOutput, SdkError> {
        Err(SdkError::Internal("not used".into()))
    }

    fn secrets(&self) -> Result<Vec<SecretItem>, SdkError> {
        Ok(Vec::new())
    }

    fn reveal(&self, _client: &str, _item_id: &str, _field: &str) -> Result<String, SdkError> {
        Err(SdkError::NotGranted)
    }

    fn browser_status(&self) -> Result<BrowserStatus, SdkError> {
        Ok(BrowserStatus {
            installed: true,
            host: "com.kestrel.bridge".into(),
            rules: 1,
            extension_id: EXTENSION_ID.into(),
            token_present: true,
        })
    }

    fn browser_mode(&self, origin: &str) -> Result<String, SdkError> {
        self.store
            .lock()
            .unwrap()
            .browser_rule(origin)
            .map_err(|error| SdkError::BadRequest(error.to_string()))
    }

    fn browser_items(&self, _origin: &str) -> Result<Vec<BrowserItem>, SdkError> {
        Ok(Vec::new())
    }

    fn browser_reveal(
        &self,
        origin: &str,
        _item_id: &str,
        _field: &str,
    ) -> Result<String, SdkError> {
        match self.store.lock().unwrap().browser_rule(origin) {
            Ok(mode) if mode == "fill" => Ok("value".into()),
            Ok(_) => Err(SdkError::NotGranted),
            Err(error) => Err(SdkError::BadRequest(error.to_string())),
        }
    }
}

fn request(line: &str) -> Request {
    protocol::parse_request(line.as_bytes()).expect("request parses")
}

/// The host binary a test should spawn. A lib-test binary can live under
/// `target/debug/build/<pkg>/<hash>/out`, so walk up until a `target*/` level
/// has `kestrel-nmhost.exe`. `KESTREL_NMHOST_PATH` wins when set.
fn built_host() -> PathBuf {
    if let Some(explicit) = std::env::var_os("KESTREL_NMHOST_PATH") {
        return PathBuf::from(explicit);
    }
    let mut dir = std::env::current_exe().expect("test executable");
    loop {
        let candidate = dir.join("kestrel-nmhost.exe");
        if candidate.is_file() {
            return candidate;
        }
        if !dir.pop() {
            break;
        }
    }
    PathBuf::from("kestrel-nmhost.exe")
}

fn reveal(auth: &Auth, backend: &dyn SdkBackend, token: &str, origin: &str) -> serde_json::Value {
    protocol::respond(
        auth,
        backend,
        &request(&format!(
            r#"{{"op":"browser.reveal","token":"{token}","origin":"{origin}","id":"item-1","field":"field-2"}}"#
        )),
        PIPE,
    )
}

#[test]
fn one_origin_has_one_spelling() {
    let cases = [
        ("https://Example.COM:443", "https://example.com"),
        ("https://Example.COM:443/login?next=1", "https://example.com"),
        ("http://Example.com:80/", "http://example.com"),
        (" example.com/path ", "https://example.com"),
        ("https://example.com.", "https://example.com"),
        ("https://example.com:8443/x", "https://example.com:8443"),
    ];
    for (raw, expected) in cases {
        assert_eq!(
            Store::canonical_browser_origin(raw).as_deref(),
            Some(expected),
            "{raw}"
        );
    }
    assert_eq!(
        Store::canonical_browser_origin("https://Example.COM:443").as_deref(),
        Store::canonical_browser_origin("https://example.com").as_deref(),
        "the exact pair named in the acceptance case"
    );
    for raw in ["ftp://example.com", "https://user@example.com", "https://x:0", ""] {
        assert_eq!(Store::canonical_browser_origin(raw), None, "{raw}");
    }
}

#[test]
fn a_missing_rule_is_ask_and_off_suppresses_fill() {
    let temp = TempStore::new("rules");
    assert_eq!(
        temp.rule("https://example.com"),
        "ask",
        "no row is ask, never fill"
    );
    temp.set_rule("https://Example.COM:443", "off");
    assert_eq!(temp.rule("https://example.com"), "off");
    temp.set_rule("https://example.com", "fill");
    assert_eq!(temp.rule("https://example.com"), "fill");
    assert_eq!(temp.store.lock().unwrap().browser_rules().unwrap().len(), 1);
    temp.store
        .lock()
        .unwrap()
        .clear_browser_rule("https://example.com")
        .unwrap();
    assert_eq!(temp.rule("https://example.com"), "ask");
}

#[test]
fn cli_and_mcp_tokens_are_forbidden() {
    let temp = TempStore::new("scope");
    let backend = PolicyBackend {
        store: Arc::clone(&temp.store),
    };
    let auth = Auth::new();
    let cli = auth.pair();
    let mcp = auth.pair_mcp("editor", Vec::new());

    for token in [cli, mcp] {
        let response = reveal(&auth, &backend, &token, "https://example.com");
        assert_eq!(response["ok"], serde_json::json!(false), "{token}");
        assert_eq!(
            response["error"],
            serde_json::json!("forbidden"),
            "a token of another scope must not reach browser.reveal: {response}"
        );
    }
}

#[test]
fn a_browser_token_without_fill_is_not_granted() {
    let temp = TempStore::new("policy");
    let backend = PolicyBackend {
        store: Arc::clone(&temp.store),
    };
    let auth = Auth::new();
    let token = auth.pair_browser();

    // No row: ask. That is the acceptance case "a Browser token with no rule".
    let response = reveal(&auth, &backend, &token, "https://example.com");
    assert_eq!(response["ok"], serde_json::json!(false), "{response}");
    assert_eq!(response["error"], serde_json::json!("not_granted"), "{response}");

    // Explicit off: still nothing.
    backend
        .store
        .lock()
        .unwrap()
        .set_browser_rule("https://example.com", "off")
        .unwrap();
    let response = reveal(&auth, &backend, &token, "https://example.com");
    assert_eq!(response["error"], serde_json::json!("not_granted"), "{response}");

    // Fill: the same request succeeds.
    backend
        .store
        .lock()
        .unwrap()
        .set_browser_rule("https://example.com", "fill")
        .unwrap();
    let response = reveal(&auth, &backend, &token, "https://example.com");
    assert_eq!(response["ok"], serde_json::json!(true), "{response}");
    assert_eq!(response["value"], serde_json::json!("value"));
}

#[test]
fn a_bad_origin_is_a_request_error() {
    let temp = TempStore::new("origin");
    let backend = PolicyBackend {
        store: Arc::clone(&temp.store),
    };
    let auth = Auth::new();
    let token = auth.pair_browser();
    let response = reveal(&auth, &backend, &token, "ftp://example.com");
    assert_eq!(response["ok"], serde_json::json!(false), "{response}");
    assert_eq!(
        response["error"],
        serde_json::json!("bad_request"),
        "{response}"
    );
}

#[test]
fn the_token_file_is_user_only() {
    let dir = std::env::temp_dir().join(format!(
        "kestrel-bridge-token-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    let path = dir.join("bridge.token");
    super::token::write(&path, "0123456789abcdef").expect("token write");
    assert_eq!(
        super::token::read(&path).unwrap().as_deref(),
        Some("0123456789abcdef")
    );
    let dacl = super::token::dacl_sddl(&path).expect("read DACL");
    assert!(dacl.starts_with("D:P"), "DACL must be protected: {dacl}");
    assert_eq!(
        dacl.matches("(A;;").count(),
        1,
        "exactly one ACE for the current user: {dacl}"
    );
    assert!(
        dacl.contains("S-1-5-"),
        "the ACE names a user SID: {dacl}"
    );
    assert!(
        !dacl.contains(";;;WD)") && !dacl.contains(";;;BU)") && !dacl.contains(";;;AU)"),
        "Everyone/Users/Authenticated Users must not appear: {dacl}"
    );
    assert!(super::token::remove(&path).unwrap());
    assert!(!super::token::remove(&path).unwrap(), "idempotent");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_manifest_names_exactly_one_extension() {
    let manifest = super::install::manifest(
        std::path::Path::new(r"C:\Apps\Kestrel\kestrel-nmhost.exe"),
        EXTENSION_ID,
    );
    assert_eq!(manifest["name"], serde_json::json!("com.kestrel.bridge"));
    assert_eq!(manifest["type"], serde_json::json!("stdio"));
    assert_eq!(
        manifest["allowed_origins"],
        serde_json::json!([format!("chrome-extension://{EXTENSION_ID}/")])
    );
    assert_eq!(
        manifest["path"],
        serde_json::json!(r"C:\Apps\Kestrel\kestrel-nmhost.exe")
    );
}

/// A real live check, kept ignored because it owns the production pipe name
/// `\\.\pipe\kestrel-sdk` and needs a built `kestrel-nmhost.exe`.
///
/// Run it with:
/// `cargo build -p kestrel-nmhost --offline` then
/// `tools/test-shell.ps1 -Filter browser::tests::live_bridge -- --ignored`.
///
/// It starts the same `sdk::pipe::Server` the app runs, against a real
/// unlocked `VaultState` and a real `browser_sites` row, writes the token file,
/// and drives the actual host binary over stdin/stdout with framed JSON. That
/// exercises host framing, token injection, the pipe, the Browser scope, the
/// origin rule, the item/origin match, and the audit row. The only thing it
/// does not exercise is the Tauri window (the GUI cannot be unlocked in this
/// environment without a person at the keyboard).
#[test]
#[ignore]
fn live_bridge() {
    use crate::sdk::pipe::{Server, Shared};
    use crate::sdk::protocol::{self, Auth};
    use kestrel_core::hello::{HelloError, Mechanism, Protector};
    use kestrel_core::model::{Category, Item};
    use kestrel_core::session::VaultState;
    use std::io::{Read, Write};
    use std::process::{Command, Stdio};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    struct UnavailableProtector;

    impl Protector for UnavailableProtector {
        fn probe(&self) -> Result<Mechanism, HelloError> {
            Err(HelloError::Unavailable("not used in this check".into()))
        }
        fn protect(&self, _name: &str, _secret: &[u8]) -> Result<Vec<u8>, HelloError> {
            Err(HelloError::Unavailable("not used in this check".into()))
        }
        fn unprotect(&self, _name: &str, _blob: &[u8]) -> Result<kestrel_core::crypto::SymKey, HelloError> {
            Err(HelloError::Unavailable("not used in this check".into()))
        }
        fn forget(&self, _name: &str) -> Result<(), HelloError> {
            Ok(())
        }
        fn has_key(&self, _name: &str) -> bool {
            false
        }
    }

    struct LiveBackend {
        state: Arc<VaultState>,
    }

    impl SdkBackend for LiveBackend {
        fn unlocked(&self) -> bool {
            !self.state.is_locked()
        }
        fn items(&self) -> Result<Vec<ItemMeta>, SdkError> {
            Ok(Vec::new())
        }
        fn copy(&self, _item_id: &str, _field: &str) -> Result<(), SdkError> {
            Ok(())
        }
        fn run(
            &self,
            _argv: &[String],
            _env: &[protocol::EnvBinding],
        ) -> Result<RunOutput, SdkError> {
            Err(SdkError::Internal("not used".into()))
        }
        fn secrets(&self) -> Result<Vec<SecretItem>, SdkError> {
            Ok(Vec::new())
        }
        fn reveal(&self, _client: &str, _item_id: &str, _field: &str) -> Result<String, SdkError> {
            Err(SdkError::NotGranted)
        }
        fn browser_status(&self) -> Result<BrowserStatus, SdkError> {
            let rules = self
                .state
                .browser_rules()
                .map_err(|error| SdkError::Internal(error.to_string()))?
                .len();
            let snapshot = super::snapshot(rules);
            Ok(BrowserStatus {
                installed: snapshot.installed,
                host: snapshot.host_name,
                rules,
                extension_id: snapshot.extension_id,
                token_present: snapshot.token_present,
            })
        }
        fn browser_mode(&self, origin: &str) -> Result<String, SdkError> {
            self.state
                .browser_rule(origin)
                .map_err(|error| SdkError::BadRequest(error.to_string()))
        }
        fn browser_items(&self, origin: &str) -> Result<Vec<BrowserItem>, SdkError> {
            Ok(self
                .state
                .browser_items(origin)
                .map_err(|error| SdkError::Internal(error.to_string()))?
                .into_iter()
                .map(|item| BrowserItem {
                    id: item.id,
                    title: item.title,
                    category: item.category,
                    fields: item
                        .fields
                        .into_iter()
                        .map(|field| protocol::BrowserField {
                            id: field.id,
                            label: field.label,
                            kind: field.kind,
                        })
                        .collect(),
                })
                .collect())
        }
        fn browser_reveal(
            &self,
            origin: &str,
            item_id: &str,
            field: &str,
        ) -> Result<String, SdkError> {
            self.state
                .browser_reveal(origin, item_id, field)
                .map_err(|error| match error {
                    kestrel_core::session::VaultError::NotGranted => SdkError::NotGranted,
                    kestrel_core::session::VaultError::Locked => SdkError::Locked,
                    kestrel_core::session::VaultError::NotFound
                    | kestrel_core::session::VaultError::FieldNotFound => SdkError::NotFound,
                    other => SdkError::Internal(other.to_string()),
                })
        }
    }

    fn send(child: &mut std::process::Child, value: &serde_json::Value) -> serde_json::Value {
        let body = serde_json::to_vec(value).unwrap();
        let stdin = child.stdin.as_mut().expect("stdin");
        stdin
            .write_all(&(body.len() as u32).to_le_bytes())
            .expect("prefix");
        stdin.write_all(&body).expect("body");
        stdin.flush().expect("flush");

        let stdout = child.stdout.as_mut().expect("stdout");
        let mut prefix = [0u8; 4];
        stdout.read_exact(&mut prefix).expect("response prefix");
        let length = u32::from_le_bytes(prefix) as usize;
        let mut response = vec![0u8; length];
        stdout.read_exact(&mut response).expect("response body");
        serde_json::from_slice(&response).expect("response json")
    }

    let dir = std::env::temp_dir().join(format!(
        "kestrel-live-bridge-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("kestrel.db");
    let state = Arc::new(
        VaultState::open_with_protector(db, Box::new(UnavailableProtector)).expect("vault opens"),
    );
    state.create("correct horse battery staple").expect("vault created");

    let mut item = Item::new(Category::Login, "Bank".into());
    item.urls = vec!["https://Example.com/login".into()];
    for field in &mut item.fields {
        match field.kind.as_str() {
            "username" => field.value = "alice".into(),
            "password" => field.value = "s3cret-value".into(),
            "url" => field.value = "https://example.com/login".into(),
            _ => {}
        }
    }
    let password_field = item
        .fields
        .iter()
        .find(|field| field.kind == "password")
        .unwrap()
        .id
        .clone();
    let item_id = item.id.clone();
    state.save(item).expect("item saved");
    state
        .browser_set_rule("https://EXAMPLE.com:443", "fill")
        .expect("rule");
    state
        .browser_set_rule("https://blocked.example", "off")
        .expect("off rule");

    let auth = Arc::new(Auth::new());
    let token = auth.pair_browser();
    let token_file = dir.join("bridge.token");
    super::token::write(&token_file, &token).expect("token file");

    let shared = Arc::new(Shared {
        backend: Arc::new(LiveBackend {
            state: Arc::clone(&state),
        }),
        auth,
        stop: Arc::new(AtomicBool::new(false)),
    });
    let server = Server::start(Arc::clone(&shared)).expect("the app pipe is free");

    let host = built_host();
    assert!(host.is_file(), "build the host first: {}", host.display());
    let mut child = Command::new(&host)
        .env("KESTREL_BRIDGE_TOKEN_FILE", &token_file)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .expect("host starts");

    let listing = send(
        &mut child,
        &serde_json::json!({
            "op": "browser.items",
            "origin": "https://Example.COM:443",
            "token": "a token the extension invented",
        }),
    );
    eprintln!("browser.items -> {listing}");
    assert_eq!(listing["ok"], serde_json::json!(true), "{listing}");
    assert_eq!(listing["mode"], serde_json::json!("fill"));
    assert_eq!(listing["items"][0]["title"], serde_json::json!("Bank"));

    let revealed = send(
        &mut child,
        &serde_json::json!({
            "op": "browser.reveal",
            "origin": "https://example.com",
            "id": item_id,
            "field": password_field,
        }),
    );
    eprintln!("browser.reveal -> {revealed}");
    assert_eq!(revealed["ok"], serde_json::json!(true), "{revealed}");
    assert_eq!(revealed["value"], serde_json::json!("s3cret-value"));

    let refused = send(
        &mut child,
        &serde_json::json!({
            "op": "browser.reveal",
            "origin": "https://blocked.example",
            "id": item_id,
            "field": password_field,
        }),
    );
    eprintln!("browser.reveal (off) -> {refused}");
    assert_eq!(refused["error"], serde_json::json!("not_granted"));

    let audit = state.mcp_audit(10).expect("audit");
    assert_eq!(
        audit[0].client, "browser:https://example.com",
        "the reveal was recorded: {audit:?}"
    );
    eprintln!("audit[0] -> {:?}", audit[0]);

    let _ = child.kill();
    let _ = child.wait();
    drop(server);
    drop(shared);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Seed a throwaway vault in the real app-data directory for a GUI live check.
///
/// This is destructive by design, so it refuses to run unless
/// `KESTREL_LIVE_APPDATA=1` is set **and** no `kestrel.db` is present: the
/// caller moves the real directory aside first and restores it afterwards.
/// It also writes the token file and registers the native host, which is what
/// Settings → Browser would do with a mouse.
#[test]
#[ignore]
fn live_app_seed() {
    use kestrel_core::hello::{HelloError, Mechanism, Protector};
    use kestrel_core::model::{Category, Item};
    use kestrel_core::session::VaultState;

    struct UnavailableProtector;

    impl Protector for UnavailableProtector {
        fn probe(&self) -> Result<Mechanism, HelloError> {
            Err(HelloError::Unavailable("not used in this check".into()))
        }
        fn protect(&self, _name: &str, _secret: &[u8]) -> Result<Vec<u8>, HelloError> {
            Err(HelloError::Unavailable("not used in this check".into()))
        }
        fn unprotect(
            &self,
            _name: &str,
            _blob: &[u8],
        ) -> Result<kestrel_core::crypto::SymKey, HelloError> {
            Err(HelloError::Unavailable("not used in this check".into()))
        }
        fn forget(&self, _name: &str) -> Result<(), HelloError> {
            Ok(())
        }
        fn has_key(&self, _name: &str) -> bool {
            false
        }
    }

    if std::env::var("KESTREL_LIVE_APPDATA").as_deref() != Ok("1") {
        panic!("set KESTREL_LIVE_APPDATA=1 and move the real data directory aside first");
    }
    let dir = super::install::data_dir().expect("app data directory");
    std::fs::create_dir_all(&dir).expect("app data directory creates");
    if dir.join("kestrel.db").exists() {
        panic!("refusing to overwrite an existing vault at {}", dir.display());
    }

    let state =
        VaultState::open_with_protector(dir.join("kestrel.db"), Box::new(UnavailableProtector))
            .expect("vault opens");
    state
        .create("correct horse battery staple")
        .expect("vault created");
    let mut item = Item::new(Category::Login, "Example Bank".into());
    item.urls = vec!["https://example.com/login".into()];
    for field in &mut item.fields {
        match field.kind.as_str() {
            "username" => field.value = "audit-user".into(),
            "password" => field.value = "audit-secret".into(),
            "url" => field.value = "https://example.com/login".into(),
            _ => {}
        }
    }
    state.save(item).expect("item saved");
    state
        .browser_set_rule("https://example.com", "fill")
        .expect("rule");

    let auth = crate::sdk::protocol::Auth::new();
    let token = auth.pair_browser();
    super::token::write(&dir.join("bridge.token"), &token).expect("token file");

    let host = built_host();
    std::env::set_var("KESTREL_NMHOST_PATH", &host);
    super::install::register(super::EXTENSION_ID).expect("host registers");
    eprintln!(
        "seeded {} (host {}, token file {})",
        dir.display(),
        host.display(),
        dir.join("bridge.token").display()
    );
}
