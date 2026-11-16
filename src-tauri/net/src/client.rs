//! The signed transport and the endpoint methods.

use std::time::Duration;

use ed25519_dalek::SigningKey;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{normalise_id, BaseUrl, ClientConfig, ConfigError};
use crate::error::{ConflictCode, Error, TransportError, UnauthorizedCode};
use crate::signing;
use crate::types::{
    CreateAccountResponse, EnrollClaimResponse, PullResponse, PushRequest, PushResponse,
    StateResponse,
};

/// A connect that hangs for ten seconds is a wrong host, not a slow vault.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Per-read and per-write inactivity budget for one request.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// A device's connection to one sync service.
///
/// Cheap to hold for the life of the app: the underlying `ureq` agent pools
/// keep-alive connections. Every endpoint method takes `&self` and builds its
/// own timestamp, nonce and signature, so a caller cannot accidentally send a
/// request without authentication or reuse a nonce.
pub struct SyncClient {
    agent: ureq::Agent,
    base_url: BaseUrl,
    account_id: String,
    device_id: String,
    signing_key: SigningKey,
}

impl SyncClient {
    /// Validates the transport policy and the identity, then builds the agent.
    ///
    /// This is the only place that can refuse a configuration: an `http://`
    /// base URL to a non-loopback host without `allow_insecure`, a `base_url`
    /// that is not a bare origin, an id that is not 32 hex characters, or a
    /// weak Ed25519 key is an error here rather than a confusing `401` later.
    pub fn new(config: ClientConfig) -> Result<SyncClient, ConfigError> {
        let base_url = BaseUrl::parse(&config.base_url, config.allow_insecure)?;
        let account_id = normalise_id("account_id", &config.account_id)?;
        let device_id = normalise_id("device_id", &config.device_id)?;
        let signing_key = SigningKey::from_bytes(&config.signing_key);
        if signing_key.verifying_key().is_weak() {
            // The service refuses to register a key it could never verify, so
            // refusing it here is the only message the caller gets.
            return Err(ConfigError::WeakSigningKey);
        }

        let agent = ureq::AgentBuilder::new()
            // A redirect is not part of the contract and would take the signed
            // target somewhere it was not signed for; treat 3xx as a failure.
            .redirects(0)
            .timeout_connect(CONNECT_TIMEOUT)
            .timeout_read(IO_TIMEOUT)
            .timeout_write(IO_TIMEOUT)
            .build();

        Ok(SyncClient {
            agent,
            base_url,
            account_id,
            device_id,
            signing_key,
        })
    }

    /// The normalised origin this client talks to.
    pub fn base_url(&self) -> &str {
        self.base_url.as_str()
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    /// `POST /v1/accounts` — creates the account and this device, and registers
    /// `device_signing_pub` derived from the configured signing key.
    ///
    /// Unauthenticated by nature: this is the request that creates the identity
    /// everything else is signed with. A second call with the same ids is
    /// [`crate::ConflictCode::AccountExists`].
    pub fn create_account(
        &self,
        agreement_pub: [u8; 32],
        device_name: &str,
    ) -> Result<CreateAccountResponse, Error> {
        #[derive(Serialize)]
        struct Body<'a> {
            account_id: &'a str,
            device_id: &'a str,
            device_signing_pub: String,
            device_agreement_pub: String,
            device_name: &'a str,
        }

        let body = Body {
            account_id: &self.account_id,
            device_id: &self.device_id,
            device_signing_pub: hex::encode(self.signing_key.verifying_key().to_bytes()),
            device_agreement_pub: hex::encode(agreement_pub),
            device_name,
        };
        self.post("/v1/accounts", &body, false)
            .and_then(|body| decode(&body))
    }

    /// `POST /v1/enroll/offer` — an existing device offers a sealed account key
    /// to the device named by `new_device_id`.
    ///
    /// The client hashes `code` and base64-encodes `sealed` itself, so the code
    /// never reaches the service and a caller cannot put the wrong digest on
    /// the wire. `expires_at` is unix seconds, in the future and at most an
    /// hour away.
    pub fn enroll_offer(
        &self,
        new_device_id: &str,
        code: &str,
        sealed: &[u8],
        expires_at: i64,
    ) -> Result<(), Error> {
        use base64::Engine as _;
        #[derive(Serialize)]
        struct Body<'a> {
            code_hash: String,
            sealed: String,
            expires_at: i64,
            new_device_id: &'a str,
        }

        let body = Body {
            code_hash: hex::encode(Sha256::digest(code.as_bytes())),
            sealed: base64::engine::general_purpose::STANDARD.encode(sealed),
            expires_at,
            new_device_id,
        };
        self.post("/v1/enroll/offer", &body, true)
            .and_then(|body| decode_empty(&body))
    }

    /// `POST /v1/enroll/claim` — the new device redeems the code and receives
    /// the sealed account key. Unauthenticated: this device has no registered
    /// key until the offering device acks.
    pub fn enroll_claim(
        &self,
        code: &str,
        agreement_pub: [u8; 32],
        device_name: &str,
    ) -> Result<EnrollClaimResponse, Error> {
        #[derive(Serialize)]
        struct Body<'a> {
            code: &'a str,
            device_id: &'a str,
            device_signing_pub: String,
            device_agreement_pub: String,
            device_name: &'a str,
        }

        let body = Body {
            code,
            device_id: &self.device_id,
            device_signing_pub: hex::encode(self.signing_key.verifying_key().to_bytes()),
            device_agreement_pub: hex::encode(agreement_pub),
            device_name,
        };
        self.post("/v1/enroll/claim", &body, false)
            .and_then(|body| decode(&body))
    }

    /// `POST /v1/enroll/ack` — the existing device confirms a claim, which is
    /// what creates the new device row. Idempotent: a retry returns `200 {}`.
    pub fn enroll_ack(&self, new_device_id: &str) -> Result<(), Error> {
        #[derive(Serialize)]
        struct Body<'a> {
            new_device_id: &'a str,
        }

        self.post("/v1/enroll/ack", &Body { new_device_id }, true)
            .and_then(|body| decode_empty(&body))
    }

    /// `POST /v1/sync/push` — applies a batch atomically and reports conflicts.
    pub fn push(&self, request: PushRequest) -> Result<PushResponse, Error> {
        self.post("/v1/sync/push", &request, true)
            .and_then(|body| decode(&body))
    }

    /// `GET /v1/sync/pull` — reads the change log after `since` (exclusive).
    /// `limit` is clamped by the service to 1000; `None` leaves its default.
    pub fn pull(&self, since: u64, limit: Option<u64>) -> Result<PullResponse, Error> {
        let target = match limit {
            Some(limit) => format!("/v1/sync/pull?since={since}&limit={limit}"),
            None => format!("/v1/sync/pull?since={since}"),
        };
        self.get(&target).and_then(|body| decode(&body))
    }

    /// `GET /v1/sync/state` — the account summary: devices, item count, bytes.
    pub fn state(&self) -> Result<StateResponse, Error> {
        self.get("/v1/sync/state").and_then(|body| decode(&body))
    }

    /// `DELETE /v1/devices/<id>` — withdraw one device's access to the account.
    ///
    /// The id is validated and normalised here so the exact bytes that are
    /// signed are exactly the bytes routed, and the path segment cannot contain
    /// a delimiter. The service refuses a device revoking itself, so the caller
    /// cannot lock the account out through this method.
    pub fn revoke_device(&self, device_id: &str) -> Result<(), Error> {
        let target = normalise_id("device_id", device_id).map_err(Error::from)?;
        self.execute("DELETE", &format!("/v1/devices/{target}"), None, true)
            .and_then(|body| decode_empty(&body))
    }

    fn post<T: Serialize>(
        &self,
        target: &str,
        body: &T,
        authenticated: bool,
    ) -> Result<String, Error> {
        let bytes = serde_json::to_vec(body)
            .map_err(|error| Error::Transport(TransportError::Encode(error)))?;
        self.execute("POST", target, Some(&bytes), authenticated)
    }

    fn get(&self, target: &str) -> Result<String, Error> {
        self.execute("GET", target, None, true)
    }

    /// Sends one request and returns the body of a `2xx` answer. Everything
    /// else leaves as a typed [`Error`].
    fn execute(
        &self,
        method: &str,
        target: &str,
        body: Option<&[u8]>,
        authenticated: bool,
    ) -> Result<String, Error> {
        let url = format!("{}{target}", self.base_url.as_str());
        let mut request = self
            .agent
            .request(method, &url)
            .set(signing::PROTOCOL_HEADER, signing::PROTOCOL_VERSION);

        if authenticated {
            let authorization = signing::authorization(
                &self.signing_key,
                &self.device_id,
                method,
                target,
                body.unwrap_or(&[]),
            );
            request = request.set("Authorization", &authorization);
        }

        let result = match body {
            Some(bytes) => {
                request = request.set("Content-Type", "application/json");
                request.send_bytes(bytes)
            }
            None => request.call(),
        };

        let (status, protocol, text) = match result {
            Ok(response) => read_response(response)?,
            // ureq reports every 4xx/5xx as a status error, body included.
            Err(ureq::Error::Status(_, response)) => read_response(response)?,
            Err(ureq::Error::Transport(error)) => {
                return Err(Error::Transport(TransportError::Io(error)))
            }
        };

        if (200..300).contains(&status) {
            return Ok(text);
        }
        Err(classify(status, protocol, &text))
    }
}

/// Reads the status, the advertised protocol version and the body. The
/// protocol header is captured before the response is consumed.
fn read_response(
    response: ureq::Response,
) -> Result<(u16, Option<String>, String), TransportError> {
    let status = response.status();
    let protocol = response
        .header(signing::PROTOCOL_HEADER)
        .map(str::to_owned);
    let text = response.into_string()?;
    Ok((status, protocol, text))
}

fn decode<T: DeserializeOwned>(body: &str) -> Result<T, Error> {
    serde_json::from_str(body).map_err(|error| Error::Transport(TransportError::Decode(error)))
}

/// The endpoints that answer `{}` still have to be checked for JSON: a proxy
/// returning an HTML page with `200` is not success.
fn decode_empty(body: &str) -> Result<(), Error> {
    #[derive(Deserialize)]
    struct Empty {}

    decode::<Empty>(body).map(|_| ())
}

/// The `error` body, as `PROTOCOL.md` defines it.
#[derive(Deserialize)]
struct ErrorBody {
    error: String,
    message: String,
}

/// Maps a non-2xx answer onto the typed vocabulary. The stable discriminator
/// is `error`; the message is the service's own text, preserved for the caller.
fn classify(status: u16, server_protocol: Option<String>, body: &str) -> Error {
    let parsed = serde_json::from_str::<ErrorBody>(body).ok();
    let (code, message) = match parsed {
        Some(error) => (error.error, error.message),
        // A proxy or a broken service may answer with something that is not
        // the protocol's error object; keep whatever text it gave us.
        None => ("unknown".to_string(), body.trim().to_string()),
    };
    let message = if message.is_empty() {
        format!("the service answered HTTP {status} without a message")
    } else {
        message
    };

    match status {
        400 | 403 => Error::Rejected { code, message },
        401 => Error::Unauthorized {
            code: UnauthorizedCode::from(code.as_str()),
            message,
        },
        409 => Error::Conflict {
            code: ConflictCode::from(code.as_str()),
            message,
        },
        426 => Error::ProtocolVersion {
            code,
            server_protocol,
            message,
        },
        _ => Error::Server {
            status,
            code,
            message,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unauthorized_codes_are_typed_and_preserved() {
        match classify(
            401,
            None,
            r#"{"error":"bad_signature","message":"the signature does not verify"}"#,
        ) {
            Error::Unauthorized { code, message } => {
                assert_eq!(code, UnauthorizedCode::BadSignature);
                assert_eq!(message, "the signature does not verify");
            }
            other => panic!("{other}"),
        }

        match classify(
            401,
            None,
            r#"{"error":"something_new","message":"from a newer minor version"}"#,
        ) {
            Error::Unauthorized { code, .. } => {
                assert_eq!(code, UnauthorizedCode::Other("something_new".into()));
                assert_eq!(code.as_str(), "something_new");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn account_exists_is_its_own_conflict() {
        match classify(
            409,
            None,
            r#"{"error":"account_exists","message":"this account id is already registered"}"#,
        ) {
            Error::Conflict { code, .. } => {
                assert_eq!(code, ConflictCode::AccountExists);
            }
            other => panic!("{other}"),
        }

        match classify(
            409,
            None,
            r#"{"error":"device_conflict","message":"this device id is already registered"}"#,
        ) {
            Error::Conflict { code, .. } => assert_eq!(code, ConflictCode::DeviceConflict),
            other => panic!("{other}"),
        }
    }

    #[test]
    fn a_400_is_rejected_with_the_servers_code() {
        match classify(
            400,
            None,
            r#"{"error":"expired_code","message":"this enrolment code has expired"}"#,
        ) {
            Error::Rejected { code, message } => {
                assert_eq!(code, "expired_code");
                assert_eq!(message, "this enrolment code has expired");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn a_426_reports_the_servers_protocol_version() {
        match classify(
            426,
            Some("1".into()),
            r#"{"error":"unsupported_protocol","message":"this server speaks protocol 1"}"#,
        ) {
            Error::ProtocolVersion {
                code,
                server_protocol,
                message,
            } => {
                assert_eq!(code, "unsupported_protocol");
                assert_eq!(server_protocol.as_deref(), Some("1"));
                assert_eq!(message, "this server speaks protocol 1");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn everything_else_is_a_server_error_with_its_status() {
        match classify(
            500,
            None,
            r#"{"error":"internal","message":"the service could not complete the request"}"#,
        ) {
            Error::Server {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 500);
                assert_eq!(code, "internal");
                assert_eq!(message, "the service could not complete the request");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn a_non_json_failure_keeps_the_raw_text() {
        match classify(502, None, "upstream is down") {
            Error::Server {
                status,
                code,
                message,
            } => {
                assert_eq!(status, 502);
                assert_eq!(code, "unknown");
                assert_eq!(message, "upstream is down");
            }
            other => panic!("{other}"),
        }
    }

    #[test]
    fn an_empty_failure_body_gets_a_readable_message() {
        match classify(503, None, "") {
            Error::Server { message, .. } => {
                assert!(message.contains("503"), "{message}");
            }
            other => panic!("{other}"),
        }
    }
}
