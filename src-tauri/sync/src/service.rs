//! Routing, authentication and the handlers.
//!
//! [`App::handle`] is synchronous: it is called from a blocking task, so a slow
//! SQLite write never stalls the HTTP reactor. Everything a handler needs is in
//! [`RequestParts`], and every failure leaves through [`ApiError`], which has
//! exactly one rendering — a JSON body and a status.

use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use http::{header, HeaderValue, Method, Response, StatusCode};
use http_body_util::Full;
use hyper::body::Bytes;
use sha2::{Digest, Sha256};

use crate::api::{
    self, AckRequest, ApiError, ClaimRequest, ClaimView, ConflictView, CreateAccountRequest,
    DeviceView, ErrorView, OfferRequest, PushRequest, PushView, RevokeView, StateView,
};
use crate::auth::{self, AuthError, ReplayCache, MAX_SKEW_SECS};
use crate::config::Config;
use crate::db::{
    self, AckOutcome, ClaimError, CreateAccount, OfferOutcome, RevokeOutcome, Store, StoreError,
};

pub const PULL_DEFAULT_LIMIT: u64 = 200;
pub const PULL_MAX_LIMIT: u64 = 1000;
/// A nonce only needs to outlive the timestamp window; see [`MAX_SKEW_SECS`].
pub const REPLAY_WINDOW_SECS: i64 = MAX_SKEW_SECS * 2;
/// Per-device nonce memory. A device that makes more than this within the
/// window loses its oldest entries, which can only cost it a re-sent request.
pub const REPLAY_PER_DEVICE: usize = 4096;

const PROTOCOL_HEADER: &str = "x-kestrel-protocol";
pub const PROTOCOL_VERSION: &str = "1";

/// One request, already drained from the socket and bounded by the body limit.
#[derive(Debug)]
pub struct RequestParts {
    pub method: Method,
    pub target: String,
    pub protocol: Option<String>,
    pub authorization: Option<String>,
    pub body: Vec<u8>,
}

#[derive(Debug)]
struct Account {
    account_id: String,
    device_id: String,
}

pub struct App {
    store: Mutex<Store>,
    replay: Mutex<ReplayCache>,
    config: Config,
}

impl App {
    pub fn new(store: Store, replay: ReplayCache, config: Config) -> App {
        App {
            store: Mutex::new(store),
            replay: Mutex::new(replay),
            config,
        }
    }

    pub fn max_body(&self) -> usize {
        self.config.max_body
    }

    pub fn handle(&self, request: RequestParts) -> Response<Full<Bytes>> {
        match self.route(request) {
            Ok(response) => response,
            Err(error) => error_response(&error),
        }
    }

    fn store(&self) -> MutexGuard<'_, Store> {
        // A panic while holding the store lock cannot have written a partial
        // transaction (SQLite would have rolled it back), so recovering the
        // guard is safe and keeps one bad request from wedging the service.
        self.store
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn replay(&self) -> MutexGuard<'_, ReplayCache> {
        self.replay
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn route(&self, request: RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        check_protocol(request.protocol.as_deref())?;

        let (path, query) = match request.target.split_once('?') {
            Some((path, query)) => (path, query),
            None => (request.target.as_str(), ""),
        };
        let method = request.method.as_str();

        match path {
            "/v1/accounts" => {
                require(method, "POST")?;
                self.create_account(&request)
            }
            "/v1/enroll/offer" => {
                require(method, "POST")?;
                self.offer(&request)
            }
            "/v1/enroll/claim" => {
                require(method, "POST")?;
                self.claim(&request)
            }
            "/v1/enroll/ack" => {
                require(method, "POST")?;
                self.ack(&request)
            }
            "/v1/sync/push" => {
                require(method, "POST")?;
                self.push(&request)
            }
            "/v1/sync/pull" => {
                require(method, "GET")?;
                self.pull(&request, query)
            }
            "/v1/sync/state" => {
                require(method, "GET")?;
                self.state(&request)
            }
            _ if path.starts_with("/v1/devices/") => {
                require(method, "DELETE")?;
                let device_id = api::validate_id("device_id", &path["/v1/devices/".len()..])?;
                self.revoke_device(&request, &device_id)
            }
            _ => Err(ApiError::not_found("no such route")),
        }
    }

    /// Verifies the request signature and returns the account it belongs to.
    ///
    /// The nonce is checked and consumed under one lock so two copies of the
    /// same request cannot both pass; the signature is verified before the
    /// nonce is consumed, so a forged request cannot burn a real nonce.
    fn authenticate(&self, request: &RequestParts) -> Result<Account, ApiError> {
        let header = request
            .authorization
            .as_deref()
            .ok_or_else(|| ApiError::from(&AuthError::Missing))?;
        let credentials = auth::parse(header).map_err(|error| ApiError::from(&error))?;

        let now = unix_now();
        if now.abs_diff(credentials.timestamp) > MAX_SKEW_SECS as u64 {
            return Err(ApiError::from(&AuthError::Stale));
        }

        let device = self
            .store()
            .device(&credentials.device_id)
            .map_err(store_error)?
            .ok_or_else(|| ApiError::from(&AuthError::UnknownDevice))?;

        let digest = auth::body_digest(&request.body);
        let message = auth::signing_string(
            request.method.as_str(),
            &request.target,
            &digest,
            credentials.timestamp,
            &credentials.nonce,
        );
        if !auth::verify(
            &device.signing_pub,
            message.as_bytes(),
            &credentials.signature,
        ) {
            return Err(ApiError::from(&AuthError::BadSignature));
        }

        // Only a device that proved possession of its key is told why it was
        // refused; a forged request stays a 401. The row is kept for audit, so
        // this is a flag, not a missing device.
        if device.revoked_at.is_some() {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "device_revoked",
                "this device has been revoked",
            ));
        }

        let mut replay = self.replay();
        if replay.contains(&credentials.device_id, &credentials.nonce, now) {
            return Err(ApiError::from(&AuthError::Replay));
        }
        replay.insert(
            &credentials.device_id,
            credentials.timestamp,
            credentials.nonce.clone(),
            now,
        );
        drop(replay);

        Ok(Account {
            account_id: device.account_id,
            device_id: device.device_id,
        })
    }

    fn create_account(&self, request: &RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        let body: CreateAccountRequest = api::parse_body(&request.body)?;
        let new = body.validate()?;
        let now = unix_now();

        let mut store = self.store();
        if self.config.max_accounts > 0 {
            let count = store.account_count().map_err(store_error)?;
            if count >= self.config.max_accounts {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "account_limit",
                    "this server has reached its account limit",
                ));
            }
        }

        let outcome = store
            .create_account(
                &new.account_id,
                &new.device_id,
                &new.signing_pub,
                &new.agreement_pub,
                &new.device_name,
                now,
            )
            .map_err(store_error)?;

        match outcome {
            CreateAccount::Created => Ok(json_response(
                StatusCode::CREATED,
                &api::AccountView {
                    account_id: new.account_id,
                },
            )),
            CreateAccount::AccountExists => Err(ApiError::conflict(
                "account_exists",
                "this account id is already registered",
            )),
            CreateAccount::DeviceExists => Err(ApiError::conflict(
                "device_conflict",
                "this device id is already registered",
            )),
        }
    }

    fn offer(&self, request: &RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        let account = self.authenticate(request)?;
        let body: OfferRequest = api::parse_body(&request.body)?;
        let now = unix_now();
        let offer = body.validate(now)?;
        if offer.new_device_id == account.device_id {
            return Err(ApiError::bad_request(
                "invalid_field",
                "new_device_id is the device making the offer",
            ));
        }

        let mut store = self.store();
        let outcome = store
            .put_offer(
                &account.account_id,
                &offer.new_device_id,
                &offer.code_hash,
                &offer.sealed,
                offer.expires_at,
                now,
            )
            .map_err(store_error)?;

        match outcome {
            OfferOutcome::Stored => Ok(json_response(StatusCode::OK, &serde_json::json!({}))),
            OfferOutcome::AlreadyEnrolled => Err(ApiError::conflict(
                "already_enrolled",
                "that device is already enrolled",
            )),
        }
    }

    fn claim(&self, request: &RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        let body: ClaimRequest = api::parse_body(&request.body)?;
        let claim = body.validate()?;
        let code_hash = hex::encode(Sha256::digest(claim.code.as_bytes()));
        let now = unix_now();

        let mut store = self.store();
        let claimed = store
            .claim_offer(
                &code_hash,
                &claim.device_id,
                &claim.signing_pub,
                &claim.agreement_pub,
                &claim.device_name,
                now,
            )
            .map_err(store_error)?;

        match claimed {
            Ok(claim) => Ok(json_response(
                StatusCode::OK,
                &ClaimView {
                    account_id: claim.account_id,
                    sealed: base64::engine::general_purpose::STANDARD.encode(claim.sealed),
                    devices: claim.devices.iter().map(device_view).collect(),
                },
            )),
            Err(ClaimError::InvalidCode) => Err(ApiError::bad_request(
                "invalid_code",
                "no unexpired enrolment for this code and device id",
            )),
            Err(ClaimError::Expired) => Err(ApiError::bad_request(
                "expired_code",
                "this enrolment code has expired",
            )),
            Err(ClaimError::AlreadyEnrolled) => Err(ApiError::conflict(
                "already_enrolled",
                "that device is already enrolled",
            )),
        }
    }

    fn ack(&self, request: &RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        let account = self.authenticate(request)?;
        let body: AckRequest = api::parse_body(&request.body)?;
        let new_device_id = body.validate()?;
        let now = unix_now();

        let mut store = self.store();
        let outcome = store
            .ack_offer(&account.account_id, &new_device_id, now)
            .map_err(store_error)?;

        match outcome {
            AckOutcome::Acknowledged | AckOutcome::AlreadyAcknowledged => {
                Ok(json_response(StatusCode::OK, &serde_json::json!({})))
            }
            AckOutcome::NotFound => Err(ApiError::bad_request(
                "unknown_offer",
                "no enrolment offer for that device",
            )),
            AckOutcome::NotClaimed => Err(ApiError::bad_request(
                "not_claimed",
                "the new device has not claimed this offer",
            )),
            AckOutcome::Expired => Err(ApiError::bad_request(
                "expired_code",
                "this enrolment code has expired",
            )),
        }
    }

    fn revoke_device(
        &self,
        request: &RequestParts,
        target_device_id: &str,
    ) -> Result<Response<Full<Bytes>>, ApiError> {
        let account = self.authenticate(request)?;
        let now = unix_now();

        let mut store = self.store();
        let outcome = store
            .revoke_device(
                &account.account_id,
                &account.device_id,
                target_device_id,
                now,
            )
            .map_err(store_error)?;

        match outcome {
            RevokeOutcome::Revoked(revoked_at) | RevokeOutcome::AlreadyRevoked(revoked_at) => {
                Ok(json_response(
                    StatusCode::OK,
                    &RevokeView {
                        device_id: target_device_id.to_string(),
                        revoked_at: revoked_at.max(0) as u64,
                    },
                ))
            }
            RevokeOutcome::Unknown => Err(ApiError::not_found("no such device in this account")),
            RevokeOutcome::SelfRevoke => Err(ApiError::bad_request(
                "invalid_field",
                "a device cannot revoke itself",
            )),
        }
    }

    fn push(&self, request: &RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        let account = self.authenticate(request)?;
        let body: PushRequest = api::parse_body(&request.body)?;
        let ops = body.validate()?;
        let now = unix_now();

        let mut store = self.store();
        let outcome = store
            .push(&account.account_id, &ops, now)
            .map_err(store_error)?;

        let view = PushView {
            applied: outcome.applied,
            conflicts: outcome
                .conflicts
                .iter()
                .map(|op| ConflictView {
                    item_id: op.item_id.clone(),
                    clock: op.clock.clone(),
                    deleted: op.deleted,
                    ciphertext: hex::encode(&op.ciphertext),
                })
                .collect(),
        };
        Ok(json_response(StatusCode::OK, &view))
    }

    fn pull(&self, request: &RequestParts, query: &str) -> Result<Response<Full<Bytes>>, ApiError> {
        let account = self.authenticate(request)?;
        let (since, limit) = parse_pull_query(query)?;

        let store = self.store();
        let page = store
            .pull(&account.account_id, since, limit)
            .map_err(store_error)?;

        let view = api::PullView {
            ops: page
                .ops
                .iter()
                .map(|op| api::PullOpView {
                    seq: op.seq,
                    item_id: op.item_id.clone(),
                    clock: op.clock.clone(),
                    deleted: op.deleted,
                    ciphertext: hex::encode(&op.ciphertext),
                })
                .collect(),
            next_seq: page.next_seq,
            has_more: page.has_more,
        };
        Ok(json_response(StatusCode::OK, &view))
    }

    fn state(&self, request: &RequestParts) -> Result<Response<Full<Bytes>>, ApiError> {
        let account = self.authenticate(request)?;
        let store = self.store();
        let snapshot = store.snapshot(&account.account_id).map_err(store_error)?;
        Ok(json_response(
            StatusCode::OK,
            &StateView {
                account_id: account.account_id,
                devices: snapshot.devices.iter().map(device_view).collect(),
                items: snapshot.items,
                bytes: snapshot.bytes,
            },
        ))
    }
}

fn device_view(device: &db::DeviceInfo) -> DeviceView {
    DeviceView {
        device_id: device.device_id.clone(),
        device_name: device.device_name.clone(),
        created_at: device.created_at.max(0) as u64,
        revoked_at: device.revoked_at.map(|at| at.max(0) as u64),
    }
}

fn require(method: &str, expected: &'static str) -> Result<(), ApiError> {
    if method == expected {
        Ok(())
    } else {
        Err(ApiError::method_not_allowed(expected))
    }
}

fn check_protocol(value: Option<&str>) -> Result<(), ApiError> {
    let Some(value) = value else {
        // Absent is treated as protocol 1: curl and the self-host health check
        // should not have to know about version negotiation.
        return Ok(());
    };
    let value = value.trim();
    let major = value.split('.').next().unwrap_or_default();
    if major == PROTOCOL_VERSION {
        return Ok(());
    }
    Err(ApiError::new(
        StatusCode::UPGRADE_REQUIRED,
        "unsupported_protocol",
        format!("this server speaks protocol {PROTOCOL_VERSION}, not {value:?}"),
    ))
}

fn parse_pull_query(query: &str) -> Result<(u64, u64), ApiError> {
    let mut since = 0_u64;
    let mut limit = PULL_DEFAULT_LIMIT;

    for pair in query.split('&').filter(|pair| !pair.is_empty()) {
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "since" => {
                since = value.parse().map_err(|_| {
                    ApiError::bad_request("invalid_query", "since must be a non-negative integer")
                })?;
            }
            "limit" => {
                let parsed: u64 = value.parse().map_err(|_| {
                    ApiError::bad_request("invalid_query", "limit must be a non-negative integer")
                })?;
                if parsed == 0 {
                    return Err(ApiError::bad_request(
                        "invalid_query",
                        "limit must be at least 1",
                    ));
                }
                limit = parsed.min(PULL_MAX_LIMIT);
            }
            // Unknown parameters are ignored so a newer client can add one
            // without a version bump.
            _ => {}
        }
    }

    Ok((since, limit))
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

fn store_error(error: StoreError) -> ApiError {
    // The detail stays in this process's stderr: it can name tables and
    // constraints, which is more than a client needs.
    eprintln!("kestrel-sync: storage failure: {error}");
    ApiError::internal("the service could not complete the request")
}

fn json_response<T: serde::Serialize>(status: StatusCode, body: &T) -> Response<Full<Bytes>> {
    match serde_json::to_vec(body) {
        Ok(bytes) => response_with_body(status, bytes),
        Err(error) => {
            eprintln!("kestrel-sync: response serialisation failed: {error}");
            response_with_body(
                StatusCode::INTERNAL_SERVER_ERROR,
                br#"{"error":"internal","message":"response could not be serialised"}"#.to_vec(),
            )
        }
    }
}

/// The one rendering of a failure, shared with the HTTP layer so a body-limit
/// or join failure looks exactly like a handler failure.
pub fn error_response(error: &ApiError) -> Response<Full<Bytes>> {
    let mut response = json_response(
        error.status,
        &ErrorView {
            error: error.code,
            message: error.message.clone(),
        },
    );
    if let Some(allow) = error.allow {
        response
            .headers_mut()
            .insert(header::ALLOW, HeaderValue::from_static(allow));
    }
    response
}

pub fn response_with_body(status: StatusCode, bytes: Vec<u8>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(bytes)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::HeaderName::from_static(PROTOCOL_HEADER),
        HeaderValue::from_static(PROTOCOL_VERSION),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn protocol_major_must_be_one() {
        assert!(check_protocol(None).is_ok());
        assert!(check_protocol(Some("1")).is_ok());
        assert!(check_protocol(Some("1.2")).is_ok());
        assert_eq!(
            check_protocol(Some("2")).expect_err("rejected").status,
            StatusCode::UPGRADE_REQUIRED
        );
    }

    #[test]
    fn pull_query_defaults_and_clamps() {
        assert_eq!(
            parse_pull_query("").expect("default"),
            (0, PULL_DEFAULT_LIMIT)
        );
        assert_eq!(parse_pull_query("since=7&limit=5").expect("parsed"), (7, 5));
        assert_eq!(
            parse_pull_query("limit=999999").expect("clamped"),
            (0, PULL_MAX_LIMIT)
        );
        assert!(parse_pull_query("limit=0").is_err());
        assert!(parse_pull_query("since=nope").is_err());
    }
}
