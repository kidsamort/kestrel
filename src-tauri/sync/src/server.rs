//! HTTP plumbing: one tokio listener, one task per connection, HTTP/1.1 only.
//!
//! There is no TLS here on purpose: self-hosting puts this behind a reverse
//! proxy that terminates TLS, and the proxy is also where rate limits and
//! access logs belong. Plain HTTP on a loopback or container-network interface
//! is the deployment model `deploy/` documents.

use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use http::{header, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use tokio::net::{TcpListener, TcpStream};

use crate::api::ApiError;
use crate::auth::ReplayCache;
use crate::config::Config;
use crate::db::Store;
use crate::service::{self, App, RequestParts, REPLAY_PER_DEVICE, REPLAY_WINDOW_SECS};

#[derive(Debug, thiserror::Error)]
pub enum StartError {
    #[error("could not open the database: {0}")]
    Store(#[from] crate::db::StoreError),
    #[error("could not bind {0}: {1}")]
    Bind(SocketAddr, std::io::Error),
}

pub struct Server {
    listener: TcpListener,
    app: Arc<App>,
    local_addr: SocketAddr,
}

impl Server {
    /// Opens the database and binds the socket. Splitting this from [`run`]
    /// lets a caller learn the actual port when it asked for `:0`, which is how
    /// the integration tests drive a real TCP connection on an ephemeral port.
    pub async fn bind(config: Config) -> Result<Server, StartError> {
        let store = Store::open(&config.db_path, &config.blob_dir)?;
        let replay = ReplayCache::new(REPLAY_WINDOW_SECS, REPLAY_PER_DEVICE);
        let app = Arc::new(App::new(store, replay, config.clone()));
        let listener = TcpListener::bind(config.addr)
            .await
            .map_err(|error| StartError::Bind(config.addr, error))?;
        let local_addr = listener
            .local_addr()
            .map_err(|error| StartError::Bind(config.addr, error))?;
        Ok(Server {
            listener,
            app,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Accepts until `shutdown` resolves. In-flight connections are left to
    /// finish on their own tasks; dropping them mid-write would be worse for a
    /// client than a connection that completes and then is not reused.
    pub async fn run(self, shutdown: impl Future<Output = ()>) -> Result<(), StartError> {
        let Server {
            listener, app, ..
        } = self;
        let mut shutdown = std::pin::pin!(shutdown);

        loop {
            tokio::select! {
                biased;
                () = &mut shutdown => return Ok(()),
                accepted = listener.accept() => match accepted {
                    Ok((stream, _peer)) => {
                        let app = app.clone();
                        tokio::spawn(async move { serve_connection(stream, app).await });
                    }
                    Err(error) => {
                        // A listener error is usually a transient accept
                        // failure (EMFILE, a connection reset during accept).
                        // Back off briefly instead of spinning.
                        eprintln!("kestrel-sync: accept failed: {error}");
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                },
            }
        }
    }
}

async fn serve_connection(stream: TcpStream, app: Arc<App>) {
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let service = service_fn(move |request| {
        let app = app.clone();
        async move { Ok::<_, Infallible>(handle(app, request).await) }
    });
    // A client that disconnects mid-request is routine, not an error worth a
    // log line; the handler already answered with a status when it could.
    let _ = http1::Builder::new().serve_connection(io, service).await;
}

async fn handle(app: Arc<App>, request: Request<Incoming>) -> Response<Full<Bytes>> {
    let (parts, body) = request.into_parts();

    let protocol = parts
        .headers
        .get("x-kestrel-protocol")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let authorization = parts
        .headers
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let target = parts
        .uri
        .path_and_query()
        .map(|path_and_query| path_and_query.as_str().to_owned())
        .unwrap_or_else(|| parts.uri.path().to_owned());

    let body = match read_body(body, app.max_body()).await {
        Ok(body) => body,
        Err(error) => return service::error_response(&error),
    };

    let request = RequestParts {
        method: parts.method,
        target,
        protocol,
        authorization,
        body,
    };

    match tokio::task::spawn_blocking(move || app.handle(request)).await {
        Ok(response) => response,
        Err(error) => {
            eprintln!("kestrel-sync: request handler failed: {error}");
            service::error_response(&ApiError::internal("the request handler failed"))
        }
    }
}

/// Reads at most `max` bytes and discards the rest.
///
/// The service must be able to say "too large" without allocating what the
/// client asked for, and the client must be able to *read* that answer instead
/// of seeing a reset. So the body is drained up to twice the limit — enough for
/// any honest client to finish writing — and beyond that the connection is
/// dropped. Nothing over `max` is ever buffered.
async fn read_body(mut body: Incoming, max: usize) -> Result<Vec<u8>, ApiError> {
    let drain_cap = max.saturating_mul(2).max(max.saturating_add(1));
    let mut buffer = Vec::new();
    let mut total = 0_usize;
    let mut oversized = false;

    while let Some(frame) = body.frame().await {
        let frame = match frame {
            Ok(frame) => frame,
            Err(_) => {
                return Err(ApiError::bad_request(
                    "invalid_body",
                    "the request body could not be read",
                ))
            }
        };
        let Ok(data) = frame.into_data() else {
            continue;
        };
        total = total.saturating_add(data.len());

        if oversized {
            if total > drain_cap {
                break;
            }
            continue;
        }
        if total > max {
            oversized = true;
            buffer = Vec::new();
            if total > drain_cap {
                break;
            }
            continue;
        }
        buffer.extend_from_slice(&data);
    }

    if oversized {
        return Err(ApiError::new(
            StatusCode::PAYLOAD_TOO_LARGE,
            "body_too_large",
            format!("request bodies are limited to {max} bytes"),
        ));
    }
    Ok(buffer)
}
