//! Transport for the SSH agent: the accept loop and framing run on one
//! platform-neutral pair of traits, so the agent protocol never sees whether a
//! client arrived on a Windows named pipe or a Unix domain socket.
//!
//! * [`Listener`] owns the listening endpoint. `bind(path)` claims it, `accept`
//!   returns the next connected [`Stream`], `path` is what the settings card
//!   shows, and `interrupt` wakes a blocked `accept` during shutdown.
//! * [`Stream`] is any `Read + Write + Send` byte stream. The Windows
//!   implementation lives in [`super::pipe`]; the Unix one is the
//!   [`std::os::unix::net::UnixStream`] below.
//! * [`Server`] is the process-lifetime accept loop: one thread accepts, each
//!   connection gets a thread, and `stop()` wakes both and joins them.
//!
//! Unix endpoints are user-private by construction: the socket lives in
//! `$XDG_RUNTIME_DIR` (or `$TMPDIR` when that is unset), is created with mode
//! `0600`, and every accepted connection is checked against the listening
//! process's own uid with `SO_PEERCRED` (Linux) or `getpeereid` (macOS/BSD).
//! A socket left behind by a crashed instance is replaced only when it is a
//! socket we own and nothing is listening on it.

use crate::agent::protocol::{self, AgentBackend};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

/// One connected client. Every platform stream is a plain byte pipe; framing
/// and the agent protocol stay in this module.
pub trait Stream: Read + Write + Send {}
impl<T: Read + Write + Send> Stream for T {}

/// The listening endpoint of one platform.
pub trait Listener: Send + Sync {
    /// Wait for the next client. `Ok(None)` means the listener cannot accept
    /// any more clients (it was interrupted by shutdown or has no instance
    /// left); any `Err` is retried by the accept loop.
    fn accept(&self) -> io::Result<Option<Box<dyn Stream>>>;

    /// The endpoint a client must be pointed at, for the status card.
    fn path(&self) -> &Path;

    /// Wake a blocked `accept` so the accept loop can observe shutdown.
    fn interrupt(&self);
}

/// Claim the platform's default agent endpoint.
#[cfg(windows)]
pub fn bind_default() -> io::Result<Box<dyn Listener>> {
    let path = Path::new(super::pipe::PIPE_PATH);
    Ok(Box::new(super::pipe::PipeListener::bind(path)?))
}

/// Claim the platform's default agent endpoint, creating the runtime directory
/// when it does not exist yet.
#[cfg(unix)]
pub fn bind_default() -> io::Result<Box<dyn Listener>> {
    let path = socket_path();
    if let Some(parent) = path.parent() {
        ensure_private_dir(parent)?;
    }
    Ok(Box::new(SocketListener::bind(&path)?))
}

/// The endpoint `ssh`/`git` must be pointed at on this platform.
pub fn agent_path() -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(super::pipe::PIPE_PATH)
    }
    #[cfg(unix)]
    {
        socket_path()
    }
}

/* ------------------------------------------------------------------ server */

/// The running agent listener: an accept thread plus one thread per client.
pub struct Server {
    stop: Arc<AtomicBool>,
    /// Shared with the accept thread; the server keeps its own reference so the
    /// endpoint (and the Unix socket's `Drop`) lives exactly as long as the
    /// server does.
    listener: Arc<dyn Listener>,
    thread: Option<JoinHandle<()>>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
}

impl Server {
    /// Bind the platform endpoint and start accepting. Returns only once the
    /// endpoint exists, so `Ok` means a client can connect right away and a
    /// failure such as "another agent owns the pipe" reaches the caller.
    pub fn start(backend: Arc<dyn AgentBackend>) -> io::Result<Server> {
        Server::start_listener(bind_default()?, backend)
    }

    fn start_listener(
        listener: Box<dyn Listener>,
        backend: Arc<dyn AgentBackend>,
    ) -> io::Result<Server> {
        let stop = Arc::new(AtomicBool::new(false));
        let workers = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = Arc::clone(&stop);
        let thread_workers = Arc::clone(&workers);
        let listener: Arc<dyn Listener> = Arc::from(listener);
        let thread_listener = Arc::clone(&listener);
        let thread = std::thread::Builder::new()
            .name("kestrel-ssh-agent".into())
            .spawn(move || accept_loop(thread_listener, backend, &thread_stop, &thread_workers))?;

        Ok(Server {
            stop,
            listener,
            thread: Some(thread),
            workers,
        })
    }

    /// The endpoint clients connect to.
    pub fn path(&self) -> PathBuf {
        self.listener.path().to_path_buf()
    }

    /// Stop accepting, wake every blocked client thread and wait for both.
    pub fn stop(mut self) {
        self.shutdown();
    }

    fn shutdown(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        self.listener.interrupt();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
        let workers = std::mem::take(&mut *self.workers.lock().expect("agent worker list"));
        for worker in workers {
            let _ = worker.join();
        }
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        // `stop()` already joined; this covers a `Server` dropped by an error
        // path, so the listener never outlives its owner.
        if self.thread.is_some() {
            self.shutdown();
        }
    }
}

fn accept_loop(
    listener: Arc<dyn Listener>,
    backend: Arc<dyn AgentBackend>,
    stop: &Arc<AtomicBool>,
    workers: &Arc<Mutex<Vec<JoinHandle<()>>>>,
) {
    while !stop.load(Ordering::SeqCst) {
        let accepted = listener.accept();
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let stream = match accepted {
            Ok(Some(stream)) => stream,
            Ok(None) => break,
            // A refused peer or a transient error never stops the agent: the
            // next iteration waits for the next client.
            Err(_) => continue,
        };
        let worker_backend = Arc::clone(&backend);
        let worker_stop = Arc::clone(stop);
        let spawned = std::thread::Builder::new()
            .name("kestrel-ssh-agent-conn".into())
            .spawn(move || serve(stream, worker_backend, worker_stop));
        match spawned {
            Ok(handle) => {
                let mut workers = workers.lock().expect("agent worker list");
                // JoinHandles of short-lived clients would otherwise
                // accumulate for the life of the process; drop the ones that
                // already exited and keep the rest for `stop()`.
                workers.retain(|worker| !worker.is_finished());
                workers.push(handle);
            }
            // Without a thread the stream is dropped and the client hangs up.
            Err(_) => {}
        }
    }
}

/// Answer requests on one connected client until it hangs up or the agent
/// stops. Shared by every platform: only the byte stream differs.
fn serve(mut stream: Box<dyn Stream>, backend: Arc<dyn AgentBackend>, stop: Arc<AtomicBool>) {
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        match read_frame(stream.as_mut(), &stop) {
            Ok(Some(request)) => {
                let response = protocol::handle_request(backend.as_ref(), &request);
                if write_all(stream.as_mut(), &response, &stop).is_err() {
                    break;
                }
            }
            Ok(None) => break,
            // The stream cannot be resynchronised after a bad length, so answer
            // the one thing the protocol allows and hang up.
            Err(FrameReadError::TooLarge) => {
                let _ = write_all(stream.as_mut(), &protocol::failure(), &stop);
                break;
            }
            Err(FrameReadError::Failed) => break,
        }
    }
}

/* ------------------------------------------------------------------ frames */

/// Why a frame could not be read. The distinction is only whether the protocol
/// still permits a reply: a bad length does, a broken connection does not.
enum FrameReadError {
    TooLarge,
    Failed,
}

/// Read one length-prefixed request. `Ok(None)` is a clean EOF between frames.
fn read_frame(
    stream: &mut dyn Stream,
    stop: &AtomicBool,
) -> Result<Option<Vec<u8>>, FrameReadError> {
    let mut header = [0u8; 4];
    match read_exact(stream, &mut header, stop)? {
        // Closing between requests is the normal end of a client session.
        ReadExact::Eof => return Ok(None),
        ReadExact::Full => {}
    }
    let len = protocol::frame_length(&header).map_err(|_| FrameReadError::TooLarge)?;
    let mut body = vec![0u8; len];
    match read_exact(stream, &mut body, stop)? {
        ReadExact::Full => Ok(Some(body)),
        // Half a frame: the client died mid-request.
        ReadExact::Eof => Err(FrameReadError::Failed),
    }
}

enum ReadExact {
    Full,
    Eof,
}

fn read_exact(
    stream: &mut dyn Stream,
    buf: &mut [u8],
    stop: &AtomicBool,
) -> Result<ReadExact, FrameReadError> {
    let mut filled = 0usize;
    while filled < buf.len() {
        match read_some(stream, &mut buf[filled..], stop)? {
            Some(0) | None => {
                return if filled == 0 {
                    Ok(ReadExact::Eof)
                } else {
                    Err(FrameReadError::Failed)
                };
            }
            Some(n) => filled += n,
        }
    }
    Ok(ReadExact::Full)
}

/// One read, with the shutdown conditions every platform can raise mid-wait.
fn read_some(
    stream: &mut dyn Stream,
    buf: &mut [u8],
    stop: &AtomicBool,
) -> Result<Option<usize>, FrameReadError> {
    loop {
        match stream.read(buf) {
            Ok(0) => return Ok(None),
            Ok(n) => return Ok(Some(n)),
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                // A read timeout is how the Unix stream notices shutdown; the
                // frame is still intact, so retry until the agent stops.
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    if stop.load(Ordering::SeqCst) {
                        return Err(FrameReadError::Failed);
                    }
                    continue;
                }
                _ => return Err(FrameReadError::Failed),
            },
        }
    }
}

fn write_all(stream: &mut dyn Stream, buf: &[u8], stop: &AtomicBool) -> Result<(), FrameReadError> {
    let mut written = 0usize;
    while written < buf.len() {
        match stream.write(&buf[written..]) {
            Ok(0) => return Err(FrameReadError::Failed),
            Ok(n) => written += n,
            Err(error) => match error.kind() {
                io::ErrorKind::Interrupted => continue,
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut => {
                    if stop.load(Ordering::SeqCst) {
                        return Err(FrameReadError::Failed);
                    }
                    continue;
                }
                _ => return Err(FrameReadError::Failed),
            },
        }
    }
    // `flush` is a no-op on Unix and `FlushFileBuffers` on Windows, where it is
    // what makes the reply visible to the client before the pipe closes.
    stream.flush().map_err(|_| FrameReadError::Failed)
}

/* --------------------------------------------------------------------- unix */

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// File name inside the runtime directory.
#[cfg(unix)]
const SOCKET_NAME: &str = "kestrel-ssh-agent.sock";

/// No other user may open the socket; the peer-uid check is the second gate.
#[cfg(unix)]
const SOCKET_MODE: u32 = 0o600;

/// The runtime directory is created with owner-only access.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// How often a blocked Unix read wakes up to notice shutdown.
#[cfg(unix)]
const SHUTDOWN_POLL: std::time::Duration = std::time::Duration::from_millis(200);

/// `$XDG_RUNTIME_DIR/kestrel-ssh-agent.sock`, falling back to
/// `$TMPDIR/kestrel-ssh-agent.sock` and then `/tmp`.
#[cfg(unix)]
pub fn socket_path() -> PathBuf {
    for key in ["XDG_RUNTIME_DIR", "TMPDIR"] {
        if let Some(value) = std::env::var_os(key) {
            if !value.is_empty() {
                return PathBuf::from(value).join(SOCKET_NAME);
            }
        }
    }
    PathBuf::from("/tmp").join(SOCKET_NAME)
}

/// Create the runtime directory with mode `0700` when it is missing. An
/// existing directory is left untouched: `$XDG_RUNTIME_DIR` is owned and
/// restricted by the session manager, and `$TMPDIR` is deliberately shared.
#[cfg(unix)]
fn ensure_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;

    match std::fs::metadata(dir) {
        Ok(metadata) if metadata.is_dir() => Ok(()),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            format!("{} is not a directory", dir.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => std::fs::DirBuilder::new()
            .recursive(true)
            .mode(DIR_MODE)
            .create(dir),
        Err(error) => Err(error),
    }
}

/// The Unix agent endpoint: a `UnixListener` that only ever hands out streams
/// owned by the same user.
#[cfg(unix)]
pub struct SocketListener {
    listener: std::os::unix::net::UnixListener,
    path: PathBuf,
    /// uid every accepted peer must match; the process's own uid in production.
    uid: u32,
}

#[cfg(unix)]
impl SocketListener {
    /// Bind `path`, replacing a socket that a previous instance left behind.
    pub fn bind(path: &Path) -> io::Result<SocketListener> {
        SocketListener::bind_for_uid(path, current_uid())
    }

    /// Explicit expected uid so the refusal path is testable without root.
    fn bind_for_uid(path: &Path, uid: u32) -> io::Result<SocketListener> {
        remove_stale_socket(path)?;
        let listener = std::os::unix::net::UnixListener::bind(path)?;
        // `bind` applies the umask; tighten to owner-only before anyone can
        // connect. The directory already hides it on a normal runtime dir.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(SOCKET_MODE))?;
        Ok(SocketListener {
            listener,
            path: path.to_path_buf(),
            uid,
        })
    }
}

#[cfg(unix)]
impl Listener for SocketListener {
    fn accept(&self) -> io::Result<Option<Box<dyn Stream>>> {
        let (stream, _) = self.listener.accept()?;
        let peer = peer_uid(&stream)?;
        if peer != self.uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "SSH agent socket {} refused a client from uid {peer}",
                    self.path.display()
                ),
            ));
        }
        // The read timeout is the only way a blocked read notices `stop()`; the
        // frame layer retries it and checks the flag in between. The write
        // timeout does the same for a client that stopped draining its socket,
        // so `stop()` can never hang on a wedged worker.
        stream.set_read_timeout(Some(SHUTDOWN_POLL))?;
        stream.set_write_timeout(Some(SHUTDOWN_POLL))?;
        Ok(Some(Box::new(stream)))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn interrupt(&self) {
        // Accepting a throwaway connection wakes the blocked `accept`; the
        // accept loop sees the stop flag and exits without serving it.
        let _ = std::os::unix::net::UnixStream::connect(&self.path);
    }
}

#[cfg(unix)]
impl Drop for SocketListener {
    fn drop(&mut self) {
        // The socket file is ours (we checked before binding), so removing it
        // on shutdown is what keeps the next start from needing the stale path.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Delete `path` only when it is a socket this user owns and nobody is
/// listening on it. Anything else is reported instead of deleted: a regular
/// file or another user's socket must never be removed by us.
#[cfg(unix)]
fn remove_stale_socket(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::{FileTypeExt, MetadataExt};

    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
    };
    if !metadata.file_type().is_socket() || metadata.uid() != current_uid() {
        return Err(already_running(path));
    }
    match std::os::unix::net::UnixStream::connect(path) {
        // Something is accepting: it is a live agent, not a leftover.
        Ok(_) => Err(already_running(path)),
        Err(error) if error.kind() == io::ErrorKind::ConnectionRefused => {
            std::fs::remove_file(path)
        }
        // Any other failure leaves the socket alone; refusing to bind is safer
        // than unlinking a socket whose state we could not observe.
        Err(_) => Err(already_running(path)),
    }
}

#[cfg(unix)]
fn already_running(path: &Path) -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrInUse,
        format!(
            "the SSH agent socket {} is already owned by another process",
            path.display()
        ),
    )
}

#[cfg(unix)]
fn current_uid() -> u32 {
    // `getuid` is async-signal-safe and cannot fail.
    unsafe { ffi::getuid() }
}

/// The uid on the other end of an accepted socket.
#[cfg(target_os = "linux")]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut cred = ffi::UCred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<ffi::UCred>() as ffi::SockLen;
    let code = unsafe {
        ffi::getsockopt(
            stream.as_raw_fd(),
            ffi::SOL_SOCKET,
            ffi::SO_PEERCRED,
            (&mut cred as *mut ffi::UCred).cast(),
            &mut len,
        )
    };
    if code != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The same contract on macOS and the BSDs, where the kernel call is
/// `getpeereid` rather than `getsockopt(SO_PEERCRED)`.
#[cfg(any(
    target_os = "macos",
    target_os = "ios",
    target_os = "freebsd",
    target_os = "dragonfly",
    target_os = "openbsd",
    target_os = "netbsd"
))]
fn peer_uid(stream: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    use std::os::fd::AsRawFd;

    let mut uid = 0u32;
    let mut gid = 0u32;
    let code = unsafe { ffi::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if code != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid)
}

/// Without a portable credential call every client is refused rather than
/// served unattributed.
#[cfg(all(
    unix,
    not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "dragonfly",
        target_os = "openbsd",
        target_os = "netbsd"
    ))
))]
fn peer_uid(_stream: &std::os::unix::net::UnixStream) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "peer credentials are not available on this platform",
    ))
}

/// Raw libc bindings for the two credential calls and `getuid`.
///
/// Only these three symbols are needed, so they are declared here instead of
/// adding a `libc` dependency just for the Unix target. The constants are
/// ABI-stable on Linux (`SOL_SOCKET` 1, `SO_PEERCRED` 17).
#[cfg(unix)]
mod ffi {
    #[cfg(target_os = "linux")]
    use std::ffi::c_void;
    use std::os::raw::{c_int, c_uint};

    /// `socklen_t` is 32-bit on every supported target.
    #[cfg(target_os = "linux")]
    pub type SockLen = c_uint;

    #[cfg(target_os = "linux")]
    pub const SOL_SOCKET: c_int = 1;
    #[cfg(target_os = "linux")]
    pub const SO_PEERCRED: c_int = 17;

    /// `struct ucred` from `sys/socket.h` on Linux.
    #[cfg(target_os = "linux")]
    #[repr(C)]
    pub struct UCred {
        pub pid: c_int,
        pub uid: c_uint,
        pub gid: c_uint,
    }

    extern "C" {
        pub fn getuid() -> c_uint;

        #[cfg(target_os = "linux")]
        pub fn getsockopt(
            socket: c_int,
            level: c_int,
            name: c_int,
            value: *mut c_void,
            len: *mut SockLen,
        ) -> c_int;

        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "dragonfly",
            target_os = "openbsd",
            target_os = "netbsd"
        ))]
        pub fn getpeereid(socket: c_int, uid: *mut c_uint, gid: *mut c_uint) -> c_int;
    }
}

/* -------------------------------------------------------------------- tests */

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::agent::protocol::AgentError;
    use std::io::{Read, Write};
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::net::UnixStream;
    use std::time::{Duration, Instant};

    struct EmptyBackend;

    impl AgentBackend for EmptyBackend {
        fn identities(&self) -> Result<Vec<protocol::AgentIdentity>, AgentError> {
            Ok(Vec::new())
        }

        fn sign(
            &self,
            _key_blob: &[u8],
            _data: &[u8],
            _flags: u32,
        ) -> Result<Option<Vec<u8>>, AgentError> {
            Ok(None)
        }
    }

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "kestrel-agent-transport-{tag}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("temp dir");
        dir
    }

    fn read_frame(stream: &mut UnixStream) -> Vec<u8> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).expect("header");
        let len = u32::from_be_bytes(header) as usize;
        let mut body = vec![0u8; len];
        stream.read_exact(&mut body).expect("body");
        body
    }

    #[test]
    fn socket_is_owner_only_and_serves_the_protocol() {
        let dir = scratch_dir("serve");
        let path = dir.join("agent.sock");
        let listener = SocketListener::bind(&path).expect("bind");
        assert_eq!(listener.path(), path.as_path());

        let mode = std::fs::metadata(&path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "socket must be owner-only, got {mode:o}");

        let server = Server::start_listener(Box::new(listener), Arc::new(EmptyBackend))
            .expect("server starts");
        assert_eq!(server.path(), path);

        let mut client = UnixStream::connect(&path).expect("connect");
        client
            .write_all(&protocol::frame(&[protocol::SSH_AGENTC_REQUEST_IDENTITIES]))
            .expect("write request");
        let response = read_frame(&mut client);
        assert_eq!(response[0], protocol::SSH_AGENT_IDENTITIES_ANSWER);
        assert_eq!(&response[1..5], &0u32.to_be_bytes(), "no keys");

        server.stop();
        assert!(!path.exists(), "shutdown must remove the socket");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_live_socket_is_never_replaced() {
        let dir = scratch_dir("live");
        let path = dir.join("agent.sock");
        let listener = SocketListener::bind(&path).expect("bind");
        let error = SocketListener::bind(&path).expect_err("second bind must fail");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(error.to_string().contains("already owned"), "{error}");
        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_foreign_file_at_the_path_is_not_deleted() {
        let dir = scratch_dir("foreign-file");
        let path = dir.join("agent.sock");
        std::fs::write(&path, b"not a socket").expect("write file");
        let error = SocketListener::bind(&path).expect_err("bind must refuse");
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
        assert!(path.exists(), "foreign file must survive");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_stale_socket_is_replaced() {
        let dir = scratch_dir("stale");
        let path = dir.join("agent.sock");
        let stale = std::os::unix::net::UnixListener::bind(&path).expect("stale bind");
        drop(stale);
        assert!(
            path.exists(),
            "dropping a UnixListener leaves the socket file"
        );
        let listener = SocketListener::bind(&path).expect("stale socket replaced");
        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_client_from_another_uid_is_refused() {
        let dir = scratch_dir("peer");
        let path = dir.join("agent.sock");
        // Pretend the agent belongs to the next uid: our own connection must
        // then be rejected exactly as another user's would be.
        let listener = SocketListener::bind_for_uid(&path, current_uid().wrapping_add(1))
            .expect("bind with a foreign owner");
        let mut client = UnixStream::connect(&path).expect("connect");
        let error = listener.accept().expect_err("peer must be refused");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("uid"), "{error}");
        assert!(
            matches!(client.read(&mut [0u8; 1]), Ok(0) | Err(_)),
            "a refused client must not be served"
        );
        drop(listener);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn runtime_directory_is_created_owner_only() {
        let dir = scratch_dir("dir");
        let nested = dir.join("runtime");
        ensure_private_dir(&nested).expect("directory");
        let mode = std::fs::metadata(&nested)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o700, "created directory must be owner-only");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn shutdown_wakes_a_blocked_accept() {
        let dir = scratch_dir("stop");
        let path = dir.join("agent.sock");
        let listener = SocketListener::bind(&path).expect("bind");
        let server = Server::start_listener(Box::new(listener), Arc::new(EmptyBackend))
            .expect("server starts");
        // Give the accept thread a moment to block inside `accept`.
        std::thread::sleep(Duration::from_millis(50));
        let started = Instant::now();
        server.stop();
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "stop must not wait for a client"
        );
        let _ = std::fs::remove_dir_all(dir);
    }
}
