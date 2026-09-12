//! The listening server.
//!
//! Binding policy is a security control, not a convenience:
//!
//!   * By default the agent binds `127.0.0.1` and a Unix socket only. The
//!     desktop app reaches it through an SSH-forwarded channel, so there is no
//!     listening port on any network interface, nothing to firewall, and no TLS
//!     certificate to provision or expire.
//!   * Binding a routable address is possible but must be spelled out
//!     explicitly in the config, and the agent logs a warning on every start.
//!
//! Concurrency is thread-per-connection from a bounded pool. See
//! `docs/SECURITY.md` for the threat model these choices fall out of.

use crate::request::{self, Body, PeerInfo};
use crate::response::{Conn, Payload, Upgraded};
use crate::router::Lookup;
use crate::{HttpError, Method, Request, Response, Router, Status};
use std::io::{BufReader, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

/// Largest body the server will spool to disk for a streaming route (upload).
pub const MAX_SPOOLED_BODY: u64 = 8 * 1024 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// TCP port. `None` disables TCP.
    pub port: Option<u16>,
    /// Bind address. Defaults to loopback; see the module docs before changing.
    pub bind: IpAddr,
    /// Unix socket path. `None` disables it.
    pub unix_socket: Option<PathBuf>,
    /// How long a connection may stay idle between requests.
    pub idle_timeout: Duration,
    /// How long a single request may take to arrive once started.
    pub read_timeout: Duration,
    /// Maximum simultaneous connections. Beyond this, new connections get 503.
    pub max_connections: usize,
    /// Where streaming request bodies are spooled.
    pub spool_dir: PathBuf,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            port: Some(8723),
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            unix_socket: Some(PathBuf::from("/run/serveros/agent.sock")),
            idle_timeout: Duration::from_secs(90),
            read_timeout: Duration::from_secs(30),
            max_connections: 64,
            spool_dir: PathBuf::from("/var/lib/serveros/spool"),
        }
    }
}

impl ServerConfig {
    pub fn binds_publicly(&self) -> bool {
        !self.bind.is_loopback()
    }
}

pub struct Server<S> {
    config: ServerConfig,
    router: Arc<Router<S>>,
    state: Arc<S>,
    live: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

impl<S: Send + Sync + 'static> Server<S> {
    pub fn new(config: ServerConfig, router: Router<S>, state: Arc<S>) -> Self {
        Server {
            config,
            router: Arc::new(router),
            state,
            live: Arc::new(AtomicUsize::new(0)),
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// A handle that makes the accept loops stop taking new connections.
    pub fn shutdown_flag(&self) -> Arc<AtomicBool> {
        self.shutdown.clone()
    }

    pub fn live_connections(&self) -> usize {
        self.live.load(Ordering::Relaxed)
    }

    /// Bind the configured listeners and serve until they close.
    pub fn run(self) -> std::io::Result<()> {
        let mut handles = Vec::new();

        if let Some(port) = self.config.port {
            let listener = TcpListener::bind(SocketAddr::new(self.config.bind, port))?;
            handles.push(self.spawn_tcp_loop(listener));
        }

        if let Some(path) = self.config.unix_socket.clone() {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            // A stale socket from an unclean stop would make bind fail.
            let _ = std::fs::remove_file(&path);
            let listener = UnixListener::bind(&path)?;
            set_socket_permissions(&path)?;
            handles.push(self.spawn_unix_loop(listener));
        }

        if handles.is_empty() {
            return Err(std::io::Error::other("no listener configured"));
        }
        for h in handles {
            let _ = h.join();
        }
        Ok(())
    }

    /// Bind a TCP listener without serving. Tests use this to take an
    /// ephemeral port and learn which one they got.
    pub fn bind_tcp(&self) -> std::io::Result<(TcpListener, SocketAddr)> {
        let listener =
            TcpListener::bind(SocketAddr::new(self.config.bind, self.config.port.unwrap_or(0)))?;
        let addr = listener.local_addr()?;
        Ok((listener, addr))
    }

    pub fn serve_tcp(&self, listener: TcpListener) -> std::thread::JoinHandle<()> {
        self.spawn_tcp_loop(listener)
    }

    fn spawn_tcp_loop(&self, listener: TcpListener) -> std::thread::JoinHandle<()> {
        let ctx = self.context();
        std::thread::Builder::new()
            .name("agent-http-tcp".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if ctx.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    let peer = match stream.peer_addr() {
                        Ok(a) if a.ip().is_loopback() => PeerInfo::Loopback { port: a.port() },
                        Ok(a) => PeerInfo::Remote { addr: a.to_string() },
                        Err(_) => PeerInfo::Remote { addr: "unknown".into() },
                    };
                    let _ = stream.set_nodelay(true);
                    ctx.clone().dispatch_connection(TcpConn(stream), peer);
                }
            })
            .expect("spawn tcp accept loop")
    }

    fn spawn_unix_loop(&self, listener: UnixListener) -> std::thread::JoinHandle<()> {
        let ctx = self.context();
        std::thread::Builder::new()
            .name("agent-http-unix".into())
            .spawn(move || {
                for stream in listener.incoming() {
                    if ctx.shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    let Ok(stream) = stream else { continue };
                    // `UnixStream::peer_cred` is still unstable and reading
                    // SO_PEERCRED directly would need `unsafe`, which this
                    // workspace forbids. Peer identity is established instead
                    // by the socket's 0600 owner-only mode: anything that can
                    // connect already runs as the agent's user.
                    let peer = PeerInfo::Unix { uid: None, pid: None };
                    ctx.clone().dispatch_connection(UnixConn(stream), peer);
                }
            })
            .expect("spawn unix accept loop")
    }

    fn context(&self) -> Arc<ServeCtx<S>> {
        Arc::new(ServeCtx {
            config: self.config.clone(),
            router: self.router.clone(),
            state: self.state.clone(),
            live: self.live.clone(),
            shutdown: self.shutdown.clone(),
        })
    }
}

struct ServeCtx<S> {
    config: ServerConfig,
    router: Arc<Router<S>>,
    state: Arc<S>,
    live: Arc<AtomicUsize>,
    shutdown: Arc<AtomicBool>,
}

impl<S: Send + Sync + 'static> ServeCtx<S> {
    fn dispatch_connection(self: Arc<Self>, conn: impl Conn + 'static, peer: PeerInfo) {
        let current = self.live.fetch_add(1, Ordering::SeqCst);
        if current >= self.config.max_connections {
            self.live.fetch_sub(1, Ordering::SeqCst);
            // Answer rather than drop, so the app can show "agent is busy"
            // instead of an ambiguous connection reset.
            let mut conn = conn;
            let _ = Response::error(
                Status::SERVICE_UNAVAILABLE,
                "agent_busy",
                "The agent is handling too many connections",
            )
            .write_to(&mut conn, Method::Get, false);
            return;
        }

        let live = self.live.clone();
        let live_on_failure = self.live.clone();
        let spawned = std::thread::Builder::new()
            .name("agent-http-conn".into())
            .spawn(move || {
                let _guard = LiveGuard(live);
                self.serve_connection(Box::new(conn), peer);
            });

        if spawned.is_err() {
            live_on_failure.fetch_sub(1, Ordering::SeqCst);
        }
    }

    fn serve_connection(&self, conn: Box<dyn Conn>, peer: PeerInfo) {
        let _ = conn.set_read_timeout(Some(self.config.idle_timeout));

        // Two handles onto the same socket: one buffered for reading (its
        // buffer must survive across pipelined requests and across a protocol
        // upgrade), one for writing.
        let Ok(writer_handle) = conn.try_clone_conn() else { return };
        let mut writer = writer_handle;
        let mut reader = BufReader::with_capacity(8 * 1024, conn);

        loop {
            let mut req = match Request::read_head(&mut reader, peer.clone()) {
                Ok(r) => r,
                Err(HttpError::Closed) => return,
                Err(HttpError::Io(_)) => return, // timeout or reset: just drop
                Err(e) => {
                    let (status, code) = match e {
                        HttpError::TooLarge(_) => (Status::PAYLOAD_TOO_LARGE, "request_too_large"),
                        _ => (Status::BAD_REQUEST, "malformed_request"),
                    };
                    let _ = Response::error(status, code, e.to_string())
                        .write_to(&mut writer, Method::Get, false);
                    return;
                }
            };

            let method = req.method;
            let keep_alive = req.keep_alive && !self.shutdown.load(Ordering::Relaxed);
            let chunked = req.headers.contains_token("transfer-encoding", "chunked");

            let _ = writer.set_read_timeout(Some(self.config.read_timeout));

            let response = match self.router.lookup(req.method, &req.uri.path) {
                Lookup::Found { handler, params, streaming_body } => {
                    req.params = params;
                    if streaming_body {
                        // Spool to disk rather than hold a multi-gigabyte upload
                        // in memory. The handler gets a path, not bytes.
                        match spool_body(
                            &mut reader,
                            &req,
                            chunked,
                            &self.config.spool_dir,
                            MAX_SPOOLED_BODY,
                        ) {
                            Ok(Some(spool)) => {
                                req.params
                                    .insert("__body_file".into(), spool.path.display().to_string());
                                let resp = handler(&self.state, req);
                                drop(spool); // removes the temp file
                                resp
                            }
                            Ok(None) => handler(&self.state, req),
                            Err(HttpError::TooLarge(what)) => Response::error(
                                Status::PAYLOAD_TOO_LARGE,
                                "request_too_large",
                                format!("{what} exceeds the agent's limit"),
                            ),
                            Err(_) => return,
                        }
                    } else {
                        match req.read_body(&mut reader) {
                            Ok(()) => handler(&self.state, req),
                            Err(HttpError::TooLarge(what)) => Response::error(
                                Status::PAYLOAD_TOO_LARGE,
                                "request_too_large",
                                format!("{what} exceeds the agent's limit"),
                            ),
                            Err(_) => return,
                        }
                    }
                }
                Lookup::MethodNotAllowed(allow) => {
                    let _ = request::drain_body(&mut reader, &req.body, chunked);
                    Response::error(
                        Status::METHOD_NOT_ALLOWED,
                        "method_not_allowed",
                        format!("{method} is not supported on this path"),
                    )
                    .header("Allow", allow)
                }
                Lookup::NotFound => {
                    let _ = request::drain_body(&mut reader, &req.body, chunked);
                    Response::error(Status::NOT_FOUND, "not_found", "No such endpoint on this agent")
                }
            };

            let is_upgrade = matches!(response.payload, Payload::Upgrade(_));
            match response.write_to(&mut writer, method, keep_alive && !is_upgrade) {
                Ok(Some(upgrade)) => {
                    upgrade(Upgraded { reader, writer });
                    return;
                }
                Ok(None) => {}
                Err(_) => return,
            }

            if !keep_alive {
                return;
            }
            let _ = writer.set_read_timeout(Some(self.config.idle_timeout));
        }
    }
}

/// A spooled request body that deletes itself when dropped.
struct Spool {
    path: PathBuf,
}

impl Drop for Spool {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

fn spool_body<R: std::io::Read>(
    reader: &mut BufReader<R>,
    req: &Request,
    chunked: bool,
    dir: &std::path::Path,
    limit: u64,
) -> Result<Option<Spool>, HttpError> {
    use std::io::Read;

    let declared = match &req.body {
        Body::Pending { len } => *len,
        Body::Bytes(_) => return Ok(None),
    };
    if declared.is_none() && !chunked {
        return Ok(None); // no body at all
    }
    if let Some(n) = declared {
        if n > limit {
            return Err(HttpError::TooLarge("request body"));
        }
        if n == 0 {
            return Ok(None);
        }
    }

    std::fs::create_dir_all(dir)?;
    let name = format!(
        "upload-{}-{}.part",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    );
    let path = dir.join(name);
    let spool = Spool { path: path.clone() };

    let mut file = std::fs::File::create(&path)?;
    restrict_file(&file)?;

    if chunked {
        // Stream chunk-by-chunk instead of buffering the whole body.
        let mut written: u64 = 0;
        loop {
            let size = read_chunk_size(reader)?;
            if size == 0 {
                // Consume trailers.
                loop {
                    let line = read_crlf_line(reader, 8192)?;
                    if line.is_empty() {
                        break;
                    }
                }
                break;
            }
            written += size as u64;
            if written > limit {
                return Err(HttpError::TooLarge("chunked body"));
            }
            let mut remaining = size;
            let mut buf = [0u8; 64 * 1024];
            while remaining > 0 {
                let want = remaining.min(buf.len());
                reader.read_exact(&mut buf[..want])?;
                file.write_all(&buf[..want])?;
                remaining -= want;
            }
            let sep = read_crlf_line(reader, 8)?;
            if !sep.is_empty() {
                return Err(HttpError::Malformed("missing chunk terminator"));
            }
        }
    } else {
        let mut remaining = declared.unwrap_or(0);
        let mut buf = [0u8; 64 * 1024];
        while remaining > 0 {
            let want = remaining.min(buf.len() as u64) as usize;
            let got = reader.read(&mut buf[..want])?;
            if got == 0 {
                return Err(HttpError::Malformed("truncated body"));
            }
            file.write_all(&buf[..got])?;
            remaining -= got as u64;
        }
    }

    file.flush()?;
    Ok(Some(spool))
}

fn restrict_file(file: &std::fs::File) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    file.set_permissions(std::fs::Permissions::from_mode(0o600))
}

fn read_crlf_line<R: std::io::Read>(
    reader: &mut BufReader<R>,
    limit: usize,
) -> Result<String, HttpError> {
    use std::io::Read;
    let mut buf = Vec::new();
    loop {
        let mut b = [0u8; 1];
        if reader.read(&mut b)? == 0 {
            return Err(HttpError::Malformed("truncated line"));
        }
        if b[0] == b'\n' {
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return String::from_utf8(buf).map_err(|_| HttpError::Malformed("non-UTF-8 line"));
        }
        if buf.len() >= limit {
            return Err(HttpError::TooLarge("line"));
        }
        buf.push(b[0]);
    }
}

fn read_chunk_size<R: std::io::Read>(reader: &mut BufReader<R>) -> Result<usize, HttpError> {
    let line = read_crlf_line(reader, 64)?;
    let size_str = line.split(';').next().unwrap_or("").trim();
    usize::from_str_radix(size_str, 16).map_err(|_| HttpError::Malformed("bad chunk size"))
}

struct LiveGuard(Arc<AtomicUsize>);
impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

pub struct TcpConn(pub TcpStream);

impl std::io::Read for TcpConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for TcpConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
impl Conn for TcpConn {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(dur)
    }
    fn try_clone_conn(&self) -> std::io::Result<Box<dyn Conn>> {
        Ok(Box::new(TcpConn(self.0.try_clone()?)))
    }
}

pub struct UnixConn(pub UnixStream);

impl std::io::Read for UnixConn {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.0.read(buf)
    }
}
impl Write for UnixConn {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.write(buf)
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.0.flush()
    }
}
impl Conn for UnixConn {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        self.0.set_read_timeout(dur)
    }
    fn try_clone_conn(&self) -> std::io::Result<Box<dyn Conn>> {
        Ok(Box::new(UnixConn(self.0.try_clone()?)))
    }
}

impl Conn for Box<dyn Conn> {
    fn set_read_timeout(&self, dur: Option<Duration>) -> std::io::Result<()> {
        (**self).set_read_timeout(dur)
    }
    fn try_clone_conn(&self) -> std::io::Result<Box<dyn Conn>> {
        (**self).try_clone_conn()
    }
}

/// Restrict the Unix socket to its owner.
///
/// The socket is the local escape hatch used by `serveros-agent status` and by
/// the install script; anything else on the box reaching it would bypass the
/// bearer-token check entirely, so the permission bits are load-bearing.
fn set_socket_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}
