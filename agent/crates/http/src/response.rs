//! Response construction and writing.
//!
//! Three body shapes, because the agent genuinely needs all three:
//!   * `Bytes`   — ordinary JSON answers.
//!   * `Stream`  — chunked output produced incrementally (log tails, file
//!                 downloads, container stats) so memory stays flat no matter
//!                 how much data flows.
//!   * `Upgrade` — hand the socket to a WebSocket session.

use crate::{Headers, Method};
use serveros_json::{Object, Value};
use std::io::{self, Write};

/// An HTTP status code with its canonical reason phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u16);

impl Status {
    pub const OK: Status = Status(200);
    pub const CREATED: Status = Status(201);
    pub const ACCEPTED: Status = Status(202);
    pub const NO_CONTENT: Status = Status(204);
    pub const BAD_REQUEST: Status = Status(400);
    pub const UNAUTHORIZED: Status = Status(401);
    pub const FORBIDDEN: Status = Status(403);
    pub const NOT_FOUND: Status = Status(404);
    pub const METHOD_NOT_ALLOWED: Status = Status(405);
    pub const CONFLICT: Status = Status(409);
    pub const PAYLOAD_TOO_LARGE: Status = Status(413);
    pub const UNPROCESSABLE: Status = Status(422);
    pub const TOO_MANY_REQUESTS: Status = Status(429);
    pub const INTERNAL: Status = Status(500);
    pub const NOT_IMPLEMENTED: Status = Status(501);
    pub const BAD_GATEWAY: Status = Status(502);
    pub const SERVICE_UNAVAILABLE: Status = Status(503);
    pub const GATEWAY_TIMEOUT: Status = Status(504);
    pub const SWITCHING_PROTOCOLS: Status = Status(101);

    pub fn reason(&self) -> &'static str {
        match self.0 {
            101 => "Switching Protocols",
            200 => "OK",
            201 => "Created",
            202 => "Accepted",
            204 => "No Content",
            206 => "Partial Content",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            409 => "Conflict",
            413 => "Content Too Large",
            415 => "Unsupported Media Type",
            422 => "Unprocessable Content",
            429 => "Too Many Requests",
            431 => "Request Header Fields Too Large",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            502 => "Bad Gateway",
            503 => "Service Unavailable",
            504 => "Gateway Timeout",
            _ => "Unknown",
        }
    }

    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.0)
    }
}

/// A socket the server can hand to a protocol upgrade.
pub trait Conn: io::Read + io::Write + Send {
    /// Set the read timeout, or clear it with `None`. WebSocket sessions clear
    /// the request-read timeout and manage liveness with ping/pong instead.
    fn set_read_timeout(&self, dur: Option<std::time::Duration>) -> io::Result<()>;

    /// Duplicate the handle so the connection can be read and written from two
    /// places at once. Required by the WebSocket session, which writes pings
    /// from a timer thread while the reader is blocked on a frame.
    fn try_clone_conn(&self) -> io::Result<Box<dyn Conn>>;
}

/// A connection after a protocol upgrade.
///
/// `reader` carries the buffer left over from parsing the request head, which
/// may already hold the first bytes the peer sent after the handshake. Handing
/// the raw socket over instead would silently drop them.
pub struct Upgraded {
    pub reader: io::BufReader<Box<dyn Conn>>,
    pub writer: Box<dyn Conn>,
}

pub enum Payload {
    Empty,
    Bytes(Vec<u8>),
    /// Written with `Transfer-Encoding: chunked`. The closure owns the writing
    /// and returns when the stream is complete.
    Stream(Box<dyn FnOnce(&mut dyn Write) -> io::Result<()> + Send>),
    /// The response line and headers are written, then the connection is handed
    /// over. Ends the connection's HTTP lifetime.
    Upgrade(Box<dyn FnOnce(Upgraded) + Send>),
}

pub struct Response {
    pub status: Status,
    pub headers: Headers,
    pub payload: Payload,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = match &self.payload {
            Payload::Empty => "empty",
            Payload::Bytes(b) => return write!(f, "Response({} , {} bytes)", self.status.0, b.len()),
            Payload::Stream(_) => "stream",
            Payload::Upgrade(_) => "upgrade",
        };
        write!(f, "Response({}, {kind})", self.status.0)
    }
}

impl Response {
    pub fn new(status: Status) -> Response {
        Response { status, headers: Headers::new(), payload: Payload::Empty }
    }

    pub fn json(value: impl Into<Value>) -> Response {
        let body = value.into().to_string().into_bytes();
        let mut r = Response::new(Status::OK);
        r.headers.insert("Content-Type", "application/json; charset=utf-8");
        r.payload = Payload::Bytes(body);
        r
    }

    pub fn json_status(status: Status, value: impl Into<Value>) -> Response {
        let mut r = Response::json(value);
        r.status = status;
        r
    }

    pub fn text(status: Status, body: impl Into<String>) -> Response {
        let mut r = Response::new(status);
        r.headers.insert("Content-Type", "text/plain; charset=utf-8");
        r.payload = Payload::Bytes(body.into().into_bytes());
        r
    }

    pub fn bytes(status: Status, content_type: &str, body: Vec<u8>) -> Response {
        let mut r = Response::new(status);
        r.headers.insert("Content-Type", content_type);
        r.payload = Payload::Bytes(body);
        r
    }

    pub fn no_content() -> Response {
        Response::new(Status::NO_CONTENT)
    }

    pub fn stream(
        content_type: &str,
        f: impl FnOnce(&mut dyn Write) -> io::Result<()> + Send + 'static,
    ) -> Response {
        let mut r = Response::new(Status::OK);
        r.headers.insert("Content-Type", content_type);
        r.payload = Payload::Stream(Box::new(f));
        r
    }

    /// A structured error.
    ///
    /// The shape is fixed across every endpoint so the macOS app can render a
    /// human message without special-casing: `code` drives the app's copy,
    /// `message` is a safe fallback, `detail` is what the "Technical details"
    /// disclosure shows.
    pub fn error(status: Status, code: &str, message: impl Into<String>) -> Response {
        let body = Object::new()
            .set("error", Object::new().set("code", code).set("message", message.into()));
        Response::json_status(status, body)
    }

    pub fn error_detail(
        status: Status,
        code: &str,
        message: impl Into<String>,
        detail: impl Into<String>,
    ) -> Response {
        let body = Object::new().set(
            "error",
            Object::new()
                .set("code", code)
                .set("message", message.into())
                .set("detail", detail.into()),
        );
        Response::json_status(status, body)
    }

    pub fn header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.insert(name, value);
        self
    }

    /// Write this response to `out`.
    ///
    /// Returns `Some(upgrade)` when the caller must hand the connection over.
    #[allow(clippy::type_complexity)]
    pub fn write_to(
        mut self,
        out: &mut dyn Write,
        method: Method,
        keep_alive: bool,
    ) -> io::Result<Option<Box<dyn FnOnce(Upgraded) + Send>>> {
        let is_upgrade = matches!(self.payload, Payload::Upgrade(_));
        let is_stream = matches!(self.payload, Payload::Stream(_));

        // Security headers. The agent serves JSON to a native client, never
        // HTML to a browser, but a mis-set Content-Type should not become an
        // XSS vector if someone points a browser at it.
        self.headers.insert("X-Content-Type-Options", "nosniff");
        self.headers.insert("Cache-Control", "no-store");
        self.headers.insert("Server", "serveros-agent");

        if !is_upgrade {
            match &self.payload {
                Payload::Bytes(b) => {
                    self.headers.insert("Content-Length", b.len().to_string());
                }
                Payload::Empty => {
                    self.headers.insert("Content-Length", "0");
                }
                Payload::Stream(_) => {
                    self.headers.insert("Transfer-Encoding", "chunked");
                }
                Payload::Upgrade(_) => unreachable!(),
            }
            self.headers
                .insert("Connection", if keep_alive { "keep-alive" } else { "close" });
        }

        let mut head = String::with_capacity(256);
        head.push_str("HTTP/1.1 ");
        head.push_str(&self.status.0.to_string());
        head.push(' ');
        head.push_str(self.status.reason());
        head.push_str("\r\n");
        for (name, value) in self.headers.iter() {
            // A header value containing CR or LF is response splitting. Values
            // here can originate from a filename, so this is a real path.
            if value.contains('\r') || value.contains('\n') {
                continue;
            }
            head.push_str(name);
            head.push_str(": ");
            head.push_str(value);
            head.push_str("\r\n");
        }
        head.push_str("\r\n");
        out.write_all(head.as_bytes())?;

        // HEAD gets the headers and nothing else.
        if method == Method::Head && !is_upgrade {
            out.flush()?;
            return Ok(None);
        }

        match self.payload {
            Payload::Empty => {}
            Payload::Bytes(b) => out.write_all(&b)?,
            Payload::Stream(f) => {
                let mut chunked = ChunkedWriter { inner: out, failed: false };
                let result = f(&mut chunked);
                // Always terminate the stream, even after a handler error, so
                // the client sees a clean end rather than a hung socket.
                chunked.finish()?;
                result?;
            }
            Payload::Upgrade(f) => {
                out.flush()?;
                return Ok(Some(f));
            }
        }
        if !is_stream {
            out.flush()?;
        }
        Ok(None)
    }
}

/// Wraps a writer in HTTP chunked transfer encoding.
struct ChunkedWriter<'a> {
    inner: &'a mut dyn Write,
    failed: bool,
}

impl ChunkedWriter<'_> {
    fn finish(&mut self) -> io::Result<()> {
        if self.failed {
            return Ok(());
        }
        self.inner.write_all(b"0\r\n\r\n")?;
        self.inner.flush()
    }
}

impl Write for ChunkedWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            // A zero-length chunk would terminate the stream prematurely.
            return Ok(0);
        }
        match (|| -> io::Result<()> {
            self.inner.write_all(format!("{:x}\r\n", buf.len()).as_bytes())?;
            self.inner.write_all(buf)?;
            self.inner.write_all(b"\r\n")
        })() {
            Ok(()) => Ok(buf.len()),
            Err(e) => {
                self.failed = true;
                Err(e)
            }
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
