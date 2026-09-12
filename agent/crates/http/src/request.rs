//! Request parsing.

use crate::uri::Uri;
use crate::{Headers, HttpError, HttpResult, Method};
use serveros_json::Value;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Read};

/// Hard limits. These are not configurable: every one of them is a
/// denial-of-service boundary, and a deployment that needs them raised has a
/// design problem rather than a configuration problem.
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
pub const MAX_HEADER_BLOCK: usize = 32 * 1024;
pub const MAX_HEADER_COUNT: usize = 100;
/// Largest in-memory body. File uploads stream instead (see `Body::Reader`).
pub const MAX_BODY: usize = 4 * 1024 * 1024;

/// The body of a request.
pub enum Body {
    /// Fully buffered. The common case.
    Bytes(Vec<u8>),
    /// Not read yet — the handler will stream it. Used by file upload, where
    /// buffering a 2 GB disk image would be fatal.
    Pending { len: Option<u64> },
}

impl Body {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Body::Bytes(b) => b,
            Body::Pending { .. } => &[],
        }
    }
}

impl std::fmt::Debug for Body {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            // Never Debug-print a body: it may hold a password for a new Linux
            // user or a database credential.
            Body::Bytes(b) => write!(f, "Bytes({} bytes)", b.len()),
            Body::Pending { len } => write!(f, "Pending({len:?})"),
        }
    }
}

#[derive(Debug)]
pub struct Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: Headers,
    pub body: Body,
    /// Path parameters captured by the router, e.g. `{id}`.
    pub params: BTreeMap<String, String>,
    /// How the peer reached us, for audit records.
    pub peer: PeerInfo,
    /// Keep-alive was negotiated for this connection.
    pub keep_alive: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PeerInfo {
    /// Loopback TCP; carries the source port only. The address is always
    /// loopback because the agent refuses to bind anywhere else by default.
    Loopback { port: u16 },
    /// Unix domain socket, with the peer's credentials if the OS gave them.
    Unix { uid: Option<u32>, pid: Option<i32> },
    /// Non-loopback TCP. Only reachable when an operator has explicitly opted
    /// in; recorded in full so the audit log is useful.
    Remote { addr: String },
}

impl PeerInfo {
    pub fn describe(&self) -> String {
        match self {
            PeerInfo::Loopback { port } => format!("127.0.0.1:{port}"),
            PeerInfo::Unix { uid: Some(uid), .. } => format!("unix(uid={uid})"),
            PeerInfo::Unix { .. } => "unix".to_string(),
            PeerInfo::Remote { addr } => addr.clone(),
        }
    }
}

impl Request {
    /// Read a request head (request line + headers) from `reader`.
    ///
    /// The body is NOT read here — `read_body` does that once the router has
    /// decided whether this route streams.
    pub fn read_head<R: Read>(reader: &mut BufReader<R>, peer: PeerInfo) -> HttpResult<Request> {
        let line = read_line(reader, MAX_REQUEST_LINE)?;
        if line.is_empty() {
            return Err(HttpError::Closed);
        }

        let mut parts = line.split(' ');
        let method_str = parts.next().ok_or(HttpError::Malformed("missing method"))?;
        let target = parts.next().ok_or(HttpError::Malformed("missing target"))?;
        let version = parts.next().ok_or(HttpError::Malformed("missing version"))?;
        if parts.next().is_some() {
            return Err(HttpError::Malformed("extra data in request line"));
        }

        let method = Method::parse(method_str).ok_or(HttpError::Malformed("unknown method"))?;
        let uri = Uri::parse(target).ok_or(HttpError::Malformed("bad request target"))?;

        let http11 = match version {
            "HTTP/1.1" => true,
            "HTTP/1.0" => false,
            _ => return Err(HttpError::Malformed("unsupported HTTP version")),
        };

        let headers = read_headers(reader)?;

        // RFC 9112: keep-alive is the HTTP/1.1 default, opt-in for 1.0.
        let keep_alive = if headers.contains_token("connection", "close") {
            false
        } else if http11 {
            true
        } else {
            headers.contains_token("connection", "keep-alive")
        };

        // Request smuggling defence: refuse anything that specifies the body
        // length two different ways.
        if headers.get("content-length").is_some()
            && headers.contains_token("transfer-encoding", "chunked")
        {
            return Err(HttpError::Malformed("both Content-Length and Transfer-Encoding"));
        }

        let len = match headers.get("content-length") {
            Some(v) => {
                let n: u64 = v
                    .trim()
                    .parse()
                    .map_err(|_| HttpError::Malformed("bad Content-Length"))?;
                Some(n)
            }
            None => None,
        };

        Ok(Request {
            method,
            uri,
            headers,
            body: Body::Pending { len },
            params: BTreeMap::new(),
            peer,
            keep_alive,
        })
    }

    /// Buffer the body into memory, enforcing [`MAX_BODY`].
    pub fn read_body<R: Read>(&mut self, reader: &mut BufReader<R>) -> HttpResult<()> {
        if let Body::Bytes(_) = self.body {
            return Ok(());
        }
        let chunked = self.headers.contains_token("transfer-encoding", "chunked");
        let bytes = if chunked {
            read_chunked(reader, MAX_BODY)?
        } else {
            match &self.body {
                Body::Pending { len: Some(n) } => {
                    if *n > MAX_BODY as u64 {
                        return Err(HttpError::TooLarge("request body"));
                    }
                    let mut buf = vec![0u8; *n as usize];
                    reader.read_exact(&mut buf)?;
                    buf
                }
                _ => Vec::new(),
            }
        };
        self.body = Body::Bytes(bytes);
        Ok(())
    }

    /// Parse the buffered body as JSON.
    pub fn json(&self) -> Result<Value, String> {
        let bytes = self.body.as_bytes();
        if bytes.is_empty() {
            return Ok(Value::Object(Default::default()));
        }
        serveros_json::from_slice(bytes).map_err(|e| e.to_string())
    }

    pub fn query(&self) -> BTreeMap<String, String> {
        self.uri.query_pairs()
    }

    pub fn query_str(&self, key: &str) -> Option<String> {
        self.query().get(key).cloned()
    }

    /// Parse a query parameter as a number, ignoring unparseable values.
    pub fn query_num<T: std::str::FromStr>(&self, key: &str) -> Option<T> {
        self.query_str(key)?.parse().ok()
    }

    /// A query flag: present and not `false`/`0` counts as true.
    pub fn query_flag(&self, key: &str) -> bool {
        match self.query_str(key) {
            Some(v) => !matches!(v.as_str(), "false" | "0" | ""),
            None => false,
        }
    }

    pub fn param(&self, key: &str) -> Option<&str> {
        self.params.get(key).map(|s| s.as_str())
    }

    /// The bearer credential, if the client sent one.
    pub fn bearer_token(&self) -> Option<&str> {
        let value = self.headers.get("authorization")?;
        let (scheme, token) = value.split_once(' ')?;
        if scheme.eq_ignore_ascii_case("bearer") {
            Some(token.trim())
        } else {
            None
        }
    }

    pub fn is_websocket_upgrade(&self) -> bool {
        self.headers.contains_token("connection", "upgrade")
            && self.headers.get("upgrade").is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
    }
}

/// Read one CRLF-terminated line, without the terminator.
fn read_line<R: Read>(reader: &mut BufReader<R>, limit: usize) -> HttpResult<String> {
    let mut buf = Vec::with_capacity(128);
    loop {
        let mut byte = [0u8; 1];
        match reader.read(&mut byte) {
            Ok(0) => {
                if buf.is_empty() {
                    return Err(HttpError::Closed);
                }
                return Err(HttpError::Malformed("truncated line"));
            }
            Ok(_) => {}
            Err(e) => return Err(HttpError::Io(e)),
        }
        match byte[0] {
            b'\n' => {
                if buf.last() == Some(&b'\r') {
                    buf.pop();
                }
                return String::from_utf8(buf).map_err(|_| HttpError::Malformed("non-UTF-8 line"));
            }
            b => {
                if buf.len() >= limit {
                    return Err(HttpError::TooLarge("line"));
                }
                buf.push(b);
            }
        }
    }
}

fn read_headers<R: Read>(reader: &mut BufReader<R>) -> HttpResult<Headers> {
    let mut headers = Headers::new();
    let mut total = 0usize;
    loop {
        let line = read_line(reader, MAX_REQUEST_LINE)?;
        if line.is_empty() {
            return Ok(headers);
        }
        total += line.len() + 2;
        if total > MAX_HEADER_BLOCK {
            return Err(HttpError::TooLarge("header block"));
        }
        if headers.len() >= MAX_HEADER_COUNT {
            return Err(HttpError::TooLarge("header count"));
        }
        // Obsolete line folding is a smuggling vector; reject it outright.
        if line.starts_with(' ') || line.starts_with('\t') {
            return Err(HttpError::Malformed("obsolete header folding"));
        }
        let (name, value) = line
            .split_once(':')
            .ok_or(HttpError::Malformed("header without colon"))?;
        if name.is_empty() || name.chars().any(|c| c.is_whitespace()) {
            return Err(HttpError::Malformed("bad header name"));
        }
        headers.append(name, value.trim());
    }
}

/// Decode `Transfer-Encoding: chunked`, enforcing a total size limit.
pub fn read_chunked<R: Read>(reader: &mut BufReader<R>, limit: usize) -> HttpResult<Vec<u8>> {
    let mut out = Vec::new();
    loop {
        let line = read_line(reader, 64)?;
        // Chunk extensions after `;` are legal and ignorable.
        let size_str = line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_str, 16)
            .map_err(|_| HttpError::Malformed("bad chunk size"))?;
        if size == 0 {
            // Consume trailers until the terminating empty line.
            loop {
                let t = read_line(reader, MAX_REQUEST_LINE)?;
                if t.is_empty() {
                    break;
                }
            }
            return Ok(out);
        }
        if out.len() + size > limit {
            return Err(HttpError::TooLarge("chunked body"));
        }
        let start = out.len();
        out.resize(start + size, 0);
        reader.read_exact(&mut out[start..])?;
        // Each chunk is followed by CRLF.
        let sep = read_line(reader, 8)?;
        if !sep.is_empty() {
            return Err(HttpError::Malformed("missing chunk terminator"));
        }
    }
}

/// Discard any unread body so the connection can be reused.
pub fn drain_body<R: Read>(reader: &mut BufReader<R>, body: &Body, chunked: bool) -> HttpResult<()> {
    if chunked {
        read_chunked(reader, MAX_BODY)?;
        return Ok(());
    }
    if let Body::Pending { len: Some(n) } = body {
        let mut remaining = *n;
        let mut scratch = [0u8; 8192];
        while remaining > 0 {
            let want = remaining.min(scratch.len() as u64) as usize;
            let got = reader.read(&mut scratch[..want])?;
            if got == 0 {
                break;
            }
            remaining -= got as u64;
        }
    }
    Ok(())
}

/// Consume a `BufRead` line-wise. Used by the log tailer.
pub fn read_available_lines<R: BufRead>(reader: &mut R, max: usize) -> std::io::Result<Vec<String>> {
    let mut lines = Vec::new();
    let mut buf = String::new();
    while lines.len() < max {
        buf.clear();
        let n = reader.read_line(&mut buf)?;
        if n == 0 {
            break;
        }
        lines.push(buf.trim_end_matches(['\n', '\r']).to_string());
    }
    Ok(lines)
}
