//! A small HTTP/1.1 client.
//!
//! Its only job is talking to local daemons over a Unix socket — the Docker
//! Engine API today, potentially others later. It is deliberately not a
//! general-purpose client: no TLS, no redirects, no cookies, no connection
//! pool. The agent never makes outbound calls to the internet.

use crate::request::read_chunked;
use crate::{Headers, HttpError, HttpResult, Method};
use serveros_json::Value;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::time::Duration;

/// Largest buffered response. Streaming responses bypass this.
pub const MAX_RESPONSE: usize = 32 * 1024 * 1024;

#[derive(Debug, Clone)]
pub enum Endpoint {
    Unix(PathBuf),
    Tcp(String),
}

#[derive(Debug, Clone)]
pub struct HttpClient {
    endpoint: Endpoint,
    /// Value for the `Host` header. Daemons ignore it but HTTP/1.1 requires it.
    host: String,
    pub timeout: Duration,
}

pub struct ClientResponse {
    pub status: u16,
    pub headers: Headers,
    pub body: Vec<u8>,
}

impl ClientResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn json(&self) -> Result<Value, String> {
        if self.body.is_empty() {
            return Ok(Value::Null);
        }
        serveros_json::from_slice(&self.body).map_err(|e| e.to_string())
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// A response whose body has not been read yet.
pub struct StreamingResponse {
    pub status: u16,
    pub headers: Headers,
    body: BodyReader,
}

impl StreamingResponse {
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }

    pub fn reader(self) -> impl Read {
        self.body
    }
}

enum BodyReader {
    Chunked(ChunkedReader),
    Length { inner: BufReader<Stream>, remaining: u64 },
    /// No framing: read until EOF. Docker uses this for hijacked streams.
    Eof(BufReader<Stream>),
}

impl Read for BodyReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            BodyReader::Chunked(c) => c.read(buf),
            BodyReader::Length { inner, remaining } => {
                if *remaining == 0 {
                    return Ok(0);
                }
                let want = (*remaining).min(buf.len() as u64) as usize;
                let got = inner.read(&mut buf[..want])?;
                *remaining -= got as u64;
                Ok(got)
            }
            BodyReader::Eof(inner) => inner.read(buf),
        }
    }
}

/// Decodes `Transfer-Encoding: chunked` incrementally.
struct ChunkedReader {
    inner: BufReader<Stream>,
    remaining: usize,
    done: bool,
}

impl Read for ChunkedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done {
            return Ok(0);
        }
        if self.remaining == 0 {
            let mut line = String::new();
            self.inner.read_line(&mut line)?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                // The CRLF that terminated the previous chunk.
                line.clear();
                self.inner.read_line(&mut line)?;
            }
            let size_str = line.trim().split(';').next().unwrap_or("").trim().to_string();
            if size_str.is_empty() {
                self.done = true;
                return Ok(0);
            }
            let size = usize::from_str_radix(&size_str, 16)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "bad chunk size"))?;
            if size == 0 {
                self.done = true;
                return Ok(0);
            }
            self.remaining = size;
        }
        let want = self.remaining.min(buf.len());
        let got = self.inner.read(&mut buf[..want])?;
        if got == 0 {
            self.done = true;
            return Ok(0);
        }
        self.remaining -= got;
        Ok(got)
    }
}

enum Stream {
    Unix(UnixStream),
    Tcp(std::net::TcpStream),
}

impl Read for Stream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Stream::Unix(s) => s.read(buf),
            Stream::Tcp(s) => s.read(buf),
        }
    }
}

impl Write for Stream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Stream::Unix(s) => s.write(buf),
            Stream::Tcp(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Stream::Unix(s) => s.flush(),
            Stream::Tcp(s) => s.flush(),
        }
    }
}

impl HttpClient {
    pub fn unix(path: impl Into<PathBuf>) -> HttpClient {
        HttpClient {
            endpoint: Endpoint::Unix(path.into()),
            host: "localhost".into(),
            timeout: Duration::from_secs(30),
        }
    }

    pub fn tcp(addr: impl Into<String>) -> HttpClient {
        let addr = addr.into();
        HttpClient { host: addr.clone(), endpoint: Endpoint::Tcp(addr), timeout: Duration::from_secs(30) }
    }

    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn connect(&self, timeout: Option<Duration>) -> HttpResult<Stream> {
        let effective = timeout.unwrap_or(self.timeout);
        match &self.endpoint {
            Endpoint::Unix(path) => {
                let s = UnixStream::connect(path)?;
                s.set_read_timeout(Some(effective))?;
                s.set_write_timeout(Some(self.timeout))?;
                Ok(Stream::Unix(s))
            }
            Endpoint::Tcp(addr) => {
                let s = std::net::TcpStream::connect(addr)?;
                s.set_read_timeout(Some(effective))?;
                s.set_write_timeout(Some(self.timeout))?;
                s.set_nodelay(true)?;
                Ok(Stream::Tcp(s))
            }
        }
    }

    fn write_request(
        &self,
        stream: &mut Stream,
        method: Method,
        path: &str,
        extra: &Headers,
        body: Option<&[u8]>,
    ) -> HttpResult<()> {
        let mut head = String::with_capacity(256);
        head.push_str(method.as_str());
        head.push(' ');
        head.push_str(path);
        head.push_str(" HTTP/1.1\r\n");
        head.push_str(&format!("Host: {}\r\n", self.host));
        head.push_str("User-Agent: serveros-agent\r\n");
        head.push_str("Accept: application/json\r\n");
        for (k, v) in extra.iter() {
            head.push_str(k);
            head.push_str(": ");
            head.push_str(v);
            head.push_str("\r\n");
        }
        match body {
            Some(b) => {
                head.push_str(&format!("Content-Length: {}\r\n", b.len()));
            }
            None if method.allows_body() => head.push_str("Content-Length: 0\r\n"),
            None => {}
        }
        head.push_str("\r\n");

        stream.write_all(head.as_bytes())?;
        if let Some(b) = body {
            stream.write_all(b)?;
        }
        stream.flush()?;
        Ok(())
    }

    /// Perform a request and buffer the whole response.
    pub fn request(
        &self,
        method: Method,
        path: &str,
        body: Option<&[u8]>,
    ) -> HttpResult<ClientResponse> {
        self.request_with(method, path, &Headers::new(), body)
    }

    pub fn request_with(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Option<&[u8]>,
    ) -> HttpResult<ClientResponse> {
        let mut stream = self.connect(None)?;
        self.write_request(&mut stream, method, path, headers, body)?;

        let mut reader = BufReader::new(stream);
        let (status, headers) = read_response_head(&mut reader)?;

        let body = if headers.contains_token("transfer-encoding", "chunked") {
            read_chunked(&mut reader, MAX_RESPONSE)?
        } else if let Some(len) = headers.get("content-length") {
            let n: usize = len.trim().parse().map_err(|_| HttpError::Malformed("bad Content-Length"))?;
            if n > MAX_RESPONSE {
                return Err(HttpError::TooLarge("response body"));
            }
            let mut buf = vec![0u8; n];
            reader.read_exact(&mut buf)?;
            buf
        } else if status == 204 || status == 304 {
            Vec::new()
        } else {
            let mut buf = Vec::new();
            reader.take(MAX_RESPONSE as u64).read_to_end(&mut buf)?;
            buf
        };

        Ok(ClientResponse { status, headers, body })
    }

    /// Perform a request and hand back the undecoded body as a reader.
    ///
    /// `read_timeout` overrides the client default; a log follow wants a long
    /// or absent timeout, while a status call wants a short one.
    pub fn request_streaming(
        &self,
        method: Method,
        path: &str,
        headers: &Headers,
        body: Option<&[u8]>,
        read_timeout: Option<Duration>,
    ) -> HttpResult<StreamingResponse> {
        let mut stream = self.connect(read_timeout)?;
        self.write_request(&mut stream, method, path, headers, body)?;

        let mut reader = BufReader::new(stream);
        let (status, headers) = read_response_head(&mut reader)?;

        let body = if headers.contains_token("transfer-encoding", "chunked") {
            BodyReader::Chunked(ChunkedReader { inner: reader, remaining: 0, done: false })
        } else if let Some(len) = headers.get("content-length") {
            let n: u64 = len.trim().parse().map_err(|_| HttpError::Malformed("bad Content-Length"))?;
            BodyReader::Length { inner: reader, remaining: n }
        } else {
            BodyReader::Eof(reader)
        };

        Ok(StreamingResponse { status, headers, body })
    }

    pub fn get(&self, path: &str) -> HttpResult<ClientResponse> {
        self.request(Method::Get, path, None)
    }

    pub fn post_json(&self, path: &str, value: &Value) -> HttpResult<ClientResponse> {
        let body = value.to_string().into_bytes();
        let mut h = Headers::new();
        h.insert("Content-Type", "application/json");
        self.request_with(Method::Post, path, &h, Some(&body))
    }

    pub fn post_empty(&self, path: &str) -> HttpResult<ClientResponse> {
        self.request(Method::Post, path, None)
    }

    pub fn delete(&self, path: &str) -> HttpResult<ClientResponse> {
        self.request(Method::Delete, path, None)
    }

    /// Whether the endpoint is reachable at all, without making a real request.
    pub fn is_reachable(&self) -> bool {
        self.connect(Some(Duration::from_millis(500))).is_ok()
    }
}

fn read_response_head<R: Read>(reader: &mut BufReader<R>) -> HttpResult<(u16, Headers)> {
    let status_line = read_line(reader)?;
    let mut parts = status_line.splitn(3, ' ');
    let _version = parts.next().ok_or(HttpError::Malformed("empty status line"))?;
    let code = parts
        .next()
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or(HttpError::Malformed("bad status code"))?;

    let mut headers = Headers::new();
    let mut total = 0usize;
    loop {
        let line = read_line(reader)?;
        if line.is_empty() {
            break;
        }
        total += line.len();
        if total > 64 * 1024 {
            return Err(HttpError::TooLarge("response headers"));
        }
        if let Some((k, v)) = line.split_once(':') {
            headers.append(k.trim(), v.trim());
        }
    }

    // 1xx responses are informational; skip to the real one.
    if (100..200).contains(&code) && code != 101 {
        return read_response_head(reader);
    }

    Ok((code, headers))
}

fn read_line<R: Read>(reader: &mut BufReader<R>) -> HttpResult<String> {
    let mut buf = Vec::with_capacity(128);
    loop {
        let mut b = [0u8; 1];
        match reader.read(&mut b) {
            Ok(0) => {
                if buf.is_empty() {
                    return Err(HttpError::Closed);
                }
                return Err(HttpError::Malformed("truncated response line"));
            }
            Ok(_) => {}
            Err(e) => return Err(HttpError::Io(e)),
        }
        if b[0] == b'\n' {
            if buf.last() == Some(&b'\r') {
                buf.pop();
            }
            return String::from_utf8(buf).map_err(|_| HttpError::Malformed("non-UTF-8 response"));
        }
        if buf.len() > 16 * 1024 {
            return Err(HttpError::TooLarge("response line"));
        }
        buf.push(b[0]);
    }
}
