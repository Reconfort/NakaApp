//! A small HTTP/1.1 server and client.
//!
//! Concurrency model: thread-per-connection from a bounded pool. The agent
//! serves one desktop app plus the occasional health probe, so a few dozen
//! threads is the right shape — it avoids an async runtime dependency and keeps
//! stack traces readable when something goes wrong at 3am on a customer's box.
//!
//! Everything is bounded on purpose: header size, body size, request line
//! length, idle time, and the number of live connections. An agent that can be
//! made to allocate without limit is an agent that takes the server down.

#![forbid(unsafe_code)]

pub mod client;
pub mod request;
pub mod response;
pub mod router;
pub mod server;
pub mod uri;
pub mod ws;

pub use request::{Body, Request};
pub use response::{Response, Status};
pub use router::{Params, Router};
pub use server::{Server, ServerConfig};

use std::fmt;

/// HTTP methods the agent understands. Anything else is answered 405.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    pub fn parse(s: &str) -> Option<Method> {
        Some(match s {
            "GET" => Method::Get,
            "HEAD" => Method::Head,
            "POST" => Method::Post,
            "PUT" => Method::Put,
            "PATCH" => Method::Patch,
            "DELETE" => Method::Delete,
            "OPTIONS" => Method::Options,
            _ => return None,
        })
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Patch => "PATCH",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }

    /// Whether a body is expected to carry meaning for this method.
    pub fn allows_body(&self) -> bool {
        matches!(self, Method::Post | Method::Put | Method::Patch | Method::Delete)
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Case-insensitive header collection preserving the order headers arrived in.
#[derive(Debug, Clone, Default)]
pub struct Headers {
    entries: Vec<(String, String)>,
}

impl Headers {
    pub fn new() -> Self {
        Headers::default()
    }

    pub fn insert(&mut self, name: impl Into<String>, value: impl Into<String>) {
        let name = name.into();
        let value = value.into();
        for slot in self.entries.iter_mut() {
            if slot.0.eq_ignore_ascii_case(&name) {
                slot.1 = value;
                return;
            }
        }
        self.entries.push((name, value));
    }

    /// Add without replacing. Only `Set-Cookie` and `Vary` legitimately repeat;
    /// the agent uses it for neither, but the client parser needs it.
    pub fn append(&mut self, name: impl Into<String>, value: impl Into<String>) {
        self.entries.push((name.into(), value.into()));
    }

    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    pub fn contains_token(&self, name: &str, token: &str) -> bool {
        self.get(name).is_some_and(|v| {
            v.split(',').any(|part| part.trim().eq_ignore_ascii_case(token))
        })
    }

    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries.iter().map(|(k, v)| (k.as_str(), v.as_str()))
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Errors surfaced while reading or writing HTTP.
#[derive(Debug)]
pub enum HttpError {
    Io(std::io::Error),
    /// The peer sent something we will not parse. Carries a short reason that
    /// is safe to log — it never contains request content.
    Malformed(&'static str),
    /// A bound was exceeded (header block, body, request line).
    TooLarge(&'static str),
    /// Peer closed cleanly before sending anything. Normal for keep-alive.
    Closed,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HttpError::Io(e) => write!(f, "io: {e}"),
            HttpError::Malformed(m) => write!(f, "malformed request: {m}"),
            HttpError::TooLarge(m) => write!(f, "too large: {m}"),
            HttpError::Closed => write!(f, "connection closed"),
        }
    }
}

impl std::error::Error for HttpError {}

impl From<std::io::Error> for HttpError {
    fn from(e: std::io::Error) -> Self {
        HttpError::Io(e)
    }
}

pub type HttpResult<T> = Result<T, HttpError>;

#[cfg(test)]
mod tests;
