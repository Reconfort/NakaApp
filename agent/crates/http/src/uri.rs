//! Path and query-string handling.
//!
//! Path normalisation matters more than usual here: several endpoints take a
//! filesystem path as a parameter, and a request-line traversal (`/..%2f..`)
//! that survives into `filesystem::` would be a directory-traversal hole. The
//! rule is that decoding happens exactly once, here, and the result is then
//! validated by whoever consumes it — never decoded again.

use std::collections::BTreeMap;

/// Percent-decode a single component.
///
/// Returns `None` for malformed escapes or for input that decodes to invalid
/// UTF-8; both indicate a client we should reject rather than guess at.
pub fn percent_decode(s: &str) -> Option<String> {
    if !s.contains('%') && !s.contains('+') {
        return Some(s.to_owned());
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if i + 2 >= bytes.len() {
                    return None;
                }
                let hi = hex(bytes[i + 1])?;
                let lo = hex(bytes[i + 2])?;
                out.push((hi << 4) | lo);
                i += 3;
            }
            // `+` means space only in a query string, never in a path. Callers
            // that care pass `decode_query_component` instead.
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

/// Like [`percent_decode`] but also maps `+` to space, per
/// `application/x-www-form-urlencoded`.
pub fn percent_decode_form(s: &str) -> Option<String> {
    let swapped: String = s.chars().map(|c| if c == '+' { ' ' } else { c }).collect();
    percent_decode(&swapped)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

/// Percent-encode for use inside a single path segment or query value.
///
/// Unreserved set per RFC 3986 plus nothing else; conservative on purpose
/// because the main consumer is the Docker Engine API, which is picky.
pub fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// A parsed request target: decoded path plus raw query.
#[derive(Debug, Clone, PartialEq)]
pub struct Uri {
    /// Percent-decoded, slash-normalised path. Always starts with `/`.
    pub path: String,
    /// Raw (still encoded) query string without the `?`.
    pub query: String,
}

impl Uri {
    /// Parse a request target. Rejects anything that is not an origin-form
    /// path, which is all the agent ever serves.
    pub fn parse(target: &str) -> Option<Uri> {
        // Absolute-form (`http://host/path`) is legal in HTTP/1.1 requests but
        // we have no virtual hosts, so strip it rather than 400.
        let target = if let Some(rest) = target.strip_prefix("http://") {
            match rest.find('/') {
                Some(i) => &rest[i..],
                None => "/",
            }
        } else {
            target
        };

        if !target.starts_with('/') {
            return None;
        }

        let (raw_path, query) = match target.split_once('?') {
            Some((p, q)) => (p, q.to_owned()),
            None => (target, String::new()),
        };

        // Fragments never reach a server, but a buggy client can send one.
        let raw_path = raw_path.split('#').next().unwrap_or(raw_path);

        let decoded = percent_decode(raw_path)?;

        // A NUL byte in a path is always an attack or a bug.
        if decoded.contains('\0') {
            return None;
        }

        Some(Uri { path: normalise_path(&decoded), query })
    }

    pub fn query_pairs(&self) -> BTreeMap<String, String> {
        parse_query(&self.query)
    }
}

/// Collapse duplicate slashes and resolve `.`/`..` segments.
///
/// `..` that would escape the root is dropped, so a normalised path can never
/// begin with `..`. Consumers still validate against their own root; this is
/// defence in depth, not the only defence.
pub fn normalise_path(path: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in path.split('/') {
        match seg {
            "" | "." => continue,
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    let mut out = String::with_capacity(path.len());
    for seg in &stack {
        out.push('/');
        out.push_str(seg);
    }
    if out.is_empty() {
        out.push('/');
    }
    out
}

/// Parse `a=1&b=2` into a map. Later keys win. Values are form-decoded.
pub fn parse_query(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (k, v) = match pair.split_once('=') {
            Some((k, v)) => (k, v),
            None => (pair, ""),
        };
        let (Some(k), Some(v)) = (percent_decode_form(k), percent_decode_form(v)) else {
            continue; // skip unparseable pairs rather than failing the request
        };
        map.insert(k, v);
    }
    map
}

/// Build `a=1&b=2` from pairs, encoding both sides.
pub fn build_query<'a>(pairs: impl IntoIterator<Item = (&'a str, &'a str)>) -> String {
    let mut out = String::new();
    for (k, v) in pairs {
        if !out.is_empty() {
            out.push('&');
        }
        out.push_str(&percent_encode(k));
        out.push('=');
        out.push_str(&percent_encode(v));
    }
    out
}
