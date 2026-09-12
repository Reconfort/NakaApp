//! A client for the Docker Engine API over its Unix socket.
//!
//! This crate is the "Docker" half of the ServerOS agent's infrastructure
//! model. It exists so the rest of the agent — and eventually the Mac app —
//! can talk about *containers, images, volumes, networks and Compose projects*
//! instead of about `docker ps` output that has to be scraped.
//!
//! Deliberate design choices, in the order they tend to bite people:
//!
//! * **We call the Engine API, never the `docker` CLI.** Shelling out means
//!   parsing human-formatted tables, inheriting the CLI's config and auth, and
//!   requiring the binary to be installed. The socket is the real interface;
//!   the CLI is just another client of it.
//!
//! * **Version negotiation is pinned low on purpose** (see [`MAX_API_VERSION`]).
//!   The Engine API is strictly additive within 1.x and the daemon rejects a
//!   version above its own, so asking for a *modest* version is what makes one
//!   binary work against Docker 20.10 on a customer's ageing Ubuntu box and
//!   against the newest release on a fresh one.
//!
//! * **Parsing is separated from I/O.** Every `parse_*` / `from_*` function
//!   takes a `&Value` or `&[u8]`, so the whole mapping layer is testable
//!   without a daemon — and the tests then pin the mapping against JSON
//!   captured from a real daemon rather than against our own assumptions.
//!
//! * **Nothing here executes arbitrary commands.** There is no `exec` wrapper
//!   and no passthrough endpoint. Each method is one named infrastructure
//!   operation, which is what makes authorisation and auditing tractable a
//!   layer up.
//!
//! * **Container environment is masked by default.** See [`containers::mask_env`].
//!   `Config.Env` is where `POSTGRES_PASSWORD` lives; treating it as ordinary
//!   metadata would put secrets on a user's screen and in the control plane's
//!   audit log.

#![forbid(unsafe_code)]

use serveros_http::client::{ClientResponse, HttpClient};
use serveros_json::Value;
use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

pub mod containers;
pub mod info;
pub mod projects;
pub mod resources;

pub use containers::{
    Container, ContainerDetail, ContainerStats, DemuxReader, EnvVar, Frame, HealthCheck, LogLine,
    LogStream, MountInfo, NetworkAttachment, Port, RestartPolicy, StreamKind, mask_env,
};
pub use info::DaemonInfo;
pub use projects::Project;
pub use resources::{Image, Network, Volume};

/// The conventional path of the Docker daemon socket.
pub const DEFAULT_SOCKET: &str = "/var/run/docker.sock";

/// Highest Engine API version this crate is written against.
///
/// Why 1.43 and not "whatever the daemon reports": every field this crate reads
/// has existed since well before 1.43, and the daemon happily serves an older
/// version than it implements — but it hard-rejects a *newer* one
/// (`client version 1.99 is too new`). Pinning a modest ceiling therefore means
/// one agent binary speaks to Docker 20.10 (API 1.41) and to Docker 29
/// (API 1.54) without a conditional in sight. Raise this only when we actually
/// need a field that requires it.
pub const MAX_API_VERSION: &str = "1.43";

/// Version used when `/version` cannot be read at all.
///
/// 1.41 ships with Docker 20.10, which is the oldest release we support, so it
/// is the safest guess when the daemon will not tell us what it speaks.
pub const FALLBACK_API_VERSION: &str = "1.41";

/// Default grace period handed to `docker stop`, in seconds. Matches the CLI.
pub const DEFAULT_STOP_TIMEOUT: i64 = 10;

/// Everything that can go wrong talking to the daemon.
///
/// The split matters to the UI: `Unavailable` means "Docker is not running
/// here" (an empty state), `NotFound` means "that container is gone" (a stale
/// view to refresh), and `Api` means "Docker refused, and here is its reason"
/// (a message worth showing verbatim).
#[derive(Debug)]
pub enum DockerError {
    /// The socket could not be reached — daemon stopped, not installed, or the
    /// agent lacks permission on the socket.
    Unavailable,
    /// The daemon answered 404. Carries Docker's own message.
    NotFound(String),
    /// The daemon answered with another error status.
    Api { status: u16, message: String },
    /// Socket-level failure after a successful connect.
    Transport(String),
    /// The daemon answered, but not with something we could decode.
    Decode(String),
}

impl fmt::Display for DockerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DockerError::Unavailable => f.write_str("the Docker daemon is not reachable"),
            DockerError::NotFound(m) => write!(f, "not found: {m}"),
            DockerError::Api { status, message } => write!(f, "docker error {status}: {message}"),
            DockerError::Transport(m) => write!(f, "transport: {m}"),
            DockerError::Decode(m) => write!(f, "malformed response: {m}"),
        }
    }
}

impl std::error::Error for DockerError {}

impl DockerError {
    /// Whether this is the "Docker isn't here" case, which callers usually
    /// render as an empty state rather than an error.
    pub fn is_unavailable(&self) -> bool {
        matches!(self, DockerError::Unavailable)
    }

    /// Stable machine-readable code for the agent's HTTP error envelope.
    pub fn code(&self) -> &'static str {
        match self {
            DockerError::Unavailable => "docker_unavailable",
            DockerError::NotFound(_) => "not_found",
            DockerError::Api { .. } => "docker_error",
            DockerError::Transport(_) => "docker_transport",
            DockerError::Decode(_) => "docker_decode",
        }
    }
}

/// A connected Docker Engine API client.
///
/// Cheap to clone; it holds no live socket. Each request opens a fresh
/// connection, which is what the daemon expects and keeps failure handling
/// trivial (there is no pool to poison).
#[derive(Debug, Clone)]
pub struct DockerClient {
    http: HttpClient,
    /// Negotiated version, e.g. `1.43`.
    version: String,
    /// Path prefix built from it, e.g. `/v1.43`.
    prefix: String,
}

impl DockerClient {
    /// Connect to the daemon and negotiate an API version.
    ///
    /// Returns [`DockerError::Unavailable`] when the socket cannot be opened at
    /// all — that is a genuinely different situation from a daemon that answers
    /// oddly, and the agent reports it as "Docker not installed / not running".
    ///
    /// If the socket *is* open but `/version` fails or is unintelligible, we
    /// keep the client and fall back to [`FALLBACK_API_VERSION`]: a daemon
    /// mid-restart should not permanently break the connection.
    pub fn connect(socket: impl Into<PathBuf>) -> Result<DockerClient, DockerError> {
        let http = HttpClient::unix(socket).with_timeout(Duration::from_secs(30));
        if !http.is_reachable() {
            return Err(DockerError::Unavailable);
        }

        // Asked unversioned: the daemon answers /version at any prefix, and we
        // do not yet know which prefix it will accept.
        let version = match http.get("/version") {
            Ok(resp) if resp.is_success() => match resp.json() {
                Ok(v) => {
                    let api = v.get("ApiVersion").and_then(Value::as_str).unwrap_or("");
                    let min = v.get("MinAPIVersion").and_then(Value::as_str).unwrap_or("");
                    negotiate_version(api, min)
                }
                Err(_) => FALLBACK_API_VERSION.to_string(),
            },
            _ => FALLBACK_API_VERSION.to_string(),
        };

        Ok(DockerClient { prefix: format!("/v{version}"), version, http })
    }

    /// Build a client for an already-configured transport, skipping the probe.
    ///
    /// Used by tests and by callers that have their own reachability policy.
    pub fn with_http(http: HttpClient, version: impl Into<String>) -> DockerClient {
        let version = version.into();
        DockerClient { prefix: format!("/v{version}"), version, http }
    }

    /// The Engine API version this client prefixes its requests with.
    pub fn api_version(&self) -> &str {
        &self.version
    }

    /// Cheap liveness check that never blocks long.
    ///
    /// Connect-only, with a sub-second timeout: this is called on every status
    /// refresh and must not stall the UI when the daemon is wedged.
    pub fn is_available(&self) -> bool {
        self.http.is_reachable()
    }

    // ---- request plumbing ------------------------------------------------

    /// Prefix a bare Engine path with the negotiated version.
    pub(crate) fn url(&self, path: &str) -> String {
        format!("{}{}", self.prefix, path)
    }

    pub(crate) fn get_json(&self, path: &str) -> Result<Value, DockerError> {
        let resp = self.http.get(&self.url(path)).map_err(transport)?;
        let resp = check(resp)?;
        resp.json().map_err(DockerError::Decode)
    }

    /// POST with no body, used by every lifecycle verb.
    ///
    /// 304 is deliberately *not* an error: Docker returns it for "already
    /// started" / "already stopped", and for our purposes the requested state
    /// has been reached, which is what the caller asked for.
    pub(crate) fn post_action(&self, path: &str) -> Result<(), DockerError> {
        let resp = self.http.post_empty(&self.url(path)).map_err(transport)?;
        if resp.status == 304 {
            return Ok(());
        }
        check(resp).map(|_| ())
    }

    pub(crate) fn delete_action(&self, path: &str) -> Result<(), DockerError> {
        let resp = self.http.delete(&self.url(path)).map_err(transport)?;
        check(resp).map(|_| ())
    }

    pub(crate) fn http(&self) -> &HttpClient {
        &self.http
    }
}

/// Map an HTTP-layer failure onto our error type.
///
/// A refused or vanished socket reads as `Unavailable` rather than as a generic
/// transport error, because it is the case the UI has a real empty state for.
pub(crate) fn transport(e: serveros_http::HttpError) -> DockerError {
    match &e {
        serveros_http::HttpError::Io(io) => match io.kind() {
            std::io::ErrorKind::NotFound
            | std::io::ErrorKind::ConnectionRefused
            | std::io::ErrorKind::PermissionDenied => DockerError::Unavailable,
            _ => DockerError::Transport(e.to_string()),
        },
        serveros_http::HttpError::Closed => DockerError::Unavailable,
        _ => DockerError::Transport(e.to_string()),
    }
}

/// Turn a non-2xx response into a `DockerError`, keeping Docker's own wording.
///
/// Docker always answers errors as `{"message":"..."}`; surfacing that verbatim
/// is the difference between "Docker error 409" and "container already
/// started", and the latter is what the user needs.
pub(crate) fn check(resp: ClientResponse) -> Result<ClientResponse, DockerError> {
    if resp.is_success() {
        return Ok(resp);
    }
    let message = error_message(&resp.body, resp.status);
    if resp.status == 404 {
        return Err(DockerError::NotFound(message));
    }
    Err(DockerError::Api { status: resp.status, message })
}

/// Extract `{"message":"..."}` from an error body, falling back to the raw text.
///
/// A body that *is* JSON but carries no message (`{}`) degrades to `HTTP 500`
/// rather than to the literal document: pasting `{}` into an error dialog tells
/// the user nothing and looks like a bug in our own code.
pub(crate) fn error_message(body: &[u8], status: u16) -> String {
    if let Ok(v) = serveros_json::from_slice(body) {
        if let Some(m) = v.get("message").and_then(Value::as_str) {
            if !m.trim().is_empty() {
                return m.to_string();
            }
        }
        return format!("HTTP {status}");
    }
    // Some proxies and older daemons answer with bare text ("page not found").
    let text = String::from_utf8_lossy(body).trim().to_string();
    if text.is_empty() { format!("HTTP {status}") } else { text }
}

// ---- version negotiation -------------------------------------------------

/// Pick the API version to speak, given what the daemon advertises.
///
/// Rules, in order:
///   1. Never exceed the daemon's `ApiVersion` — it answers `too new` and the
///      whole client is dead.
///   2. Never go below its `MinAPIVersion` — it answers `too old`.
///   3. Otherwise stay at [`MAX_API_VERSION`], the version we are actually
///      written and tested against.
///
/// Rule 2 beats rule 3 when a future daemon drops support for 1.43: speaking
/// its minimum is a better bet than speaking a version it has removed.
pub fn negotiate_version(daemon_api: &str, daemon_min: &str) -> String {
    let ours = parse_version(MAX_API_VERSION);
    let api = parse_version(daemon_api);
    let min = parse_version(daemon_min);

    // Without a usable ApiVersion there is nothing to negotiate against.
    let Some(api) = api else {
        return FALLBACK_API_VERSION.to_string();
    };
    let Some(ours) = ours else {
        return FALLBACK_API_VERSION.to_string();
    };

    let mut chosen = if api < ours { api } else { ours };
    if let Some(min) = min {
        if chosen < min {
            chosen = min;
        }
    }
    format!("{}.{}", chosen.0, chosen.1)
}

/// Parse `"1.43"` into `(1, 43)`. Anything else is `None`.
///
/// Comparison is on the tuple, never on the string: `"1.9"` sorts after
/// `"1.43"` lexically, which would negotiate a version the daemon rejects.
pub fn parse_version(s: &str) -> Option<(u32, u32)> {
    let (major, minor) = s.trim().split_once('.')?;
    Some((major.parse().ok()?, minor.parse().ok()?))
}

// ---- shared parsing helpers ----------------------------------------------

/// Read a string field, treating `""` as absent.
///
/// Docker fills unset strings with `""` rather than omitting them
/// (`Gateway: ""`, `WorkingDir: ""`), and an empty string in the UI is worse
/// than a missing field: it renders as a blank row instead of being skipped.
pub(crate) fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Read a string at a nested path, treating `""` as absent.
pub(crate) fn str_path(v: &Value, path: &str) -> Option<String> {
    v.path(path)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

pub(crate) fn u64_field(v: &Value, key: &str) -> Option<u64> {
    v.get(key).and_then(Value::as_u64)
}

pub(crate) fn i64_field(v: &Value, key: &str) -> Option<i64> {
    v.get(key).and_then(Value::as_i64)
}

pub(crate) fn bool_field(v: &Value, key: &str) -> Option<bool> {
    v.get(key).and_then(Value::as_bool)
}

/// Read a `{"k":"v"}` map, tolerating `null` and non-string values.
pub(crate) fn string_map(v: Option<&Value>) -> Vec<(String, String)> {
    let Some(obj) = v.and_then(Value::as_object) else {
        return Vec::new();
    };
    obj.iter()
        .filter_map(|(k, v)| v.as_str().map(|s| (k.to_string(), s.to_string())))
        .collect()
}

/// Serialise a `(key, value)` list back to a JSON object.
pub(crate) fn map_to_json(pairs: &[(String, String)]) -> Value {
    let mut o = serveros_json::Object::with_capacity(pairs.len());
    for (k, v) in pairs {
        o.insert(k.clone(), v.clone());
    }
    Value::Object(o)
}

/// Read an array of strings, tolerating `null` and mixed contents.
pub(crate) fn string_list(v: Option<&Value>) -> Vec<String> {
    let Some(arr) = v.and_then(Value::as_array) else {
        return Vec::new();
    };
    arr.iter().filter_map(Value::as_str).map(str::to_owned).collect()
}

/// The first twelve characters of an id, with any `sha256:` prefix removed.
///
/// This is what Docker shows everywhere and what a user will recognise; full
/// 64-character digests are for API calls, not for people.
pub(crate) fn short_id(id: &str) -> String {
    let bare = id.strip_prefix("sha256:").unwrap_or(id);
    bare.chars().take(12).collect()
}

/// Parse an RFC 3339 timestamp into Unix seconds.
///
/// Docker mixes representations — the container *list* gives `Created` as an
/// epoch integer while *inspect* gives an RFC 3339 string — and the app wants
/// one numeric type it can format in the user's locale.
///
/// Go's zero time (`0001-01-01T00:00:00Z`) is returned as `None`, not as a
/// large negative number: Docker uses it for "never", e.g. `FinishedAt` on a
/// running container, and "1 January year 1" on screen is a bug report.
pub fn parse_rfc3339(s: &str) -> Option<i64> {
    let b = s.as_bytes();
    if b.len() < 19 {
        return None;
    }
    if b[4] != b'-' || b[7] != b'-' || b[13] != b':' || b[16] != b':' {
        return None;
    }
    if !matches!(b[10], b'T' | b't' | b' ') {
        return None;
    }

    let num = |range: std::ops::Range<usize>| -> Option<i64> {
        let slice = s.get(range)?;
        if slice.is_empty() || !slice.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        slice.parse().ok()
    };

    let year = num(0..4)?;
    let month = num(5..7)?;
    let day = num(8..10)?;
    let hour = num(11..13)?;
    let minute = num(14..16)?;
    // 60 is a leap second; accept it rather than reject the whole record.
    let second = num(17..19)?;

    if !(1..=12).contains(&month) || !(1..=31).contains(&day) {
        return None;
    }
    if hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    if year <= 1 {
        return None; // Go's zero value: "never happened".
    }

    let mut epoch = days_from_civil(year, month as u32, day as u32) * 86_400
        + hour * 3_600
        + minute * 60
        + second;

    // Skip any fractional part; we deal in whole seconds.
    let rest = s[19..].trim_start_matches(|c: char| c == '.' || c.is_ascii_digit());

    // Offsets are rare from Docker (it emits UTC) but legal, and getting them
    // wrong would shift a timestamp by hours.
    let rest_b = rest.as_bytes();
    if !rest_b.is_empty() && matches!(rest_b[0], b'+' | b'-') && rest.len() >= 6 {
        let sign = if rest_b[0] == b'-' { -1 } else { 1 };
        let oh: i64 = rest.get(1..3)?.parse().ok()?;
        let om: i64 = rest.get(4..6)?.parse().ok()?;
        epoch -= sign * (oh * 3_600 + om * 60);
    }

    Some(epoch)
}

/// Days since the Unix epoch for a civil date (Howard Hinnant's algorithm).
///
/// Written out rather than pulled in: it is fifteen lines, has no edge cases
/// past year 1, and the alternative is a dependency.
fn days_from_civil(year: i64, month: u32, day: u32) -> i64 {
    let y = if month <= 2 { year - 1 } else { year };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400; // [0, 399]
    let mp = ((month + 9) % 12) as i64; // March = 0
    let doy = (153 * mp + 2) / 5 + day as i64 - 1; // [0, 365]
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy; // [0, 146096]
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests;
