//! Connecting, authenticating, and running read-only statements.
//!
//! # No TLS, on purpose
//!
//! This client refuses to connect to anything but the loopback interface or a
//! unix socket, and it implements no TLS. That is a deliberate security
//! posture, not a missing feature.
//!
//! The agent runs *on the database host*. The whole architecture (see the
//! product docs: macOS app → control plane → server agent → Linux) exists so
//! that the app never opens a database port to the network. Traffic from the
//! agent to PostgreSQL never leaves the machine: it goes over `127.0.0.1` or,
//! better, `/var/run/postgresql/.s.PGSQL.5432`. On that path TLS protects
//! against nothing an attacker who is already inside the host's network
//! namespace could not do more directly, while costing us an X.509 stack — the
//! single largest piece of attack surface we would have to own and patch
//! forever in a dependency-free workspace.
//!
//! The corollary is the important half: because we cannot protect a network
//! hop, we do not make one. [`PgConfig`] with a non-loopback
//! [`PgHost::Tcp`] fails with [`PgError::RemoteHostNotAllowed`] before a socket
//! is opened. Managing a remote database means running an agent next to it.
//!
//! # Read-only, on purpose
//!
//! [`PgConnection::query`] runs [`is_read_only`] over the statement first and
//! refuses anything that is not a single `SELECT`, `SHOW` or `WITH ... SELECT`.
//! The database inventory feature exists to *show* the operator their data
//! estate; if arbitrary SQL could ride in on the same endpoint, the feature
//! would be a remote-code-execution hole wearing a dashboard.
//!
//! The guard is a syntactic one and it is not the only line of defence — the
//! role the agent authenticates as should itself be read-only, and a `SELECT`
//! calling a volatile function can still have effects. It is, however, the
//! check that makes the *product surface* safe by construction, and it is
//! enforced at the one choke point every caller goes through.
//! [`PgConnection::query_unchecked`] is `pub(crate)` so that the fixed
//! statements in [`crate::inventory`] can bypass the parser, and so that
//! nothing outside this crate can.
//!
//! # Text format only
//!
//! Rows come back as `Option<String>` in PostgreSQL's text format. Binary
//! format would need a type-OID decoder per type and would buy nothing: the
//! values go straight into JSON for a Swift client, and we would only be
//! converting them back to text at the edge.

use std::fmt;
use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::auth::{self, ScramClient};
use crate::error::PgError;
use crate::protocol::{self, Auth, Backend, MessageReader};

/// How long a query may block on the socket before we give up.
///
/// Separate from `connect_timeout`, which covers the handshake. An inventory
/// query that has not answered in a minute means the server is in trouble, and
/// a hung agent thread is worse than a reported failure.
pub const DEFAULT_QUERY_TIMEOUT: Duration = Duration::from_secs(60);

/// Where the database is. Both variants are on this machine, by construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PgHost {
    /// A loopback TCP address. Anything else is refused at connect time.
    Tcp(String),
    /// The **directory** holding the socket, e.g. `/var/run/postgresql`. The
    /// socket file itself is `.s.PGSQL.<port>`, which is why the port still
    /// matters for a unix connection.
    Unix(PathBuf),
}

impl PgHost {
    /// The conventional socket directory on Debian/Ubuntu.
    pub fn default_socket_dir() -> PgHost {
        PgHost::Unix(PathBuf::from("/var/run/postgresql"))
    }

    /// Full path to the socket file for `port`.
    fn socket_path(dir: &Path, port: u16) -> PathBuf {
        dir.join(format!(".s.PGSQL.{port}"))
    }
}

impl fmt::Display for PgHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgHost::Tcp(h) => f.write_str(h),
            PgHost::Unix(p) => write!(f, "{}", p.display()),
        }
    }
}

/// Everything needed to open one connection.
///
/// `Debug` is hand-written so the password cannot reach a log line; see
/// [`crate::error`].
#[derive(Clone)]
pub struct PgConfig {
    /// Loopback TCP host or unix socket directory.
    pub host: PgHost,
    /// TCP port, or the number in the socket filename for a unix connection.
    pub port: u16,
    /// Role to authenticate as.
    pub user: String,
    /// Password, if the server asks for one. Never stored on the connection.
    pub password: Option<String>,
    /// Database to attach to. A connection is bound to exactly one.
    pub database: String,
    /// Budget for the socket connect and the whole authentication handshake.
    pub connect_timeout: Duration,
}

impl PgConfig {
    /// A configuration for the local cluster's socket, with sane defaults.
    pub fn local(user: impl Into<String>, database: impl Into<String>) -> PgConfig {
        PgConfig {
            host: PgHost::default_socket_dir(),
            port: 5432,
            user: user.into(),
            password: None,
            database: database.into(),
            connect_timeout: Duration::from_secs(5),
        }
    }
}

impl fmt::Debug for PgConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("user", &self.user)
            // Never the value, and never the length either — a length is a
            // meaningful hint to anyone reading a log.
            .field("password", &self.password.as_ref().map(|_| "<redacted>"))
            .field("database", &self.database)
            .field("connect_timeout", &self.connect_timeout)
            .finish()
    }
}

/// The rows and column names one statement produced.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct QueryResult {
    /// Column names, in the order the server described them.
    pub columns: Vec<String>,
    /// Rows in text format. `None` is SQL `NULL`.
    pub rows: Vec<Vec<Option<String>>>,
}

impl QueryResult {
    /// The single value of a one-row, one-column result, if that is what this
    /// is. Returns `None` for an empty result or a SQL `NULL`.
    pub fn scalar(&self) -> Option<&str> {
        match self.rows.first() {
            Some(row) => row.first().and_then(|v| v.as_deref()),
            None => None,
        }
    }

    /// Index of a column by name.
    pub fn column(&self, name: &str) -> Option<usize> {
        self.columns.iter().position(|c| c == name)
    }
}

/// Either kind of local socket, behind one `Read + Write`.
enum Transport {
    Tcp(TcpStream),
    Unix(UnixStream),
}

impl Transport {
    fn set_timeouts(&self, timeout: Option<Duration>) -> std::io::Result<()> {
        match self {
            Transport::Tcp(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
            Transport::Unix(s) => {
                s.set_read_timeout(timeout)?;
                s.set_write_timeout(timeout)
            }
        }
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Transport::Tcp(s) => s.read(buf),
            Transport::Unix(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Transport::Tcp(s) => s.write(buf),
            Transport::Unix(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Transport::Tcp(s) => s.flush(),
            Transport::Unix(s) => s.flush(),
        }
    }
}

/// One authenticated connection to one database.
///
/// Holds no password: the credential is consumed during [`PgConnection::connect`]
/// and never copied onto the struct, so a `PgConnection` in a heap dump or a
/// `Debug` print cannot leak one.
pub struct PgConnection {
    io: MessageReader<Transport>,
    parameters: Vec<(String, String)>,
    backend_pid: i32,
    backend_secret: i32,
    database: String,
    user: String,
}

impl fmt::Debug for PgConnection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PgConnection")
            .field("user", &self.user)
            .field("database", &self.database)
            .field("backend_pid", &self.backend_pid)
            .field("server_version", &self.server_version())
            .finish()
    }
}

impl PgConnection {
    /// Open a socket, run the StartupMessage and the authentication handshake,
    /// and return once the server reports ReadyForQuery.
    pub fn connect(cfg: &PgConfig) -> Result<Self, PgError> {
        let transport = open_transport(cfg)?;
        transport.set_timeouts(Some(cfg.connect_timeout))?;
        let mut io = MessageReader::new(transport);

        io.send(&protocol::encode_startup(&[
            ("user", &cfg.user),
            ("database", &cfg.database),
            ("application_name", "serveros-agent"),
            // Makes the server's promise about string encoding explicit, so the
            // decoder can reject non-UTF-8 rather than guess.
            ("client_encoding", "UTF8"),
        ]))?;

        let mut conn = PgConnection {
            io,
            parameters: Vec::new(),
            backend_pid: 0,
            backend_secret: 0,
            database: cfg.database.clone(),
            user: cfg.user.clone(),
        };
        conn.authenticate(cfg)?;

        // The handshake is over; a query may legitimately take longer than the
        // connect budget, but not forever.
        let query_timeout = cfg.connect_timeout.max(DEFAULT_QUERY_TIMEOUT);
        conn.io.transport().set_timeouts(Some(query_timeout))?;
        Ok(conn)
    }

    /// Drive the `R` message exchange through to ReadyForQuery.
    fn authenticate(&mut self, cfg: &PgConfig) -> Result<(), PgError> {
        let mut scram: Option<ScramClient> = None;

        loop {
            match self.io.read_message()? {
                Backend::Authentication(Auth::Ok) => {}
                Backend::Authentication(Auth::CleartextPassword) => {
                    let password = self.require_password(cfg)?;
                    self.io.send(&protocol::encode_password(password.as_bytes()))?;
                }
                Backend::Authentication(Auth::Md5Password(salt)) => {
                    let password = self.require_password(cfg)?;
                    let response = auth::md5_password(password, &cfg.user, salt);
                    self.io.send(&protocol::encode_password(response.as_bytes()))?;
                }
                Backend::Authentication(Auth::Sasl(mechanisms)) => {
                    // Check we have a password before advertising a mechanism,
                    // so a password-less config fails with a clear message
                    // instead of halfway through a SCRAM exchange.
                    self.require_password(cfg)?;
                    let mechanism = auth::select_mechanism(&mechanisms)?;
                    let client = ScramClient::new()?;
                    let first = client.client_first();
                    self.io.send(&protocol::encode_sasl_initial(mechanism, first.as_bytes()))?;
                    scram = Some(client);
                }
                Backend::Authentication(Auth::SaslContinue(data)) => {
                    let client = scram.as_mut().ok_or(PgError::ScramFailed(
                        "the server sent SASLContinue without asking for SASL first",
                    ))?;
                    let password = self.require_password(cfg)?;
                    let final_message = client.client_final(&data, password)?;
                    self.io.send(&protocol::encode_sasl_response(final_message.as_bytes()))?;
                }
                Backend::Authentication(Auth::SaslFinal(data)) => {
                    let client = scram.as_ref().ok_or(PgError::ScramFailed(
                        "the server sent SASLFinal without asking for SASL first",
                    ))?;
                    // Mandatory: this is where the server proves it is the
                    // database and not a proof-harvesting relay.
                    client.verify_server_final(&data)?;
                }
                Backend::ParameterStatus { name, value } => self.set_parameter(name, value),
                Backend::BackendKeyData { pid, secret } => {
                    self.backend_pid = pid;
                    self.backend_secret = secret;
                }
                Backend::ReadyForQuery(_) => return Ok(()),
                Backend::Error(e) => return Err(PgError::from_server(e)),
                Backend::Notice(_) | Backend::Notification { .. } | Backend::Unhandled(_) => {}
                other => {
                    return Err(PgError::Protocol(format!(
                        "unexpected message during authentication: {other:?}"
                    )));
                }
            }
        }
    }

    fn require_password<'a>(&self, cfg: &'a PgConfig) -> Result<&'a str, PgError> {
        cfg.password.as_deref().ok_or(PgError::PasswordRequired)
    }

    fn set_parameter(&mut self, name: String, value: String) {
        // The server re-sends ParameterStatus whenever a value changes.
        if let Some(slot) = self.parameters.iter_mut().find(|(n, _)| *n == name) {
            slot.1 = value;
        } else {
            self.parameters.push((name, value));
        }
    }

    /// Run one read-only statement.
    ///
    /// Refuses anything [`is_read_only`] does not recognise as a single
    /// `SELECT`, `SHOW` or `WITH ... SELECT`.
    pub fn query(&mut self, sql: &str) -> Result<QueryResult, PgError> {
        if !is_read_only(sql) {
            return Err(PgError::NotReadOnly { keyword: leading_keyword(sql) });
        }
        self.query_unchecked(sql)
    }

    /// Run a statement without the read-only guard.
    ///
    /// `pub(crate)` on purpose: this exists for the fixed, literal statements
    /// in [`crate::inventory`], which are part of this crate's source and
    /// cannot be influenced by a caller. No string that came from outside the
    /// crate may reach this function.
    pub(crate) fn query_unchecked(&mut self, sql: &str) -> Result<QueryResult, PgError> {
        self.io.send(&protocol::encode_query(sql))?;

        let mut result = QueryResult::default();
        let mut failure: Option<PgError> = None;

        loop {
            match self.io.read_message()? {
                Backend::RowDescription(fields) => {
                    // A Simple Query may carry several result sets. Our
                    // statements never do (the guard forbids the `;` that would
                    // be needed), so the last description wins and the rows
                    // reset with it.
                    result.columns = fields.into_iter().map(|f| f.name).collect();
                    result.rows.clear();
                }
                Backend::DataRow(values) => {
                    let mut row = Vec::with_capacity(values.len());
                    for v in values {
                        match v {
                            None => row.push(None),
                            Some(bytes) => row.push(Some(String::from_utf8(bytes).map_err(
                                |_| {
                                    PgError::Protocol(
                                        "a column value was not valid UTF-8".to_string(),
                                    )
                                },
                            )?)),
                        }
                    }
                    result.rows.push(row);
                }
                Backend::CommandComplete(_) | Backend::EmptyQueryResponse => {}
                Backend::ParameterStatus { name, value } => self.set_parameter(name, value),
                Backend::Error(e) => {
                    // Keep reading: the server still owes us a ReadyForQuery,
                    // and abandoning it here would desynchronise the stream for
                    // every later query on this connection.
                    failure = Some(PgError::from_server(e));
                }
                Backend::ReadyForQuery(_) => break,
                Backend::Notice(_)
                | Backend::Notification { .. }
                | Backend::Unhandled(_)
                | Backend::BackendKeyData { .. }
                | Backend::Authentication(_) => {}
            }
        }

        match failure {
            Some(e) => Err(e),
            None => Ok(result),
        }
    }

    /// A runtime parameter the server reported, e.g. `server_encoding`.
    pub fn parameter(&self, name: &str) -> Option<&str> {
        self.parameters.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }

    /// The server version string, e.g. `16.13`, from ParameterStatus.
    pub fn server_version(&self) -> Option<&str> {
        self.parameter("server_version")
    }

    /// The database this connection is attached to.
    pub fn database(&self) -> &str {
        &self.database
    }

    /// The role this connection authenticated as.
    pub fn user(&self) -> &str {
        &self.user
    }

    /// The backend process id, as it appears in `pg_stat_activity.pid`.
    pub fn backend_pid(&self) -> i32 {
        self.backend_pid
    }

    /// Send Terminate and close.
    ///
    /// Takes `self` because a connection is not usable afterwards. Failure is
    /// swallowed: the socket is going away either way, and a noisy error on a
    /// goodbye message helps nobody.
    pub fn close(mut self) {
        let _ = self.io.send(&protocol::encode_terminate());
    }
}

/// Open the socket, refusing any host that is not on this machine.
fn open_transport(cfg: &PgConfig) -> Result<Transport, PgError> {
    match &cfg.host {
        PgHost::Unix(dir) => {
            let path = PgHost::socket_path(dir, cfg.port);
            let stream = UnixStream::connect(&path).map_err(|e| {
                PgError::Io(std::io::Error::new(
                    e.kind(),
                    format!("{}: {e}", path.display()),
                ))
            })?;
            Ok(Transport::Unix(stream))
        }
        PgHost::Tcp(host) => {
            let addr = resolve_loopback(host, cfg.port)?;
            let stream = TcpStream::connect_timeout(&addr, cfg.connect_timeout)
                .map_err(|e| PgError::Io(std::io::Error::new(e.kind(), format!("{addr}: {e}"))))?;
            // PostgreSQL's protocol is request/response; Nagle would add up to
            // 40 ms to every round trip for no benefit.
            let _ = stream.set_nodelay(true);
            Ok(Transport::Tcp(stream))
        }
    }
}

/// Resolve `host` and insist the result is loopback. See the module docs.
fn resolve_loopback(host: &str, port: u16) -> Result<std::net::SocketAddr, PgError> {
    let mut addrs = (host, port)
        .to_socket_addrs()
        .map_err(|e| PgError::Io(std::io::Error::new(e.kind(), format!("{host}: {e}"))))?
        .peekable();
    if addrs.peek().is_none() {
        return Err(PgError::RemoteHostNotAllowed(host.to_string()));
    }
    // Every address the name resolves to must be loopback. Accepting a name
    // that resolves to both 127.0.0.1 and a public address would let a DNS
    // change turn a local connection into a cleartext network one.
    let mut chosen = None;
    for addr in addrs {
        if !addr.ip().is_loopback() {
            return Err(PgError::RemoteHostNotAllowed(host.to_string()));
        }
        if chosen.is_none() {
            chosen = Some(addr);
        }
    }
    chosen.ok_or_else(|| PgError::RemoteHostNotAllowed(host.to_string()))
}

// ---------------------------------------------------------------------------
// The read-only guard
// ---------------------------------------------------------------------------

/// True when `sql` is a single read-only statement.
///
/// Accepts exactly one statement (a trailing `;` is fine) whose first keyword
/// is `SELECT`, `SHOW`, or a `WITH` whose body contains no data-modifying CTE.
/// Comments — `--` to end of line and nested `/* */` — are stripped first, so
/// `-- harmless\nDROP TABLE t` does not sneak past on the comment.
///
/// String literals, dollar-quoted bodies and quoted identifiers are recognised
/// and their contents ignored, so `SELECT ';'` is accepted and
/// `SELECT 1; DROP TABLE t` is not.
///
/// This is a keyword guard, not a SQL parser. It cannot know that a `SELECT`
/// calls a volatile function that writes, and it deliberately does not try; the
/// authenticated role's own privileges are the backstop for that. What it does
/// guarantee is that no statement whose *verb* is a write ever reaches the
/// server through [`PgConnection::query`].
pub fn is_read_only(sql: &str) -> bool {
    let tokens = match tokenize(sql) {
        Some(t) => t,
        None => return false, // unterminated literal or comment: refuse
    };

    let mut words = tokens.iter();
    // A parenthesised select — `(SELECT 1)` — is still a select.
    let first = loop {
        match words.next() {
            Some(Token::Punct('(')) => continue,
            Some(Token::Word(w)) => break w.as_str(),
            _ => return false,
        }
    };

    match first {
        "select" | "show" => {}
        "with" => {
            // `WITH t AS (INSERT ... RETURNING ...) SELECT * FROM t` is a
            // perfectly ordinary way to write through a CTE, and its first
            // keyword is WITH. Scan the whole statement for a write verb.
            if tokens.iter().any(|t| match t {
                Token::Word(w) => {
                    matches!(w.as_str(), "insert" | "update" | "delete" | "merge" | "truncate")
                }
                _ => false,
            }) {
                return false;
            }
        }
        _ => return false,
    }

    // Exactly one statement. A `;` is allowed only as the last token.
    let separators = tokens
        .iter()
        .enumerate()
        .filter(|(_, t)| matches!(t, Token::Punct(';')))
        .map(|(i, _)| i)
        .collect::<Vec<_>>();
    match separators.as_slice() {
        [] => true,
        [only] => *only == tokens.len() - 1,
        _ => false,
    }
}

/// The leading keyword, uppercased, for error reporting.
///
/// Only the keyword — never the statement — so a rejected
/// `ALTER USER ... PASSWORD '...'` cannot put a credential in a log.
fn leading_keyword(sql: &str) -> String {
    match tokenize(sql).and_then(|t| {
        t.into_iter().find_map(|t| match t {
            Token::Word(w) => Some(w),
            _ => None,
        })
    }) {
        Some(w) => w.to_uppercase(),
        None => "<empty>".to_string(),
    }
}

/// The only distinctions the guard needs to make.
#[derive(Debug, PartialEq, Eq)]
enum Token {
    /// A bare word, lowercased.
    Word(String),
    /// A significant punctuation character: `;`, `(`, `)`.
    Punct(char),
    /// A literal or quoted identifier, contents discarded.
    Literal,
}

/// Split `sql` into guard-relevant tokens, or `None` if it is malformed.
///
/// Returning `None` rather than a best effort matters: an unterminated `/*` or
/// `'` means we cannot know where the statement ends, and a guard that guesses
/// is not a guard.
fn tokenize(sql: &str) -> Option<Vec<Token>> {
    let b = sql.as_bytes();
    let mut i = 0;
    let mut out = Vec::new();

    while i < b.len() {
        let c = b[i];
        match c {
            // whitespace
            b' ' | b'\t' | b'\n' | b'\r' | 0x0b | 0x0c => i += 1,

            // line comment
            b'-' if b.get(i + 1) == Some(&b'-') => {
                i += 2;
                while i < b.len() && b[i] != b'\n' {
                    i += 1;
                }
            }

            // block comment, nestable as PostgreSQL allows
            b'/' if b.get(i + 1) == Some(&b'*') => {
                let mut depth = 1;
                i += 2;
                while i < b.len() && depth > 0 {
                    if b[i] == b'/' && b.get(i + 1) == Some(&b'*') {
                        depth += 1;
                        i += 2;
                    } else if b[i] == b'*' && b.get(i + 1) == Some(&b'/') {
                        depth -= 1;
                        i += 2;
                    } else {
                        i += 1;
                    }
                }
                if depth > 0 {
                    return None; // unterminated
                }
            }

            // string literal; '' is an escaped quote
            b'\'' => {
                i += 1;
                loop {
                    if i >= b.len() {
                        return None;
                    }
                    if b[i] == b'\'' {
                        if b.get(i + 1) == Some(&b'\'') {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push(Token::Literal);
            }

            // quoted identifier; "" is an escaped quote
            b'"' => {
                i += 1;
                loop {
                    if i >= b.len() {
                        return None;
                    }
                    if b[i] == b'"' {
                        if b.get(i + 1) == Some(&b'"') {
                            i += 2;
                            continue;
                        }
                        i += 1;
                        break;
                    }
                    i += 1;
                }
                out.push(Token::Literal);
            }

            // dollar-quoted string: $tag$ ... $tag$
            b'$' => {
                if let Some(end_of_tag) = b[i + 1..].iter().position(|&x| x == b'$') {
                    let tag = &b[i..i + end_of_tag + 2]; // includes both $
                    let is_tag = tag[1..tag.len() - 1]
                        .iter()
                        .all(|&x| x == b'_' || x.is_ascii_alphanumeric());
                    if is_tag {
                        let body_start = i + tag.len();
                        match find(&b[body_start..], tag) {
                            Some(rel) => {
                                i = body_start + rel + tag.len();
                                out.push(Token::Literal);
                                continue;
                            }
                            None => return None, // unterminated
                        }
                    }
                }
                // A lone `$` (a `$1` parameter, say) is not interesting.
                i += 1;
            }

            b';' | b'(' | b')' => {
                out.push(Token::Punct(c as char));
                i += 1;
            }

            _ if c.is_ascii_alphabetic() || c == b'_' || !c.is_ascii() => {
                let start = i;
                while i < b.len()
                    && (b[i].is_ascii_alphanumeric()
                        || b[i] == b'_'
                        || b[i] == b'$'
                        || !b[i].is_ascii())
                {
                    i += 1;
                }
                // Non-ASCII bytes only ever appear inside identifiers here, and
                // this slice began on a character boundary, so it is valid.
                let word = String::from_utf8_lossy(&b[start..i]).to_ascii_lowercase();
                out.push(Token::Word(word));
            }

            // digits, operators, commas, dots: not relevant to the guard
            _ => i += 1,
        }
    }

    Some(out)
}

/// First index of `needle` in `haystack`.
fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&i| &haystack[i..i + needle.len()] == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- the read-only guard ----------------------------------------------

    #[test]
    fn accepts_plain_selects() {
        for sql in [
            "SELECT 1",
            "select 1",
            "SeLeCt 1",
            "SELECT * FROM pg_database",
            "SELECT count(*) FROM pg_stat_activity",
            "  SELECT 1",
            "\n\t SELECT 1",
            "SELECT 1;",
            "SELECT 1 ;  ",
            "(SELECT 1)",
            "SELECT ';'",
            "SELECT 'DROP TABLE x'",
            "SELECT $$ DROP TABLE x; $$",
            "SELECT \"weird;column\" FROM t",
        ] {
            assert!(is_read_only(sql), "should accept {sql:?}");
        }
    }

    #[test]
    fn accepts_show() {
        for sql in ["SHOW server_version", "show data_directory", "SHOW ALL"] {
            assert!(is_read_only(sql), "should accept {sql:?}");
        }
    }

    #[test]
    fn accepts_read_only_ctes() {
        for sql in [
            "with x as (select 1) select * from x",
            "WITH x AS (SELECT 1) SELECT * FROM x",
            "WITH RECURSIVE t(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM t WHERE n < 5) SELECT n FROM t",
        ] {
            assert!(is_read_only(sql), "should accept {sql:?}");
        }
    }

    #[test]
    fn accepts_comments_before_a_select() {
        for sql in [
            "-- a comment\nSELECT 1",
            "/* a comment */ SELECT 1",
            "/* nested /* inner */ still a comment */ SELECT 1",
            "--\n--\nSELECT 1",
            "SELECT 1 -- trailing",
            "SELECT 1 /* trailing */",
        ] {
            assert!(is_read_only(sql), "should accept {sql:?}");
        }
    }

    #[test]
    fn rejects_statement_chaining() {
        for sql in [
            "SELECT 1; DROP TABLE x",
            "SELECT 1;DROP TABLE x",
            "SELECT 1; SELECT 2",
            "SELECT 1 ; -- c\n DELETE FROM t",
            "SHOW all; DROP DATABASE d",
        ] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_writes_hidden_behind_comments() {
        for sql in [
            "-- c\nDROP TABLE x",
            "-- SELECT 1\nDROP TABLE x",
            "/* */ UPDATE t SET a = 1",
            "/* SELECT 1 */ DELETE FROM t",
            "/* nested /* */ */ TRUNCATE t",
        ] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_data_modifying_ctes() {
        for sql in [
            "WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x",
            "with x as (delete from t returning *) select * from x",
            "WITH x AS (UPDATE t SET a=1 RETURNING *) SELECT * FROM x",
            "WITH x AS (MERGE INTO t USING s ON true WHEN MATCHED THEN DELETE) SELECT 1",
        ] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_every_write_verb() {
        for sql in [
            "INSERT INTO t VALUES (1)",
            "UPDATE t SET a = 1",
            "DELETE FROM t",
            "DROP TABLE x",
            "TRUNCATE t",
            "VACUUM",
            "VACUUM FULL",
            "ANALYZE",
            "CREATE TABLE t (a int)",
            "ALTER TABLE t ADD COLUMN b int",
            "GRANT ALL ON t TO public",
            "REVOKE ALL ON t FROM public",
            "COPY t TO STDOUT",
            "COPY (SELECT 1) TO STDOUT",
            "CALL do_something()",
            "DO $$ BEGIN PERFORM 1; END $$",
            "BEGIN",
            "COMMIT",
            "ROLLBACK",
            "SET work_mem = '1GB'",
            "RESET ALL",
            "EXPLAIN ANALYZE SELECT 1",
            "REFRESH MATERIALIZED VIEW mv",
            "ALTER USER bob PASSWORD 'hunter2'",
            "CREATE ROLE evil SUPERUSER",
            "LOCK TABLE t",
            "NOTIFY channel",
            "LISTEN channel",
            "CHECKPOINT",
            "REINDEX INDEX i",
            "CLUSTER t",
        ] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_mixed_case_write_verbs() {
        for sql in ["DrOp TaBlE x", "uPdAtE t SET a=1", "Vacuum", "TrUnCaTe t"] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_leading_newline_writes() {
        for sql in ["\nDROP TABLE x", "\r\n\tDELETE FROM t", "\n\n  VACUUM"] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_empty_and_comment_only_statements() {
        for sql in ["", "   ", "\n", "-- only a comment", "/* only */", ";"] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn rejects_unterminated_literals_and_comments() {
        // We cannot know where these end, so we must not guess.
        for sql in [
            "SELECT 'unterminated",
            "SELECT \"unterminated",
            "/* unterminated SELECT 1",
            "SELECT $$ unterminated",
        ] {
            assert!(!is_read_only(sql), "should reject {sql:?}");
        }
    }

    #[test]
    fn semicolons_inside_literals_do_not_count_as_separators() {
        assert!(is_read_only("SELECT ';;;' AS a"));
        assert!(is_read_only("SELECT 'it''s; fine'"));
        assert!(is_read_only("SELECT $tag$ a;b $tag$"));
        assert!(is_read_only("SELECT \"a;b\" FROM t"));
    }

    #[test]
    fn write_verbs_inside_literals_do_not_trip_the_cte_scan() {
        assert!(is_read_only("with x as (select 'insert') select * from x"));
        assert!(is_read_only("WITH x AS (SELECT $$delete$$) SELECT * FROM x"));
    }

    #[test]
    fn a_select_containing_the_word_update_is_still_accepted() {
        // `FOR UPDATE` takes row locks but writes no data, and blanket-banning
        // the word inside a SELECT would be surprising. Documented behaviour.
        assert!(is_read_only("SELECT * FROM t FOR UPDATE"));
    }

    #[test]
    fn leading_keyword_is_uppercased_and_never_the_statement() {
        assert_eq!(leading_keyword("alter user bob password 'hunter2'"), "ALTER");
        assert_eq!(leading_keyword("-- c\n  drop table x"), "DROP");
        assert_eq!(leading_keyword(""), "<empty>");
        assert_eq!(leading_keyword("   ;  "), "<empty>");
    }

    #[test]
    fn every_inventory_statement_passes_the_guard() {
        // Belt and braces: the inventory module uses `query_unchecked`, but if
        // one of its statements would fail the guard that is a smell worth
        // catching.
        for sql in crate::inventory::ALL_STATEMENTS {
            assert!(is_read_only(sql), "inventory statement rejected: {sql}");
        }
    }

    // ---- configuration and redaction --------------------------------------

    #[test]
    fn config_debug_redacts_the_password() {
        let cfg = PgConfig {
            host: PgHost::Tcp("127.0.0.1".into()),
            port: 5432,
            user: "serveros".into(),
            password: Some("hunter2".into()),
            database: "postgres".into(),
            connect_timeout: Duration::from_secs(5),
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("hunter2"), "{rendered}");
        assert!(rendered.contains("<redacted>"), "{rendered}");
        assert!(rendered.contains("serveros"), "{rendered}");
    }

    #[test]
    fn config_debug_shows_none_for_a_missing_password() {
        let mut cfg = PgConfig::local("u", "d");
        cfg.password = None;
        assert!(format!("{cfg:?}").contains("password: None"));
    }

    #[test]
    fn local_config_defaults_to_the_debian_socket_directory() {
        let cfg = PgConfig::local("serveros", "postgres");
        assert_eq!(cfg.host, PgHost::default_socket_dir());
        assert_eq!(cfg.port, 5432);
        assert!(cfg.password.is_none());
    }

    #[test]
    fn socket_path_is_the_directory_plus_the_well_known_name() {
        let p = PgHost::socket_path(Path::new("/var/run/postgresql"), 5433);
        assert_eq!(p, PathBuf::from("/var/run/postgresql/.s.PGSQL.5433"));
    }

    // ---- the loopback-only posture ----------------------------------------

    #[test]
    fn loopback_literals_resolve() {
        assert!(resolve_loopback("127.0.0.1", 5432).is_ok());
        assert!(resolve_loopback("::1", 5432).is_ok());
        assert!(resolve_loopback("localhost", 5432).is_ok());
    }

    #[test]
    fn non_loopback_addresses_are_refused_before_any_socket_is_opened() {
        for host in ["10.0.0.5", "8.8.8.8", "192.168.1.10"] {
            match resolve_loopback(host, 5432) {
                Err(PgError::RemoteHostNotAllowed(h)) => assert_eq!(h, host),
                other => panic!("expected {host} to be refused, got {other:?}"),
            }
        }
    }

    #[test]
    fn connect_refuses_a_remote_host_without_touching_the_network() {
        let cfg = PgConfig {
            host: PgHost::Tcp("10.99.99.99".into()),
            port: 5432,
            user: "u".into(),
            password: None,
            database: "d".into(),
            // Deliberately tiny: if this actually dialled, the test would take
            // longer than the timeout rather than returning instantly.
            connect_timeout: Duration::from_millis(1),
        };
        assert!(matches!(
            PgConnection::connect(&cfg),
            Err(PgError::RemoteHostNotAllowed(_))
        ));
    }

    #[test]
    fn query_result_scalar_handles_empty_and_null() {
        let empty = QueryResult::default();
        assert_eq!(empty.scalar(), None);

        let null = QueryResult { columns: vec!["a".into()], rows: vec![vec![None]] };
        assert_eq!(null.scalar(), None);

        let value = QueryResult {
            columns: vec!["a".into()],
            rows: vec![vec![Some("16.13".into())]],
        };
        assert_eq!(value.scalar(), Some("16.13"));
        assert_eq!(value.column("a"), Some(0));
        assert_eq!(value.column("nope"), None);
    }
}
