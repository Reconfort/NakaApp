//! The one error type this crate hands back, and the structured server error
//! it carries.
//!
//! Two rules govern this module, and both exist because the agent runs on
//! customer infrastructure and its errors end up in logs, crash reports and the
//! macOS app's "view technical details" sheet:
//!
//!   1. **No secret ever reaches `Display`.** `PgError` has no variant that can
//!      hold a password, and the read-only guard deliberately reports only the
//!      leading SQL keyword rather than the statement — `ALTER USER bob
//!      PASSWORD 'hunter2'` must not become a log line. `PgConfig` gets a
//!      hand-written `Debug` for the same reason.
//!   2. **Variants map to decisions, not to call sites.** Each variant is a
//!      distinct thing the app can *say* to a human: wrong password, no such
//!      database, server full, this host is not local. `Server` is the residual
//!      "the database refused and here is exactly why", which is the honest
//!      answer for the long tail of SQLSTATEs we have no special UI for.

use std::fmt;

/// A decoded `ErrorResponse` (`E`) or `NoticeResponse` (`N`) payload.
///
/// Only the five fields the product actually surfaces are kept. The wire format
/// carries a dozen more (file, line, routine, schema, constraint...), which are
/// useful to a PostgreSQL hacker and noise to everyone else; dropping them at
/// the parse boundary keeps the struct small and the UI honest.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServerError {
    /// `S` — `ERROR`, `FATAL`, `PANIC`, `WARNING`, `NOTICE`, ...
    pub severity: String,
    /// `C` — the five-character SQLSTATE, e.g. `28P01`.
    pub code: String,
    /// `M` — the primary human-readable message. Always present in practice.
    pub message: String,
    /// `D` — optional secondary detail.
    pub detail: Option<String>,
    /// `H` — optional suggestion of what to do about it.
    pub hint: Option<String>,
}

impl ServerError {
    /// True when the server said this is a hard failure rather than a notice.
    pub fn is_fatal(&self) -> bool {
        matches!(self.severity.as_str(), "FATAL" | "PANIC")
    }

    /// True for the class of errors that mean "your role may not see this",
    /// which the inventory layer degrades to `null` instead of failing on.
    ///
    /// Class `42` is syntax/access-rule violation (`42501 insufficient
    /// privilege`), class `2F`/`38` cover function-side permission trouble, and
    /// `55000` shows up when a statistics view is unavailable. A monitoring
    /// role that cannot read `pg_database_size` should produce a dashboard with
    /// one blank tile, not an error banner.
    pub fn is_permission_denied(&self) -> bool {
        self.code.starts_with("42") || self.code.starts_with("2F") || self.code == "55000"
    }
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let severity = if self.severity.is_empty() { "ERROR" } else { &self.severity };
        write!(f, "{severity}: {}", self.message)?;
        if !self.code.is_empty() {
            write!(f, " (SQLSTATE {})", self.code)?;
        }
        if let Some(d) = &self.detail {
            write!(f, "; {d}")?;
        }
        if let Some(h) = &self.hint {
            write!(f, "; hint: {h}")?;
        }
        Ok(())
    }
}

/// Anything that can go wrong talking to PostgreSQL.
#[derive(Debug)]
pub enum PgError {
    /// The socket failed: refused, reset, timed out, or the path is not there.
    Io(std::io::Error),
    /// The server sent something the v3 protocol does not allow, or sent it in
    /// an order we cannot make sense of. Always a bug report — in our decoder
    /// or in whatever is pretending to be PostgreSQL on that port.
    Protocol(String),
    /// The server demanded an authentication method we do not implement. The
    /// payload is the raw sub-type code from the `R` message (7 = GSSAPI,
    /// 9 = SSPI, 2 = Kerberos V5).
    UnsupportedAuth(i32),
    /// The server asked for a password and the configuration has none.
    PasswordRequired,
    /// The server offers only `SCRAM-SHA-256-PLUS`, i.e. it requires TLS
    /// channel binding, and this client has no TLS to bind to.
    ChannelBindingRequired,
    /// The SCRAM exchange itself failed a check we are obliged to make. This is
    /// not "wrong password" — it is "the peer did not behave like PostgreSQL".
    ScramFailed(&'static str),
    /// The password was rejected (`28P01`) or the role may not connect
    /// (`28000`).
    AuthFailed(ServerError),
    /// The requested database does not exist (`3D000`).
    NoSuchDatabase(ServerError),
    /// The server is at `max_connections` (`53300`).
    TooManyConnections(ServerError),
    /// Any other `ErrorResponse`, carried verbatim.
    Server(ServerError),
    /// Refused before opening a socket: the configured TCP host is not the
    /// loopback interface. See the `client` module docs for why.
    RemoteHostNotAllowed(String),
    /// `query` was handed something that is not a single read-only statement.
    /// Carries only the offending leading keyword, never the statement text.
    NotReadOnly {
        /// The first keyword we found, uppercased, or `<empty>`.
        keyword: String,
    },
    /// A per-database call was made on a connection bound to another database.
    /// PostgreSQL has no cross-database query, so the caller must reconnect.
    DatabaseMismatch {
        /// The database the caller asked about.
        requested: String,
        /// The database this connection is actually attached to.
        connected: String,
    },
    /// The password contains characters SASLprep forbids. Never carries the
    /// password — only which rule it broke.
    UnsupportedPassword(&'static str),
}

impl PgError {
    /// Map a server error onto the specific variants the UI knows how to talk
    /// about, falling back to `Server`.
    pub fn from_server(e: ServerError) -> PgError {
        match e.code.as_str() {
            // 28P01 invalid_password, 28000 invalid_authorization_specification.
            // Both mean "we did not let you in"; the app shows one message.
            "28P01" | "28000" => PgError::AuthFailed(e),
            "3D000" => PgError::NoSuchDatabase(e),
            "53300" => PgError::TooManyConnections(e),
            _ => PgError::Server(e),
        }
    }

    /// A short, human sentence for the app's error surface. The technical
    /// detail stays available through `Display`/`Debug` behind "view details".
    /// Whether PostgreSQL answered but would not let the agent in.
    ///
    /// The distinction matters to whoever is looking at the screen. "PostgreSQL
    /// is not available on this server" is a fact about the machine and there
    /// is nothing to do about it. "PostgreSQL is running and the agent cannot
    /// sign in" is a fact about one role, fixed by one `CREATE ROLE`. Reporting
    /// both as unavailable produced a screen that said ServerOS could see
    /// PostgreSQL *and* that PostgreSQL was not available, in the same panel.
    pub fn is_authentication_failure(&self) -> bool {
        matches!(
            self,
            PgError::AuthFailed(_)
                | PgError::PasswordRequired
                | PgError::ScramFailed(_)
                | PgError::UnsupportedAuth(_)
                | PgError::ChannelBindingRequired
        )
    }

    pub fn user_message(&self) -> String {
        match self {
            PgError::Io(_) => "ServerOS could not reach PostgreSQL.".into(),
            PgError::Protocol(_) => {
                "The service on that port did not answer as PostgreSQL.".into()
            }
            PgError::UnsupportedAuth(_) => {
                "This PostgreSQL server requires an authentication method ServerOS does not \
                 support."
                    .into()
            }
            PgError::PasswordRequired => "This PostgreSQL server requires a password.".into(),
            PgError::ChannelBindingRequired => {
                "This PostgreSQL server requires TLS channel binding.".into()
            }
            PgError::ScramFailed(_) => {
                "The PostgreSQL server failed authentication verification.".into()
            }
            PgError::AuthFailed(_) => "PostgreSQL rejected these credentials.".into(),
            PgError::NoSuchDatabase(_) => "That database does not exist on this server.".into(),
            PgError::TooManyConnections(_) => {
                "PostgreSQL has no connection slots left.".into()
            }
            PgError::Server(e) => e.message.clone(),
            PgError::RemoteHostNotAllowed(_) => {
                "ServerOS only connects to PostgreSQL on this machine.".into()
            }
            PgError::NotReadOnly { .. } => "Only read-only statements are allowed here.".into(),
            PgError::DatabaseMismatch { .. } => {
                "That database needs its own connection.".into()
            }
            PgError::UnsupportedPassword(_) => {
                "This password cannot be used with SCRAM authentication.".into()
            }
        }
    }
}

impl fmt::Display for PgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PgError::Io(e) => write!(f, "postgresql connection failed: {e}"),
            PgError::Protocol(what) => write!(f, "unexpected postgresql protocol data: {what}"),
            PgError::UnsupportedAuth(n) => write!(
                f,
                "postgresql requested authentication method {n}, which the agent does not \
                 implement (only trust, password, md5 and SCRAM-SHA-256 are supported)"
            ),
            PgError::PasswordRequired => {
                write!(f, "postgresql asked for a password but none is configured")
            }
            PgError::ChannelBindingRequired => write!(
                f,
                "postgresql requires SCRAM-SHA-256-PLUS (TLS channel binding), but the agent \
                 connects over a loopback socket without TLS and has no channel to bind to; \
                 allow plain scram-sha-256 for local connections in pg_hba.conf"
            ),
            PgError::ScramFailed(why) => write!(f, "SCRAM authentication check failed: {why}"),
            PgError::AuthFailed(e) => write!(f, "postgresql rejected the credentials: {e}"),
            PgError::NoSuchDatabase(e) => write!(f, "no such database: {e}"),
            PgError::TooManyConnections(e) => write!(f, "postgresql is out of connections: {e}"),
            PgError::Server(e) => write!(f, "{e}"),
            PgError::RemoteHostNotAllowed(host) => write!(
                f,
                "refusing to connect to postgresql at {host:?}: the agent only speaks to a \
                 database on the same host, over loopback or a unix socket, because it has no \
                 TLS implementation to protect a network hop"
            ),
            PgError::NotReadOnly { keyword } => write!(
                f,
                "refused: only a single SELECT, SHOW or WITH...SELECT may be run here, and this \
                 statement begins with {keyword}"
            ),
            PgError::DatabaseMismatch { requested, connected } => write!(
                f,
                "this connection is attached to database {connected:?}, so it cannot list \
                 objects in {requested:?}; open a connection to {requested:?} instead"
            ),
            PgError::UnsupportedPassword(why) => {
                write!(f, "password cannot be used for SCRAM: {why}")
            }
        }
    }
}

impl std::error::Error for PgError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            PgError::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for PgError {
    fn from(e: std::io::Error) -> Self {
        PgError::Io(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(code: &str) -> ServerError {
        ServerError {
            severity: "FATAL".into(),
            code: code.into(),
            message: "something happened".into(),
            detail: None,
            hint: None,
        }
    }

    #[test]
    fn sqlstate_28p01_is_auth_failed() {
        assert!(matches!(PgError::from_server(err("28P01")), PgError::AuthFailed(_)));
    }

    #[test]
    fn sqlstate_28000_is_auth_failed() {
        assert!(matches!(PgError::from_server(err("28000")), PgError::AuthFailed(_)));
    }

    #[test]
    fn sqlstate_3d000_is_no_such_database() {
        assert!(matches!(PgError::from_server(err("3D000")), PgError::NoSuchDatabase(_)));
    }

    #[test]
    fn sqlstate_53300_is_too_many_connections() {
        assert!(matches!(
            PgError::from_server(err("53300")),
            PgError::TooManyConnections(_)
        ));
    }

    #[test]
    fn unknown_sqlstate_falls_through_to_server() {
        assert!(matches!(PgError::from_server(err("XX000")), PgError::Server(_)));
    }

    #[test]
    fn server_error_displays_every_field() {
        let e = ServerError {
            severity: "ERROR".into(),
            code: "42501".into(),
            message: "permission denied for table t".into(),
            detail: Some("role monitor".into()),
            hint: Some("grant SELECT".into()),
        };
        let s = e.to_string();
        assert!(s.contains("ERROR"), "{s}");
        assert!(s.contains("42501"), "{s}");
        assert!(s.contains("permission denied for table t"), "{s}");
        assert!(s.contains("role monitor"), "{s}");
        assert!(s.contains("grant SELECT"), "{s}");
    }

    #[test]
    fn permission_denied_classification() {
        assert!(err("42501").is_permission_denied());
        assert!(err("2F004").is_permission_denied());
        assert!(err("55000").is_permission_denied());
        assert!(!err("3D000").is_permission_denied());
        assert!(!err("28P01").is_permission_denied());
    }

    #[test]
    fn fatal_classification() {
        assert!(err("28P01").is_fatal());
        let mut n = err("00000");
        n.severity = "NOTICE".into();
        assert!(!n.is_fatal());
    }

    #[test]
    fn not_read_only_never_echoes_the_statement() {
        // The guard stores only the keyword precisely so a rejected
        // `ALTER USER ... PASSWORD '...'` cannot leak into a log line.
        let e = PgError::NotReadOnly { keyword: "ALTER".into() };
        let rendered = format!("{e} {e:?}");
        assert!(!rendered.contains("hunter2"));
        assert!(rendered.contains("ALTER"));
    }

    #[test]
    fn channel_binding_error_explains_the_local_socket_posture() {
        let s = PgError::ChannelBindingRequired.to_string();
        assert!(s.contains("pg_hba.conf"), "{s}");
        assert!(s.contains("loopback"), "{s}");
    }

    #[test]
    fn remote_host_error_names_the_host_and_the_reason() {
        let s = PgError::RemoteHostNotAllowed("db.example.com".into()).to_string();
        assert!(s.contains("db.example.com"), "{s}");
        assert!(s.contains("TLS"), "{s}");
    }

    #[test]
    fn unsupported_auth_names_the_code() {
        let s = PgError::UnsupportedAuth(7).to_string();
        assert!(s.contains('7'), "{s}");
        assert!(s.contains("SCRAM-SHA-256"), "{s}");
    }

    #[test]
    fn database_mismatch_tells_the_caller_what_to_do() {
        let e = PgError::DatabaseMismatch { requested: "shop".into(), connected: "postgres".into() };
        let s = e.to_string();
        assert!(s.contains("shop"), "{s}");
        assert!(s.contains("postgres"), "{s}");
    }

    #[test]
    fn every_variant_has_a_user_message() {
        let variants = [
            PgError::Io(std::io::Error::from(std::io::ErrorKind::ConnectionRefused)),
            PgError::Protocol("x".into()),
            PgError::UnsupportedAuth(9),
            PgError::PasswordRequired,
            PgError::ChannelBindingRequired,
            PgError::ScramFailed("x"),
            PgError::AuthFailed(err("28P01")),
            PgError::NoSuchDatabase(err("3D000")),
            PgError::TooManyConnections(err("53300")),
            PgError::Server(err("XX000")),
            PgError::RemoteHostNotAllowed("h".into()),
            PgError::NotReadOnly { keyword: "DROP".into() },
            PgError::DatabaseMismatch { requested: "a".into(), connected: "b".into() },
            PgError::UnsupportedPassword("x"),
        ];
        for v in &variants {
            let m = v.user_message();
            assert!(!m.is_empty(), "{v:?}");
            // Every message we write ourselves reads as a sentence. `Server` is
            // the deliberate exception: it passes PostgreSQL's own wording
            // through verbatim, and PostgreSQL does not punctuate its messages.
            if !matches!(v, PgError::Server(_)) {
                assert!(m.ends_with('.'), "{m}");
            }
        }
    }

    #[test]
    fn io_errors_convert_and_keep_their_source() {
        use std::error::Error;
        let e: PgError = std::io::Error::from(std::io::ErrorKind::TimedOut).into();
        assert!(matches!(e, PgError::Io(_)));
        assert!(e.source().is_some());
    }
}
