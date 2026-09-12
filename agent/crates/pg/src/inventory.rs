//! What the Databases screen shows: discovery, one instance's health, and the
//! four lists beneath it.
//!
//! # Shape of the data
//!
//! Every function here returns [`Value`] rather than a Rust struct. These
//! results go straight out of the agent's HTTP layer to a Swift `Decodable`,
//! and an intermediate struct per screen would be a second schema to keep in
//! sync with the first for no gain. The JSON *is* the contract.
//!
//! # Degrading instead of failing
//!
//! The role the agent connects as is usually not a superuser — the right
//! configuration is a dedicated monitoring role with `pg_monitor`, and plenty
//! of operators will give it less than that. So every field in
//! [`instance_overview`] is gathered by its own statement and a server-side
//! refusal fills that field with `null` rather than failing the call. One blank
//! tile is a far better answer than an error banner over a screen that could
//! have shown eleven correct numbers.
//!
//! # Statements are fixed
//!
//! Every statement in this module is a literal in this source file. They run
//! through `query_unchecked` because they are known-good and need constructs
//! the read-only guard has no reason to learn; no caller-supplied string ever
//! reaches that function. The one caller-supplied value anywhere in the module
//! is `list_tables`'s database name, and it is compared against the connection
//! rather than interpolated.
//!
//! # Live query text is a data-leak surface
//!
//! `pg_stat_activity.query` holds whatever SQL is running right now, which
//! routinely contains customer data in literals and, on a bad day, a password
//! from a `CREATE ROLE`. [`list_connections`] therefore omits it unless the
//! caller passes [`QueryTextPolicy::IncludeTruncated`], and even then the
//! server truncates to 120 characters before the text crosses the socket. The
//! default is [`QueryTextPolicy::Omit`], and the safe thing must be the easy
//! thing.

use std::fs;
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::Duration;

use serveros_json::{Object, Value, round};

use crate::client::{PgConnection, QueryResult};
use crate::error::PgError;

// ---------------------------------------------------------------------------
// Statements
// ---------------------------------------------------------------------------

const SQL_VERSION: &str = "SHOW server_version";
const SQL_VERSION_NUM: &str = "SHOW server_version_num";
const SQL_DATA_DIRECTORY: &str = "SHOW data_directory";
const SQL_MAX_CONNECTIONS: &str = "SHOW max_connections";
const SQL_CURRENT_CONNECTIONS: &str = "SELECT count(*) FROM pg_stat_activity";
const SQL_DATABASE_COUNT: &str = "SELECT count(*) FROM pg_database";

/// Start time and the server's own clock in one round trip, so `uptime` is not
/// skewed by a difference between the agent's clock and the database's.
const SQL_UPTIME: &str = "SELECT extract(epoch FROM pg_postmaster_start_time())::bigint, \
                          extract(epoch FROM now())::bigint";

/// The `has_database_privilege` filter keeps a database we may not inspect from
/// turning the whole aggregate into a permission error.
const SQL_TOTAL_SIZE: &str = "SELECT sum(pg_database_size(datname))::bigint FROM pg_database \
                              WHERE has_database_privilege(datname, 'CONNECT')";

const SQL_STAT_DATABASE: &str = "SELECT sum(blks_hit) * 100.0 / \
                                 nullif(sum(blks_hit) + sum(blks_read), 0), \
                                 sum(xact_commit), sum(xact_rollback), sum(deadlocks) \
                                 FROM pg_stat_database";

const SQL_DATABASES: &str = "SELECT d.datname, pg_get_userbyid(d.datdba), \
                             CASE WHEN has_database_privilege(d.datname, 'CONNECT') \
                                  THEN pg_database_size(d.datname) END, \
                             pg_encoding_to_char(d.encoding), d.datcollate, \
                             d.datconnlimit, d.datistemplate \
                             FROM pg_database d ORDER BY d.datname";

const SQL_TABLES: &str = "SELECT s.schemaname, s.relname, s.n_live_tup, \
                          pg_total_relation_size(s.relid), pg_table_size(s.relid), \
                          pg_indexes_size(s.relid), s.seq_scan, s.idx_scan, \
                          extract(epoch FROM greatest(s.last_vacuum, s.last_autovacuum))::bigint, \
                          extract(epoch FROM greatest(s.last_analyze, s.last_autoanalyze))::bigint \
                          FROM pg_stat_user_tables s \
                          ORDER BY pg_total_relation_size(s.relid) DESC, s.schemaname, s.relname";

/// `query` is replaced by a literal NULL so the text never leaves the server.
const SQL_CONNECTIONS: &str = "SELECT pid, usename, datname, client_addr, application_name, \
                               state, extract(epoch FROM query_start)::bigint, \
                               extract(epoch FROM state_change)::bigint, wait_event_type, \
                               backend_type, NULL FROM pg_stat_activity ORDER BY pid";

const SQL_CONNECTIONS_WITH_QUERY: &str = "SELECT pid, usename, datname, client_addr, \
                                          application_name, state, \
                                          extract(epoch FROM query_start)::bigint, \
                                          extract(epoch FROM state_change)::bigint, \
                                          wait_event_type, backend_type, left(query, 120) \
                                          FROM pg_stat_activity ORDER BY pid";

/// `pg_roles` is the right view to read: unlike `pg_authid` it replaces every
/// password hash with `********`, so a role listing cannot carry a verifier
/// even by accident. We do not select the column at all, which makes that two
/// independent reasons rather than one.
const SQL_ROLES: &str = "SELECT rolname, rolsuper, rolcreatedb, rolcreaterole, rolcanlogin, \
                         rolreplication, rolbypassrls, rolconnlimit, \
                         extract(epoch FROM rolvaliduntil)::bigint \
                         FROM pg_roles ORDER BY rolname";

/// Every fixed statement, so a test can hold them to the same guard callers
/// are held to. Test-only: it carries no behaviour, just the inventory of what
/// this module is allowed to run.
#[cfg(test)]
pub(crate) const ALL_STATEMENTS: &[&str] = &[
    SQL_VERSION,
    SQL_VERSION_NUM,
    SQL_DATA_DIRECTORY,
    SQL_MAX_CONNECTIONS,
    SQL_CURRENT_CONNECTIONS,
    SQL_DATABASE_COUNT,
    SQL_UPTIME,
    SQL_TOTAL_SIZE,
    SQL_STAT_DATABASE,
    SQL_DATABASES,
    SQL_TABLES,
    SQL_CONNECTIONS,
    SQL_CONNECTIONS_WITH_QUERY,
    SQL_ROLES,
];

/// Longest `query_preview` we will carry, in characters.
pub const QUERY_PREVIEW_CHARS: usize = 120;

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

/// The conventional places a PostgreSQL unix socket lives.
const SOCKET_DIRS: [&str; 2] = ["/var/run/postgresql", "/tmp"];

/// The port range we will believe a *TCP-only* listener is PostgreSQL on.
///
/// A unix socket named `.s.PGSQL.<port>` is unambiguous, so any port found that
/// way is reported. A bare listening TCP port is not, and reporting every
/// listening socket on the box as a possible database would make the discovery
/// screen useless. 5432 upward covers the default and the conventional
/// second/third cluster.
const TCP_PORT_RANGE: std::ops::RangeInclusive<u16> = 5432..=5499;

/// A PostgreSQL instance that appears to be running on this host.
///
/// Discovery finds *where* a database is, never *how to log in to it*. The
/// agent has no business guessing credentials, and a product that tried would
/// be indistinguishable from one probing for weak passwords.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveredInstance {
    /// Port, from the socket filename or the listening TCP socket.
    pub port: u16,
    /// Directory holding the unix socket, when there is one.
    pub socket_dir: Option<String>,
    /// Whether a connection could actually be opened (no authentication
    /// attempted).
    pub reachable: bool,
}

impl DiscoveredInstance {
    /// JSON for the discovery list.
    pub fn to_json(&self) -> Value {
        Value::Object(
            Object::new()
                .set("port", self.port)
                .set("socket_dir", self.socket_dir.clone())
                .set("reachable", self.reachable),
        )
    }
}

/// Find PostgreSQL instances running on this host.
pub fn discover_instances() -> Vec<DiscoveredInstance> {
    let mut found: Vec<DiscoveredInstance> = Vec::new();

    for dir in SOCKET_DIRS {
        for port in socket_ports(Path::new(dir)) {
            if found.iter().any(|i| i.port == port) {
                continue;
            }
            let reachable = unix_reachable(dir, port);
            found.push(DiscoveredInstance {
                port,
                socket_dir: Some(dir.to_string()),
                reachable,
            });
        }
    }

    for port in listening_tcp_ports() {
        if let Some(existing) = found.iter_mut().find(|i| i.port == port) {
            // A socket we could not open but a port we can is still reachable.
            existing.reachable = existing.reachable || tcp_reachable(port);
            continue;
        }
        if TCP_PORT_RANGE.contains(&port) {
            found.push(DiscoveredInstance {
                port,
                socket_dir: None,
                reachable: tcp_reachable(port),
            });
        }
    }

    found.sort_by_key(|i| i.port);
    found
}

/// Ports from `.s.PGSQL.<port>` files in one directory.
fn socket_ports(dir: &Path) -> Vec<u16> {
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return Vec::new(), // missing or unreadable: simply nothing here
    };
    let mut ports = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let name = match name.to_str() {
            Some(n) => n,
            None => continue,
        };
        // `.s.PGSQL.5432.lock` sits next to the socket; it is not one.
        if let Some(rest) = name.strip_prefix(".s.PGSQL.")
            && let Ok(port) = rest.parse::<u16>()
        {
            ports.push(port);
        }
    }
    ports.sort_unstable();
    ports
}

fn unix_reachable(dir: &str, port: u16) -> bool {
    UnixStream::connect(Path::new(dir).join(format!(".s.PGSQL.{port}"))).is_ok()
}

fn tcp_reachable(port: u16) -> bool {
    let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    TcpStream::connect_timeout(&addr, Duration::from_millis(250)).is_ok()
}

/// Listening TCP ports on loopback or on every interface, from `/proc/net`.
///
/// `local_address` is `<hex address>:<hex port>`, the address in the host's
/// byte order (little-endian on everything we ship to), and `st` is the TCP
/// state — `0A` is LISTEN.
fn listening_tcp_ports() -> Vec<u16> {
    let mut ports = Vec::new();
    for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let local = match fields.nth(1) {
                Some(l) => l,
                None => continue,
            };
            if fields.next() != Some("00000000:0000") {
                continue; // has a remote peer, so not a listener
            }
            if fields.next() != Some("0A") {
                continue; // not LISTEN
            }
            if let Some((_, port_hex)) = local.rsplit_once(':')
                && let Ok(port) = u16::from_str_radix(port_hex, 16)
                && !ports.contains(&port)
            {
                ports.push(port);
            }
        }
    }
    ports.sort_unstable();
    ports
}

// ---------------------------------------------------------------------------
// Overview
// ---------------------------------------------------------------------------

/// Health and headline numbers for one instance.
///
/// See the module docs: any single field may come back `null` because the
/// connected role may not read it.
pub fn instance_overview(conn: &mut PgConnection) -> Result<Value, PgError> {
    let version = optional_scalar(conn, SQL_VERSION)?.map(|v| short_version(&v));
    let version_num = optional_scalar(conn, SQL_VERSION_NUM)?.and_then(|v| parse_i64(&v));
    let data_directory = optional_scalar(conn, SQL_DATA_DIRECTORY)?;
    let max_connections = optional_scalar(conn, SQL_MAX_CONNECTIONS)?.and_then(|v| parse_i64(&v));
    let current_connections =
        optional_scalar(conn, SQL_CURRENT_CONNECTIONS)?.and_then(|v| parse_i64(&v));
    let database_count = optional_scalar(conn, SQL_DATABASE_COUNT)?.and_then(|v| parse_i64(&v));
    let total_size_bytes = optional_scalar(conn, SQL_TOTAL_SIZE)?.and_then(|v| parse_i64(&v));

    let (started_at, uptime_seconds) = match optional(conn, SQL_UPTIME)? {
        Some(r) => {
            let started = cell(&r, 0, 0).and_then(parse_i64);
            let now = cell(&r, 0, 1).and_then(parse_i64);
            (started, started.zip(now).map(|(s, n)| (n - s).max(0)))
        }
        None => (None, None),
    };

    let stats = optional(conn, SQL_STAT_DATABASE)?;
    let cache_hit_ratio = stats
        .as_ref()
        .and_then(|r| cell(r, 0, 0))
        .and_then(parse_f64)
        .map(|v| round(v, 1));
    let transactions_committed = stats.as_ref().and_then(|r| cell(r, 0, 1)).and_then(parse_i64);
    let transactions_rolled_back = stats.as_ref().and_then(|r| cell(r, 0, 2)).and_then(parse_i64);
    let deadlocks = stats.as_ref().and_then(|r| cell(r, 0, 3)).and_then(parse_i64);

    let connection_usage_percent = match (current_connections, max_connections) {
        (Some(current), Some(max)) if max > 0 => {
            Some(round(current as f64 * 100.0 / max as f64, 1))
        }
        _ => None,
    };

    let (health, health_reason) = assess_health(connection_usage_percent, cache_hit_ratio);

    Ok(Value::Object(
        Object::new()
            .set("version", version)
            .set("version_num", version_num)
            .set("uptime_seconds", uptime_seconds)
            .set("started_at", started_at)
            .set("data_directory", data_directory)
            .set("max_connections", max_connections)
            .set("current_connections", current_connections)
            .set("connection_usage_percent", connection_usage_percent)
            .set("database_count", database_count)
            .set("total_size_bytes", total_size_bytes)
            .set("cache_hit_ratio", cache_hit_ratio)
            .set("transactions_committed", transactions_committed)
            .set("transactions_rolled_back", transactions_rolled_back)
            .set("deadlocks", deadlocks)
            .set("health", health)
            .set("health_reason", health_reason),
    ))
}

/// Turn two numbers into the one word and one sentence the UI leads with.
///
/// Kept separate and pure so the thresholds are testable without a database.
/// The sentence is the product's voice: it says what is wrong, not which view
/// it came from.
fn assess_health(
    connection_usage_percent: Option<f64>,
    cache_hit_ratio: Option<f64>,
) -> (&'static str, Option<String>) {
    if let Some(usage) = connection_usage_percent {
        if usage > 95.0 {
            return (
                "critical",
                Some(format!(
                    "PostgreSQL is using {usage:.0}% of its connection slots and is about to \
                     refuse new connections."
                )),
            );
        }
        if usage > 80.0 {
            return (
                "warning",
                Some(format!("PostgreSQL is using {usage:.0}% of its connection slots.")),
            );
        }
    }
    if let Some(ratio) = cache_hit_ratio
        && ratio < 90.0
    {
        return (
            "warning",
            Some(format!(
                "Only {ratio:.0}% of block reads are served from cache, so queries are going to \
                 disk more than they should."
            )),
        );
    }
    ("healthy", None)
}

/// `SHOW server_version` returns `16.13` on a source build and
/// `16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)` on a packaged one. The product wants
/// the number; the packaging detail belongs on the details pane, not the tile.
fn short_version(raw: &str) -> String {
    raw.split_whitespace().next().unwrap_or(raw).to_string()
}

// ---------------------------------------------------------------------------
// Lists
// ---------------------------------------------------------------------------

/// Every database on the instance.
///
/// `table_count` is always `null`: counting tables means connecting to each
/// database in turn, which is a per-database round trip the list view has no
/// business paying for. [`list_tables`] fills it in where it matters.
pub fn list_databases(conn: &mut PgConnection) -> Result<Value, PgError> {
    let result = conn.query_unchecked(SQL_DATABASES)?;
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        out.push(Value::Object(
            Object::new()
                .set("name", text(row, 0))
                .set("owner", text(row, 1))
                .set("size_bytes", int(row, 2))
                .set("encoding", text(row, 3))
                .set("collation", text(row, 4))
                .set("connection_limit", int(row, 5))
                .set("is_template", boolean(row, 6))
                .set("table_count", Value::Null),
        ));
    }
    Ok(Value::Array(out))
}

/// Tables in the database this connection is attached to.
///
/// `database` must name that database. PostgreSQL has no cross-database query,
/// so there is no way to honour a different name on this connection, and
/// quietly returning the wrong database's tables would be worse than refusing.
pub fn list_tables(conn: &mut PgConnection, database: &str) -> Result<Value, PgError> {
    if conn.database() != database {
        return Err(PgError::DatabaseMismatch {
            requested: database.to_string(),
            connected: conn.database().to_string(),
        });
    }

    let result = conn.query_unchecked(SQL_TABLES)?;
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        out.push(Value::Object(
            Object::new()
                .set("schema", text(row, 0))
                .set("name", text(row, 1))
                // `n_live_tup` is an estimate the statistics collector keeps;
                // it is `0` for a table that has never been touched, never
                // negative, and cheap. An exact count means a sequential scan.
                .set("rows_estimate", int(row, 2))
                .set("total_size_bytes", int(row, 3))
                .set("table_size_bytes", int(row, 4))
                .set("index_size_bytes", int(row, 5))
                .set("seq_scans", int(row, 6))
                .set("index_scans", int(row, 7))
                .set("last_vacuum", int(row, 8))
                .set("last_analyze", int(row, 9)),
        ));
    }
    Ok(Value::Array(out))
}

/// Whether [`list_connections`] may carry the SQL text of running statements.
///
/// Defaults to [`QueryTextPolicy::Omit`]. See the module docs for why this is a
/// decision the caller has to make explicitly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QueryTextPolicy {
    /// `query_preview` is `null`, and the text never leaves the server.
    #[default]
    Omit,
    /// `query_preview` carries at most [`QUERY_PREVIEW_CHARS`] characters.
    IncludeTruncated,
}

/// Current backend connections.
pub fn list_connections(conn: &mut PgConnection, policy: QueryTextPolicy) -> Result<Value, PgError> {
    let sql = match policy {
        QueryTextPolicy::Omit => SQL_CONNECTIONS,
        QueryTextPolicy::IncludeTruncated => SQL_CONNECTIONS_WITH_QUERY,
    };
    let result = conn.query_unchecked(sql)?;

    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        // The server already applied `left(query, 120)`; truncating again costs
        // nothing and means a server that ignored it cannot widen the leak.
        let preview = match policy {
            QueryTextPolicy::Omit => None,
            QueryTextPolicy::IncludeTruncated => {
                row.get(10).and_then(|v| v.as_deref()).map(truncate_preview)
            }
        };
        out.push(Value::Object(
            Object::new()
                .set("pid", int(row, 0))
                .set("user", text(row, 1))
                .set("database", text(row, 2))
                .set("client_addr", text(row, 3))
                .set("application_name", text(row, 4))
                .set("state", text(row, 5))
                .set("query_start", int(row, 6))
                .set("state_change", int(row, 7))
                .set("wait_event_type", text(row, 8))
                .set("backend_type", text(row, 9))
                .set("query_preview", preview),
        ));
    }
    Ok(Value::Array(out))
}

/// Roles on the instance. Never carries a password verifier — see
/// [`SQL_ROLES`]'s comment.
pub fn list_roles(conn: &mut PgConnection) -> Result<Value, PgError> {
    let result = conn.query_unchecked(SQL_ROLES)?;
    let mut out = Vec::with_capacity(result.rows.len());
    for row in &result.rows {
        out.push(Value::Object(
            Object::new()
                .set("name", text(row, 0))
                .set("is_superuser", boolean(row, 1))
                .set("can_create_db", boolean(row, 2))
                .set("can_create_role", boolean(row, 3))
                .set("can_login", boolean(row, 4))
                .set("is_replication", boolean(row, 5))
                .set("bypasses_rls", boolean(row, 6))
                .set("connection_limit", int(row, 7))
                .set("valid_until", int(row, 8)),
        ));
    }
    Ok(Value::Array(out))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Run a statement, turning a server-side refusal into `None`.
///
/// Only [`PgError::Server`] is swallowed: that is the class where the server
/// answered, declined, and left the connection usable (a permission error is
/// SQLSTATE `42501`, which lands here). An I/O or protocol failure means the
/// connection is gone and every later field would be `null` too, so those
/// propagate and the caller gets one honest error instead of a screen of
/// blanks.
fn optional(conn: &mut PgConnection, sql: &str) -> Result<Option<QueryResult>, PgError> {
    match conn.query_unchecked(sql) {
        Ok(r) => Ok(Some(r)),
        Err(PgError::Server(_)) => Ok(None),
        Err(e) => Err(e),
    }
}

fn optional_scalar(conn: &mut PgConnection, sql: &str) -> Result<Option<String>, PgError> {
    Ok(optional(conn, sql)?.and_then(|r| r.scalar().map(|s| s.to_string())))
}

fn cell(result: &QueryResult, row: usize, column: usize) -> Option<&str> {
    result.rows.get(row)?.get(column)?.as_deref()
}

fn parse_i64(s: &str) -> Option<i64> {
    s.trim().parse().ok()
}

fn parse_f64(s: &str) -> Option<f64> {
    s.trim().parse().ok()
}

fn text(row: &[Option<String>], index: usize) -> Option<String> {
    row.get(index)?.clone()
}

fn int(row: &[Option<String>], index: usize) -> Option<i64> {
    parse_i64(row.get(index)?.as_deref()?)
}

/// PostgreSQL renders booleans as `t`/`f` in text format.
fn boolean(row: &[Option<String>], index: usize) -> Option<bool> {
    match row.get(index)?.as_deref()? {
        "t" | "true" => Some(true),
        "f" | "false" => Some(false),
        _ => None,
    }
}

/// Truncate to [`QUERY_PREVIEW_CHARS`] *characters*, not bytes, so a preview
/// never splits a UTF-8 sequence.
fn truncate_preview(s: &str) -> String {
    match s.char_indices().nth(QUERY_PREVIEW_CHARS) {
        Some((byte, _)) => s[..byte].to_string(),
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_version_drops_the_packaging_suffix() {
        assert_eq!(short_version("16.13 (Ubuntu 16.13-0ubuntu0.24.04.1)"), "16.13");
        assert_eq!(short_version("16.13"), "16.13");
        assert_eq!(short_version("17beta1"), "17beta1");
        assert_eq!(short_version(""), "");
    }

    #[test]
    fn health_is_healthy_when_everything_is_fine() {
        let (h, why) = assess_health(Some(12.0), Some(99.2));
        assert_eq!(h, "healthy");
        assert!(why.is_none());
    }

    #[test]
    fn health_warns_above_eighty_percent_of_connections() {
        let (h, why) = assess_health(Some(81.0), Some(99.0));
        assert_eq!(h, "warning");
        assert!(why.unwrap().contains("connection slots"));
        // Exactly 80 is not yet a warning.
        assert_eq!(assess_health(Some(80.0), Some(99.0)).0, "healthy");
    }

    #[test]
    fn health_is_critical_above_ninety_five_percent_of_connections() {
        let (h, why) = assess_health(Some(96.0), Some(99.0));
        assert_eq!(h, "critical");
        assert!(why.unwrap().contains("refuse new connections"));
        assert_eq!(assess_health(Some(95.0), Some(99.0)).0, "warning");
    }

    #[test]
    fn health_warns_on_a_poor_cache_hit_ratio() {
        let (h, why) = assess_health(Some(10.0), Some(72.0));
        assert_eq!(h, "warning");
        assert!(why.unwrap().contains("cache"));
        assert_eq!(assess_health(Some(10.0), Some(90.0)).0, "healthy");
    }

    #[test]
    fn connections_outrank_the_cache_ratio_when_both_are_bad() {
        let (h, why) = assess_health(Some(99.0), Some(10.0));
        assert_eq!(h, "critical");
        assert!(why.unwrap().contains("connection slots"));
    }

    #[test]
    fn health_is_healthy_when_nothing_could_be_measured() {
        let (h, why) = assess_health(None, None);
        assert_eq!(h, "healthy");
        assert!(why.is_none());
    }

    #[test]
    fn health_reasons_read_as_sentences() {
        for (usage, ratio) in [(Some(99.0), None), (Some(85.0), None), (None, Some(50.0))] {
            let (_, why) = assess_health(usage, ratio);
            let why = why.expect("a non-healthy state must explain itself");
            assert!(why.ends_with('.'), "{why}");
            assert!(why.starts_with(|c: char| c.is_uppercase()), "{why}");
        }
    }

    #[test]
    fn text_format_booleans_decode() {
        let row = vec![Some("t".to_string()), Some("f".to_string()), None, Some("?".to_string())];
        assert_eq!(boolean(&row, 0), Some(true));
        assert_eq!(boolean(&row, 1), Some(false));
        assert_eq!(boolean(&row, 2), None);
        assert_eq!(boolean(&row, 3), None);
        assert_eq!(boolean(&row, 9), None);
    }

    #[test]
    fn numeric_and_text_cells_decode_and_tolerate_nulls() {
        let row = vec![Some("42".to_string()), None, Some("not a number".to_string())];
        assert_eq!(int(&row, 0), Some(42));
        assert_eq!(int(&row, 1), None);
        assert_eq!(int(&row, 2), None);
        assert_eq!(int(&row, 7), None);
        assert_eq!(text(&row, 0).as_deref(), Some("42"));
        assert_eq!(text(&row, 1), None);
    }

    #[test]
    fn preview_truncation_counts_characters_not_bytes() {
        let ascii = "x".repeat(500);
        assert_eq!(truncate_preview(&ascii).chars().count(), QUERY_PREVIEW_CHARS);

        // Four-byte characters: byte-slicing at 120 would panic or corrupt.
        let wide = "🙂".repeat(300);
        let cut = truncate_preview(&wide);
        assert_eq!(cut.chars().count(), QUERY_PREVIEW_CHARS);
        assert!(wide.starts_with(&cut));

        assert_eq!(truncate_preview("short"), "short");
    }

    #[test]
    fn query_text_policy_defaults_to_omitting() {
        assert_eq!(QueryTextPolicy::default(), QueryTextPolicy::Omit);
    }

    #[test]
    fn the_omitting_statement_cannot_carry_query_text() {
        assert!(SQL_CONNECTIONS.contains("NULL"));
        assert!(!SQL_CONNECTIONS.contains("left(query"));
        assert!(SQL_CONNECTIONS_WITH_QUERY.contains("left(query, 120)"));
    }

    #[test]
    fn no_statement_reads_a_password_verifier() {
        for sql in ALL_STATEMENTS {
            assert!(!sql.contains("pg_authid"), "{sql}");
            assert!(!sql.contains("rolpassword"), "{sql}");
        }
    }

    #[test]
    fn discovered_instance_json_shape() {
        let i = DiscoveredInstance {
            port: 5432,
            socket_dir: Some("/var/run/postgresql".into()),
            reachable: true,
        };
        assert_eq!(
            i.to_json().to_string(),
            r#"{"port":5432,"socket_dir":"/var/run/postgresql","reachable":true}"#
        );

        let tcp_only = DiscoveredInstance { port: 5433, socket_dir: None, reachable: false };
        assert_eq!(
            tcp_only.to_json().to_string(),
            r#"{"port":5433,"socket_dir":null,"reachable":false}"#
        );
    }

    #[test]
    fn socket_port_scan_ignores_lock_files_and_strangers() {
        let dir = std::env::temp_dir().join(format!("serveros-pg-scan-{}", std::process::id()));
        let _ = fs::create_dir_all(&dir);
        for name in [".s.PGSQL.5432", ".s.PGSQL.5433", ".s.PGSQL.5432.lock", "unrelated"] {
            let _ = fs::write(dir.join(name), b"");
        }
        let ports = socket_ports(&dir);
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(ports, vec![5432, 5433]);
    }

    #[test]
    fn socket_port_scan_of_a_missing_directory_is_empty_not_an_error() {
        assert!(socket_ports(Path::new("/nonexistent/serveros/pg")).is_empty());
    }

    #[test]
    fn discovery_never_returns_duplicate_ports() {
        let found = discover_instances();
        let mut ports: Vec<u16> = found.iter().map(|i| i.port).collect();
        let count = ports.len();
        ports.sort_unstable();
        ports.dedup();
        assert_eq!(ports.len(), count);
        // And it is sorted, so the UI does not have to be.
        assert!(found.windows(2).all(|w| w[0].port <= w[1].port));
    }
}
