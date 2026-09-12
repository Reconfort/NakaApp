//! PostgreSQL — discovery, inventory and live connections.
//!
//! # Two very different kinds of answer
//!
//! [`list_instances`] needs no credential at all: it looks for sockets in the
//! conventional directories and for listening ports, and reports *where* a
//! database is. That distinction is deliberate — discovery must never involve
//! guessing how to log in, because a product that tries credentials against
//! databases it finds is indistinguishable from one probing for weak passwords.
//!
//! Everything else connects, using the single monitoring role configured in
//! `postgres.*`. The connection is read-only by construction (see
//! `serveros-pg`), and the password — when the role needs one — is read from a
//! file at the moment of use, never stored in the config, never logged, and
//! never present in a response.
//!
//! # "PostgreSQL isn't reachable" is a screen, not a crash
//!
//! A database that is down, restarting, or refusing our role is an ordinary
//! state of a server, and the app has an empty state for it. So a connection
//! failure answers 503 with [`PgError::user_message`], not 500. A 500 would
//! tell the user that ServerOS is broken, when what is actually true is that
//! their database is not running — and those lead to completely different next
//! actions.

use crate::api::{bad_request, collection, internal, unavailable};
use crate::auth::{Principal, Scope};
use crate::state::AgentState;
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use serveros_pg::{PgConfig, PgConnection, PgError, PgHost, QueryTextPolicy, inventory};

/// Why PostgreSQL support might be off, phrased for the 503's `detail`.
const DISABLED_REASON: &str =
    "PostgreSQL support is turned off in this agent's configuration (postgres.enabled is false)";

/// `GET /v1/databases` — PostgreSQL instances on this host.
///
/// Credential-free. `reachable` means a socket accepted a connection, not that
/// anyone authenticated: it separates "there is a cluster here but it is down"
/// from "there is no cluster here", which are different screens.
pub fn list_instances(_state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let instances = inventory::discover_instances();
    collection(instances.iter().map(|i| i.to_json()).collect())
}

/// `GET /v1/databases/postgres` — health and headline numbers for the
/// configured instance.
pub fn postgres_overview(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    with_connection(state, None, |conn| inventory::instance_overview(conn))
}

/// `GET /v1/databases/postgres/databases` — every database on the instance.
pub fn postgres_databases(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    with_connection(state, None, |conn| inventory::list_databases(conn).map(wrap_items))
}

/// `GET /v1/databases/postgres/tables` — tables in one database.
///
/// `?database=` selects it, defaulting to the configured one. PostgreSQL has no
/// cross-database query, so this opens a connection *to that database* rather
/// than asking the default connection about it — see `PgError::DatabaseMismatch`,
/// which exists precisely so that returning the wrong database's tables is
/// impossible rather than merely unlikely.
pub fn postgres_tables(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let database = match req.query_str("database") {
        Some(name) => {
            if let Err(response) = validate_database_name(&name) {
                return response;
            }
            name
        }
        None => state.config.postgres.database.clone(),
    };

    let target = database.clone();
    with_connection(state, Some(database), move |conn| {
        inventory::list_tables(conn, &target).map(wrap_items)
    })
}

/// `GET /v1/databases/postgres/connections` — what is connected right now.
///
/// # `?include_query=true`
///
/// A running statement's text is one of the most sensitive things a database
/// holds: `UPDATE users SET email = 'someone@example.com' WHERE id = 42` is
/// personal data, and `SELECT ... WHERE token = '...'` is a credential. So the
/// default is [`QueryTextPolicy::Omit`] — the text never leaves the server — and
/// including it requires *both* the explicit flag and `admin` scope. A caller
/// with `write` can restart the database and still not read what it is running.
///
/// As with revealing container environment, the flag is ignored rather than
/// rejected for an under-privileged caller, so the answer degrades instead of
/// failing.
pub fn postgres_connections(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let policy = if req.query_flag("include_query") && principal.has(Scope::Admin) {
        QueryTextPolicy::IncludeTruncated
    } else {
        QueryTextPolicy::Omit
    };

    with_connection(state, None, move |conn| {
        inventory::list_connections(conn, policy).map(wrap_items)
    })
}

/// `GET /v1/databases/postgres/roles` — roles on the instance.
///
/// Never carries a password verifier; the query that backs it does not select
/// one.
pub fn postgres_roles(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    with_connection(state, None, |conn| inventory::list_roles(conn).map(wrap_items))
}

// ---------------------------------------------------------------- plumbing ---

/// Wrap a bare array in the standard collection envelope.
///
/// The inventory functions return arrays because they are a library; the API
/// returns objects because a bare array cannot grow a `total` later without
/// breaking every client.
fn wrap_items(value: Value) -> Value {
    let items = match value {
        Value::Array(items) => items,
        other => return other,
    };
    Object::new().set("total", items.len()).set("items", Value::Array(items)).into()
}

/// Open a connection, run one inventory query, and always close.
///
/// Connections are not pooled. The agent runs a handful of catalogue queries a
/// minute, and a pool held open against a database the operator is trying to
/// restart is an obstacle, not an optimisation.
fn with_connection<F>(state: &AgentState, database: Option<String>, f: F) -> Response
where
    F: FnOnce(&mut PgConnection) -> Result<Value, PgError>,
{
    let config = match pg_config(state, database) {
        Ok(config) => config,
        Err(response) => return response,
    };

    let mut conn = match PgConnection::connect(&config) {
        Ok(conn) => conn,
        // Not reachable, wrong credentials, no such database: all of these are
        // states of the customer's database, not faults in the agent.
        Err(e) => return unavailable("PostgreSQL", &e.user_message()),
    };

    let result = f(&mut conn);
    conn.close();

    match result {
        Ok(value) => Response::json(value),
        Err(e) => query_response(e),
    }
}

/// Build the connection configuration from `postgres.*`.
///
/// The password is read here, at the moment of use, and lives only as long as
/// the `PgConfig` — which has a hand-written `Debug` that omits it, and which
/// the connection never stores.
fn pg_config(state: &AgentState, database: Option<String>) -> Result<PgConfig, Response> {
    let settings = &state.config.postgres;
    if !settings.enabled {
        return Err(unavailable("PostgreSQL", DISABLED_REASON));
    }

    let password = match &settings.password_file {
        Some(path) => match std::fs::read_to_string(path) {
            // Trim: a password file written with `echo` ends in a newline, and
            // a trailing newline is the single most common reason a correct
            // password is rejected.
            Ok(text) => Some(text.trim_end_matches(['\n', '\r']).to_string()),
            Err(e) => {
                return Err(internal(
                    "ServerOS couldn't read the PostgreSQL password file on this server.",
                    // The path, not the contents. A failure to read a secret
                    // must not be an excuse to print one.
                    format!("{}: {e}", path.display()),
                ));
            }
        },
        None => None,
    };

    Ok(PgConfig {
        host: PgHost::Unix(settings.socket_dir.clone()),
        port: settings.port,
        user: settings.user.clone(),
        password,
        database: database.unwrap_or_else(|| settings.database.clone()),
        connect_timeout: std::time::Duration::from_secs(5),
    })
}

/// A query that failed after the connection was established.
///
/// Distinct from a connection failure: the database is up and answered, so this
/// is either a permission the monitoring role lacks or something genuinely
/// wrong. The user message comes from the crate; the detail carries the SQLSTATE
/// and server text for the disclosure.
fn query_response(e: PgError) -> Response {
    let status = match &e {
        PgError::NoSuchDatabase(_) => Status::NOT_FOUND,
        PgError::DatabaseMismatch { .. } | PgError::NotReadOnly { .. } => Status::BAD_REQUEST,
        PgError::TooManyConnections(_) | PgError::Io(_) => Status::SERVICE_UNAVAILABLE,
        _ => Status::BAD_GATEWAY,
    };
    Response::error_detail(status, "database_error", e.user_message(), e.to_string())
}

/// Database names come from the caller, so they are checked before they become
/// part of a connection request.
///
/// PostgreSQL identifiers may contain almost anything when quoted, but a name
/// arriving over HTTP with a NUL, a newline or 200 characters in it is a probe,
/// not a database.
fn validate_database_name(name: &str) -> Result<(), Response> {
    if name.is_empty() {
        return Err(bad_request("\"database\" cannot be empty."));
    }
    if name.len() > 63 {
        return Err(bad_request("That database name is too long."));
    }
    if name.chars().any(|c| c.is_control()) {
        return Err(bad_request("That database name contains characters PostgreSQL cannot use."));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn database_names_are_checked_before_use() {
        assert!(validate_database_name("app_production").is_ok());
        assert!(validate_database_name("").is_err());
        assert!(validate_database_name("a\nb").is_err());
        assert!(validate_database_name("a\0b").is_err());
        assert!(validate_database_name(&"x".repeat(64)).is_err());
    }

    #[test]
    fn arrays_gain_a_collection_envelope() {
        let wrapped = wrap_items(Value::Array(vec![Value::from(1), Value::from(2)]));
        assert_eq!(wrapped.get("total").and_then(Value::as_u64), Some(2));
        assert_eq!(wrapped.get("items").and_then(Value::as_array).map(<[Value]>::len), Some(2));
    }

    #[test]
    fn objects_pass_through_unwrapped() {
        // `instance_overview` already returns an object; it must not be nested.
        let overview = Value::Object(Object::new().set("version", "16.2"));
        assert_eq!(wrap_items(overview).get("version").and_then(Value::as_str), Some("16.2"));
    }

    #[test]
    fn a_disabled_instance_reports_unavailable_not_an_error() {
        let mut config = crate::config::Config::default();
        config.postgres.enabled = false;
        // Point the activity log somewhere disposable; a unit test must not
        // create /var/lib/serveros on whoever's machine runs it.
        config.data_dir = std::env::temp_dir().join(format!("serveros-pg-off-{}", std::process::id()));
        let state = AgentState::new(config, vec![0u8; 32]);
        let response = pg_config(&state, None).expect_err("must refuse when disabled");
        assert_eq!(response.status, Status::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn query_failures_map_to_states_the_ui_can_explain() {
        assert_eq!(
            query_response(PgError::DatabaseMismatch {
                requested: "app".into(),
                connected: "postgres".into()
            })
            .status,
            Status::BAD_REQUEST
        );
        assert_eq!(
            query_response(PgError::NotReadOnly { keyword: "DROP".into() }).status,
            Status::BAD_REQUEST
        );
    }

    #[test]
    fn a_user_message_never_carries_the_technical_text() {
        let e = PgError::NotReadOnly { keyword: "DROP".into() };
        assert_eq!(e.user_message(), "Only read-only statements are allowed here.");
        assert!(!e.user_message().contains("DROP"));
    }
}
