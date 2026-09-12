//! Tests against a real PostgreSQL server.
//!
//! The unit tests live beside the code they cover; what is here needs an actual
//! cluster, because the things most worth proving about a wire-protocol client
//! are exactly the things a mock cannot prove. A hand-rolled fake server would
//! agree with whatever mistake the client makes — the RFC 7677 vectors in
//! [`crate::auth`] catch arithmetic errors, but only a real `postgres` process
//! catches a misread of what PostgreSQL actually puts on the socket.
//!
//! Every test here goes through [`live_pg`], which returns `None` and prints a
//! skip notice when no cluster is listening, so `cargo test` still passes on a
//! machine without one. The cluster used during development was:
//!
//! ```text
//! useradd -m pgtest
//! mkdir -p /tmp/pgdata && chown pgtest /tmp/pgdata && chmod 700 /tmp/pgdata
//! su pgtest -c "initdb -D /tmp/pgdata -A scram-sha-256 --pwfile=... -U serveros"
//! su pgtest -c "pg_ctl -D /tmp/pgdata \
//!     -o '-k /tmp -p 55432 -c listen_addresses=127.0.0.1' -l /tmp/pg.log start"
//! ```
//!
//! with a `pg_hba.conf` that selects the authentication method by role, so all
//! three paths are exercised against one running cluster with no reloads:
//!
//! ```text
//! local  all  all        trust
//! host   all  md5user    127.0.0.1/32  md5
//! host   all  trustuser  127.0.0.1/32  trust
//! host   all  all        127.0.0.1/32  scram-sha-256
//! ```

use std::net::TcpStream;
use std::time::Duration;

use crate::client::{PgConfig, PgConnection, PgHost};
use crate::error::PgError;
use crate::inventory::{self, QueryTextPolicy};

/// Port the test cluster listens on. Overridable so this can be pointed at a
/// cluster someone else started.
fn test_port() -> u16 {
    std::env::var("SERVEROS_PG_TEST_PORT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(55432)
}

/// The SCRAM role's password.
fn test_password() -> String {
    std::env::var("SERVEROS_PG_TEST_PASSWORD").unwrap_or_else(|_| "secretpw".to_string())
}

/// A config for the live cluster, or `None` if nothing is listening.
///
/// Returning `None` rather than failing is what lets the suite pass in CI
/// without a database, and the `eprintln!` is what stops that from silently
/// becoming "we never test the important half".
fn live_pg() -> Option<PgConfig> {
    let port = test_port();
    let addr = format!("127.0.0.1:{port}").parse().ok()?;
    if TcpStream::connect_timeout(&addr, Duration::from_millis(500)).is_err() {
        eprintln!(
            "SKIP: no PostgreSQL listening on 127.0.0.1:{port}; live protocol tests not run"
        );
        return None;
    }
    Some(PgConfig {
        host: PgHost::Tcp("127.0.0.1".into()),
        port,
        user: "serveros".into(),
        password: Some(test_password()),
        database: "postgres".into(),
        connect_timeout: Duration::from_secs(5),
    })
}

/// `live_pg`, connected.
macro_rules! connect_or_skip {
    () => {
        match live_pg() {
            Some(cfg) => match PgConnection::connect(&cfg) {
                Ok(c) => c,
                Err(e) => panic!("connect failed: {e}"),
            },
            None => return,
        }
    };
}

// ---------------------------------------------------------------------------
// Authentication, against the real server
// ---------------------------------------------------------------------------

#[test]
fn scram_sha_256_authenticates_against_real_postgresql() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT 1").unwrap();
    assert_eq!(r.scalar(), Some("1"));
    conn.close();
}

#[test]
fn md5_authenticates_against_real_postgresql() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.user = "md5user".into();
    cfg.password = Some("md5pw".into());

    let mut conn = match PgConnection::connect(&cfg) {
        Ok(c) => c,
        Err(e) => panic!("md5 connect failed: {e}"),
    };
    assert_eq!(conn.query("SELECT current_user").unwrap().scalar(), Some("md5user"));
    conn.close();
}

#[test]
fn trust_authenticates_against_real_postgresql() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.user = "trustuser".into();
    // No password at all: the server must never ask.
    cfg.password = None;

    let mut conn = match PgConnection::connect(&cfg) {
        Ok(c) => c,
        Err(e) => panic!("trust connect failed: {e}"),
    };
    assert_eq!(conn.query("SELECT current_user").unwrap().scalar(), Some("trustuser"));
    conn.close();
}

#[test]
fn unix_socket_connects_and_is_the_default_posture() {
    if live_pg().is_none() {
        return;
    }
    // The development cluster is started with `-k /tmp`, so its socket is
    // /tmp/.s.PGSQL.<port>. `local ... trust` in pg_hba means no password.
    let cfg = PgConfig {
        host: PgHost::Unix("/tmp".into()),
        port: test_port(),
        user: "serveros".into(),
        password: None,
        database: "postgres".into(),
        connect_timeout: Duration::from_secs(5),
    };
    let mut conn = match PgConnection::connect(&cfg) {
        Ok(c) => c,
        Err(e) => panic!("unix socket connect failed: {e}"),
    };
    assert_eq!(conn.query("SELECT 1").unwrap().scalar(), Some("1"));
    conn.close();
}

#[test]
fn a_wrong_password_is_reported_as_auth_failed() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.password = Some("definitely-not-the-password".into());

    match PgConnection::connect(&cfg) {
        Err(PgError::AuthFailed(e)) => {
            assert_eq!(e.code, "28P01");
            assert!(e.message.to_lowercase().contains("password"), "{e}");
        }
        other => panic!("expected AuthFailed, got {other:?}"),
    }
}

#[test]
fn a_wrong_password_error_never_contains_the_password() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.password = Some("swordfish-9271".into());
    let e = PgConnection::connect(&cfg).unwrap_err();
    let rendered = format!("{e} {e:?} {}", e.user_message());
    assert!(!rendered.contains("swordfish-9271"), "{rendered}");
}

#[test]
fn a_missing_password_is_reported_before_the_exchange_starts() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.password = None; // but pg_hba demands scram for this role over TCP
    assert!(matches!(PgConnection::connect(&cfg), Err(PgError::PasswordRequired)));
}

#[test]
fn an_unknown_database_is_reported_as_no_such_database() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.database = "serveros_no_such_database".into();

    match PgConnection::connect(&cfg) {
        Err(PgError::NoSuchDatabase(e)) => {
            assert_eq!(e.code, "3D000");
            assert!(e.message.contains("serveros_no_such_database"), "{e}");
        }
        other => panic!("expected NoSuchDatabase, got {other:?}"),
    }
}

#[test]
fn an_unknown_role_is_reported_as_auth_failed() {
    let mut cfg = match live_pg() {
        Some(c) => c,
        None => return,
    };
    cfg.user = "serveros_no_such_role".into();
    // 28P01 (16 reports invalid_password for an unknown role too, to avoid
    // confirming which roles exist) or 28000; both map to AuthFailed.
    assert!(matches!(PgConnection::connect(&cfg), Err(PgError::AuthFailed(_))));
}

// ---------------------------------------------------------------------------
// Protocol behaviour, against the real server
// ---------------------------------------------------------------------------

#[test]
fn server_version_comes_from_parameter_status() {
    let conn = connect_or_skip!();
    let version = conn.server_version().expect("server_version parameter");
    assert!(version.starts_with("16"), "unexpected version {version:?}");
    conn.close();
}

#[test]
fn other_parameter_status_values_are_recorded() {
    let conn = connect_or_skip!();
    assert_eq!(conn.parameter("client_encoding"), Some("UTF8"));
    assert_eq!(conn.parameter("server_encoding"), Some("UTF8"));
    assert!(conn.backend_pid() > 0);
    conn.close();
}

#[test]
fn the_application_name_we_send_is_what_the_server_reports() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT current_setting('application_name')").unwrap();
    assert_eq!(r.scalar(), Some("serveros-agent"));
    conn.close();
}

#[test]
fn null_columns_come_back_as_none_not_empty_strings() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT NULL::text, ''::text, 'x'::text").unwrap();
    assert_eq!(r.rows.len(), 1);
    assert_eq!(r.rows[0][0], None);
    assert_eq!(r.rows[0][1], Some(String::new()));
    assert_eq!(r.rows[0][2], Some("x".to_string()));
    conn.close();
}

#[test]
fn column_names_come_from_row_description() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT 1 AS alpha, 2 AS beta").unwrap();
    assert_eq!(r.columns, vec!["alpha".to_string(), "beta".to_string()]);
    assert_eq!(r.column("beta"), Some(1));
    conn.close();
}

#[test]
fn multi_row_results_arrive_in_order() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT n FROM generate_series(1, 500) AS n ORDER BY n").unwrap();
    assert_eq!(r.rows.len(), 500);
    assert_eq!(r.rows[0][0].as_deref(), Some("1"));
    assert_eq!(r.rows[499][0].as_deref(), Some("500"));
    conn.close();
}

#[test]
fn a_large_result_spanning_many_reads_reassembles() {
    let mut conn = connect_or_skip!();
    // ~256 KiB in one column: guaranteed to cross many socket reads.
    let r = conn.query("SELECT repeat('abcd', 65536)").unwrap();
    assert_eq!(r.scalar().map(|s| s.len()), Some(262_144));
    conn.close();
}

#[test]
fn non_ascii_round_trips_as_utf8() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT 'héllo — 日本語 🙂'::text").unwrap();
    assert_eq!(r.scalar(), Some("héllo — 日本語 🙂"));
    conn.close();
}

#[test]
fn an_empty_result_set_is_not_an_error() {
    let mut conn = connect_or_skip!();
    let r = conn.query("SELECT 1 WHERE false").unwrap();
    assert!(r.rows.is_empty());
    assert_eq!(r.columns.len(), 1);
    conn.close();
}

#[test]
fn a_server_error_leaves_the_connection_usable() {
    let mut conn = connect_or_skip!();
    // Syntactically a SELECT, so the guard lets it through; the server refuses.
    match conn.query("SELECT * FROM serveros_no_such_table") {
        Err(PgError::Server(e)) => assert_eq!(e.code, "42P01"),
        other => panic!("expected a server error, got {other:?}"),
    }
    // The ReadyForQuery after the error must have been consumed, or this
    // desynchronises and returns the previous statement's frames.
    assert_eq!(conn.query("SELECT 42").unwrap().scalar(), Some("42"));
    conn.close();
}

#[test]
fn notices_do_not_disturb_the_result_stream() {
    let mut conn = connect_or_skip!();
    // `query_unchecked` because this is DDL; it emits a NOTICE and no rows.
    conn.query_unchecked("DROP TABLE IF EXISTS serveros_pg_notice_probe").unwrap();
    assert_eq!(conn.query("SELECT 7").unwrap().scalar(), Some("7"));
    conn.close();
}

// ---------------------------------------------------------------------------
// The read-only guard, against the real server
// ---------------------------------------------------------------------------

#[test]
fn drop_table_is_refused_before_it_reaches_the_server() {
    let mut conn = connect_or_skip!();
    match conn.query("DROP TABLE serveros_pg_guard_probe") {
        Err(PgError::NotReadOnly { keyword }) => assert_eq!(keyword, "DROP"),
        other => panic!("expected the guard to refuse, got {other:?}"),
    }
    // Refused locally, so the connection never left the idle state.
    assert_eq!(conn.query("SELECT 1").unwrap().scalar(), Some("1"));
    conn.close();
}

#[test]
fn chained_statements_are_refused_even_though_postgresql_would_run_them() {
    let mut conn = connect_or_skip!();
    // Simple Query really does execute both halves, which is exactly why the
    // guard exists.
    assert!(matches!(
        conn.query("SELECT 1; CREATE TABLE serveros_pg_chained (a int)"),
        Err(PgError::NotReadOnly { .. })
    ));
    let r = conn
        .query("SELECT count(*) FROM pg_class WHERE relname = 'serveros_pg_chained'")
        .unwrap();
    assert_eq!(r.scalar(), Some("0"), "the chained CREATE TABLE must not have run");
    conn.close();
}

#[test]
fn a_data_modifying_cte_is_refused() {
    let mut conn = connect_or_skip!();
    assert!(matches!(
        conn.query("WITH x AS (INSERT INTO t VALUES (1) RETURNING *) SELECT * FROM x"),
        Err(PgError::NotReadOnly { .. })
    ));
    conn.close();
}

// ---------------------------------------------------------------------------
// Inventory, against the real server
// ---------------------------------------------------------------------------

#[test]
fn instance_overview_reports_plausible_values() {
    let mut conn = connect_or_skip!();
    let v = inventory::instance_overview(&mut conn).unwrap();

    let version = v.get("version").and_then(|v| v.as_str()).expect("version");
    assert!(version.starts_with("16"), "{version}");
    // Only the number, not the Ubuntu packaging suffix.
    assert!(!version.contains(' '), "{version}");

    let version_num = v.get("version_num").and_then(|v| v.as_i64()).expect("version_num");
    assert!((160_000..170_000).contains(&version_num), "{version_num}");

    let max = v.get("max_connections").and_then(|v| v.as_i64()).expect("max_connections");
    assert!(max > 0, "{max}");

    let current = v.get("current_connections").and_then(|v| v.as_i64()).expect("current");
    assert!(current >= 1, "at least this connection should be counted, got {current}");
    assert!(current <= max);

    let usage = v.get("connection_usage_percent").and_then(|v| v.as_f64()).expect("usage");
    assert!((0.0..=100.0).contains(&usage), "{usage}");

    let dir = v.get("data_directory").and_then(|v| v.as_str()).expect("data_directory");
    assert!(dir.starts_with('/'), "{dir}");

    let dbs = v.get("database_count").and_then(|v| v.as_i64()).expect("database_count");
    assert!(dbs >= 3, "postgres, template0 and template1 at minimum, got {dbs}");

    let size = v.get("total_size_bytes").and_then(|v| v.as_i64()).expect("total_size_bytes");
    assert!(size > 1_000_000, "an initdb'd cluster is megabytes, got {size}");

    let uptime = v.get("uptime_seconds").and_then(|v| v.as_i64()).expect("uptime_seconds");
    assert!(uptime >= 0, "{uptime}");
    let started = v.get("started_at").and_then(|v| v.as_i64()).expect("started_at");
    assert!(started > 1_600_000_000, "{started}");

    let ratio = v.get("cache_hit_ratio").and_then(|v| v.as_f64()).expect("cache_hit_ratio");
    assert!((0.0..=100.0).contains(&ratio), "{ratio}");

    assert!(v.get("transactions_committed").and_then(|v| v.as_i64()).unwrap() > 0);
    assert!(v.get("transactions_rolled_back").and_then(|v| v.as_i64()).is_some());
    assert!(v.get("deadlocks").and_then(|v| v.as_i64()).is_some());

    let health = v.get("health").and_then(|v| v.as_str()).expect("health");
    assert!(matches!(health, "healthy" | "warning" | "critical"), "{health}");
    // An idle single-connection test cluster should be healthy.
    assert_eq!(health, "healthy", "overview was {}", v.to_string_pretty());
    assert!(v.get("health_reason").unwrap().is_null());

    conn.close();
}

#[test]
fn instance_overview_emits_every_documented_key() {
    let mut conn = connect_or_skip!();
    let v = inventory::instance_overview(&mut conn).unwrap();
    for key in [
        "version",
        "version_num",
        "uptime_seconds",
        "started_at",
        "data_directory",
        "max_connections",
        "current_connections",
        "connection_usage_percent",
        "database_count",
        "total_size_bytes",
        "cache_hit_ratio",
        "transactions_committed",
        "transactions_rolled_back",
        "deadlocks",
        "health",
        "health_reason",
    ] {
        assert!(v.get(key).is_some(), "missing key {key} in {}", v.to_string_pretty());
    }
    conn.close();
}

#[test]
fn list_databases_sees_the_standard_databases() {
    let mut conn = connect_or_skip!();
    let v = inventory::list_databases(&mut conn).unwrap();
    let rows = v.as_array().expect("an array");
    assert!(rows.len() >= 3);

    let names: Vec<&str> = rows.iter().filter_map(|r| r.get("name")?.as_str()).collect();
    assert!(names.contains(&"postgres"), "{names:?}");
    assert!(names.contains(&"template1"), "{names:?}");
    assert!(names.contains(&"template0"), "{names:?}");

    let postgres = rows.iter().find(|r| r.get("name").and_then(|v| v.as_str()) == Some("postgres"))
        .expect("the postgres database");
    assert!(postgres.get("size_bytes").and_then(|v| v.as_i64()).unwrap() > 0);
    assert_eq!(postgres.get("encoding").and_then(|v| v.as_str()), Some("UTF8"));
    assert_eq!(postgres.get("is_template").and_then(|v| v.as_bool()), Some(false));
    assert!(postgres.get("owner").and_then(|v| v.as_str()).is_some());
    assert!(postgres.get("collation").and_then(|v| v.as_str()).is_some());
    assert!(postgres.get("table_count").unwrap().is_null(), "documented as always null");

    let template1 = rows.iter().find(|r| r.get("name").and_then(|v| v.as_str()) == Some("template1"))
        .unwrap();
    assert_eq!(template1.get("is_template").and_then(|v| v.as_bool()), Some(true));

    conn.close();
}

#[test]
fn list_tables_sees_a_table_that_was_just_created() {
    let mut conn = connect_or_skip!();
    let table = format!("serveros_pg_fixture_{}", std::process::id());

    // Created through `query_unchecked`, which is crate-private precisely so a
    // caller cannot do this. The test needs the fixture; the product does not.
    conn.query_unchecked(&format!("DROP TABLE IF EXISTS {table}")).unwrap();
    conn.query_unchecked(&format!("CREATE TABLE {table} (id int primary key, note text)"))
        .unwrap();
    conn.query_unchecked(&format!(
        "INSERT INTO {table} SELECT g, 'row ' || g FROM generate_series(1, 250) g"
    ))
    .unwrap();
    // Make the planner statistics real so `n_live_tup` is populated promptly.
    conn.query_unchecked(&format!("ANALYZE {table}")).unwrap();

    let v = inventory::list_tables(&mut conn, "postgres").unwrap();
    let rows = v.as_array().expect("an array").to_vec();

    let found = rows
        .iter()
        .find(|r| r.get("name").and_then(|v| v.as_str()) == Some(table.as_str()))
        .unwrap_or_else(|| panic!("{table} not in {}", v.to_string_pretty()));

    assert_eq!(found.get("schema").and_then(|v| v.as_str()), Some("public"));
    assert!(found.get("total_size_bytes").and_then(|v| v.as_i64()).unwrap() > 0);
    assert!(found.get("table_size_bytes").and_then(|v| v.as_i64()).unwrap() > 0);
    // A primary key means there is an index taking space.
    assert!(found.get("index_size_bytes").and_then(|v| v.as_i64()).unwrap() > 0);
    assert!(found.get("seq_scans").and_then(|v| v.as_i64()).is_some());
    assert!(found.get("index_scans").and_then(|v| v.as_i64()).is_some());
    assert_eq!(found.get("rows_estimate").and_then(|v| v.as_i64()), Some(250));
    // Analyzed just now; never vacuumed.
    assert!(found.get("last_analyze").and_then(|v| v.as_i64()).is_some());
    assert!(found.get("last_vacuum").is_some());

    conn.query_unchecked(&format!("DROP TABLE {table}")).unwrap();
    conn.close();
}

#[test]
fn list_tables_refuses_a_database_this_connection_is_not_attached_to() {
    let mut conn = connect_or_skip!();
    match inventory::list_tables(&mut conn, "template1") {
        Err(PgError::DatabaseMismatch { requested, connected }) => {
            assert_eq!(requested, "template1");
            assert_eq!(connected, "postgres");
        }
        other => panic!("expected DatabaseMismatch, got {other:?}"),
    }
    conn.close();
}

#[test]
fn list_connections_omits_query_text_by_default() {
    let mut conn = connect_or_skip!();
    let v = inventory::list_connections(&mut conn, QueryTextPolicy::default()).unwrap();
    let rows = v.as_array().expect("an array");
    assert!(!rows.is_empty(), "this connection at least should appear");

    let mine = rows
        .iter()
        .find(|r| r.get("pid").and_then(|v| v.as_i64()) == Some(conn.backend_pid() as i64))
        .expect("our own backend");
    assert_eq!(mine.get("user").and_then(|v| v.as_str()), Some("serveros"));
    assert_eq!(mine.get("database").and_then(|v| v.as_str()), Some("postgres"));
    assert_eq!(mine.get("application_name").and_then(|v| v.as_str()), Some("serveros-agent"));
    assert_eq!(mine.get("state").and_then(|v| v.as_str()), Some("active"));
    assert_eq!(mine.get("backend_type").and_then(|v| v.as_str()), Some("client backend"));
    assert!(mine.get("query_start").and_then(|v| v.as_i64()).is_some());
    assert!(mine.get("state_change").and_then(|v| v.as_i64()).is_some());

    // The whole point: no SQL text anywhere in the payload.
    for row in rows {
        assert!(row.get("query_preview").unwrap().is_null(), "{}", v.to_string_pretty());
    }
    assert!(!v.to_string().contains("pg_stat_activity"));

    conn.close();
}

#[test]
fn list_connections_includes_a_truncated_preview_when_asked() {
    let mut conn = connect_or_skip!();
    let v = inventory::list_connections(&mut conn, QueryTextPolicy::IncludeTruncated).unwrap();
    let rows = v.as_array().expect("an array");

    let mine = rows
        .iter()
        .find(|r| r.get("pid").and_then(|v| v.as_i64()) == Some(conn.backend_pid() as i64))
        .expect("our own backend");
    let preview = mine.get("query_preview").and_then(|v| v.as_str()).expect("a preview");
    // The running statement is our own, so we know exactly what it says — and
    // it is far longer than the cap, which is what makes this a truncation
    // test rather than a "does the column arrive" test.
    assert!(preview.starts_with("SELECT pid, usename, datname"), "{preview}");
    assert_eq!(
        preview.chars().count(),
        inventory::QUERY_PREVIEW_CHARS,
        "a statement longer than the cap must come back cut to exactly the cap: {preview}"
    );
    // The tail of the real statement — including the query text column itself —
    // must have been cut off.
    assert!(!preview.contains("pg_stat_activity"), "{preview}");
    conn.close();
}

#[test]
fn list_roles_sees_the_test_roles_and_no_password_verifier() {
    let mut conn = connect_or_skip!();
    let v = inventory::list_roles(&mut conn).unwrap();
    let rows = v.as_array().expect("an array");

    let names: Vec<&str> = rows.iter().filter_map(|r| r.get("name")?.as_str()).collect();
    assert!(names.contains(&"serveros"), "{names:?}");
    assert!(names.contains(&"md5user"), "{names:?}");
    assert!(names.contains(&"trustuser"), "{names:?}");
    // pg_monitor and friends ship with every cluster.
    assert!(names.iter().any(|n| n.starts_with("pg_")), "{names:?}");

    let serveros = rows
        .iter()
        .find(|r| r.get("name").and_then(|v| v.as_str()) == Some("serveros"))
        .unwrap();
    assert_eq!(serveros.get("is_superuser").and_then(|v| v.as_bool()), Some(true));
    assert_eq!(serveros.get("can_login").and_then(|v| v.as_bool()), Some(true));
    assert!(serveros.get("connection_limit").and_then(|v| v.as_i64()).is_some());

    // No verifier, no hash, nothing that looks like one.
    let rendered = v.to_string();
    assert!(!rendered.contains("SCRAM-SHA-256$"), "{rendered}");
    assert!(!rendered.contains("md57"), "{rendered}");
    assert!(!rendered.contains("********"), "{rendered}");

    conn.close();
}

#[test]
fn every_inventory_call_succeeds_against_the_real_cluster() {
    let mut conn = connect_or_skip!();
    assert!(inventory::instance_overview(&mut conn).is_ok());
    assert!(inventory::list_databases(&mut conn).is_ok());
    assert!(inventory::list_tables(&mut conn, "postgres").is_ok());
    assert!(inventory::list_connections(&mut conn, QueryTextPolicy::Omit).is_ok());
    assert!(inventory::list_roles(&mut conn).is_ok());
    conn.close();
}

#[test]
fn discovery_finds_the_running_test_cluster() {
    if live_pg().is_none() {
        return;
    }
    let port = test_port();
    let found = inventory::discover_instances();
    let ours = found
        .iter()
        .find(|i| i.port == port)
        .unwrap_or_else(|| panic!("port {port} not among {found:?}"));
    assert!(ours.reachable, "{ours:?}");
    // The development cluster runs with `-k /tmp`.
    assert_eq!(ours.socket_dir.as_deref(), Some("/tmp"));
}
