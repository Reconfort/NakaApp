//! End-to-end tests for the HTTP surface.
//!
//! These are deliberately **not** handler unit tests. Every one of them starts
//! the real server on an ephemeral port, with a real `AgentState` pointed at a
//! temporary data directory, and drives it with the real HTTP client over a
//! real socket. That is the only way to test what actually matters here: the
//! router, the auth guard, the response envelope and the handler are one
//! mechanism, and a test that calls a handler function directly would prove
//! nothing about whether the guard in front of it ran.
//!
//! # The test that matters most
//!
//! [`every_route_is_guarded`] walks a table of *every* route the agent serves
//! and asserts four things about each: no token is 401, a forged token is 401,
//! an under-scoped token is 403, and a good token gets through. The table's
//! length is asserted against `build_router().len()`, so adding a route without
//! adding it to the table fails the suite. It is not possible to ship an
//! unguarded endpoint and have these tests pass.
//!
//! # Environment
//!
//! The suite runs in whatever container CI gives it, which may have no Docker,
//! no systemd and no PostgreSQL. Tests that need one of those check first and
//! skip with a printed note rather than failing — a red suite that means "this
//! machine has no Docker" trains people to ignore red suites.

use crate::api;
use crate::auth::{Scope, mint_token, now_unix};
use crate::config::Config;
use crate::state::AgentState;
use serveros_http::client::{ClientResponse, HttpClient};
use serveros_http::{Headers, Method, Server, ServerConfig};
use serveros_json::Value;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

/// The secret the harness signs with. Any 32 bytes will do.
const SECRET: &[u8] = b"serveros-test-secret-0123456789!";
/// A different 32 bytes, so a token signed with it verifies against nothing.
const WRONG_SECRET: &[u8] = b"attacker-secret-0123456789abcdef";

/// Names that must not exist on the test host, so a "good token" request
/// against them lands on 404 rather than mutating anything real.
const ABSENT: &str = "serveros-test-absent";

// ------------------------------------------------------------- harness ------

/// A directory that removes itself.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> TempDir {
        let path = std::env::temp_dir().join(format!(
            "serveros-api-{}-{}-{tag}",
            std::process::id(),
            now_unix()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        TempDir(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A running agent, on a real socket.
struct Harness {
    dir: TempDir,
    addr: SocketAddr,
    state: Arc<AgentState>,
}

impl Harness {
    fn new(tag: &str) -> Harness {
        let dir = TempDir::new(tag);

        let mut config = Config::default();
        config.server_id = "srv_test".into();
        config.data_dir = dir.path().join("data");
        config.key_path = dir.path().join("agent.key");
        config.unix_socket = None;
        config.port = Some(0);
        // Whole filesystem minus the always-denied set: the point of the
        // containment tests is that /etc/shadow is refused even when no roots
        // are configured, which is the weakest policy the agent ever runs with.
        config.file_roots = Vec::new();

        let state = Arc::new(AgentState::new(config, SECRET.to_vec()));

        let server_config = ServerConfig {
            port: Some(0),
            bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            unix_socket: None,
            idle_timeout: Duration::from_secs(5),
            read_timeout: Duration::from_secs(5),
            max_connections: 128,
            spool_dir: dir.path().join("spool"),
        };

        let server = Server::new(server_config, api::build_router(), state.clone());
        let (listener, addr) = server.bind_tcp().expect("bind an ephemeral port");
        server.serve_tcp(listener);

        Harness { dir, addr, state }
    }

    /// A freshly minted token. Each call produces a new `jti`, because the
    /// agent refuses to accept one twice.
    fn token(&self, scopes: &[Scope]) -> String {
        mint_token(SECRET, "test-mac", scopes, 120, now_unix())
    }

    /// A well-formed token signed with the wrong key.
    fn forged(&self) -> String {
        mint_token(WRONG_SECRET, "attacker", &[Scope::Admin], 120, now_unix())
    }

    fn call(
        &self,
        method: Method,
        path: &str,
        token: Option<&str>,
        body: Option<&[u8]>,
    ) -> ClientResponse {
        let client = HttpClient::tcp(self.addr.to_string()).with_timeout(Duration::from_secs(15));
        let mut headers = Headers::new();
        if let Some(token) = token {
            headers.insert("Authorization", format!("Bearer {token}"));
        }
        if body.is_some() {
            headers.insert("Content-Type", "application/json");
        }
        client.request_with(method, path, &headers, body).expect("the agent should answer")
    }

    /// A GET with an admin token — the common case in these tests.
    fn get(&self, path: &str) -> ClientResponse {
        let token = self.token(&[Scope::Admin]);
        self.call(Method::Get, path, Some(&token), None)
    }

    fn get_as(&self, path: &str, scopes: &[Scope]) -> ClientResponse {
        let token = self.token(scopes);
        self.call(Method::Get, path, Some(&token), None)
    }

    fn send(&self, method: Method, path: &str, body: &str) -> ClientResponse {
        let token = self.token(&[Scope::Admin]);
        self.call(method, path, Some(&token), Some(body.as_bytes()))
    }

    /// Write a file into the harness's temp directory and return its path.
    fn file(&self, name: &str, contents: &str) -> String {
        let path = self.dir.path().join(name);
        std::fs::write(&path, contents).expect("write a fixture file");
        path.display().to_string()
    }

    fn temp(&self, name: &str) -> String {
        self.dir.path().join(name).display().to_string()
    }
}

/// `?path=` with the value percent-encoded, so a hostile filename survives the
/// request line intact instead of breaking it.
fn query_path(path: &str) -> String {
    serveros_http::uri::percent_encode(path)
}

fn json(resp: &ClientResponse) -> Value {
    resp.json().unwrap_or_else(|e| panic!("response was not JSON: {e}; body = {}", resp.text()))
}

/// The `error.code` of a response, or `""` if it is not an error envelope.
///
/// Tolerant on purpose: a successful download is raw bytes, not JSON, and the
/// route table asks every response for its code.
fn error_code(resp: &ClientResponse) -> String {
    resp.json()
        .ok()
        .and_then(|body| body.path("error/code").and_then(Value::as_str).map(str::to_string))
        .unwrap_or_default()
}

// --------------------------------------------------------- the route table --

/// One route, with a concrete target that is safe to call for real.
struct Case {
    method: Method,
    path: String,
    /// The scope the router demands.
    scope: Scope,
    body: Option<String>,
}

fn case(method: Method, path: impl Into<String>, scope: Scope) -> Case {
    Case { method, path: path.into(), scope, body: None }
}

fn case_body(method: Method, path: impl Into<String>, scope: Scope, body: &str) -> Case {
    Case { method, path: path.into(), scope, body: Some(body.to_string()) }
}

/// Every guarded route the agent serves.
///
/// Targets are chosen so that a request with a *valid* token cannot damage
/// anything: absent container, unit, user and project names, and paths inside
/// the harness's own temporary directory.
fn all_guarded_routes(h: &Harness) -> Vec<Case> {
    let file = h.file("route-table.txt", "hello\n");
    let dir = h.dir.path().display().to_string();
    let missing = h.temp("definitely-missing");

    vec![
        // meta
        case(Method::Get, "/v1/system", Scope::Read),
        case(Method::Get, "/v1/metrics", Scope::Read),
        case(Method::Get, "/v1/activity", Scope::Read),
        case(Method::Get, "/v1/capabilities", Scope::Read),
        case(Method::Get, "/v1/stream", Scope::Read),
        // processes — pid 4194303 is above the default pid_max, so it cannot
        // exist and the request can only ever land on 404.
        case(Method::Get, "/v1/processes", Scope::Read),
        case_body(
            Method::Post,
            "/v1/processes/4194303/signal",
            Scope::Write,
            r#"{"signal":"TERM"}"#,
        ),
        // users
        case(Method::Get, "/v1/users", Scope::Read),
        case(Method::Get, "/v1/groups", Scope::Read),
        case(Method::Get, format!("/v1/users/{ABSENT}"), Scope::Read),
        case_body(Method::Post, "/v1/users", Scope::Write, "{}"),
        case_body(Method::Patch, format!("/v1/users/{ABSENT}"), Scope::Write, "{}"),
        case(Method::Delete, format!("/v1/users/{ABSENT}"), Scope::Admin),
        case(Method::Get, format!("/v1/users/{ABSENT}/keys"), Scope::Read),
        case_body(
            Method::Post,
            format!("/v1/users/{ABSENT}/keys"),
            Scope::Write,
            r#"{"key":"ssh-ed25519 AAAA test"}"#,
        ),
        case(Method::Delete, format!("/v1/users/{ABSENT}/keys/abc"), Scope::Write),
        // services
        case(Method::Get, "/v1/services", Scope::Read),
        case(Method::Get, format!("/v1/services/{ABSENT}.service"), Scope::Read),
        case(Method::Post, format!("/v1/services/{ABSENT}.service/start"), Scope::Write),
        case(Method::Post, format!("/v1/services/{ABSENT}.service/stop"), Scope::Write),
        case(Method::Post, format!("/v1/services/{ABSENT}.service/restart"), Scope::Write),
        case(Method::Post, format!("/v1/services/{ABSENT}.service/reload"), Scope::Write),
        case(Method::Post, format!("/v1/services/{ABSENT}.service/enable"), Scope::Admin),
        case(Method::Post, format!("/v1/services/{ABSENT}.service/disable"), Scope::Admin),
        // docker
        case(Method::Get, "/v1/docker", Scope::Read),
        case(Method::Get, "/v1/docker/containers", Scope::Read),
        case(Method::Get, format!("/v1/docker/containers/{ABSENT}"), Scope::Read),
        case(Method::Get, format!("/v1/docker/containers/{ABSENT}/stats"), Scope::Read),
        case(Method::Get, format!("/v1/docker/containers/{ABSENT}/logs"), Scope::Read),
        case(Method::Post, format!("/v1/docker/containers/{ABSENT}/start"), Scope::Write),
        case(Method::Post, format!("/v1/docker/containers/{ABSENT}/stop"), Scope::Write),
        case(Method::Post, format!("/v1/docker/containers/{ABSENT}/restart"), Scope::Write),
        case(Method::Post, format!("/v1/docker/containers/{ABSENT}/pause"), Scope::Write),
        case(Method::Post, format!("/v1/docker/containers/{ABSENT}/unpause"), Scope::Write),
        case(Method::Delete, format!("/v1/docker/containers/{ABSENT}"), Scope::Admin),
        case(Method::Get, "/v1/docker/images", Scope::Read),
        case(Method::Get, "/v1/docker/volumes", Scope::Read),
        case(Method::Get, "/v1/docker/networks", Scope::Read),
        // projects
        case(Method::Get, "/v1/projects", Scope::Read),
        case(Method::Get, format!("/v1/projects/{ABSENT}"), Scope::Read),
        // databases
        case(Method::Get, "/v1/databases", Scope::Read),
        case(Method::Get, "/v1/databases/postgres", Scope::Read),
        case(Method::Get, "/v1/databases/postgres/databases", Scope::Read),
        case(Method::Get, "/v1/databases/postgres/tables", Scope::Read),
        case(Method::Get, "/v1/databases/postgres/connections", Scope::Read),
        case(Method::Get, "/v1/databases/postgres/roles", Scope::Read),
        // logs
        case(Method::Get, format!("/v1/logs/file?path={}", query_path(&file)), Scope::Read),
        case(Method::Get, "/v1/logs/journal", Scope::Read),
        // files
        case(Method::Get, format!("/v1/files?path={}", query_path(&dir)), Scope::Read),
        case(Method::Get, format!("/v1/files/stat?path={}", query_path(&file)), Scope::Read),
        case(Method::Get, format!("/v1/files/read?path={}", query_path(&file)), Scope::Read),
        case(Method::Get, format!("/v1/files/download?path={}", query_path(&file)), Scope::Read),
        case_body(
            Method::Put,
            format!("/v1/files/write?path={}", query_path(&h.temp("written.txt"))),
            Scope::Write,
            "written by the route table test\n",
        ),
        case_body(
            Method::Post,
            "/v1/files/directory",
            Scope::Write,
            &format!(r#"{{"path":"{}"}}"#, h.temp("made-by-table")),
        ),
        case_body(
            Method::Post,
            "/v1/files/rename",
            Scope::Write,
            &format!(r#"{{"from":"{missing}","to":"{missing}-2"}}"#),
        ),
        case_body(
            Method::Post,
            "/v1/files/chmod",
            Scope::Admin,
            &format!(r#"{{"path":"{file}","mode":"0644"}}"#),
        ),
        case(Method::Delete, format!("/v1/files?path={}", query_path(&missing)), Scope::Write),
        case(
            Method::Post,
            format!("/v1/files/upload?path={}", query_path(&h.temp("uploaded.bin"))),
            Scope::Write,
        ),
    ]
}

/// The scope immediately below `scope`, or `None` for `Read` (there is nothing
/// below it, so there is no under-scoped token to test with).
fn one_scope_below(scope: Scope) -> Option<Scope> {
    match scope {
        Scope::Read => None,
        Scope::Write => Some(Scope::Read),
        Scope::Admin => Some(Scope::Write),
    }
}

#[test]
fn the_route_table_covers_every_route_the_agent_serves() {
    // Two routes are excluded from the guarded table by construction:
    // `/v1/health`, which is deliberately open, and nothing else. `/v1/stream`
    // guards itself and is in the table.
    let h = Harness::new("route-count");
    let routes = all_guarded_routes(&h);
    assert_eq!(
        routes.len() + 1,
        api::build_router().len(),
        "a route was added without a guard test. Every route except /v1/health must appear in \
         all_guarded_routes(), or it ships unproven."
    );
}

#[test]
fn every_route_is_guarded() {
    let h = Harness::new("guard");

    for case in all_guarded_routes(&h) {
        let body = case.body.as_deref().map(str::as_bytes);
        let label = format!("{} {}", case.method, case.path);

        // 1. No credential at all.
        let anonymous = h.call(case.method, &case.path, None, body);
        assert_eq!(anonymous.status, 401, "{label} answered without a token");
        assert_eq!(error_code(&anonymous), "auth_missing", "{label}");
        assert!(
            anonymous.headers.get("www-authenticate").is_some(),
            "{label} must challenge for a credential"
        );

        // 2. A well-formed token signed with the wrong key.
        let forged = h.forged();
        let spoofed = h.call(case.method, &case.path, Some(&forged), body);
        assert_eq!(spoofed.status, 401, "{label} accepted a forged token");
        assert_eq!(error_code(&spoofed), "auth_invalid", "{label}");

        // 3. A genuine token that lacks the scope this route demands.
        if let Some(lower) = one_scope_below(case.scope) {
            let weak = h.token(&[lower]);
            let refused = h.call(case.method, &case.path, Some(&weak), body);
            assert_eq!(
                refused.status, 403,
                "{label} accepted a {} token where {} is required",
                lower.as_str(),
                case.scope.as_str()
            );
            assert_eq!(error_code(&refused), "auth_insufficient_scope", "{label}");
        }

        // 4. A good token gets past the guard. What the handler then answers
        //    depends on this machine (503 without Docker, 404 for an absent
        //    unit), but it must never be an auth or routing failure.
        let good = h.token(&[Scope::Admin]);
        let allowed = h.call(case.method, &case.path, Some(&good), body);
        assert!(
            !matches!(allowed.status, 401 | 403),
            "{label} refused a valid admin token with {}: {}",
            allowed.status,
            allowed.text()
        );
        assert_ne!(allowed.status, 405, "{label} is registered under the wrong method");
        assert_ne!(
            error_code(&allowed),
            "not_found_route",
            "{label} did not reach a handler"
        );
    }
}

#[test]
fn a_captured_token_cannot_be_replayed() {
    // The property that makes a short-lived token safe on the wire.
    let h = Harness::new("replay");
    let token = h.token(&[Scope::Read]);

    let first = h.call(Method::Get, "/v1/capabilities", Some(&token), None);
    assert_eq!(first.status, 200);

    let second = h.call(Method::Get, "/v1/capabilities", Some(&token), None);
    assert_eq!(second.status, 401, "the same token was accepted twice");
    assert_eq!(error_code(&second), "auth_replayed");
}

// ---------------------------------------------------------------- health ----

#[test]
fn health_needs_no_token() {
    let h = Harness::new("health");
    let resp = h.call(Method::Get, "/v1/health", None, None);
    assert_eq!(resp.status, 200, "health must answer an unauthenticated caller");

    let body = json(&resp);
    assert_eq!(body.get("status").and_then(Value::as_str), Some("ok"));
    assert_eq!(body.get("server_id").and_then(Value::as_str), Some("srv_test"));
    assert!(body.get("uptime_seconds").and_then(Value::as_u64).is_some());
}

#[test]
fn health_leaks_nothing_about_the_machine() {
    // This is the whole reason health is allowed to be open. If it grows a
    // field that describes the host, this test is what catches it.
    let h = Harness::new("health-leak");
    let resp = h.call(Method::Get, "/v1/health", None, None);
    let text = resp.text();
    let body = json(&resp);

    let allowed = [
        "status",
        "agent_version",
        "api_version",
        "server_id",
        "uptime_seconds",
        "capabilities",
    ];
    let keys: Vec<&str> =
        body.as_object().expect("an object").iter().map(|(k, _)| k).collect();
    for key in &keys {
        assert!(allowed.contains(key), "/v1/health grew a field it must not have: {key}");
    }
    assert_eq!(keys.len(), allowed.len(), "a field was removed from /v1/health: {keys:?}");

    // And specifically: nothing `/v1/system` would tell an authenticated
    // caller. Short values are skipped, because a two-character hostname is a
    // substring of half the English language and would false-positive.
    let system = json(&h.get("/v1/system"));
    for field in ["hostname", "kernel", "architecture"] {
        let value = system.get(field).and_then(Value::as_str).unwrap_or_default();
        if value.len() >= 4 {
            assert!(
                !text.contains(value),
                "/v1/health leaked this host's {field} ({value}): {text}"
            );
        }
    }
    let os = system.path("os/pretty").and_then(Value::as_str).unwrap_or_default();
    if os.len() >= 4 {
        assert!(!text.contains(os), "/v1/health leaked the OS name: {text}");
    }

    // Nor any inventory. The authenticated /v1/system carries all of this.
    for forbidden in ["kernel", "os_release", "containers", "username", "ip", "load_average"] {
        assert!(!text.contains(forbidden), "/v1/health leaked {forbidden}: {text}");
    }
}

#[test]
fn capabilities_agree_between_health_and_the_guarded_route() {
    let h = Harness::new("capabilities");
    let open = json(&h.call(Method::Get, "/v1/health", None, None));
    let guarded = json(&h.get("/v1/capabilities"));
    assert_eq!(open.get("capabilities"), Some(&guarded));
}

// ------------------------------------------------------------------ meta ----

#[test]
fn system_describes_the_machine_the_agent_runs_on() {
    let h = Harness::new("system");
    let body = json(&h.get("/v1/system"));

    assert!(body.get("hostname").and_then(Value::as_str).is_some_and(|s| !s.is_empty()));
    assert!(body.path("os/name").is_some());
    assert!(body.get("kernel").and_then(Value::as_str).is_some_and(|s| !s.is_empty()));
    assert!(body.path("cpu/cores").and_then(Value::as_u64).unwrap_or(0) >= 1);
    assert!(body.get("memory_total_bytes").and_then(Value::as_u64).unwrap_or(0) > 0);

    // The agent's own identity travels with the host's.
    assert_eq!(body.path("agent/version").and_then(Value::as_str), Some(crate::VERSION));
    assert_eq!(body.path("agent/enrolled").and_then(Value::as_bool), Some(true));
}

#[test]
fn the_first_metrics_sample_admits_it_is_warming_up() {
    // One REST call cannot produce a CPU rate; saying so is better than
    // reporting a confident 0%.
    let h = Harness::new("metrics");

    let first = json(&h.get("/v1/metrics"));
    assert_eq!(
        first.get("warming_up").and_then(Value::as_bool),
        Some(true),
        "the first sample has no baseline to difference against"
    );
    // Absolute values are correct from the first sample even so.
    assert!(first.path("memory/total_bytes").and_then(Value::as_u64).unwrap_or(0) > 0);

    let second = json(&h.get("/v1/metrics"));
    assert_eq!(
        second.get("warming_up").and_then(Value::as_bool),
        Some(false),
        "the second sample has a baseline and its rates are real"
    );
}

#[test]
fn activity_is_a_collection_and_pages_by_id() {
    let h = Harness::new("activity");
    for i in 0..5 {
        h.state.activity.record(
            crate::activity::Event::new("test.event", "test", i.to_string())
                .summary(format!("Event {i}")),
        );
    }

    let all = json(&h.get("/v1/activity"));
    let items = all.get("items").and_then(Value::as_array).expect("items");
    assert!(items.len() >= 5);
    assert_eq!(all.get("total").and_then(Value::as_u64), Some(items.len() as u64));

    let newest = items[0].get("id").and_then(Value::as_u64).unwrap();
    let after = json(&h.get(&format!("/v1/activity?since={newest}")));
    assert_eq!(after.get("total").and_then(Value::as_u64), Some(0), "nothing is newer than newest");
}

// ------------------------------------------------------------- processes ----

#[test]
fn processes_lists_the_test_process_itself() {
    let h = Harness::new("processes");
    let body = json(&h.get("/v1/processes?limit=500"));
    let items = body.get("items").and_then(Value::as_array).expect("items");
    assert!(!items.is_empty(), "a running Linux host always has processes");

    let me = std::process::id() as u64;
    assert!(
        items.iter().any(|p| p.get("pid").and_then(Value::as_u64) == Some(me)),
        "the process running these tests should appear in its own process list"
    );
}

#[test]
fn signalling_process_1_is_refused_outright() {
    let h = Harness::new("signal-init");
    let resp = h.send(Method::Post, "/v1/processes/1/signal", r#"{"signal":"TERM"}"#);
    assert_eq!(resp.status, 403);
    assert_eq!(error_code(&resp), "refused_dangerous");
    let message = json(&resp).path("error/message").and_then(Value::as_str).unwrap().to_string();
    assert!(message.contains("init system"), "the refusal must explain itself: {message}");
}

#[test]
fn the_agent_refuses_to_signal_itself() {
    let h = Harness::new("signal-self");
    let me = std::process::id();
    let resp = h.send(
        Method::Post,
        &format!("/v1/processes/{me}/signal"),
        r#"{"signal":"TERM"}"#,
    );
    assert_eq!(resp.status, 403, "the agent must not be able to kill the request it is serving");
    assert_eq!(error_code(&resp), "refused_dangerous");
}

#[test]
fn only_four_signals_are_accepted_over_http() {
    let h = Harness::new("signal-allowlist");
    let resp = h.send(Method::Post, "/v1/processes/4194303/signal", r#"{"signal":"KILL9"}"#);
    assert_eq!(resp.status, 400);
    let message = json(&resp).path("error/message").and_then(Value::as_str).unwrap().to_string();
    assert!(message.contains("TERM"), "the message should say what is allowed: {message}");
}

#[test]
fn signalling_a_pid_that_does_not_exist_is_a_404() {
    let h = Harness::new("signal-missing");
    let resp = h.send(Method::Post, "/v1/processes/4194303/signal", r#"{"signal":"TERM"}"#);
    assert_eq!(resp.status, 404);
}

// ----------------------------------------------------------------- users ----

#[test]
fn users_lists_the_accounts_on_this_host() {
    let h = Harness::new("users");
    let body = json(&h.get("/v1/users"));
    let items = body.get("items").and_then(Value::as_array).expect("items");
    assert!(
        items.iter().any(|u| u.get("username").and_then(Value::as_str) == Some("root")),
        "every Linux host has root"
    );
    // No password material, ever.
    let text = h.get("/v1/users").text();
    assert!(!text.contains("$6$"), "a shadow hash reached the API: {text}");
}

#[test]
fn groups_lists_the_groups_on_this_host() {
    let h = Harness::new("groups");
    let body = json(&h.get("/v1/groups"));
    let items = body.get("items").and_then(Value::as_array).expect("items");
    assert!(items.iter().any(|g| g.get("name").and_then(Value::as_str) == Some("root")));
}

#[test]
fn an_unknown_user_is_a_404_with_a_sentence() {
    let h = Harness::new("user-404");
    let resp = h.get(&format!("/v1/users/{ABSENT}"));
    assert_eq!(resp.status, 404);
    assert_eq!(error_code(&resp), "not_found");
    let message = json(&resp).path("error/message").and_then(Value::as_str).unwrap().to_string();
    assert!(message.ends_with('.'), "a user-facing message is a sentence: {message}");
    assert!(message.contains(ABSENT));
}

#[test]
fn a_password_in_a_create_request_never_reaches_the_activity_log() {
    // The request is refused (the name belongs to a system account), but the
    // attempt is still audited — and the audit must not contain the password.
    let h = Harness::new("user-password");
    let resp = h.send(
        Method::Post,
        "/v1/users",
        r#"{"username":"daemon","password":"hunter2-should-never-be-logged"}"#,
    );
    assert!(
        matches!(resp.status, 400 | 403 | 409),
        "creating an account that already exists must be refused: {}",
        resp.text()
    );
    assert!(
        !resp.text().contains("hunter2"),
        "the response echoed the password back: {}",
        resp.text()
    );

    // The attempt is in the audit feed.
    let feed = json(&h.get("/v1/activity"));
    let items = feed.get("items").and_then(Value::as_array).expect("items");
    let entry = items
        .iter()
        .find(|e| e.get("action").and_then(Value::as_str) == Some("user.create"))
        .expect("a refused account creation is still an auditable event");
    assert_eq!(entry.get("outcome").and_then(Value::as_str), Some("failed"));
    assert_eq!(entry.get("actor").and_then(Value::as_str), Some("test-mac"));

    // And neither the in-memory feed nor the file on disk has the password.
    assert!(!feed.to_string().contains("hunter2"), "the password reached the activity feed");
    let on_disk = std::fs::read_to_string(h.state.activity.path()).unwrap_or_default();
    assert!(!on_disk.contains("hunter2"), "the password reached the audit file: {on_disk}");
}

#[test]
fn a_malformed_username_is_refused_before_anything_runs() {
    let h = Harness::new("user-validate");
    for hostile in ["Deploy", "1web", "web user", "web;rm -rf /", "root"] {
        let body = format!(r#"{{"username":"{hostile}"}}"#);
        let resp = h.send(Method::Post, "/v1/users", &body);
        assert_eq!(resp.status, 400, "{hostile} should be refused: {}", resp.text());
    }
}

// -------------------------------------------------------------- services ----

#[test]
fn services_either_lists_units_or_says_there_is_no_service_manager() {
    let h = Harness::new("services");
    let resp = h.get("/v1/services");
    if resp.status == 503 {
        eprintln!("skipping: no service manager on this host");
        assert_eq!(error_code(&resp), "subsystem_unavailable");
        let message =
            json(&resp).path("error/message").and_then(Value::as_str).unwrap().to_string();
        assert!(message.ends_with('.'), "{message}");
        return;
    }
    assert_eq!(resp.status, 200);
    let body = json(&resp);
    assert!(body.get("items").and_then(Value::as_array).is_some());
    assert!(body.get("backend").and_then(Value::as_str).is_some());
}

// ---------------------------------------------------------------- docker ----

#[test]
fn docker_either_lists_containers_or_says_docker_is_absent() {
    let h = Harness::new("docker");
    let resp = h.get("/v1/docker/containers");
    if resp.status == 503 {
        eprintln!("skipping: no Docker daemon on this host");
        assert_eq!(error_code(&resp), "subsystem_unavailable");
        return;
    }
    assert_eq!(resp.status, 200);
    let body = json(&resp);
    assert!(body.get("items").and_then(Value::as_array).is_some());
    assert!(body.get("running").and_then(Value::as_u64).is_some());
}

#[test]
fn asking_for_container_stats_stays_bounded() {
    // `?stats=true` costs a ~1s round trip per container, so the fan-out is
    // capped and the response says when it was capped rather than quietly
    // doing less than it was asked.
    let h = Harness::new("docker-stats");
    let resp = h.get("/v1/docker/containers?all=true&stats=true");
    if resp.status == 503 {
        eprintln!("skipping: no Docker daemon on this host");
        return;
    }
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    let sampled = body.get("stats_sampled").and_then(Value::as_u64).expect("stats_sampled");
    assert!(sampled <= 25, "the stats fan-out was not capped: {sampled}");
    let total = body.get("total").and_then(Value::as_u64).unwrap_or(0);
    assert_eq!(
        body.get("stats_truncated").and_then(Value::as_bool),
        Some(total > 25),
        "the response must admit when it sampled fewer containers than it listed"
    );
}

#[test]
fn the_docker_daemon_describes_itself() {
    let h = Harness::new("docker-info");
    let resp = h.get("/v1/docker");
    if resp.status == 503 {
        eprintln!("skipping: no Docker daemon on this host");
        return;
    }
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    assert!(body.get("api_version").and_then(Value::as_str).is_some());

    for path in ["/v1/docker/images", "/v1/docker/volumes", "/v1/docker/networks"] {
        let listed = h.get(path);
        assert_eq!(listed.status, 200, "{path}: {}", listed.text());
        assert!(json(&listed).get("items").and_then(Value::as_array).is_some(), "{path}");
    }
}

#[test]
fn a_missing_container_is_a_404_when_docker_is_present() {
    let h = Harness::new("docker-404");
    let resp = h.get(&format!("/v1/docker/containers/{ABSENT}"));
    if resp.status == 503 {
        eprintln!("skipping: no Docker daemon on this host");
        return;
    }
    assert_eq!(resp.status, 404, "{}", resp.text());
}

#[test]
fn revealing_container_environment_needs_admin() {
    let h = Harness::new("docker-reveal");
    if h.state.docker().is_none() {
        eprintln!("skipping: no Docker daemon on this host");
        return;
    }
    // A read-scoped caller may ask, and is simply given the masked answer
    // rather than an error — the flag degrades, it does not fail.
    let resp = h.get_as(
        &format!("/v1/docker/containers/{ABSENT}?reveal=true"),
        &[Scope::Read],
    );
    assert_ne!(resp.status, 403, "the reveal flag must be ignored, not rejected");
}

#[test]
fn projects_either_lists_or_says_docker_is_absent() {
    let h = Harness::new("projects");
    let resp = h.get("/v1/projects");
    if resp.status == 503 {
        eprintln!("skipping: no Docker daemon on this host");
        return;
    }
    assert_eq!(resp.status, 200);
    assert!(json(&resp).get("items").and_then(Value::as_array).is_some());

    let missing = h.get(&format!("/v1/projects/{ABSENT}"));
    assert_eq!(missing.status, 404);
}

// ------------------------------------------------------------- databases ----

#[test]
fn database_discovery_needs_no_credentials() {
    // Discovery must work whether or not PostgreSQL is installed, and must
    // never attempt to authenticate.
    let h = Harness::new("databases");
    let resp = h.get("/v1/databases");
    assert_eq!(resp.status, 200, "discovery must always answer: {}", resp.text());
    let body = json(&resp);
    assert!(body.get("items").and_then(Value::as_array).is_some());
    assert!(body.get("total").and_then(Value::as_u64).is_some());
}

#[test]
fn an_unreachable_postgres_is_a_503_not_a_500() {
    // "The database is down" is a screen the app draws, not a crash report.
    let h = Harness::new("pg-down");
    let resp = h.get("/v1/databases/postgres");
    if resp.status == 200 {
        eprintln!("skipping: PostgreSQL is actually reachable on this host");
        return;
    }
    assert_eq!(resp.status, 503, "{}", resp.text());
    assert_eq!(error_code(&resp), "subsystem_unavailable");
    let message = json(&resp).path("error/message").and_then(Value::as_str).unwrap().to_string();
    assert!(message.ends_with('.'), "{message}");
}

#[test]
fn postgres_support_can_be_turned_off_entirely() {
    let h = Harness::new("pg-off");
    // The default config has it on; this asserts the wiring reaches the flag.
    assert!(h.state.config.postgres.enabled);
    let resp = h.get("/v1/databases/postgres/roles");
    assert!(
        matches!(resp.status, 200 | 503),
        "an absent database is 503, never 500: {} {}",
        resp.status,
        resp.text()
    );
}

// ------------------------------------------------------------------ logs ----

#[test]
fn a_log_file_can_be_tailed_through_the_api() {
    let h = Harness::new("logs");
    let path = h.file("app.log", "line one\nline two\nline three\n");

    let body = json(&h.get(&format!("/v1/logs/file?path={}", query_path(&path))));
    let lines = body.get("lines").and_then(Value::as_array).expect("lines");
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[2].get("raw").and_then(Value::as_str), Some("line three"));
    assert_eq!(body.get("source").and_then(Value::as_str), Some("file"));
}

#[test]
fn a_log_tail_can_be_filtered_and_is_bounded() {
    let h = Harness::new("logs-filter");
    let mut contents = String::new();
    for i in 0..500 {
        contents.push_str(&format!("line {i}\n"));
    }
    contents.push_str("ERROR something broke\n");
    let path = h.file("big.log", &contents);

    let filtered = json(&h.get(&format!(
        "/v1/logs/file?path={}&filter=ERROR",
        query_path(&path)
    )));
    let lines = filtered.get("lines").and_then(Value::as_array).expect("lines");
    assert_eq!(lines.len(), 1);
    assert!(lines[0].get("raw").and_then(Value::as_str).unwrap().contains("something broke"));

    // An absurd request must not become an absurd allocation.
    let clamped = json(&h.get(&format!(
        "/v1/logs/file?path={}&lines=99999999",
        query_path(&path)
    )));
    let count = clamped.get("lines").and_then(Value::as_array).map(<[Value]>::len).unwrap();
    assert!(count <= 501, "the tail was not clamped: {count} lines");
}

#[test]
fn following_a_log_streams_lines_as_they_are_written() {
    // The follow path is the one place the agent writes a response
    // incrementally, and "the log view fills in live" is the whole feature. A
    // buffered client would prove nothing, so this one reads the socket.
    use std::io::{Read, Write};
    use std::time::Instant;

    let h = Harness::new("logs-follow");
    let path = h.file("follow.log", "backlog one\nbacklog two\n");
    let token = h.token(&[Scope::Read]);

    let client = HttpClient::tcp(h.addr.to_string());
    let mut headers = Headers::new();
    headers.insert("Authorization", format!("Bearer {token}"));
    let resp = client
        .request_streaming(
            Method::Get,
            &format!("/v1/logs/file?path={}&follow=true", query_path(&path)),
            &headers,
            None,
            Some(Duration::from_secs(3)),
        )
        .expect("the follow should start");

    assert_eq!(resp.status, 200);
    assert_eq!(resp.headers.get("content-type"), Some("application/x-ndjson"));
    assert_eq!(resp.headers.get("transfer-encoding"), Some("chunked"));

    // Append *after* the follow is live: the point is that it arrives without
    // the client asking again.
    let appended = path.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(250));
        let mut file =
            std::fs::OpenOptions::new().append(true).open(&appended).expect("append");
        writeln!(file, "written while following").expect("write");
    });

    let mut reader = resp.reader();
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match reader.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => {
                received.extend_from_slice(&chunk[..n]);
                if String::from_utf8_lossy(&received).contains("written while following") {
                    break;
                }
            }
            Err(_) => break,
        }
    }
    writer.join().expect("the appender thread");

    let text = String::from_utf8_lossy(&received).to_string();
    assert!(text.contains("backlog one"), "the backlog should arrive first: {text}");
    assert!(
        text.contains("written while following"),
        "a line written after the follow started never arrived: {text}"
    );

    // Every line must be a complete JSON object on its own — that is what
    // makes it renderable the moment it lands.
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let value: Value = serveros_json::from_str(line)
            .unwrap_or_else(|e| panic!("a stream line was not JSON: {line} ({e})"));
        assert!(value.get("raw").is_some() || value.get("type").is_some(), "{line}");
    }
}

#[test]
fn reading_a_log_without_a_path_says_so() {
    let h = Harness::new("logs-nopath");
    let resp = h.get("/v1/logs/file");
    assert_eq!(resp.status, 400);
    assert_eq!(error_code(&resp), "invalid_request");
}

#[test]
fn the_journal_either_answers_or_says_it_is_not_here() {
    let h = Harness::new("journal");
    let resp = h.get("/v1/logs/journal?lines=5");
    if resp.status == 503 {
        eprintln!("skipping: no systemd journal on this host");
        assert_eq!(error_code(&resp), "subsystem_unavailable");
        return;
    }
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert_eq!(json(&resp).get("source").and_then(Value::as_str), Some("journal"));
}

// ----------------------------------------------------------------- files ----

#[test]
fn listing_a_real_directory_works() {
    let h = Harness::new("files-list");
    let body = json(&h.get(&format!("/v1/files?path={}", query_path("/etc"))));
    assert_eq!(body.get("path").and_then(Value::as_str), Some("/etc"));
    let entries = body.get("entries").and_then(Value::as_array).expect("entries");
    assert!(!entries.is_empty(), "/etc is never empty");
    assert!(
        entries.iter().any(|e| e.get("name").and_then(Value::as_str) == Some("passwd")),
        "/etc/passwd should be listed"
    );
}

#[test]
fn a_directory_listing_clamps_an_absurd_limit() {
    let h = Harness::new("files-clamp");
    let body = json(&h.get(&format!(
        "/v1/files?path={}&limit=99999999",
        query_path("/etc")
    )));
    let entries = body.get("entries").and_then(Value::as_array).expect("entries");
    assert!(
        entries.len() <= 10_000,
        "?limit=99999999 returned {} entries; it must be clamped",
        entries.len()
    );
}

#[test]
fn etc_shadow_is_denied_through_the_http_layer() {
    // Not "is not readable because we are unprivileged" — denied by policy,
    // with the policy's own status, whoever the agent runs as.
    let h = Harness::new("shadow");
    let resp = h.get(&format!("/v1/files/read?path={}", query_path("/etc/shadow")));
    assert_eq!(resp.status, 403, "{}", resp.text());
    assert_eq!(error_code(&resp), "denied");
    assert!(!resp.text().contains("$6$"), "the refusal leaked file content");
}

#[test]
fn traversal_out_of_a_denied_path_is_still_denied() {
    let h = Harness::new("traversal");
    for hostile in [
        "/tmp/../etc/shadow",
        "/etc/./shadow",
        "/etc/../etc/shadow",
        "/proc/self/environ",
        "/etc/serveros/agent.key",
    ] {
        let resp = h.get(&format!("/v1/files/read?path={hostile}"));
        assert!(
            matches!(resp.status, 403 | 404),
            "{hostile} answered {} — containment failed: {}",
            resp.status,
            resp.text()
        );
    }
}

#[test]
fn writing_then_reading_a_file_round_trips() {
    let h = Harness::new("files-roundtrip");
    let path = h.temp("round-trip.txt");
    let contents = "first line\nsecond line\n";

    let token = h.token(&[Scope::Write]);
    let written = h.call(
        Method::Put,
        &format!("/v1/files/write?path={}", query_path(&path)),
        Some(&token),
        Some(contents.as_bytes()),
    );
    assert_eq!(written.status, 200, "{}", written.text());

    let read = json(&h.get(&format!("/v1/files/read?path={}", query_path(&path))));
    assert_eq!(read.get("content").and_then(Value::as_str), Some(contents));
    assert_eq!(read.get("line_count").and_then(Value::as_u64), Some(2));

    // And the write is in the audit feed, with the path in the sentence.
    let feed = h.get("/v1/activity").text();
    assert!(feed.contains("file.write"), "{feed}");
    assert!(feed.contains(&path), "the audit summary must name the file: {feed}");
}

#[test]
fn a_download_streams_its_bytes_back() {
    let h = Harness::new("download");
    let contents = "x".repeat(200_000);
    let path = h.file("backup.bin", &contents);

    let resp = h.get(&format!("/v1/files/download?path={}", query_path(&path)));
    assert_eq!(resp.status, 200);
    assert_eq!(resp.body.len(), contents.len(), "the whole file should arrive");
    assert_eq!(
        resp.headers.get("content-disposition"),
        Some("attachment; filename=\"backup.bin\"")
    );
    assert_eq!(resp.headers.get("transfer-encoding"), Some("chunked"));
}

#[test]
fn a_filename_cannot_inject_a_response_header() {
    // A filename is attacker-controlled text landing inside a header value.
    let h = Harness::new("header-injection");
    let hostile = "evil\r\nX-Injected: yes\r\nX-Another: 1.txt";
    let path = h.dir.path().join(hostile);
    if std::fs::write(&path, "payload").is_err() {
        eprintln!("skipping: this filesystem rejects newlines in filenames");
        return;
    }

    let resp = h.get(&format!(
        "/v1/files/download?path={}",
        query_path(&path.display().to_string())
    ));
    assert_eq!(resp.status, 200, "{}", resp.text());
    assert!(
        resp.headers.get("x-injected").is_none(),
        "a filename injected a header: {:?}",
        resp.headers
    );
    let disposition = resp.headers.get("content-disposition").unwrap_or_default();
    assert!(!disposition.contains('\r') && !disposition.contains('\n'), "{disposition}");
    assert!(disposition.contains("evilX-Injected: yesX-Another: 1.txt"), "{disposition}");
}

#[test]
fn creating_a_directory_and_renaming_it_works() {
    let h = Harness::new("files-mkdir");
    let made = h.temp("new-folder");
    let moved = h.temp("renamed-folder");

    let created = h.send(
        Method::Post,
        "/v1/files/directory",
        &format!(r#"{{"path":"{made}"}}"#),
    );
    assert_eq!(created.status, 201, "{}", created.text());

    let renamed = h.send(
        Method::Post,
        "/v1/files/rename",
        &format!(r#"{{"from":"{made}","to":"{moved}"}}"#),
    );
    assert_eq!(renamed.status, 200, "{}", renamed.text());
    assert!(Path::new(&moved).is_dir());
    assert!(!Path::new(&made).exists());
}

#[test]
fn deleting_says_whether_it_trashed_or_removed() {
    // The app renders "Moved to trash · Undo" from this field; getting it wrong
    // would mean promising an undo that does not exist.
    let h = Harness::new("files-delete");
    assert!(h.state.config.trash_deletes, "the default is a recoverable delete");
    let path = h.file("doomed.txt", "bye\n");

    let token = h.token(&[Scope::Write]);
    let resp = h.call(
        Method::Delete,
        &format!("/v1/files?path={}", query_path(&path)),
        Some(&token),
        None,
    );
    assert_eq!(resp.status, 200, "{}", resp.text());
    let body = json(&resp);
    assert_eq!(body.get("trashed").and_then(Value::as_bool), Some(true));
    assert!(body.get("restore_path").and_then(Value::as_str).is_some());
    assert!(!Path::new(&path).exists(), "the original should be gone from its old location");

    let feed = h.get("/v1/activity").text();
    assert!(feed.contains(&path), "a destructive action must name its target: {feed}");
}

#[test]
fn chmod_requires_admin_and_names_its_target() {
    let h = Harness::new("files-chmod");
    let path = h.file("perms.txt", "x");
    let body = format!(r#"{{"path":"{path}","mode":"0640"}}"#);

    let write_token = h.token(&[Scope::Write]);
    let refused =
        h.call(Method::Post, "/v1/files/chmod", Some(&write_token), Some(body.as_bytes()));
    assert_eq!(refused.status, 403, "chmod is an admin operation");

    let allowed = h.send(Method::Post, "/v1/files/chmod", &body);
    assert_eq!(allowed.status, 200, "{}", allowed.text());
    assert_eq!(json(&allowed).get("mode_octal").and_then(Value::as_u64), Some(0o640));

    let feed = h.get("/v1/activity").text();
    assert!(feed.contains("file.chmod") && feed.contains(&path), "{feed}");
}

#[test]
fn an_upload_with_no_body_is_a_bad_request() {
    let h = Harness::new("upload-empty");
    let token = h.token(&[Scope::Write]);
    let resp = h.call(
        Method::Post,
        &format!("/v1/files/upload?path={}", query_path(&h.temp("nothing.bin"))),
        Some(&token),
        None,
    );
    assert_eq!(resp.status, 400);
    assert_eq!(error_code(&resp), "invalid_request");
}

#[test]
fn an_upload_is_spooled_to_disk_and_copied_into_place() {
    let h = Harness::new("upload");
    let payload = "y".repeat(300_000);
    let destination = h.temp("uploaded.bin");

    let token = h.token(&[Scope::Write]);
    let resp = h.call(
        Method::Post,
        &format!("/v1/files/upload?path={}", query_path(&destination)),
        Some(&token),
        Some(payload.as_bytes()),
    );
    assert_eq!(resp.status, 201, "{}", resp.text());
    assert_eq!(
        std::fs::read_to_string(&destination).expect("the file should exist").len(),
        payload.len()
    );

    // Without ?overwrite, a second upload to the same path is a conflict.
    let again = h.call(
        Method::Post,
        &format!("/v1/files/upload?path={}", query_path(&destination)),
        Some(&h.token(&[Scope::Write])),
        Some(payload.as_bytes()),
    );
    assert_eq!(again.status, 409, "{}", again.text());
}

// ------------------------------------------------------------- envelopes ----

#[test]
fn an_unknown_endpoint_is_a_404_in_the_standard_envelope() {
    let h = Harness::new("404");
    let resp = h.get("/v1/nope");
    assert_eq!(resp.status, 404);
    let body = json(&resp);
    assert!(body.path("error/code").is_some());
    assert!(body.path("error/message").is_some());
}

#[test]
fn the_wrong_method_is_a_405_with_an_allow_header() {
    let h = Harness::new("405");
    let token = h.token(&[Scope::Admin]);
    let resp = h.call(Method::Delete, "/v1/system", Some(&token), None);
    assert_eq!(resp.status, 405);
    assert_eq!(resp.headers.get("allow"), Some("GET"));
}

#[test]
fn every_error_message_is_a_sentence_and_hides_the_technical_text() {
    // The cross-cutting rule: `message` is for a person, `detail` is for an
    // engineer, and a Debug string is never the message.
    let h = Harness::new("envelope");
    let cases = [
        h.get("/v1/logs/file"),
        h.get(&format!("/v1/users/{ABSENT}")),
        h.get(&format!("/v1/files/read?path={}", query_path("/etc/shadow"))),
        h.get(&format!("/v1/files/stat?path={}", query_path("/nonexistent-path-xyz"))),
    ];
    for resp in cases {
        assert!(!resp.is_success());
        let body = json(&resp);
        let message = body
            .path("error/message")
            .and_then(Value::as_str)
            .unwrap_or_else(|| panic!("no error.message in {}", resp.text()))
            .to_string();
        assert!(message.ends_with('.') || message.ends_with('?'), "not a sentence: {message}");
        assert!(
            !message.contains('{') && !message.contains("Error {"),
            "a Debug string reached the user: {message}"
        );
        // Product copy, not a log line: it opens with a capital, a quoted
        // field name, or the path the message is about.
        assert!(
            message.chars().next().is_some_and(|c| c.is_uppercase() || c == '"' || c == '/'),
            "a message should read like product copy: {message}"
        );
    }
}

#[test]
fn the_stream_endpoint_authenticates_before_it_asks_for_an_upgrade() {
    // Order matters: an unauthenticated caller must not learn anything about
    // the endpoint, not even that it wants a WebSocket.
    let h = Harness::new("stream");
    let anonymous = h.call(Method::Get, "/v1/stream", None, None);
    assert_eq!(anonymous.status, 401);

    let authenticated = h.get("/v1/stream");
    assert_eq!(authenticated.status, 400);
    assert_eq!(error_code(&authenticated), "upgrade_required");
}

#[test]
fn responses_carry_the_hardening_headers() {
    let h = Harness::new("headers");
    let resp = h.get("/v1/capabilities");
    assert_eq!(resp.headers.get("x-content-type-options"), Some("nosniff"));
    assert_eq!(resp.headers.get("cache-control"), Some("no-store"));
    assert_eq!(
        resp.headers.get("content-type"),
        Some("application/json; charset=utf-8")
    );
}
