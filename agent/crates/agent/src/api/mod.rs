//! The HTTP surface.
//!
//! # The rule this module exists to enforce
//!
//! Every route except `/v1/health` goes through [`guarded`], which verifies the
//! caller's token and its scope *before* the handler runs. Handlers never see an
//! unauthenticated request and cannot forget to check — the only way to register
//! a route is through a helper that has already checked.
//!
//! # Shape of the API
//!
//! Resources are nouns, actions are POSTs to a sub-path:
//!
//! ```text
//!   GET  /v1/docker/containers
//!   GET  /v1/docker/containers/{id}
//!   POST /v1/docker/containers/{id}/restart
//! ```
//!
//! There is no generic execution endpoint. Adding a capability means adding a
//! route, which means deciding its scope and its audit record at the same time —
//! that coupling is the point.

use crate::auth::{AuthError, Principal, Scope};
use crate::state::AgentState;
use serveros_http::{Method, Request, Response, Router, Status};
use serveros_json::{Object, Value};
use std::sync::Arc;

#[cfg(test)]
mod tests;

pub mod databases;
pub mod docker;
pub mod files;
pub mod logs;
pub mod meta;
pub mod processes;
pub mod projects;
pub mod services;
pub mod users;

/// Assemble the full route table.
///
/// Order matters: the router takes the first pattern that matches, so literal
/// paths are registered before catch-alls.
pub fn build_router() -> Router<AgentState> {
    let r = Router::new();

    // --- unauthenticated -----------------------------------------------------
    // Health is deliberately open: it is how the installer knows the agent came
    // up, and how a Mac distinguishes "agent down" from "credential wrong". It
    // reveals only liveness, version and capability flags — never inventory.
    let r = r.get("/v1/health", meta::health);

    // --- meta ---------------------------------------------------------------
    let r = r
        .get("/v1/system", guarded(Scope::Read, meta::system))
        .get("/v1/metrics", guarded(Scope::Read, meta::metrics))
        .get("/v1/activity", guarded(Scope::Read, meta::activity))
        .get("/v1/capabilities", guarded(Scope::Read, meta::capabilities))
        .get("/v1/stream", crate::stream::handle_stream);

    // --- processes ----------------------------------------------------------
    let r = r
        .get("/v1/processes", guarded(Scope::Read, processes::list))
        .post("/v1/processes/{pid}/signal", guarded(Scope::Write, processes::signal));

    // --- users --------------------------------------------------------------
    let r = r
        .get("/v1/users", guarded(Scope::Read, users::list))
        .get("/v1/groups", guarded(Scope::Read, users::groups))
        .get("/v1/users/{name}", guarded(Scope::Read, users::get))
        .post("/v1/users", guarded(Scope::Write, users::create))
        .patch("/v1/users/{name}", guarded(Scope::Write, users::update))
        .delete("/v1/users/{name}", guarded(Scope::Admin, users::delete))
        .get("/v1/users/{name}/keys", guarded(Scope::Read, users::list_keys))
        .post("/v1/users/{name}/keys", guarded(Scope::Write, users::add_key))
        .delete("/v1/users/{name}/keys/{fingerprint}", guarded(Scope::Write, users::remove_key));

    // --- services -----------------------------------------------------------
    let r = r
        .get("/v1/services", guarded(Scope::Read, services::list))
        .get("/v1/services/{unit}", guarded(Scope::Read, services::get))
        .post("/v1/services/{unit}/start", guarded(Scope::Write, services::start))
        .post("/v1/services/{unit}/stop", guarded(Scope::Write, services::stop))
        .post("/v1/services/{unit}/restart", guarded(Scope::Write, services::restart))
        .post("/v1/services/{unit}/reload", guarded(Scope::Write, services::reload))
        .post("/v1/services/{unit}/enable", guarded(Scope::Admin, services::enable))
        .post("/v1/services/{unit}/disable", guarded(Scope::Admin, services::disable));

    // --- docker -------------------------------------------------------------
    let r = r
        .get("/v1/docker", guarded(Scope::Read, docker::info))
        .get("/v1/docker/containers", guarded(Scope::Read, docker::list_containers))
        .get("/v1/docker/containers/{id}", guarded(Scope::Read, docker::inspect_container))
        .get("/v1/docker/containers/{id}/stats", guarded(Scope::Read, docker::container_stats))
        .get("/v1/docker/containers/{id}/logs", guarded(Scope::Read, docker::container_logs))
        .post("/v1/docker/containers/{id}/start", guarded(Scope::Write, docker::start))
        .post("/v1/docker/containers/{id}/stop", guarded(Scope::Write, docker::stop))
        .post("/v1/docker/containers/{id}/restart", guarded(Scope::Write, docker::restart))
        .post("/v1/docker/containers/{id}/pause", guarded(Scope::Write, docker::pause))
        .post("/v1/docker/containers/{id}/unpause", guarded(Scope::Write, docker::unpause))
        .delete("/v1/docker/containers/{id}", guarded(Scope::Admin, docker::remove))
        .get("/v1/docker/images", guarded(Scope::Read, docker::images))
        .get("/v1/docker/volumes", guarded(Scope::Read, docker::volumes))
        .get("/v1/docker/networks", guarded(Scope::Read, docker::networks));

    // --- projects -----------------------------------------------------------
    let r = r
        .get("/v1/projects", guarded(Scope::Read, projects::list))
        .get("/v1/projects/{name}", guarded(Scope::Read, projects::get));

    // --- databases ----------------------------------------------------------
    let r = r
        .get("/v1/databases", guarded(Scope::Read, databases::list_instances))
        .get("/v1/databases/postgres", guarded(Scope::Read, databases::postgres_overview))
        .get("/v1/databases/postgres/databases", guarded(Scope::Read, databases::postgres_databases))
        .get("/v1/databases/postgres/tables", guarded(Scope::Read, databases::postgres_tables))
        .get("/v1/databases/postgres/connections", guarded(Scope::Read, databases::postgres_connections))
        .get("/v1/databases/postgres/roles", guarded(Scope::Read, databases::postgres_roles));

    // --- logs ---------------------------------------------------------------
    let r = r
        .get("/v1/logs/file", guarded(Scope::Read, logs::file))
        .get("/v1/logs/journal", guarded(Scope::Read, logs::journal));

    // --- files --------------------------------------------------------------
    // The upload route is registered as a streaming-body route: the server
    // spools the request to disk instead of buffering it, so a 2 GB upload
    // costs 64 KiB of memory rather than 2 GB.
    r.get("/v1/files", guarded(Scope::Read, files::list))
        .get("/v1/files/stat", guarded(Scope::Read, files::stat))
        .get("/v1/files/read", guarded(Scope::Read, files::read))
        .get("/v1/files/download", guarded(Scope::Read, files::download))
        .put("/v1/files/write", guarded(Scope::Write, files::write))
        .post("/v1/files/directory", guarded(Scope::Write, files::create_directory))
        .post("/v1/files/rename", guarded(Scope::Write, files::rename))
        .post("/v1/files/chmod", guarded(Scope::Admin, files::chmod))
        .delete("/v1/files", guarded(Scope::Write, files::delete))
        .route_streaming_body(Method::Post, "/v1/files/upload", guarded(Scope::Write, files::upload))
}

/// Wrap a handler so it only runs for an authenticated caller with `scope`.
pub fn guarded<F>(scope: Scope, handler: F) -> impl Fn(&Arc<AgentState>, Request) -> Response
where
    F: Fn(&AgentState, &Request, &Principal) -> Response + Send + Sync + 'static,
{
    move |state: &Arc<AgentState>, req: Request| {
        let peer = req.peer.describe();
        match state.auth.authorise(req.bearer_token(), &peer, scope) {
            Ok(principal) => handler(state, &req, &principal),
            Err(e) => auth_error_response(e),
        }
    }
}

/// Render an authorisation failure.
///
/// Public because `/v1/stream` authorises itself — it has to, since it upgrades
/// the connection rather than returning a body — and an endpoint that refuses a
/// caller differently from every other endpoint is an endpoint whose refusal
/// the app has to special-case. Same status, same code, same `WWW-Authenticate`
/// challenge, everywhere.
pub fn auth_error_response(e: AuthError) -> Response {
    let mut resp = Response::error(Status(e.status()), e.code(), e.message());
    if let AuthError::RateLimited { retry_after_secs } = e {
        resp = resp.header("Retry-After", retry_after_secs.to_string());
    }
    if e.status() == 401 {
        resp = resp.header("WWW-Authenticate", "Bearer realm=\"serveros-agent\"");
    }
    resp
}

// ---------------------------------------------------------------- helpers ---

/// Wrap a list in the envelope every collection endpoint uses.
///
/// A bare JSON array cannot grow a `total` or a `next_cursor` later without
/// breaking every client, so collections are always objects.
pub fn collection(items: Vec<Value>) -> Response {
    let total = items.len();
    Response::json(Object::new().set("total", total).set("items", Value::Array(items)))
}

pub fn collection_with(items: Vec<Value>, extra: Object) -> Response {
    let mut obj = Object::new().set("total", items.len()).set("items", Value::Array(items));
    for (k, v) in extra.iter() {
        obj.insert(k, v.clone());
    }
    Response::json(obj)
}

/// 404 for a named resource.
pub fn not_found(kind: &str, id: &str) -> Response {
    Response::error(
        Status::NOT_FOUND,
        "not_found",
        format!("No {kind} named \"{id}\" on this server."),
    )
}

/// 400 for bad input, with the offending field named.
pub fn bad_request(message: impl Into<String>) -> Response {
    Response::error(Status::BAD_REQUEST, "invalid_request", message)
}

/// 503 for a subsystem this host does not have.
///
/// Distinct from an error: nothing is broken, the capability is simply absent,
/// and the app should say so rather than showing a failure.
pub fn unavailable(subsystem: &str, reason: &str) -> Response {
    Response::error_detail(
        Status::SERVICE_UNAVAILABLE,
        "subsystem_unavailable",
        format!("{subsystem} is not available on this server."),
        reason,
    )
}

/// 500 with the technical detail tucked behind `detail`.
pub fn internal(message: impl Into<String>, detail: impl std::fmt::Display) -> Response {
    Response::error_detail(Status::INTERNAL, "internal_error", message, detail.to_string())
}

/// Read a required string field from a JSON body.
pub fn required_str(body: &Value, field: &str) -> Result<String, Response> {
    body.get(field)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| bad_request(format!("\"{field}\" is required.")))
}

/// Parse the request body as a JSON object, with a clear error if it is not.
pub fn json_body(req: &Request) -> Result<Value, Response> {
    req.json().map_err(|e| {
        Response::error_detail(
            Status::BAD_REQUEST,
            "invalid_json",
            "The request body could not be read as JSON.",
            e,
        )
    })
}

/// First of `candidates` that exists on this host.
///
/// A handful of operations have no syscall-free, structured alternative and
/// must invoke a system binary (`kill`, `useradd`, `chpasswd`). Each of those
/// resolves its program through an **absolute allow-list** rather than through
/// `$PATH`: a privileged agent that inherits a path is a privileged agent that
/// runs whatever the environment points at. A missing binary is a capability
/// this host lacks — answer [`unavailable`], not a 500.
pub fn find_binary(candidates: &[&'static str]) -> Option<&'static str> {
    candidates.iter().copied().find(|p| std::path::Path::new(p).is_file())
}

/// Record an activity event derived from a mutating request.
pub fn record(
    state: &AgentState,
    req: &Request,
    principal: &Principal,
    event: crate::activity::Event,
) {
    state.activity.record(event.actor(&principal.subject).peer(req.peer.describe()));
}
