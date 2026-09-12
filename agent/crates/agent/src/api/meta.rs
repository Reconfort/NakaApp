//! Identity, liveness, live numbers and the audit feed.
//!
//! # Why `health` is the only open route
//!
//! An installer that has just started the agent, and a Mac that has just failed
//! to authenticate, both need to answer the same question: *is the agent even
//! there?* If that question required a credential, "agent is down" and "my
//! credential is wrong" would be indistinguishable, and the app would have to
//! guess which error to show. So `health` answers without a token — and in
//! exchange it is held to a hard rule: **it reveals liveness, version and
//! capability flags, and nothing else**. No hostname, no addresses, no
//! container or user names, no path, no inventory. Anything that describes the
//! machine rather than the agent belongs behind [`system`].
//!
//! Everything else here requires `read` and describes the host: what machine
//! this is ([`system`]), what it is doing right now ([`metrics`]), and what has
//! been done to it ([`activity`]).

use crate::api::{collection, internal};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_http::{Request, Response};
use serveros_json::{Object, Value};
use std::sync::Arc;

/// Default number of activity events returned when `?limit` is absent.
const ACTIVITY_DEFAULT_LIMIT: usize = 50;
/// Ceiling on `?limit`. The in-memory ring holds 200; asking for more would
/// read the same 200 and allocate a bigger vector to hold them.
const ACTIVITY_MAX_LIMIT: usize = 200;

/// `GET /v1/health` — unauthenticated liveness.
///
/// Registered raw rather than through `guarded`, so its signature is the
/// router's own. Keep the response to these six fields: this is the one
/// endpoint anything that can reach the socket can read.
pub fn health(state: &Arc<AgentState>, _req: Request) -> Response {
    Response::json(
        Object::new()
            .set("status", "ok")
            .set("agent_version", crate::VERSION)
            .set("api_version", crate::API_VERSION)
            .set("server_id", state.config.server_id.as_str())
            .set("uptime_seconds", state.uptime_seconds())
            .set("capabilities", state.capabilities()),
    )
}

/// `GET /v1/system` — what machine this is.
///
/// The static half of the server view: OS, kernel, CPU, memory ceiling, boot
/// time. It changes on reboot, not on refresh, so the app caches it and does
/// not put it on the metrics cadence.
pub fn system(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let info = match serveros_linux::read_system_info() {
        Ok(info) => info,
        Err(e) => {
            return internal("ServerOS couldn't read this server's system information.", e);
        }
    };

    let Value::Object(mut obj) = info.to_json() else {
        // `SystemInfo::to_json` always builds an object; this arm exists so the
        // shape is enforced rather than assumed.
        return internal(
            "ServerOS couldn't read this server's system information.",
            "system info did not serialise as an object",
        );
    };

    // The agent's own identity travels with the host's: the app shows "agent
    // 0.1.0, up 3 days" next to "Ubuntu 24.04, up 41 days", and a mismatch
    // between the two is itself diagnostic.
    obj.insert(
        "agent",
        Object::new()
            .set("version", crate::VERSION)
            .set("uptime_seconds", state.uptime_seconds())
            .set("started_at", state.started_at_unix())
            .set("enrolled", true),
    );

    Response::json(obj)
}

/// `GET /v1/metrics` — one live sample.
///
/// # Why a single REST call cannot give you a correct CPU percentage
///
/// CPU utilisation is not a value the kernel keeps; it is a *rate*, derived by
/// differencing two `/proc/stat` readings taken some interval apart. One
/// request can only take one reading. The agent therefore keeps a single
/// server-side sampler (see `AgentState::sampler`) whose baseline is whatever
/// the previous sample left behind, and the first sample after start has no
/// baseline at all — every percentage and every rate in it is `0.0`, while the
/// absolute values (memory, capacity, counters) are correct immediately.
///
/// That is reported honestly as `"warming_up": true` so the app can show
/// "measuring…" instead of a confident, wrong 0%. The live WebSocket channel is
/// the intended source for metrics: it samples on a fixed cadence, so every
/// frame after the first is a true interval measurement. This endpoint exists
/// for one-off reads and for clients that cannot hold a socket open.
pub fn metrics(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let Ok(mut sampler) = state.sampler.lock() else {
        return internal(
            "ServerOS couldn't read this server's live metrics.",
            "the metrics sampler lock is poisoned",
        );
    };

    // Read before sampling: `sample()` installs the baseline it just used.
    let warming_up = !sampler.has_baseline();

    match sampler.sample() {
        Ok(sample) => {
            let Value::Object(obj) = sample.to_json() else {
                return internal(
                    "ServerOS couldn't read this server's live metrics.",
                    "metrics did not serialise as an object",
                );
            };
            Response::json(obj.set("warming_up", warming_up))
        }
        Err(e) => internal("ServerOS couldn't read this server's live metrics.", e),
    }
}

/// `GET /v1/activity` — the agent's own audit feed, newest first.
///
/// `?since=<id>` makes this incrementally pollable: the app keeps the highest
/// id it has seen and asks only for what came after it, so a quiet server
/// returns an empty list rather than the same fifty rows every few seconds.
pub fn activity(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let limit = req
        .query_num::<usize>("limit")
        .unwrap_or(ACTIVITY_DEFAULT_LIMIT)
        .clamp(1, ACTIVITY_MAX_LIMIT);
    let since = req.query_num::<u64>("since");

    collection(state.activity.recent(limit, since))
}

/// `GET /v1/capabilities` — what this agent can actually do on this host.
///
/// The app reads this to decide which sidebar sections exist at all. An absent
/// capability is not an error and must not be rendered as one: "Docker isn't
/// installed on this server" is a complete, calm answer.
pub fn capabilities(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    Response::json(state.capabilities())
}
