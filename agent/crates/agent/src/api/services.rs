//! systemd units, as a product surface.
//!
//! This module is deliberately thin. All of the difficulty — speaking D-Bus,
//! validating unit names, telling "no such unit" apart from "polkit said no",
//! and falling back to `systemctl` on a host with no reachable bus — lives in
//! `serveros-systemd`, which already renders both halves of every failure: a
//! sentence for the user ([`SystemdError::user_message`]) and the detail for an
//! engineer ([`SystemdError::technical_detail`]). Re-deriving either of those
//! here would mean two places disagree about what a failure means.
//!
//! So the HTTP layer's whole job is three things:
//!
//!   1. Turn "no service manager on this host" into a 503 that reads as an
//!      empty state rather than as a breakage — a container with no systemd is
//!      a normal server, not a broken one.
//!   2. Map the crate's error onto a status with [`SystemdError::http_status`].
//!   3. Write one audit record per state change, phrased the way the activity
//!      feed will show it: *Restarted nginx*, not `service.restart ok`.

use crate::activity::Event;
use crate::api::{collection_with, internal, record, unavailable};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use serveros_systemd::{ServiceManager, SystemdError, display_name};
use std::sync::Arc;

/// Why a host might have no service manager, phrased for the 503's `detail`.
const NO_MANAGER_REASON: &str =
    "systemd is not this host's init system, or its bus is unreachable and systemctl is absent";

/// `GET /v1/services` — the services worth showing a person.
///
/// `?type=.timer` (or `.socket`, `.mount`, …) switches to the unfiltered list
/// of one unit type. Without it the crate's own curation applies: template
/// units, generated mounts and the several hundred units nobody manages are
/// left out, because a services screen that opens on 400 rows is a services
/// screen nobody reads.
pub fn list(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let manager = match manager(state) {
        Ok(manager) => manager,
        Err(response) => return response,
    };

    let requested_type = req.query_str("type");
    let result = match &requested_type {
        Some(suffix) => {
            let suffix = if suffix.starts_with('.') {
                suffix.clone()
            } else {
                format!(".{suffix}")
            };
            manager.list_units_of_type(&suffix)
        }
        None => manager.list_units(),
    };

    match result {
        Ok(units) => {
            let running = units.iter().filter(|u| u.state() == "running").count();
            let items: Vec<Value> = units.iter().map(|u| u.to_json()).collect();
            collection_with(
                items,
                Object::new()
                    .set("running", running)
                    .set("backend", manager.backend_name()),
            )
        }
        Err(e) => systemd_response(e),
    }
}

/// `GET /v1/services/{unit}` — one unit in full.
pub fn get(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let manager = match manager(state) {
        Ok(manager) => manager,
        Err(response) => return response,
    };
    let unit = unit_name(req);

    match manager.unit(&unit) {
        Ok(detail) => Response::json(detail.to_json()),
        Err(e) => systemd_response(e),
    }
}

/// `POST /v1/services/{unit}/start`
pub fn start(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    act(state, req, principal, Action::Start)
}

/// `POST /v1/services/{unit}/stop`
pub fn stop(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    act(state, req, principal, Action::Stop)
}

/// `POST /v1/services/{unit}/restart`
pub fn restart(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    act(state, req, principal, Action::Restart)
}

/// `POST /v1/services/{unit}/reload` — re-read configuration without dropping
/// connections, for the units that support it.
pub fn reload(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    act(state, req, principal, Action::Reload)
}

/// `POST /v1/services/{unit}/enable` — start at boot. Admin scope: this
/// outlives the session that asked for it.
pub fn enable(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    act(state, req, principal, Action::Enable)
}

/// `POST /v1/services/{unit}/disable` — do not start at boot.
pub fn disable(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    act(state, req, principal, Action::Disable)
}

/// The six state changes, so one function can do the work and one audit record
/// can be guaranteed per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Action {
    Start,
    Stop,
    Restart,
    Reload,
    Enable,
    Disable,
}

impl Action {
    /// Dotted name for the audit record.
    fn event(self) -> &'static str {
        match self {
            Action::Start => "service.start",
            Action::Stop => "service.stop",
            Action::Restart => "service.restart",
            Action::Reload => "service.reload",
            Action::Enable => "service.enable",
            Action::Disable => "service.disable",
        }
    }

    /// Past tense, for the sentence the activity feed shows.
    fn past(self) -> &'static str {
        match self {
            Action::Start => "Started",
            Action::Stop => "Stopped",
            Action::Restart => "Restarted",
            Action::Reload => "Reloaded",
            Action::Enable => "Enabled at boot",
            Action::Disable => "Disabled at boot",
        }
    }

    fn failed(self) -> &'static str {
        match self {
            Action::Start => "Could not start",
            Action::Stop => "Could not stop",
            Action::Restart => "Could not restart",
            Action::Reload => "Could not reload",
            Action::Enable => "Could not enable",
            Action::Disable => "Could not disable",
        }
    }

    fn run(self, manager: &Arc<dyn ServiceManager>, unit: &str) -> Result<(), SystemdError> {
        match self {
            Action::Start => manager.start(unit),
            Action::Stop => manager.stop(unit),
            Action::Restart => manager.restart(unit),
            Action::Reload => manager.reload(unit),
            Action::Enable => manager.enable(unit),
            Action::Disable => manager.disable(unit),
        }
    }
}

fn act(state: &AgentState, req: &Request, principal: &Principal, action: Action) -> Response {
    let unit = unit_name(req);
    let pretty = display_name(&unit).to_string();

    let (response, ok, summary) = match manager(state) {
        Err(response) => (
            response,
            false,
            format!("{} {pretty}: this server has no service manager", action.failed()),
        ),
        Ok(manager) => match action.run(&manager, &unit) {
            Ok(()) => {
                // Re-read the unit so the response carries the state the app
                // should now render, rather than making it poll to find out.
                let body = match manager.unit(&unit) {
                    Ok(detail) => detail.to_json(),
                    Err(_) => Object::new().set("name", unit.as_str()).into(),
                };
                (Response::json(body), true, format!("{} {pretty}", action.past()))
            }
            Err(e) => {
                let summary = format!("{} {pretty}", action.failed());
                (systemd_response(e), false, summary)
            }
        },
    };

    record(
        state,
        req,
        principal,
        Event::new(action.event(), "service", &unit).summary(summary).outcome(ok),
    );
    response
}

/// The unit named in the path, with `.service` supplied when it was omitted.
///
/// `POST /v1/services/nginx/restart` is what a person types and what a command
/// palette will send; requiring the suffix would be pedantry. Anything that
/// already carries a unit suffix is passed through untouched, and the crate
/// validates the name before it reaches any backend.
fn unit_name(req: &Request) -> String {
    let raw = req.param("unit").unwrap_or_default();
    match serveros_systemd::unit_suffix(raw) {
        Some(_) => raw.to_string(),
        None => format!("{raw}.service"),
    }
}

fn manager(state: &AgentState) -> Result<Arc<dyn ServiceManager>, Response> {
    state
        .services()
        .ok_or_else(|| unavailable("Service management", NO_MANAGER_REASON))
}

/// Map a `SystemdError` onto the agent's error envelope.
///
/// Status, human message and technical detail all come from the crate. Only the
/// stable machine `code` is decided here, because it is an HTTP-layer contract
/// with the macOS app rather than a property of systemd.
fn systemd_response(e: SystemdError) -> Response {
    let status = Status(e.http_status());
    let code = match &e {
        SystemdError::InvalidUnitName { .. } => "invalid_request",
        SystemdError::NoSuchUnit(_) => "not_found",
        SystemdError::PermissionDenied(_) => "permission_denied",
        SystemdError::Unavailable(_) => "subsystem_unavailable",
        _ => "service_error",
    };
    if status == Status::INTERNAL {
        // Keep the one shared shape for 500s so the app's "technical details"
        // disclosure works the same everywhere.
        return internal(e.user_message(), e.technical_detail());
    }
    Response::error_detail(status, code, e.user_message(), e.technical_detail())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_names_and_copy_are_complete() {
        for action in [
            Action::Start,
            Action::Stop,
            Action::Restart,
            Action::Reload,
            Action::Enable,
            Action::Disable,
        ] {
            assert!(action.event().starts_with("service."));
            assert!(!action.past().is_empty());
            assert!(action.failed().starts_with("Could not"));
        }
        assert_eq!(Action::Restart.past(), "Restarted");
    }

    #[test]
    fn systemd_errors_map_to_the_right_status_and_code() {
        let not_found = systemd_response(SystemdError::NoSuchUnit("nginx.service".into()));
        assert_eq!(not_found.status, Status::NOT_FOUND);

        let denied = systemd_response(SystemdError::PermissionDenied("nginx.service".into()));
        assert_eq!(denied.status, Status::FORBIDDEN);

        let absent = systemd_response(SystemdError::Unavailable("no systemd".into()));
        assert_eq!(absent.status, Status::SERVICE_UNAVAILABLE);

        let bad_name = systemd_response(SystemdError::InvalidUnitName {
            name: "../etc/passwd".into(),
            reason: "not a unit name",
        });
        assert_eq!(bad_name.status, Status::BAD_REQUEST);
    }

    #[test]
    fn a_user_message_never_leaks_the_raw_error() {
        // The rule the whole error envelope exists for.
        let e = SystemdError::NoSuchUnit("nginx.service".into());
        let message = e.user_message();
        assert!(message.ends_with('.'), "{message}");
        assert!(!message.contains("NoSuchUnit"), "{message}");
    }
}
