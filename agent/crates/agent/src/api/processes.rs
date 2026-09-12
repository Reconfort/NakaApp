//! What is running on this server, and the one thing you can do about it.
//!
//! Listing is pure `/proc` reading — see `serveros-linux`, which never shells
//! out. Signalling is the exception, and it is worth stating plainly why.
//!
//! # Why `/bin/kill` and not a syscall
//!
//! There is no way to send a signal from safe Rust. `std` exposes no `kill`,
//! and the syscall needs `libc`, which needs `unsafe`, which this workspace
//! forbids outright (`#![forbid(unsafe_code)]` in every crate). The remaining
//! options are: drop the capability, relax the `unsafe` ban for one call, or
//! invoke the one system binary whose entire job is this.
//!
//! We invoke the binary, under conditions that keep it closer to a syscall than
//! to a shell command:
//!
//!   * **argv, never a shell.** `Command::new("/bin/kill")` with separate
//!     arguments. There is no string a shell parses, so there is nothing to
//!     quote, escape, or get wrong.
//!   * **An absolute, allow-listed path.** `$PATH` never decides what runs.
//!   * **No caller-controlled strings.** The signal is checked against a
//!     four-item list and the pid is re-rendered from a parsed `u32`, so both
//!     arguments are values this module produced, not text a client sent.
//!   * **Validated before it runs.** The pid must exist in `/proc`, and pid 1
//!     and the agent's own pid are refused outright — see [`signal`].
//!
//! That is a named, bounded operation with a typed argument, which is the
//! property the architecture actually cares about. It is emphatically not a
//! general "run this command" endpoint, and there is no path from here to one.

use crate::activity::Event;
use crate::api::{bad_request, collection_with, find_binary, internal, record, unavailable};
use crate::auth::Principal;
use crate::state::AgentState;
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use serveros_linux::{ProcessQuery, SortKey};
use std::process::Command;

/// Rows returned when `?limit` is absent — enough to fill a window.
const DEFAULT_LIMIT: usize = 50;
/// Ceiling on `?limit`. A busy host has thousands of processes and nobody
/// scrolls past a few hundred; serialising the rest is pure waste.
const MAX_LIMIT: usize = 500;

/// Signals a caller may send.
///
/// Deliberately tiny. These four cover "ask it to stop", "reload your config",
/// "interrupt" and "stop now"; everything else is either a niche debugging
/// signal or a way to put a process into a state a GUI cannot explain.
const ALLOWED_SIGNALS: &[&str] = &["TERM", "HUP", "INT", "KILL"];

/// Absolute candidates for `kill(1)`. util-linux installs it in `/bin` on
/// Debian-family systems and `/usr/bin` on merged-`/usr` systems.
const KILL_BINARIES: &[&str] = &["/bin/kill", "/usr/bin/kill"];

/// `GET /v1/processes` — the process table.
///
/// `?search=` matches name, command line and owner, case-insensitively.
/// `?sort=cpu|memory|pid|name` defaults to `cpu`, because "what is eating my
/// server" is the question this screen exists to answer.
pub fn list(_state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let sort = match req.query_str("sort").as_deref() {
        Some("memory") | Some("mem") => SortKey::Memory,
        Some("pid") => SortKey::Pid,
        Some("name") => SortKey::Name,
        // An unrecognised sort falls back to the default rather than failing:
        // a stale client asking for a key we removed should still get a list.
        _ => SortKey::Cpu,
    };
    let limit = req.query_num::<usize>("limit").unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);

    let query = ProcessQuery {
        search: req.query_str("search").filter(|s| !s.trim().is_empty()),
        sort,
        limit,
    };

    match serveros_linux::list_processes(&query) {
        Ok(processes) => {
            let items = match serveros_linux::process_json(&processes) {
                Value::Array(items) => items,
                _ => Vec::new(),
            };
            collection_with(
                items,
                Object::new().set("sort", sort_name(sort)).set("limit", limit),
            )
        }
        Err(e) => internal("ServerOS couldn't read the process list on this server.", e),
    }
}

fn sort_name(key: SortKey) -> &'static str {
    match key {
        SortKey::Cpu => "cpu",
        SortKey::Memory => "memory",
        SortKey::Pid => "pid",
        SortKey::Name => "name",
    }
}

/// `POST /v1/processes/{pid}/signal` — send one of four signals to one process.
///
/// Body: `{"signal": "TERM"}`. Omitted means `TERM`, the signal that asks
/// politely; `KILL` has to be typed.
///
/// Three refusals happen before anything is executed, and all three matter:
///
///   * **pid 1** is the init system. Signalling it is how a container dies and
///     how a host becomes unbootable-in-place. There is no UI gesture that
///     should reach it, so it is refused rather than confirmed.
///   * **The agent's own pid** would kill the process answering the request —
///     the user would see a dropped connection and no explanation, and would
///     have no way back in without SSH. Restarting the agent is the service
///     manager's job (`POST /v1/services/serveros-agent.service/restart`).
///   * **A pid with no `/proc` entry** does not exist. Checking first turns a
///     confusing "No such process" from a binary into a plain 404, and closes
///     the window where a recycled pid gets signalled instead.
pub fn signal(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let raw_pid = req.param("pid").unwrap_or_default().to_string();

    // A pid that will not parse names no resource, so there is nothing to audit
    // and nothing happened: answer and stop before the record.
    let Ok(pid) = raw_pid.parse::<u32>() else {
        return bad_request("That process id is not a number.");
    };
    if pid == 0 {
        return bad_request("0 is not a process id.");
    }

    let (response, ok, summary) = signal_inner(req, pid);

    record(
        state,
        req,
        principal,
        Event::new("process.signal", "process", pid.to_string())
            .summary(summary)
            .outcome(ok),
    );

    response
}

/// The body of [`signal`], factored out so the caller records exactly one
/// activity event whichever way this returns.
fn signal_inner(req: &Request, pid: u32) -> (Response, bool, String) {
    let body = match crate::api::json_body(req) {
        Ok(body) => body,
        Err(response) => {
            return (response, false, format!("Rejected a malformed signal request for pid {pid}"));
        }
    };

    let signal = match body.get("signal") {
        None | Some(Value::Null) => "TERM".to_string(),
        Some(Value::String(s)) => normalise_signal(s),
        Some(_) => {
            return (
                bad_request("\"signal\" must be a string, for example \"TERM\"."),
                false,
                format!("Rejected a malformed signal request for pid {pid}"),
            );
        }
    };

    if !ALLOWED_SIGNALS.contains(&signal.as_str()) {
        return (
            bad_request(format!(
                "ServerOS can send {} — not \"{signal}\".",
                human_list(ALLOWED_SIGNALS)
            )),
            false,
            format!("Refused an unsupported signal for pid {pid}"),
        );
    }

    if pid == 1 {
        return (
            Response::error(
                Status::FORBIDDEN,
                "refused_dangerous",
                "ServerOS will not signal process 1. It is this server's init system, and \
                 stopping it would take the whole machine down.",
            ),
            false,
            "Refused to signal process 1".to_string(),
        );
    }

    if pid == std::process::id() {
        return (
            Response::error(
                Status::FORBIDDEN,
                "refused_dangerous",
                "ServerOS will not signal its own agent. To restart it, use the ServerOS agent \
                 service instead.",
            ),
            false,
            "Refused to signal the ServerOS agent itself".to_string(),
        );
    }

    if !std::path::Path::new(&format!("/proc/{pid}")).is_dir() {
        return (
            crate::api::not_found("process", &pid.to_string()),
            false,
            format!("No process {pid} to signal"),
        );
    }

    // Read the name before signalling, so the audit summary says what was
    // stopped rather than just its number.
    let name = process_name(pid);

    let Some(binary) = find_binary(KILL_BINARIES) else {
        return (
            unavailable(
                "Signalling processes",
                "the kill(1) binary is not installed at /bin/kill or /usr/bin/kill",
            ),
            false,
            format!("Could not signal {name}: no kill binary on this server"),
        );
    };

    // argv, never a shell: three separate arguments, both of which this module
    // produced (`signal` came from the allow-list, `pid` from a parsed u32).
    let output = Command::new(binary)
        .arg("-s")
        .arg(&signal)
        .arg(pid.to_string())
        .output();

    match output {
        Ok(out) if out.status.success() => (
            Response::json(
                Object::new()
                    .set("pid", pid)
                    .set("name", name.as_str())
                    .set("signal", signal.as_str())
                    .set("sent", true),
            ),
            true,
            format!("Sent SIG{signal} to {name}"),
        ),
        Ok(out) => {
            let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
            (
                Response::error_detail(
                    Status::INTERNAL,
                    "signal_failed",
                    format!("ServerOS couldn't send SIG{signal} to {name}."),
                    if detail.is_empty() {
                        format!("kill exited with status {}", out.status)
                    } else {
                        detail
                    },
                ),
                false,
                format!("Failed to send SIG{signal} to {name}"),
            )
        }
        Err(e) => (
            internal(format!("ServerOS couldn't send SIG{signal} to {name}."), e),
            false,
            format!("Failed to send SIG{signal} to {name}"),
        ),
    }
}

/// `sigterm`, `SIGTERM` and `term` all mean `TERM`.
fn normalise_signal(raw: &str) -> String {
    let upper = raw.trim().to_ascii_uppercase();
    upper.strip_prefix("SIG").unwrap_or(&upper).to_string()
}

/// `/proc/<pid>/comm`, or the pid as a string when it cannot be read.
fn process_name(pid: u32) -> String {
    std::fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim().to_string())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("process {pid}"))
}

/// `["A","B","C"]` -> `"A, B or C"`, for a message a person reads.
fn human_list(items: &[&str]) -> String {
    match items {
        [] => String::new(),
        [only] => (*only).to_string(),
        [rest @ .., last] => format!("{} or {last}", rest.join(", ")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signal_names_are_normalised() {
        assert_eq!(normalise_signal("term"), "TERM");
        assert_eq!(normalise_signal("SIGKILL"), "KILL");
        assert_eq!(normalise_signal("  sighup "), "HUP");
        assert_eq!(normalise_signal("STOP"), "STOP");
    }

    #[test]
    fn only_four_signals_are_allowed() {
        for good in ["TERM", "HUP", "INT", "KILL"] {
            assert!(ALLOWED_SIGNALS.contains(&good));
        }
        // STOP and CONT leave a process in a state a GUI cannot explain; USR1
        // and friends are application-defined. None of them belongs here.
        for bad in ["STOP", "CONT", "USR1", "SEGV", "9", ""] {
            assert!(!ALLOWED_SIGNALS.contains(&bad), "{bad} must not be allowed");
        }
    }

    #[test]
    fn human_list_reads_like_a_sentence() {
        assert_eq!(human_list(&["TERM", "HUP", "INT", "KILL"]), "TERM, HUP, INT or KILL");
        assert_eq!(human_list(&["TERM"]), "TERM");
    }

    #[test]
    fn process_name_falls_back_when_proc_is_unreadable() {
        // Pid 0 never exists, so this exercises the fallback rather than /proc.
        assert_eq!(process_name(0), "process 0");
    }

    #[test]
    fn sort_names_round_trip() {
        assert_eq!(sort_name(SortKey::Cpu), "cpu");
        assert_eq!(sort_name(SortKey::Memory), "memory");
        assert_eq!(sort_name(SortKey::Pid), "pid");
        assert_eq!(sort_name(SortKey::Name), "name");
    }
}
