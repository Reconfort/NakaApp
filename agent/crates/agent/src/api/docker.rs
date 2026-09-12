//! Containers, images, volumes, networks and the daemon itself.
//!
//! Delegation to `serveros-docker`, which speaks the Engine API over its Unix
//! socket. The HTTP layer adds four things the crate deliberately does not:
//!
//!   * **"Docker isn't here" is a state, not a failure.** A server without
//!     Docker is an ordinary server. It answers 503 with a sentence, and the
//!     app draws an empty state rather than an error.
//!   * **Cost control on list views.** `?stats=true` is genuinely expensive —
//!     the daemon holds each stats request open for about a second to produce a
//!     CPU delta — so it is opt-in and capped. See [`STATS_FANOUT_LIMIT`].
//!   * **Revealing masked environment is an authorisation decision.** See
//!     [`inspect_container`].
//!   * **One audit record per state change**, phrased for the activity feed.

use crate::activity::Event;
use crate::api::{collection, collection_with, record, unavailable};
use crate::auth::{Principal, Scope};
use crate::state::AgentState;
use serveros_docker::{DockerClient, DockerError, Frame, LogStream, StreamKind};
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use std::io::Write;
use std::sync::Arc;

/// How many containers `?stats=true` will sample in one request.
///
/// Each sample costs a round trip the daemon deliberately holds open for ~1s
/// (`one-shot=false`, so `precpu_stats` is populated and the CPU percentage is
/// real). On a 200-container host, sampling everything would make one list call
/// take minutes and hold a connection thread for all of it. The list is already
/// ordered as the daemon returns it, so the cap takes the first 25 and reports
/// `stats_truncated` rather than silently doing less than it was asked.
const STATS_FANOUT_LIMIT: usize = 25;

/// Default number of log lines. Roughly two screens.
const DEFAULT_TAIL: usize = 200;
/// Ceiling on `?tail`. Beyond this the app should be following, not paging.
const MAX_TAIL: usize = 5_000;

/// Content type for a followed log stream: one JSON object per line.
const NDJSON: &str = "application/x-ndjson";

/// Why Docker might be missing, phrased for the 503's `detail`.
const NO_DOCKER_REASON: &str =
    "the Docker daemon socket is not present or the agent cannot open it";

/// `GET /v1/docker` — the daemon itself: version, driver, counts.
pub fn info(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    match docker.info() {
        Ok(info) => Response::json(info.to_json()),
        Err(e) => docker_response(e),
    }
}

/// `GET /v1/docker/containers` — the container list.
///
/// `?all=true` includes stopped containers. `?stats=true` additionally samples
/// live CPU and memory for up to [`STATS_FANOUT_LIMIT`] of them.
pub fn list_containers(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };

    let all = req.query_flag("all");
    let mut containers = match docker.list(all) {
        Ok(containers) => containers,
        Err(e) => return docker_response(e),
    };

    let want_stats = req.query_flag("stats");
    let mut sampled = 0usize;
    if want_stats {
        for container in containers.iter_mut().take(STATS_FANOUT_LIMIT) {
            // A container that exits between the list and the sample is not an
            // error — it is a race the UI resolves on the next refresh. Skip it
            // and keep the row.
            if let Ok(stats) = docker.stats_once(&container.id) {
                container.apply_stats(&stats);
                sampled += 1;
            }
        }
    }

    let running = containers.iter().filter(|c| c.state == "running").count();
    let items: Vec<Value> = containers.iter().map(|c| c.to_json()).collect();

    collection_with(
        items,
        Object::new()
            .set("running", running)
            .set("stats_sampled", sampled)
            .set("stats_truncated", want_stats && containers.len() > STATS_FANOUT_LIMIT),
    )
}

/// `GET /v1/docker/containers/{id}` — one container in full.
///
/// # `?reveal=true`
///
/// `Config.Env` is where `POSTGRES_PASSWORD` and `STRIPE_SECRET_KEY` live, so
/// the crate masks secret-looking values by default. Unmasking them is a
/// privileged read, not a display preference:
///
///   * it requires `admin` scope — `write` is enough to restart production, and
///     still not enough to read its credentials;
///   * the flag is *ignored*, not rejected, for anyone else, so a client that
///     always sends it degrades to masked output instead of failing; and
///   * it writes an audit record. Reads are not normally recorded, but "who
///     read the database password, and when" is a question an operator will
///     eventually need answered.
pub fn inspect_container(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    let id = req.param("id").unwrap_or_default().to_string();

    let asked_to_reveal = req.query_flag("reveal");
    let reveal = asked_to_reveal && principal.has(Scope::Admin);

    match docker.inspect(&id) {
        Ok(detail) => {
            if reveal {
                record(
                    state,
                    req,
                    principal,
                    Event::new("docker.container.reveal_env", "container", &detail.container.name)
                        .summary(format!(
                            "Revealed the environment variables of {}",
                            detail.container.name
                        )),
                );
            }
            Response::json(detail.to_json_with(reveal))
        }
        Err(e) => docker_response(e),
    }
}

/// `GET /v1/docker/containers/{id}/stats` — one live sample.
pub fn container_stats(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    let id = req.param("id").unwrap_or_default().to_string();

    match docker.stats_once(&id) {
        Ok(stats) => Response::json(stats.to_json()),
        Err(e) => docker_response(e),
    }
}

/// `GET /v1/docker/containers/{id}/logs` — recent output, or a live follow.
///
/// `?tail=` (default 200, capped at 5000), `?since=<unix seconds>`,
/// `?timestamps=true`, `?follow=true`.
///
/// Following returns newline-delimited JSON on a chunked response rather than a
/// JSON array, and flushes after every line. That is the difference between a
/// log view that fills in as the container speaks and one that shows nothing
/// until the container stops — and an array could never be closed at all.
pub fn container_logs(state: &AgentState, req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    let id = req.param("id").unwrap_or_default().to_string();
    let tail = req.query_num::<usize>("tail").unwrap_or(DEFAULT_TAIL).min(MAX_TAIL);
    let since = req.query_num::<i64>("since");
    let timestamps = req.query_flag("timestamps");

    if !req.query_flag("follow") {
        return match docker.logs(&id, tail, since, timestamps) {
            Ok(lines) => {
                let items: Vec<Value> = lines.iter().map(|l| l.to_json()).collect();
                collection_with(items, Object::new().set("container", id.as_str()))
            }
            Err(e) => docker_response(e),
        };
    }

    let stream = match docker.logs_frames(&id, tail, since, timestamps) {
        Ok(stream) => stream,
        Err(e) => return docker_response(e),
    };

    Response::stream(NDJSON, move |out| stream_logs(stream, timestamps, out))
}

/// Write a followed log stream as NDJSON, one flush per line.
///
/// A write failure ends the follow: the client has gone, and there is nobody
/// left to buffer for.
fn stream_logs(
    mut stream: LogStream,
    timestamps: bool,
    out: &mut dyn Write,
) -> std::io::Result<()> {
    let mut splitter = LineSplitter::default();
    loop {
        match stream.next_frame() {
            Ok(Some(frame)) => {
                for line in splitter.push(frame, timestamps) {
                    writeln!(out, "{line}")?;
                    out.flush()?;
                }
            }
            Ok(None) => break,
            // A truncated frame ends the stream cleanly rather than failing the
            // response: the lines already delivered are still correct.
            Err(_) => break,
        }
    }
    for line in splitter.flush(timestamps) {
        writeln!(out, "{line}")?;
    }
    out.flush()
}

/// Reassembles Docker frames into whole lines.
///
/// Frames are chunks of a socket read, not lines: a long log line routinely
/// arrives split across two of them, and stdout and stderr interleave. Emitting
/// per frame would tear such a line in half on screen, so bytes are held per
/// stream until their newline arrives.
#[derive(Default)]
struct LineSplitter {
    pending: Vec<(StreamKind, Vec<u8>)>,
}

impl LineSplitter {
    fn push(&mut self, frame: Frame, timestamps: bool) -> Vec<String> {
        let slot = match self.pending.iter().position(|(k, _)| *k == frame.stream) {
            Some(i) => i,
            None => {
                self.pending.push((frame.stream, Vec::new()));
                self.pending.len() - 1
            }
        };
        self.pending[slot].1.extend_from_slice(&frame.data);

        let Some(last) = self.pending[slot].1.iter().rposition(|b| *b == b'\n') else {
            return Vec::new();
        };
        let complete: Vec<u8> = self.pending[slot].1.drain(..=last).collect();
        render(frame.stream, complete, timestamps)
    }

    /// Emit whatever is left when the stream ends, newline or not. A container
    /// that dies mid-line still said something worth showing.
    fn flush(&mut self, timestamps: bool) -> Vec<String> {
        let mut out = Vec::new();
        for (stream, buf) in std::mem::take(&mut self.pending) {
            if !buf.is_empty() {
                out.extend(render(stream, buf, timestamps));
            }
        }
        out
    }
}

/// Reuse the crate's own frame-to-line mapping, so timestamp parsing and
/// stream labelling behave identically here and in the non-follow path.
fn render(stream: StreamKind, data: Vec<u8>, timestamps: bool) -> Vec<String> {
    serveros_docker::containers::frames_to_lines(&[Frame { stream, data }], timestamps)
        .iter()
        .map(|line| line.to_json().to_string())
        .collect()
}

/// `POST /v1/docker/containers/{id}/start`
pub fn start(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    lifecycle(state, req, principal, Lifecycle::Start)
}

/// `POST /v1/docker/containers/{id}/stop` — `?t=` seconds of grace before
/// SIGKILL (Docker's own default is 10).
pub fn stop(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    lifecycle(state, req, principal, Lifecycle::Stop)
}

/// `POST /v1/docker/containers/{id}/restart` — also honours `?t=`.
pub fn restart(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    lifecycle(state, req, principal, Lifecycle::Restart)
}

/// `POST /v1/docker/containers/{id}/pause`
pub fn pause(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    lifecycle(state, req, principal, Lifecycle::Pause)
}

/// `POST /v1/docker/containers/{id}/unpause`
pub fn unpause(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    lifecycle(state, req, principal, Lifecycle::Unpause)
}

/// `DELETE /v1/docker/containers/{id}` — `?force=true` removes a running
/// container, `?volumes=true` also removes its anonymous volumes.
///
/// Admin scope, because it is the one container operation with nothing to undo.
pub fn remove(state: &AgentState, req: &Request, principal: &Principal) -> Response {
    lifecycle(state, req, principal, Lifecycle::Remove)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Lifecycle {
    Start,
    Stop,
    Restart,
    Pause,
    Unpause,
    Remove,
}

impl Lifecycle {
    fn event(self) -> &'static str {
        match self {
            Lifecycle::Start => "docker.container.start",
            Lifecycle::Stop => "docker.container.stop",
            Lifecycle::Restart => "docker.container.restart",
            Lifecycle::Pause => "docker.container.pause",
            Lifecycle::Unpause => "docker.container.unpause",
            Lifecycle::Remove => "docker.container.remove",
        }
    }

    fn past(self) -> &'static str {
        match self {
            Lifecycle::Start => "Started",
            Lifecycle::Stop => "Stopped",
            Lifecycle::Restart => "Restarted",
            Lifecycle::Pause => "Paused",
            Lifecycle::Unpause => "Resumed",
            Lifecycle::Remove => "Removed",
        }
    }

    fn failed(self) -> &'static str {
        match self {
            Lifecycle::Start => "Could not start",
            Lifecycle::Stop => "Could not stop",
            Lifecycle::Restart => "Could not restart",
            Lifecycle::Pause => "Could not pause",
            Lifecycle::Unpause => "Could not resume",
            Lifecycle::Remove => "Could not remove",
        }
    }

    fn run(self, docker: &Arc<DockerClient>, req: &Request, id: &str) -> Result<(), DockerError> {
        // `?t=` is clamped rather than rejected: a negative grace period is a
        // client bug, not something to fail a restart over.
        let grace = req.query_num::<i64>("t").map(|t| t.clamp(0, 3600));
        match self {
            Lifecycle::Start => docker.start(id),
            Lifecycle::Stop => docker.stop(id, grace),
            Lifecycle::Restart => docker.restart(id, grace),
            Lifecycle::Pause => docker.pause(id),
            Lifecycle::Unpause => docker.unpause(id),
            Lifecycle::Remove => {
                docker.remove(id, req.query_flag("force"), req.query_flag("volumes"))
            }
        }
    }
}

fn lifecycle(
    state: &AgentState,
    req: &Request,
    principal: &Principal,
    action: Lifecycle,
) -> Response {
    let id = req.param("id").unwrap_or_default().to_string();

    let (response, ok, summary, name) = match client(state) {
        Err(response) => (
            response,
            false,
            format!("{} {id}: Docker is not available on this server", action.failed()),
            id.clone(),
        ),
        Ok(docker) => {
            // Resolve the name before acting: after a removal there is nothing
            // left to ask, and "Removed estatify-api" is the line the activity
            // feed needs — "Removed 9f2c1ab3de77" is not.
            let name = docker
                .inspect(&id)
                .map(|d| d.container.name)
                .unwrap_or_else(|_| id.clone());

            match action.run(&docker, req, &id) {
                Ok(()) => (
                    Response::json(
                        Object::new()
                            .set("id", id.as_str())
                            .set("name", name.as_str())
                            .set("action", action.event())
                            .set("ok", true),
                    ),
                    true,
                    format!("{} {name}", action.past()),
                    name,
                ),
                Err(e) => {
                    let summary = format!("{} {name}", action.failed());
                    (docker_response(e), false, summary, name)
                }
            }
        }
    };

    record(
        state,
        req,
        principal,
        Event::new(action.event(), "container", name)
            .summary(summary)
            .meta("container_id", id.as_str())
            .outcome(ok),
    );
    response
}

/// `GET /v1/docker/images`
pub fn images(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    match docker.images() {
        Ok(images) => collection(images.iter().map(|i| i.to_json()).collect()),
        Err(e) => docker_response(e),
    }
}

/// `GET /v1/docker/volumes`
pub fn volumes(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    match docker.volumes() {
        Ok(volumes) => collection(volumes.iter().map(|v| v.to_json()).collect()),
        Err(e) => docker_response(e),
    }
}

/// `GET /v1/docker/networks`
pub fn networks(state: &AgentState, _req: &Request, _principal: &Principal) -> Response {
    let docker = match client(state) {
        Ok(docker) => docker,
        Err(response) => return response,
    };
    match docker.networks() {
        Ok(networks) => collection(networks.iter().map(|n| n.to_json()).collect()),
        Err(e) => docker_response(e),
    }
}

/// The Docker client, or the 503 that says this host has no Docker.
pub(crate) fn client(state: &AgentState) -> Result<Arc<DockerClient>, Response> {
    state.docker().ok_or_else(|| unavailable("Docker", NO_DOCKER_REASON))
}

/// Map a `DockerError` onto the agent's error envelope.
///
/// Docker's own message is worth keeping verbatim in `detail` — "container
/// already started", "port is already allocated" — because it is frequently the
/// most useful sentence available. It is not used as the user-facing `message`,
/// which stays in the product's voice and ends in a full stop.
pub(crate) fn docker_response(e: DockerError) -> Response {
    let (status, message) = match &e {
        DockerError::Unavailable => {
            return unavailable("Docker", NO_DOCKER_REASON);
        }
        DockerError::NotFound(_) => (
            Status::NOT_FOUND,
            "That container no longer exists on this server.".to_string(),
        ),
        DockerError::Api { status: 409, .. } => (
            Status::CONFLICT,
            "Docker refused that because the container is not in a state where it makes sense."
                .to_string(),
        ),
        DockerError::Api { status: 400, .. } => (
            Status::BAD_REQUEST,
            "Docker rejected that request.".to_string(),
        ),
        DockerError::Api { .. } => (Status::BAD_GATEWAY, "Docker refused that operation.".to_string()),
        DockerError::Transport(_) => (
            Status::BAD_GATEWAY,
            "ServerOS lost its connection to the Docker daemon on this server.".to_string(),
        ),
        DockerError::Decode(_) => (
            Status::BAD_GATEWAY,
            "ServerOS couldn't understand the Docker daemon's response.".to_string(),
        ),
    };
    Response::error_detail(status, e.code(), message, e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(stream: StreamKind, text: &str) -> Frame {
        Frame { stream, data: text.as_bytes().to_vec() }
    }

    #[test]
    fn a_line_split_across_frames_is_emitted_once_and_whole() {
        let mut splitter = LineSplitter::default();
        assert!(splitter.push(frame(StreamKind::Stdout, "hello, "), false).is_empty());
        let lines = splitter.push(frame(StreamKind::Stdout, "world\n"), false);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("hello, world"), "{}", lines[0]);
    }

    #[test]
    fn stdout_and_stderr_do_not_bleed_into_each_other() {
        let mut splitter = LineSplitter::default();
        assert!(splitter.push(frame(StreamKind::Stdout, "out-part"), false).is_empty());
        let err = splitter.push(frame(StreamKind::Stderr, "boom\n"), false);
        assert_eq!(err.len(), 1);
        assert!(err[0].contains("boom") && err[0].contains("stderr"), "{}", err[0]);

        let out = splitter.push(frame(StreamKind::Stdout, "ial\n"), false);
        assert_eq!(out.len(), 1);
        assert!(out[0].contains("out-partial"), "{}", out[0]);
    }

    #[test]
    fn a_final_line_without_a_newline_is_still_delivered() {
        let mut splitter = LineSplitter::default();
        assert!(splitter.push(frame(StreamKind::Stdout, "dying words"), false).is_empty());
        let tail = splitter.flush(false);
        assert_eq!(tail.len(), 1);
        assert!(tail[0].contains("dying words"));
    }

    #[test]
    fn every_emitted_line_is_one_json_object() {
        let mut splitter = LineSplitter::default();
        let lines = splitter.push(frame(StreamKind::Stdout, "a\nb\nc\n"), false);
        assert_eq!(lines.len(), 3);
        for line in &lines {
            assert!(!line.contains('\n'), "NDJSON lines may not contain newlines: {line}");
            let parsed = serveros_json::from_str(line).expect("valid JSON");
            assert!(parsed.get("message").is_some());
        }
    }

    #[test]
    fn docker_errors_map_to_states_the_ui_has_a_screen_for() {
        assert_eq!(docker_response(DockerError::Unavailable).status, Status::SERVICE_UNAVAILABLE);
        assert_eq!(
            docker_response(DockerError::NotFound("no such container".into())).status,
            Status::NOT_FOUND
        );
        assert_eq!(
            docker_response(DockerError::Api { status: 409, message: "already started".into() })
                .status,
            Status::CONFLICT
        );
        assert_eq!(
            docker_response(DockerError::Transport("reset".into())).status,
            Status::BAD_GATEWAY
        );
    }

    #[test]
    fn the_stats_fanout_cap_is_small_enough_to_stay_interactive() {
        // 25 samples at ~1s each is already slow; the point of the constant is
        // that it can never become "however many containers this host has".
        assert!(STATS_FANOUT_LIMIT <= 25);
        assert!(MAX_TAIL >= DEFAULT_TAIL);
    }
}
