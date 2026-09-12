//! The live channel.
//!
//! One WebSocket at `/v1/stream` carries everything the desktop app needs to
//! keep a server view current: metrics, container state, service state and new
//! activity. The app subscribes to the channels the visible screen actually
//! needs and unsubscribes when it navigates away, so a window sitting on the
//! Files screen is not paying for container polling.
//!
//! # Why one socket rather than polling
//!
//! Polling four endpoints every two seconds means four TCP round trips through
//! an SSH tunnel, four token verifications, and a metrics sampler that never
//! sees two consecutive samples from the same caller (so CPU percentages would
//! be wrong). One socket with a server-side sampler fixes all three.
//!
//! # Backpressure
//!
//! The producer never queues. If a send blocks because the client is not
//! reading, the tick is simply skipped — a late metric is worthless, and a
//! growing queue is how an agent runs a server out of memory.

use crate::auth::Scope;
use crate::state::AgentState;
use serveros_http::ws::{self, Message, WsSender};
use serveros_http::{Request, Response, Status};
use serveros_json::{Object, Value};
use std::collections::BTreeSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Channels a client may subscribe to.
pub const CHANNELS: &[&str] = &["metrics", "docker", "services", "activity"];

/// How often each channel is refreshed. Metrics are the only genuinely
/// high-frequency thing; container and service state change rarely and polling
/// them at metric speed would be pure waste.
fn channel_interval(channel: &str, metrics_secs: u64) -> Duration {
    match channel {
        "metrics" => Duration::from_secs(metrics_secs),
        "docker" => Duration::from_secs(5),
        "services" => Duration::from_secs(10),
        "activity" => Duration::from_secs(3),
        _ => Duration::from_secs(10),
    }
}

/// Upgrade `/v1/stream` to a WebSocket.
pub fn handle_stream(state: &Arc<AgentState>, req: Request) -> Response {
    // The token may arrive in the Authorization header (what the desktop app
    // does) or as a query parameter (so `websocat` and curl-style debugging
    // work). Query tokens are single-use and expire in minutes like any other,
    // and the agent never logs a request target for this route.
    let query_token = req.query_str("token");
    let token = req.bearer_token().map(|s| s.to_string()).or(query_token);

    let peer = req.peer.describe();
    let principal = match state.auth.authorise(token.as_deref(), &peer, Scope::Read) {
        Ok(p) => p,
        // Refuse exactly the way every guarded route refuses — including the
        // `WWW-Authenticate` challenge and the `Retry-After` on a lockout — so
        // the app has one credential-failure path rather than two.
        Err(e) => return crate::api::auth_error_response(e),
    };

    if !req.is_websocket_upgrade() {
        return Response::error(
            Status::BAD_REQUEST,
            "upgrade_required",
            "This endpoint is a WebSocket. Connect with an Upgrade: websocket request.",
        );
    }

    let state = Arc::clone(state);
    let subject = principal.subject.clone();

    ws::accept(&req, move |mut receiver, sender| {
        let session = Arc::new(Session {
            state,
            subscriptions: Mutex::new(BTreeSet::new()),
            closed: AtomicBool::new(false),
        });

        let welcome = Object::new()
            .set("type", "welcome")
            .set("agent_version", crate::VERSION)
            .set("api_version", crate::API_VERSION)
            .set("server_id", session.state.config.server_id.as_str())
            .set("channels", Value::array(CHANNELS.to_vec()))
            .set("metrics_interval_ms", session.state.config.metrics_interval_secs * 1000)
            .set("capabilities", session.state.capabilities());
        if sender.send_text(&Value::Object(welcome).to_string()).is_err() {
            return;
        }

        let keepalive = ws::spawn_keepalive(sender.clone(), Duration::from_secs(30));
        let producer = spawn_producer(session.clone(), sender.clone());

        // Receive loop owns the session lifetime: when it ends, the producer
        // and keepalive threads notice through `closed` and wind down.
        loop {
            match receiver.recv(&sender) {
                Ok(Message::Text(text)) => {
                    if let Some(reply) = session.handle_client_message(&text) {
                        if sender.send_text(&reply).is_err() {
                            break;
                        }
                    }
                }
                Ok(Message::Close { .. }) => {
                    let _ = sender.close(1000, "bye");
                    break;
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }

        session.closed.store(true, Ordering::SeqCst);
        let _ = sender.close(1000, "closing");
        let _ = producer.join();
        drop(keepalive);

        crate::logging::debug_with(
            "stream closed",
            Object::new().set("subject", subject.as_str()),
        );
    })
}

struct Session {
    state: Arc<AgentState>,
    subscriptions: Mutex<BTreeSet<String>>,
    closed: AtomicBool,
}

impl Session {
    fn handle_client_message(&self, text: &str) -> Option<String> {
        let Ok(msg) = serveros_json::from_str(text) else {
            return Some(error_frame("invalid_json", "That message was not valid JSON."));
        };
        let kind = msg.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match kind {
            "subscribe" | "unsubscribe" => {
                let requested: Vec<String> = msg
                    .get("channels")
                    .and_then(|v| v.as_array())
                    .map(|items| {
                        items.iter().filter_map(|i| i.as_str()).map(str::to_string).collect()
                    })
                    .unwrap_or_default();

                let unknown: Vec<&String> =
                    requested.iter().filter(|c| !CHANNELS.contains(&c.as_str())).collect();
                if !unknown.is_empty() {
                    return Some(error_frame(
                        "unknown_channel",
                        &format!(
                            "Unknown channel: {}. Known channels are {}.",
                            unknown.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", "),
                            CHANNELS.join(", ")
                        ),
                    ));
                }

                let mut subs = self.subscriptions.lock().ok()?;
                for channel in requested {
                    if kind == "subscribe" {
                        subs.insert(channel);
                    } else {
                        subs.remove(&channel);
                    }
                }
                let list: Vec<&str> = subs.iter().map(|s| s.as_str()).collect();
                Some(
                    Value::Object(
                        Object::new()
                            .set("type", "subscribed")
                            .set("channels", Value::array(list)),
                    )
                    .to_string(),
                )
            }
            "ping" => Some(
                Value::Object(Object::new().set("type", "pong").set("at", crate::auth::now_unix()))
                    .to_string(),
            ),
            other => Some(error_frame(
                "unknown_message",
                &format!("Unrecognised message type \"{other}\"."),
            )),
        }
    }

    fn is_subscribed(&self, channel: &str) -> bool {
        self.subscriptions.lock().map(|s| s.contains(channel)).unwrap_or(false)
    }
}

fn error_frame(code: &str, message: &str) -> String {
    Value::Object(
        Object::new().set("type", "error").set("code", code).set("message", message),
    )
    .to_string()
}

fn data_frame(channel: &str, data: Value) -> String {
    Value::Object(
        Object::new()
            .set("type", channel)
            .set("at", crate::auth::now_unix())
            .set("data", data),
    )
    .to_string()
}

/// The producer thread: wakes on a short tick and emits whichever channels are
/// both subscribed and due.
fn spawn_producer(session: Arc<Session>, sender: WsSender) -> std::thread::JoinHandle<()> {
    std::thread::Builder::new()
        .name("agent-stream".into())
        .spawn(move || {
            let metrics_secs = session.state.config.metrics_interval_secs;
            let mut last: Vec<(String, Instant)> = CHANNELS
                .iter()
                .map(|c| ((*c).to_string(), Instant::now() - Duration::from_secs(3600)))
                .collect();
            let mut last_activity_id: u64 = 0;

            while !session.closed.load(Ordering::Relaxed) && !sender.is_closed() {
                std::thread::sleep(Duration::from_millis(250));

                for (channel, last_sent) in last.iter_mut() {
                    if session.closed.load(Ordering::Relaxed) {
                        return;
                    }
                    if !session.is_subscribed(channel) {
                        continue;
                    }
                    if last_sent.elapsed() < channel_interval(channel, metrics_secs) {
                        continue;
                    }

                    let frame = match channel.as_str() {
                        "metrics" => produce_metrics(&session.state),
                        "docker" => produce_docker(&session.state),
                        "services" => produce_services(&session.state),
                        "activity" => produce_activity(&session.state, &mut last_activity_id),
                        _ => None,
                    };

                    *last_sent = Instant::now();

                    if let Some(frame) = frame {
                        // A failed send means the peer is gone or not reading.
                        // Either way the session is over; do not queue.
                        if sender.send_text(&frame).is_err() {
                            session.closed.store(true, Ordering::SeqCst);
                            return;
                        }
                    }
                }
            }
        })
        .expect("spawn stream producer")
}

fn produce_metrics(state: &AgentState) -> Option<String> {
    let mut sampler = state.sampler.lock().ok()?;
    match sampler.sample() {
        Ok(metrics) => Some(data_frame("metrics", metrics.to_json())),
        Err(e) => Some(error_frame("metrics_unavailable", &e.to_string())),
    }
}

fn produce_docker(state: &AgentState) -> Option<String> {
    let docker = state.docker()?;
    match docker.list(true) {
        Ok(containers) => {
            let items: Vec<Value> = containers.iter().map(|c| c.to_json()).collect();
            // `Container` has no `is_running()`; Docker's state is a string and
            // the crate keeps it verbatim rather than inventing an enum the
            // daemon might outgrow. `running` is the one value the app counts.
            let running = containers.iter().filter(|c| c.state == "running").count();
            Some(data_frame(
                "docker",
                Object::new()
                    .set("total", items.len())
                    .set("running", running)
                    .set("containers", Value::Array(items))
                    .into(),
            ))
        }
        Err(e) => Some(error_frame("docker_unavailable", &e.to_string())),
    }
}

fn produce_services(state: &AgentState) -> Option<String> {
    let services = state.services()?;
    match services.list_units() {
        Ok(units) => {
            let items: Vec<Value> = units.iter().map(|u| u.to_json()).collect();
            Some(data_frame(
                "services",
                Object::new().set("total", items.len()).set("units", Value::Array(items)).into(),
            ))
        }
        Err(e) => Some(error_frame("services_unavailable", &e.to_string())),
    }
}

fn produce_activity(state: &AgentState, last_id: &mut u64) -> Option<String> {
    let events = state.activity.recent(50, Some(*last_id));
    if events.is_empty() {
        return None; // nothing new: say nothing
    }
    if let Some(newest) = events.first().and_then(|v| v.get("id")).and_then(|v| v.as_u64()) {
        *last_id = newest;
    }
    Some(data_frame("activity", Object::new().set("events", Value::Array(events)).into()))
}
